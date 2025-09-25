#include "vdi_container_manager.h"

#include "vdi_broker_config.h"

void vdi_log_refresh_outcome(bool refreshed, bool reloaded);

#include <curl/curl.h>
#include <json/json.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <system_error>
#include <thread>

namespace
{
constexpr char kPodmanSocket[] = "/var/run/podman/podman.sock";
const std::string kPodmanApiBase = "http://d/v5.3.0/libpod/containers/";

using namespace std::chrono_literals;

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    const auto total = size * nmemb;
    auto* buffer = static_cast<std::string*>(userp);
    buffer->append(static_cast<const char*>(contents), total);
    return total;
}

std::string BuildUrl(const std::string& containerName, const std::string& endpoint)
{
    std::string url = kPodmanApiBase;
    url.append(containerName);
    url.append(endpoint);
    return url;
}

bool BuildImageFromDockerfile(const std::string& image, const std::string& dockerfilePath)
{
    if (dockerfilePath.empty())
    {
        std::cerr << "Dockerfile path not configured; unable to build image " << image << std::endl;
        return false;
    }

    std::filesystem::path dockerfile(dockerfilePath);
    if (!std::filesystem::exists(dockerfile))
    {
        std::cerr << "Dockerfile not found at " << dockerfilePath << std::endl;
        return false;
    }

    std::filesystem::path context = dockerfile.parent_path();
    if (context.empty())
        context = std::filesystem::path(".");

    std::string command = "podman build -t \"" + image + "\" -f \"" + dockerfile.generic_string() +
                          "\" \"" + context.generic_string() + "\"";

    std::clog << "Building Podman image '" << image << "' using Dockerfile " << dockerfilePath << std::endl;

    const int rc = std::system(command.c_str());
    if (rc != 0)
    {
        std::cerr << "podman build failed with exit code " << rc << std::endl;
        return false;
    }

    std::clog << "Successfully built Podman image '" << image << "'" << std::endl;
    return true;
}

std::string GetContainerInfo(const std::string& containerName, const std::string& endpoint)
{
    CURL* curl = curl_easy_init();
    if (!curl)
        return {};

    std::string response;
    std::string url = BuildUrl(containerName, endpoint);

    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, kPodmanSocket);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    const CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        std::cerr << "Failed to query container info: " << curl_easy_strerror(res) << std::endl;
        curl_easy_cleanup(curl);
        return {};
    }

    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);

    if (httpCode == 404)
        return {};
    if (httpCode >= 400)
    {
        std::cerr << "HTTP error code: " << httpCode << std::endl;
        return {};
    }

    return response;
}

bool ContainerExistsInternal(const std::string& containerName)
{
    const std::string payload = GetContainerInfo(containerName, "/json");
    if (payload.empty())
        std::clog << "Container does not exist: " << containerName << std::endl;
    return !payload.empty();
}

bool ContainerRunningInternal(const std::string& containerName)
{
    const std::string payload = GetContainerInfo(containerName, "/json");
    if (payload.empty())
        return false;

    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errs;
    std::istringstream stream(payload);

    if (!Json::parseFromStream(builder, stream, &root, &errs))
    {
        std::cerr << "Failed to parse container info: " << errs << std::endl;
        return false;
    }

    const auto status = root["State"]["Status"].asString();
    return status == "running";
}

bool WaitForProcessInternal(const std::string& containerName, const std::string& processName)
{
    std::clog << "Waiting for <" << processName << "> in container: " << containerName << std::endl;

    for (int attempts = 0; attempts < 10; attempts++)
    {
        const std::string response = GetContainerInfo(containerName, "/top");
        if (response.empty())
        {
            std::this_thread::sleep_for(2s);
            continue;
        }

        Json::Value root;
        Json::CharReaderBuilder builder;
        std::string errs;
        std::istringstream stream(response);

        if (!Json::parseFromStream(builder, stream, &root, &errs))
        {
            std::cerr << "Error parsing JSON: " << errs << std::endl;
            return false;
        }

        const auto& processes = root["Processes"];
        if (!processes.isArray())
        {
            std::cerr << "Invalid JSON: 'Processes' missing or not array" << std::endl;
            return false;
        }

        for (const auto& process : processes)
        {
            if (!process.isArray() || process.empty())
                continue;

            if (process[process.size() - 1].asString() == processName)
                return true;
        }

        std::this_thread::sleep_for(2s);
    }

    return false;
}

Json::Value BuildCreatePayload(const std::string& containerName, const std::string& username)
{
    auto& config = vdi::Config();

    Json::Value root(Json::objectValue);
    root["name"] = containerName;
    root["hostname"] = containerName;
    root["image"] = config.PodmanImage();

    Json::Value caps(Json::arrayValue);
    caps.append("SYS_ADMIN");
    caps.append("NET_ADMIN");
    caps.append("SYS_PTRACE");
    caps.append("AUDIT_CONTROL");
    root["cap_add"] = caps;

    Json::Value devices(Json::arrayValue);
    Json::Value fuse(Json::objectValue);
    fuse["path"] = "/dev/fuse";
    devices.append(fuse);

    const auto driDevice = config.DriDevice();
    if (!driDevice.empty())
    {
        Json::Value dri(Json::objectValue);
        dri["path"] = driDevice;
        devices.append(dri);
    }
    root["devices"] = devices;
    root["systemd"] = "always";

    Json::Value env(Json::objectValue);
    env["GSK_RENDERER"] = "ngl";
    root["env"] = env;

    Json::Value mounts(Json::arrayValue);
    auto appendMount = [&mounts](const std::string& source, const std::string& destination, bool readOnly) {
        if (source.empty() || destination.empty())
            return;
        Json::Value mount(Json::objectValue);
        mount["Source"] = source;
        mount["Destination"] = destination;
        mount["Type"] = "bind";
        if (readOnly)
            mount["ReadOnly"] = true;
        mounts.append(mount);
    };

    appendMount("/etc/vdi", "/etc/vdi", true);
    appendMount(config.PasswdPath(), "/etc/passwd", true);
    appendMount(config.GroupPath(), "/etc/group", true);
    appendMount(config.ShadowPath(), "/etc/shadow", true);
    appendMount(config.HomePath(), "/home", false);

    const auto pamPath = config.PamPath();
    if (!pamPath.empty())
        appendMount(pamPath, pamPath, true);

    root["mounts"] = mounts;

    Json::Value command(Json::arrayValue);
    command.append("/usr/sbin/init");
    root["command"] = command;

    return root;
}

bool CreateContainerInternal(const std::string& containerName, const std::string& username,
                             bool allowBuild = true)
{
    CURL* curl = curl_easy_init();
    if (!curl)
        return false;

    const Json::Value payload = BuildCreatePayload(containerName, username);
    Json::StreamWriterBuilder writerBuilder;
    writerBuilder["indentation"] = "";
    const std::string payloadStr = Json::writeString(writerBuilder, payload);

    std::clog << "Creating container " << containerName << " with payload: " << payloadStr << std::endl;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    const std::string url = kPodmanApiBase + std::string("create");
    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, kPodmanSocket);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payloadStr.c_str());

    const CURLcode res = curl_easy_perform(curl);
    bool success = false;
    bool missingImage = false;

    if (res == CURLE_OK)
    {
        long httpCode = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
        success = (httpCode >= 200 && httpCode < 300);
        if (!success)
        {
            std::cerr << "Failed to create container, HTTP code: " << httpCode << std::endl;
            if (httpCode == 404)
                missingImage = true;
        }
    }
    else
    {
        std::cerr << "Failed to create container: " << curl_easy_strerror(res) << std::endl;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (!success && missingImage && allowBuild)
    {
        auto& config = vdi::Config();
        const std::string image = config.PodmanImage();
        const std::string dockerfile = config.DockerfilePath();
        if (BuildImageFromDockerfile(image, dockerfile))
            return CreateContainerInternal(containerName, username, false);
    }

    return success;
}

bool StartContainerInternal(const std::string& containerName)
{
    CURL* curl = curl_easy_init();
    if (!curl)
        return false;

    const std::string url = BuildUrl(containerName, "/start");

    std::clog << "Starting container: " << containerName << std::endl;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, kPodmanSocket);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "{}");

    const CURLcode res = curl_easy_perform(curl);
    bool success = false;

    if (res == CURLE_OK)
    {
        long httpCode = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
        success = (httpCode >= 200 && httpCode < 300);
        if (!success)
            std::cerr << "Failed to start container, HTTP code: " << httpCode << std::endl;
    }
    else
    {
        std::cerr << "Failed to start container: " << curl_easy_strerror(res) << std::endl;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success;
}

std::string GetContainerIpInternal(const std::string& containerName)
{
    const std::string payload = GetContainerInfo(containerName, "/json");
    if (payload.empty())
        return {};

    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errs;
    std::istringstream stream(payload);

    if (!Json::parseFromStream(builder, stream, &root, &errs))
    {
        std::cerr << "Failed to parse container JSON info: " << errs << std::endl;
        return {};
    }

    const auto& networks = root["NetworkSettings"]["Networks"];
    if (!networks.isObject())
    {
        std::cerr << "No network information available for container." << std::endl;
        return {};
    }

    for (const auto& name : networks.getMemberNames())
    {
        const auto& network = networks[name];
        const std::string ip = network["IPAddress"].asString();
        if (!ip.empty())
        {
            std::clog << "Found IP: " << ip << std::endl;
            return ip;
        }
    }

    return {};
}
} // namespace

namespace vdi
{

std::string ManageContainer(const std::string& username, const std::string& containerPrefix)
{
    auto& configuration = Config();
    const bool refreshed = configuration.Refresh();
    const bool reloaded = configuration.ConsumeReloadedFlag();
    if (reloaded || !refreshed)
        vdi_log_refresh_outcome(refreshed, reloaded);

    const std::string prefix = containerPrefix.empty() ? std::string("vdi-") : containerPrefix;
    const std::string containerName = prefix + username;

    if (!ContainerExistsInternal(containerName))
    {
        if (!CreateContainerInternal(containerName, username))
        {
            std::cerr << "Failed to create container for user " << username << std::endl;
            return {};
        }
    }

    if (!ContainerRunningInternal(containerName))
    {
        if (!StartContainerInternal(containerName))
        {
            std::cerr << "Failed to start container " << containerName << std::endl;
            return {};
        }
    }

    bool compositorReady = WaitForProcessInternal(containerName, "/usr/bin/gnome-shell");
    compositorReady &= WaitForProcessInternal(containerName,
                                              "/usr/libexec/gnome-remote-desktop-daemon --headless");
    if (!compositorReady)
        std::clog << "GNOME compositor not ready in container " << containerName << std::endl;

    const std::string ip = GetContainerIpInternal(containerName);
    if (ip.empty())
        std::cerr << "Failed to retrieve IP for container " << containerName << std::endl;

    return ip;
}

} // namespace vdi
