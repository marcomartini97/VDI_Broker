#include "vdi_container_manager_internal.h"
#include "vdi_container_manager_constants.h"
#include "vdi_broker_config.h"
#include "vdi_logging.h"

#include <curl/curl.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <inttypes.h>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <json/json.h>

#define TAG MODULE_TAG("vdi-container-manager")

namespace vdi
{

struct EnsuredNetworkInfo
{
    VdiBrokerConfig::PodmanNetworkMode mode;
    std::string parent;
};

class ContainerPayloadBuilder
{
public:
    ContainerPayloadBuilder(const std::string& containerName, const std::string& username,
                             const std::string& image, vdi::VdiBrokerConfig& config)
        : config_(config), containerName_(containerName), username_(username), image_(image),
          nvidiaEnabled_(config.NvidiaGpuEnabled())
    {
        root_["name"] = containerName_;
        root_["hostname"] = containerName_;
        root_["image"] = image_;
        root_["terminal"] = true;
        root_["systemd"] = "always";
    }

    Json::Value Build()
    {
        AddCapabilities();
        AddDevices();
        AddEnvironment();
        AddMounts();
        AddResourceLimits();
        AddNetwork();

        root_["devices"] = devices_;
        root_["mounts"] = mounts_;
        return root_;
    }

private:
    void AddCapabilities()
    {
        Json::Value caps(Json::arrayValue);
        caps.append("SYS_ADMIN");
        caps.append("NET_ADMIN");
        caps.append("SYS_PTRACE");
        caps.append("AUDIT_CONTROL");
        caps.append("SYS_NICE");
        root_["cap_add"] = caps;
    }

    void AddDevices()
    {
        AddDefaultDevices();
        AddNvidiaDevices();
    }

    void AddDefaultDevices()
    {
        AppendDevice("/dev/fuse");

        const auto driRenderDevices = config_.DriRenderDevices();
        for (const auto& device : driRenderDevices)
            AppendDevice(device);

        const auto driCardDevices = config_.DriCardDevices();
        for (const auto& device : driCardDevices)
            AppendDevice(device);
    }

    void AddNvidiaDevices()
    {
        if (!nvidiaEnabled_)
            return;

        const std::string base = "/dev/nvidia" + std::to_string(config_.NvidiaGpuSlot());
        const std::array<std::string, 6> nvidiaDevices = {
            "/dev/nvidia-caps", base, "/dev/nvidiactl", "/dev/nvidia-modeset",
            "/dev/nvidia-uvm", "/dev/nvidia-uvm-tools"};

        for (const auto& dev : nvidiaDevices)
            AppendDevice(dev);
    }

    void AddEnvironment()
    {
        Json::Value env(Json::objectValue);
        if (nvidiaEnabled_)
            env["GSK_RENDERER"] = "ngl";
        root_["env"] = env;
    }

    void AddMounts()
    {
        AddDefaultMounts();
        AddCustomMounts();
    }

    void AddDefaultMounts()
    {
        AppendMount(config_.PasswdPath(), "/etc/passwd", true);
        AppendMount(config_.GroupPath(), "/etc/group", true);
        AppendMount(config_.ShadowPath(), "/etc/shadow", true);
        AppendMount(config_.HomePath(), "/home", false);
    }

    void AddCustomMounts()
    {
        const auto customMounts = config_.CustomMounts();
        for (const auto& mount : customMounts)
            AppendMount(mount.source, mount.destination, mount.readOnly);
    }

    void AddResourceLimits()
    {
        const auto resourceLimits = config_.ResourceLimitsForUser(username_);
        if (resourceLimits.empty())
            return;

        Json::Value limits(Json::objectValue);
        for (const auto& entry : resourceLimits)
        {
            Json::Value limit(Json::objectValue);
            limit["limit"] = static_cast<Json::Int64>(entry.second);
            limits[entry.first] = limit;
        }

        root_["resource_limits"] = limits;
    }

    void AddNetwork()
    {
        const auto mode = config_.ActivePodmanNetworkMode();
        if (mode == vdi::VdiBrokerConfig::PodmanNetworkMode::None)
            return;

        const std::string networkName = config_.PodmanNetworkName();
        if (networkName.empty())
            return;

        Json::Value networks(Json::objectValue);
        Json::Value networkOptions(Json::objectValue);
        const std::string interfaceName = config_.PodmanNetworkInterface();
        if (!interfaceName.empty())
            networkOptions["interface_name"] = interfaceName;
        networks[networkName] = networkOptions;
        root_["networks"] = networks;
    }

    void AppendDevice(const std::string& path)
    {
        if (path.empty())
            return;

        if (!appendedDevices_.insert(path).second)
            return;

        Json::Value device(Json::objectValue);
        device["path"] = path;
        devices_.append(device);
    }

    void AppendMount(const std::string& source, const std::string& destination, bool readOnly)
    {
        if (source.empty() || destination.empty())
            return;

        Json::Value mount(Json::objectValue);
        mount["Source"] = source;
        mount["Destination"] = destination;
        mount["Type"] = "bind";
        if (readOnly)
            mount["ReadOnly"] = true;
        mounts_.append(mount);
    }

    vdi::VdiBrokerConfig& config_;
    std::string containerName_;
    std::string username_;
    std::string image_;
    Json::Value root_{Json::objectValue};
    Json::Value devices_{Json::arrayValue};
    Json::Value mounts_{Json::arrayValue};
    std::unordered_set<std::string> appendedDevices_;
    bool nvidiaEnabled_ = false;
};


std::string BuildUrl(const std::string& containerName, const std::string& endpoint)
{
    std::string url = kPodmanApiBase;
    url.append(containerName);
    url.append(endpoint);
    return url;
}


const char* PodmanModeToString(vdi::VdiBrokerConfig::PodmanNetworkMode mode)
{
    switch (mode)
    {
    case vdi::VdiBrokerConfig::PodmanNetworkMode::MacVlan:
        return "macvlan";
    case vdi::VdiBrokerConfig::PodmanNetworkMode::BridgeUnmanaged:
        return "bridge-unmanaged";
    case vdi::VdiBrokerConfig::PodmanNetworkMode::Bridge:
        return "bridge";
    case vdi::VdiBrokerConfig::PodmanNetworkMode::None:
    default:
        return "disabled";
    }
}


bool QueryPodmanNetworkExists(const std::string& networkName, bool& exists)
{
    exists = false;
    CURL* curl = curl_easy_init();
    if (!curl)
        return false;

    std::unique_ptr<char, decltype(&curl_free)> escaped(
        curl_easy_escape(curl, networkName.c_str(), static_cast<int>(networkName.size())),
        curl_free);
    if (!escaped)
    {
        curl_easy_cleanup(curl);
        return false;
    }

    std::string url = "http://d/v5.3.0/libpod/networks/";
    url.append(escaped.get());

    std::string response;
    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, kPodmanSocket);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    const CURLcode res = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    if (res == CURLE_OK)
    {
        exists = (httpCode >= 200 && httpCode < 300);
        curl_easy_cleanup(curl);
        return true;
    }

    if (res == CURLE_HTTP_RETURNED_ERROR)
    {
        if (httpCode >= 200 && httpCode < 300)
        {
            exists = true;
            curl_easy_cleanup(curl);
            return true;
        }

        if (httpCode == 404)
        {
            exists = false;
            curl_easy_cleanup(curl);
            return true;
        }

        VDI_LOG_ERROR(TAG, "Failed to inspect Podman network %s, HTTP code: %ld",
                      networkName.c_str(), httpCode);
        curl_easy_cleanup(curl);
        return false;
    }

    VDI_LOG_ERROR(TAG, "Failed to query Podman network %s: %s", networkName.c_str(),
                  curl_easy_strerror(res));
    curl_easy_cleanup(curl);
    return false;
}


bool CreatePodmanNetwork(const vdi::VdiBrokerConfig& config,
                         vdi::VdiBrokerConfig::PodmanNetworkMode mode)
{
    const std::string networkName = config.PodmanNetworkName();
    if (networkName.empty())
    {
        VDI_LOG_ERROR(TAG, "Cannot create Podman network: name is empty.");
        return false;
    }

    if (mode == vdi::VdiBrokerConfig::PodmanNetworkMode::None)
    {
        VDI_LOG_INFO(TAG, "Podman network creation skipped because networking is disabled.");
        return true;
    }

    CURL* curl = curl_easy_init();
    if (!curl)
        return false;

    Json::Value payload(Json::objectValue);
    Json::Value ipam_options(Json::objectValue);
    payload["name"] = networkName;

    if (mode == vdi::VdiBrokerConfig::PodmanNetworkMode::MacVlan)
    {
        payload["driver"] = "macvlan";
        const std::string parent = config.PodmanNetworkParentInterface();
        if (parent.empty())
        {
            VDI_LOG_ERROR(TAG, "Macvlan network selected but no parent interface provided.");
            curl_easy_cleanup(curl);
            return false;
        }
        payload["network_interface"] = parent;
        ipam_options["driver"] = "dhcp";
        payload["ipam_options"] = ipam_options;
    }
    else if (mode == vdi::VdiBrokerConfig::PodmanNetworkMode::Bridge ||
             mode == vdi::VdiBrokerConfig::PodmanNetworkMode::BridgeUnmanaged)
    {
        payload["driver"] = "bridge";
        Json::Value options(Json::objectValue);
        bool hasOptions = false;
        const std::string parent = config.PodmanNetworkParentInterface();
        if (!parent.empty())
        {
            payload["network_interface"] = parent;
            options["com.docker.network.bridge.name"] = parent;
            hasOptions = true;
        }
        if (mode == vdi::VdiBrokerConfig::PodmanNetworkMode::BridgeUnmanaged)
        {
            options["mode"] = "unmanaged";
            ipam_options["driver"] = "dhcp";
            payload["ipam_options"] = ipam_options;
            options["isolate"] = "false";
            hasOptions = true;
        }
        if (hasOptions)
            payload["options"] = options;
    }
    else
    {
        VDI_LOG_INFO(TAG, "Podman network mode is disabled; nothing to create.");
        curl_easy_cleanup(curl);
        return true;
    }

    Json::StreamWriterBuilder writer;
    writer["indentation"] = "";
    const std::string payloadStr = Json::writeString(writer, payload);

    std::string response;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, kPodmanSocket);
    curl_easy_setopt(curl, CURLOPT_URL, "http://d/v5.3.0/libpod/networks/create");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payloadStr.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    const CURLcode res = curl_easy_perform(curl);
    bool success = false;
    if (res == CURLE_OK || res == CURLE_HTTP_RETURNED_ERROR)
    {
        long httpCode = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
        success = (httpCode >= 200 && httpCode < 300);
        if (!success && httpCode == 409)
        {
            VDI_LOG_INFO(TAG, "Podman network %s already exists.", networkName.c_str());
            success = true;
        }
        if (!success)
        {
            VDI_LOG_ERROR(
                TAG, "Failed to create Podman network %s (%s), HTTP code: %ld, response: %s",
                networkName.c_str(), PodmanModeToString(mode), httpCode, response.c_str());
        }
    }
    else
    {
        VDI_LOG_ERROR(TAG, "Failed to create Podman network %s (%s): %s", networkName.c_str(),
                      PodmanModeToString(mode), curl_easy_strerror(res));
    }

    if (success)
    {
        VDI_LOG_INFO(TAG, "Created Podman network %s using %s configuration.",
                     networkName.c_str(), PodmanModeToString(mode));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success;
}


bool EnsurePodmanNetwork(vdi::VdiBrokerConfig& config)
{
    const auto mode = config.ActivePodmanNetworkMode();
    if (mode == vdi::VdiBrokerConfig::PodmanNetworkMode::None)
    {
        VDI_LOG_INFO(TAG, "Podman network management disabled via configuration.");
        return true;
    }

    const std::string networkName = config.PodmanNetworkName();
    if (networkName.empty())
    {
        VDI_LOG_ERROR(TAG, "Podman network mode enabled but network name is not configured.");
        return false;
    }

    const std::string parentInterface = config.PodmanNetworkParentInterface();

    static std::mutex ensureMutex;
    static std::unordered_map<std::string, EnsuredNetworkInfo> ensuredNetworks;

    {
        std::lock_guard<std::mutex> guard(ensureMutex);
        const auto it = ensuredNetworks.find(networkName);
        if (it != ensuredNetworks.end())
        {
            if (it->second.mode == mode && it->second.parent == parentInterface)
            {
                VDI_LOG_INFO(TAG, "Podman network '%s' already ensured (mode=%s, parent=%s).",
                             networkName.c_str(), PodmanModeToString(it->second.mode),
                             parentInterface.empty() ? "<none>" : parentInterface.c_str());
                return true;
            }

            VDI_LOG_INFO(TAG,
                         "Revalidating Podman network '%s' due to configuration change (mode: %s -> %s, parent: %s -> %s).",
                         networkName.c_str(), PodmanModeToString(it->second.mode),
                         PodmanModeToString(mode),
                         it->second.parent.empty() ? "<none>" : it->second.parent.c_str(),
                         parentInterface.empty() ? "<none>" : parentInterface.c_str());
        }
    }

    const std::string interfaceName = config.PodmanNetworkInterface();
    VDI_LOG_INFO(TAG, "Ensuring Podman network '%s' (requested=%s, interface=%s, parent=%s)",
                 networkName.c_str(), PodmanModeToString(mode),
                 interfaceName.empty() ? "<default>" : interfaceName.c_str(),
                 parentInterface.empty() ? "<none>" : parentInterface.c_str());

    bool exists = false;
    if (!QueryPodmanNetworkExists(networkName, exists))
        return false;

    vdi::VdiBrokerConfig::PodmanNetworkMode finalMode = mode;

    if (!exists)
    {
        if (!CreatePodmanNetwork(config, mode))
        {
            if (mode == vdi::VdiBrokerConfig::PodmanNetworkMode::MacVlan)
            {
                VDI_LOG_WARN(TAG,
                             "Macvlan network creation failed; falling back to bridge network "
                             "configuration.");
                if (!CreatePodmanNetwork(config, vdi::VdiBrokerConfig::PodmanNetworkMode::Bridge))
                    return false;
                finalMode = vdi::VdiBrokerConfig::PodmanNetworkMode::Bridge;
            }
            else
            {
                return false;
            }
        }
    }
    else
    {
        VDI_LOG_INFO(TAG, "Podman network '%s' already present.", networkName.c_str());
    }

    {
        std::lock_guard<std::mutex> guard(ensureMutex);
        ensuredNetworks[networkName] = {finalMode, parentInterface};
    }

    VDI_LOG_INFO(TAG, "Podman network '%s' ready (mode=%s, parent=%s).", networkName.c_str(),
                 PodmanModeToString(finalMode),
                 parentInterface.empty() ? "<none>" : parentInterface.c_str());
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
        VDI_LOG_ERROR(TAG, "Failed to query container info: %s", curl_easy_strerror(res));
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
        VDI_LOG_ERROR(TAG, "HTTP error code while querying container info: %ld", httpCode);
        return {};
    }

    return response;
}






Json::Value BuildCreatePayload(const std::string& containerName, const std::string& username,
                               const std::string& image)
{
    auto& config = vdi::Config();
    ContainerPayloadBuilder builder(containerName, username, image, config);
    return builder.Build();
}


bool CreateContainerInternal(const std::string& containerName, const std::string& username,
                             bool allowBuild)
{
    CURL* curl = curl_easy_init();
    if (!curl)
        return false;

    auto& config = vdi::Config();
    const std::string image = config.PodmanImageForUser(username);
    const bool hasCustomImage = config.HasUserImage(username);
    const Json::Value payload = BuildCreatePayload(containerName, username, image);
    Json::StreamWriterBuilder writerBuilder;
    writerBuilder["indentation"] = "";
    const std::string payloadStr = Json::writeString(writerBuilder, payload);

    VDI_LOG_INFO(TAG, "Creating container %s with payload: %s", containerName.c_str(),
              payloadStr.c_str());

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
            VDI_LOG_ERROR(TAG, "Failed to create container, HTTP code: %ld", httpCode);
            if (httpCode == 404)
                missingImage = true;
        }
    }
    else
    {
        VDI_LOG_ERROR(TAG, "Failed to create container: %s", curl_easy_strerror(res));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (!success && missingImage)
    {
        if (hasCustomImage)
        {
            VDI_LOG_ERROR(TAG,
                     "Podman image %s configured for user %s is missing; skipping auto-build",
                     image.c_str(), username.c_str());
        }
        else if (allowBuild)
        {
            const std::string dockerfile = config.DockerfilePath();
            if (BuildImageFromDockerfile(image, dockerfile))
                return CreateContainerInternal(containerName, username, false);
        }
    }

    return success;
}


bool StartContainerInternal(const std::string& containerName)
{
    CURL* curl = curl_easy_init();
    if (!curl)
        return false;

    const std::string url = BuildUrl(containerName, "/start");

    VDI_LOG_INFO(TAG, "Starting container: %s", containerName.c_str());

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
            VDI_LOG_ERROR(TAG, "Failed to start container, HTTP code: %ld", httpCode);
    }
    else
    {
        VDI_LOG_ERROR(TAG, "Failed to start container: %s", curl_easy_strerror(res));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success;
}

} // namespace vdi
