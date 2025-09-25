#include "vdi_container_manager.h"

#include "vdi_broker_config.h"

void vdi_log_refresh_outcome(bool refreshed, bool reloaded);

#include <curl/curl.h>
#include <json/json.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <system_error>
#include <thread>

namespace
{
constexpr char kPodmanSocket[] = "/var/run/podman/podman.sock";
const std::string kPodmanApiBase = "http://d/v5.3.0/libpod/containers/";
constexpr char kPodmanBuildEndpoint[] = "http://d/v5.3.0/libpod/build";

using namespace std::chrono_literals;

struct TarHeader
{
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char checksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char padding[12];
};

const std::array<char, 512> kTarZeroBlock{};

bool WriteOctal(char* dest, size_t width, std::uint64_t value)
{
    if (width == 0)
        return false;

    const auto written = std::snprintf(dest, width, "%0*llo",
                                       static_cast<int>(width - 1),
                                       static_cast<unsigned long long>(value));
    if (written < 0 || static_cast<size_t>(written) >= width)
        return false;

    return true;
}

bool SetTarHeaderName(const std::string& name, TarHeader& header)
{
    std::string trimmed = name;
    while (!trimmed.empty() && trimmed.back() == '/')
        trimmed.pop_back();

    if (trimmed.empty())
        return false;

    if (trimmed.size() <= sizeof(header.name))
    {
        std::copy(trimmed.begin(), trimmed.end(), header.name);
        return true;
    }

    const auto slashPosition = trimmed.rfind('/');
    if (slashPosition == std::string::npos)
        return false;

    const std::string prefix = trimmed.substr(0, slashPosition);
    const std::string basename = trimmed.substr(slashPosition + 1);

    if (basename.empty() || prefix.size() > sizeof(header.prefix) ||
        basename.size() > sizeof(header.name))
        return false;

    std::copy(prefix.begin(), prefix.end(), header.prefix);
    std::copy(basename.begin(), basename.end(), header.name);
    return true;
}

bool WriteTarHeader(std::ofstream& stream, const std::string& tarName, char typeflag,
                    std::uint64_t size, std::uint32_t mode, std::uint64_t mtime)
{
    TarHeader header{};

    if (!SetTarHeaderName(tarName, header))
    {
        std::cerr << "Tar entry name too long: " << tarName << std::endl;
        return false;
    }

    if (!WriteOctal(header.mode, sizeof(header.mode), mode) ||
        !WriteOctal(header.uid, sizeof(header.uid), 0) ||
        !WriteOctal(header.gid, sizeof(header.gid), 0) ||
        !WriteOctal(header.size, sizeof(header.size), size) ||
        !WriteOctal(header.mtime, sizeof(header.mtime), mtime))
    {
        std::cerr << "Failed to encode tar header fields for entry: " << tarName << std::endl;
        return false;
    }

    std::fill(std::begin(header.checksum), std::end(header.checksum), ' ');
    header.typeflag = typeflag;
    std::memcpy(header.magic, "ustar", 5);
    std::memcpy(header.version, "00", 2);

    const unsigned char* raw = reinterpret_cast<const unsigned char*>(&header);
    unsigned int checksum = 0;
    for (size_t i = 0; i < sizeof(TarHeader); ++i)
        checksum += raw[i];

    std::snprintf(header.checksum, sizeof(header.checksum), "%06o", checksum);
    header.checksum[6] = '\0';
    header.checksum[7] = ' ';

    stream.write(reinterpret_cast<const char*>(&header), sizeof(header));
    return stream.good();
}

bool AddDirectoryEntry(std::ofstream& tarStream, const std::string& tarName, std::uint64_t mtime)
{
    return WriteTarHeader(tarStream, tarName, '5', 0, 0755, mtime);
}

bool AddFileEntry(std::ofstream& tarStream, const std::filesystem::path& sourcePath,
                  const std::string& tarName, std::uint64_t mtime)
{
    std::error_code ec;
    const auto fileSize = std::filesystem::file_size(sourcePath, ec);
    if (ec)
    {
        std::cerr << "Failed to stat file for tar entry: " << sourcePath << " ("
                  << ec.message() << ")" << std::endl;
        return false;
    }

    if (!WriteTarHeader(tarStream, tarName, '0', fileSize, 0644, mtime))
        return false;

    std::ifstream input(sourcePath, std::ios::binary);
    if (!input)
    {
        std::cerr << "Failed to open file for tar entry: " << sourcePath << std::endl;
        return false;
    }

    std::array<char, 8192> buffer{};
    while (input.read(buffer.data(), buffer.size()))
        tarStream.write(buffer.data(), buffer.size());
    if (input.gcount() > 0)
        tarStream.write(buffer.data(), input.gcount());

    if (!tarStream)
    {
        std::cerr << "Failed while writing tar contents for: " << tarName << std::endl;
        return false;
    }

    const std::uint64_t padding = (512 - (fileSize % 512)) % 512;
    if (padding != 0)
        tarStream.write(kTarZeroBlock.data(), padding);

    return tarStream.good();
}

bool CreateTarArchive(const std::filesystem::path& contextDir, const std::filesystem::path& tarPath)
{
    std::ofstream tarStream(tarPath, std::ios::binary | std::ios::trunc);
    if (!tarStream)
    {
        std::cerr << "Failed to create temporary build context: " << tarPath << std::endl;
        return false;
    }

    const std::uint64_t now = static_cast<std::uint64_t>(std::time(nullptr));

    std::error_code ec;
    if (!std::filesystem::exists(contextDir, ec))
    {
        std::cerr << "Build context directory missing: " << contextDir << std::endl;
        return false;
    }

    // Ensure the root context directory is present in the archive so relative paths resolve.
    if (!AddDirectoryEntry(tarStream, "./", now))
        return false;

    const auto options = std::filesystem::directory_options::skip_permission_denied;
    for (std::filesystem::recursive_directory_iterator it(contextDir, options), end; it != end; ++it)
    {
        const auto relative = std::filesystem::relative(it->path(), contextDir, ec);
        if (ec)
        {
            std::cerr << "Failed to resolve relative path for tar entry: " << it->path()
                      << " (" << ec.message() << ")" << std::endl;
            return false;
        }

        std::string tarName = relative.generic_string();
        if (tarName.empty())
            continue;

        if (it->is_symlink())
        {
            std::cerr << "Symlinks are not supported in build context: " << it->path() << std::endl;
            return false;
        }

        if (it->is_directory())
        {
            if (tarName.back() != '/')
                tarName.push_back('/');
            if (!AddDirectoryEntry(tarStream, tarName, now))
                return false;
        }
        else if (it->is_regular_file())
        {
            if (!AddFileEntry(tarStream, it->path(), tarName, now))
                return false;
        }
        else
        {
            std::cerr << "Unsupported file type in build context: " << it->path() << std::endl;
            return false;
        }
    }

    tarStream.write(kTarZeroBlock.data(), kTarZeroBlock.size());
    tarStream.write(kTarZeroBlock.data(), kTarZeroBlock.size());

    return tarStream.good();
}

struct CurlReadContext
{
    std::ifstream stream;
};

size_t TarReadCallback(char* buffer, size_t size, size_t nmemb, void* userdata)
{
    auto* context = static_cast<CurlReadContext*>(userdata);
    if (!context || !context->stream)
        return 0;

    context->stream.read(buffer, static_cast<std::streamsize>(size * nmemb));
    return static_cast<size_t>(context->stream.gcount());
}

size_t StreamLogsCallback(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    auto* out = static_cast<std::ostream*>(userdata);
    const size_t total = size * nmemb;
    if (out && total > 0)
    {
        out->write(ptr, static_cast<std::streamsize>(total));
        out->flush();
    }
    return total;
}

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

    std::string dockerfileName;
    try
    {
        dockerfileName = std::filesystem::relative(dockerfile, context).generic_string();
    }
    catch (const std::filesystem::filesystem_error& ex)
    {
        std::cerr << "Failed to resolve Dockerfile relative path: " << ex.what() << std::endl;
        return false;
    }

    if (dockerfileName.empty())
        dockerfileName = dockerfile.filename().generic_string();

    std::filesystem::path tarPath;
    try
    {
        tarPath = std::filesystem::temp_directory_path() / "vdi-podman-build.tar";
    }
    catch (const std::filesystem::filesystem_error& ex)
    {
        std::cerr << "Failed to resolve temporary directory for build context: " << ex.what()
                  << std::endl;
        return false;
    }

    if (!CreateTarArchive(context, tarPath))
        return false;

    struct ScopedPath
    {
        explicit ScopedPath(std::filesystem::path p) : path(std::move(p)) {}
        ~ScopedPath()
        {
            if (path.empty())
                return;

            std::error_code ec;
            std::filesystem::remove(path, ec);
        }

        std::filesystem::path path;
    } tarCleanup(tarPath);

    std::error_code ec;
    const auto tarSize = std::filesystem::file_size(tarPath, ec);
    if (ec)
    {
        std::cerr << "Failed to stat build context archive: " << ec.message() << std::endl;
        return false;
    }

    CurlReadContext readContext{};
    readContext.stream.open(tarPath, std::ios::binary);
    if (!readContext.stream)
    {
        std::cerr << "Failed to open build context archive for upload: " << tarPath << std::endl;
        return false;
    }

    CURL* curl = curl_easy_init();
    if (!curl)
    {
        std::cerr << "Failed to initialise curl for Podman image build" << std::endl;
        return false;
    }

    std::unique_ptr<char, decltype(&curl_free)> escapedImage(
        curl_easy_escape(curl, image.c_str(), static_cast<int>(image.size())), curl_free);
    if (!escapedImage)
    {
        std::cerr << "Failed to escape image name for Podman request" << std::endl;
        curl_easy_cleanup(curl);
        return false;
    }

    std::unique_ptr<char, decltype(&curl_free)> escapedDockerfile(
        curl_easy_escape(curl, dockerfileName.c_str(), static_cast<int>(dockerfileName.size())), curl_free);
    if (!escapedDockerfile)
    {
        std::cerr << "Failed to escape Dockerfile path for Podman request" << std::endl;
        curl_easy_cleanup(curl);
        return false;
    }

    std::string url = kPodmanBuildEndpoint;
    url += "?t=";
    url += escapedImage.get();
    url += "&dockerfile=";
    url += escapedDockerfile.get();

    std::clog << "Building Podman image '" << image << "' using Dockerfile " << dockerfilePath
              << " via Podman API" << std::endl;

    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, kPodmanSocket);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, TarReadCallback);
    curl_easy_setopt(curl, CURLOPT_READDATA, &readContext);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(tarSize));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, StreamLogsCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &std::cout);

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/x-tar");
    headers = curl_slist_append(headers, "Expect:");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    const CURLcode res = curl_easy_perform(curl);

    long httpCode = 0;
    if (res == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    if (headers)
        curl_slist_free_all(headers);

    curl_easy_cleanup(curl);

    if (res != CURLE_OK)
    {
        std::cerr << "Podman image build failed: " << curl_easy_strerror(res) << std::endl;
        return false;
    }

    if (httpCode >= 400)
    {
        std::cerr << "Podman image build returned HTTP status " << httpCode << std::endl;
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
