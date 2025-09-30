#include "vdi_container_manager.h"

#include "vdi_broker_config.h"

void vdi_log_refresh_outcome(bool refreshed, bool reloaded);

#include <freerdp/server/proxy/proxy_modules_api.h>

#include <winpr/wlog.h>

#include <curl/curl.h>
#include <json/json.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <inttypes.h>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sstream>
#include <system_error>
#include <thread>
#include <unordered_set>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define TAG MODULE_TAG("vdi-container-manager")

namespace
{
constexpr char kPodmanSocket[] = "/var/run/podman/podman.sock";
const std::string kPodmanApiBase = "http://d/v5.3.0/libpod/containers/";
constexpr char kPodmanBuildEndpoint[] = "http://d/v5.3.0/libpod/build";
constexpr int kProcessCheckAttempts = 20;
constexpr auto kReadinessPollInterval = std::chrono::seconds{1};
constexpr auto kPortReadyTimeout = std::chrono::seconds{30};
constexpr std::uint16_t kRdpPort = 3389;

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
        WLog_ERR(TAG, "Tar entry name too long: %s", tarName.c_str());
        return false;
    }

    if (!WriteOctal(header.mode, sizeof(header.mode), mode) ||
        !WriteOctal(header.uid, sizeof(header.uid), 0) ||
        !WriteOctal(header.gid, sizeof(header.gid), 0) ||
        !WriteOctal(header.size, sizeof(header.size), size) ||
        !WriteOctal(header.mtime, sizeof(header.mtime), mtime))
    {
        WLog_ERR(TAG, "Failed to encode tar header fields for entry: %s", tarName.c_str());
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
        WLog_ERR(TAG, "Failed to stat file for tar entry: %s (%s)",
                 sourcePath.string().c_str(), ec.message().c_str());
        return false;
    }

    if (!WriteTarHeader(tarStream, tarName, '0', fileSize, 0644, mtime))
        return false;

    std::ifstream input(sourcePath, std::ios::binary);
    if (!input)
    {
        WLog_ERR(TAG, "Failed to open file for tar entry: %s", sourcePath.string().c_str());
        return false;
    }

    std::array<char, 8192> buffer{};
    while (input.read(buffer.data(), buffer.size()))
        tarStream.write(buffer.data(), buffer.size());
    if (input.gcount() > 0)
        tarStream.write(buffer.data(), input.gcount());

    if (!tarStream)
    {
        WLog_ERR(TAG, "Failed while writing tar contents for: %s", tarName.c_str());
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
        WLog_ERR(TAG, "Failed to create temporary build context: %s", tarPath.string().c_str());
        return false;
    }

    const std::uint64_t now = static_cast<std::uint64_t>(std::time(nullptr));

    std::error_code ec;
    if (!std::filesystem::exists(contextDir, ec))
    {
        WLog_ERR(TAG, "Build context directory missing: %s", contextDir.string().c_str());
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
            WLog_ERR(TAG, "Failed to resolve relative path for tar entry: %s (%s)",
                     it->path().string().c_str(), ec.message().c_str());
            return false;
        }

        std::string tarName = relative.generic_string();
        if (tarName.empty())
            continue;

        if (it->is_symlink())
        {
            WLog_WARN(TAG, "Symlinks are not supported in build context: %s",
                      it->path().string().c_str());
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
            WLog_ERR(TAG, "Unsupported file type in build context: %s",
                     it->path().string().c_str());
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
        WLog_ERR(TAG, "Dockerfile path not configured; unable to build image %s", image.c_str());
        return false;
    }

    std::filesystem::path dockerfile(dockerfilePath);
    if (!std::filesystem::exists(dockerfile))
    {
        WLog_ERR(TAG, "Dockerfile not found at %s", dockerfilePath.c_str());
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
        WLog_ERR(TAG, "Failed to resolve Dockerfile relative path: %s", ex.what());
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
        WLog_ERR(TAG, "Failed to resolve temporary directory for build context: %s", ex.what());
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
        WLog_ERR(TAG, "Failed to stat build context archive: %s", ec.message().c_str());
        return false;
    }

    CurlReadContext readContext{};
    readContext.stream.open(tarPath, std::ios::binary);
    if (!readContext.stream)
    {
        WLog_ERR(TAG, "Failed to open build context archive for upload: %s", tarPath.string().c_str());
        return false;
    }

    CURL* curl = curl_easy_init();
    if (!curl)
    {
        WLog_ERR(TAG, "Failed to initialise curl for Podman image build");
        return false;
    }

    std::unique_ptr<char, decltype(&curl_free)> escapedImage(
        curl_easy_escape(curl, image.c_str(), static_cast<int>(image.size())), curl_free);
    if (!escapedImage)
    {
        WLog_ERR(TAG, "Failed to escape image name for Podman request");
        curl_easy_cleanup(curl);
        return false;
    }

    std::unique_ptr<char, decltype(&curl_free)> escapedDockerfile(
        curl_easy_escape(curl, dockerfileName.c_str(), static_cast<int>(dockerfileName.size())), curl_free);
    if (!escapedDockerfile)
    {
        WLog_ERR(TAG, "Failed to escape Dockerfile path for Podman request");
        curl_easy_cleanup(curl);
        return false;
    }

    std::string url = kPodmanBuildEndpoint;
    url += "?t=";
    url += escapedImage.get();
    url += "&dockerfile=";
    url += escapedDockerfile.get();

    WLog_INFO(TAG, "Building Podman image '%s' using Dockerfile %s via Podman API", image.c_str(),
              dockerfilePath.c_str());

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
        WLog_ERR(TAG, "Podman image build failed: %s", curl_easy_strerror(res));
        return false;
    }

    if (httpCode >= 400)
    {
        WLog_ERR(TAG, "Podman image build returned HTTP status %ld", httpCode);
        return false;
    }

    WLog_INFO(TAG, "Successfully built Podman image '%s'", image.c_str());
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
        WLog_ERR(TAG, "Failed to query container info: %s", curl_easy_strerror(res));
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
        WLog_ERR(TAG, "HTTP error code while querying container info: %ld", httpCode);
        return {};
    }

    return response;
}

bool ContainerExistsInternal(const std::string& containerName)
{
    const std::string payload = GetContainerInfo(containerName, "/json");
    if (payload.empty())
        WLog_INFO(TAG, "Container does not exist: %s", containerName.c_str());
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
        WLog_ERR(TAG, "Failed to parse container info: %s", errs.c_str());
        return false;
    }

    const auto status = root["State"]["Status"].asString();
    return status == "running";
}

bool WaitForProcessInternal(const std::string& containerName, const std::string& processName)
{
    WLog_INFO(TAG, "Waiting for <%s> in container: %s", processName.c_str(), containerName.c_str());

    auto trim = [](const std::string& value) {
        const auto start = value.find_first_not_of(" \t");
        if (start == std::string::npos)
            return std::string{};
        const auto end = value.find_last_not_of(" \t");
        return value.substr(start, end - start + 1);
    };

    const std::string trimmedName = trim(processName);
    std::string execToken = trimmedName;
    const auto whitespacePos = execToken.find_first_of(" \t");
    if (whitespacePos != std::string::npos)
        execToken.resize(whitespacePos);

    std::string execBasename;
    if (!execToken.empty())
    {
        const auto slashPos = execToken.find_last_of('/');
        execBasename = (slashPos == std::string::npos) ? execToken : execToken.substr(slashPos + 1);
    }

    const auto matchesProcess = [&](const Json::Value& process) {
        if (!process.isArray() || process.empty())
            return false;

        const std::string commandField = process[process.size() - 1].asString();
        if (!trimmedName.empty() && commandField.find(trimmedName) != std::string::npos)
            return true;
        if (!execToken.empty() && commandField.find(execToken) != std::string::npos)
            return true;
        if (!execBasename.empty() && commandField.find(execBasename) != std::string::npos)
            return true;

        for (const auto& field : process)
        {
            const std::string value = field.asString();
            if (!trimmedName.empty() && value == trimmedName)
                return true;
            if (!execToken.empty() && value == execToken)
                return true;
            if (!execBasename.empty() && value == execBasename)
                return true;
        }

        return false;
    };

    for (int attempts = 0; attempts < kProcessCheckAttempts; attempts++)
    {
        const std::string response = GetContainerInfo(containerName, "/top");
        if (response.empty())
        {
            std::this_thread::sleep_for(kReadinessPollInterval);
            continue;
        }

        Json::Value root;
        Json::CharReaderBuilder builder;
        std::string errs;
        std::istringstream stream(response);

        if (!Json::parseFromStream(builder, stream, &root, &errs))
        {
            WLog_ERR(TAG, "Error parsing JSON: %s", errs.c_str());
            return false;
        }

        const auto& processes = root["Processes"];
        if (!processes.isArray())
        {
            WLog_ERR(TAG, "Invalid JSON: 'Processes' missing or not array");
            return false;
        }

        for (const auto& process : processes)
        {
            if (matchesProcess(process))
                return true;
        }

        std::this_thread::sleep_for(kReadinessPollInterval);
    }

    WLog_WARN(TAG, "Process <%s> not detected in container %s after %d attempts",
              processName.c_str(), containerName.c_str(), kProcessCheckAttempts);
    return false;
}

bool WaitForTcpPort(const std::string& host, std::uint16_t port)
{
    WLog_INFO(TAG, "Waiting for TCP port %" PRIu16 " on host %s", port, host.c_str());

    const auto deadline = std::chrono::steady_clock::now() + kPortReadyTimeout;
    const std::string portString = std::to_string(port);

    struct addrinfo hints
    {
    };
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;

    while (std::chrono::steady_clock::now() < deadline)
    {
        struct addrinfo* info = nullptr;
        const int gaiErr = getaddrinfo(host.c_str(), portString.c_str(), &hints, &info);
        if (gaiErr != 0)
        {
            WLog_ERR(TAG, "Failed to resolve address %s for port check: %s", host.c_str(),
                     gai_strerror(gaiErr));
            return false;
        }

        bool connected = false;
        for (struct addrinfo* entry = info; entry != nullptr; entry = entry->ai_next)
        {
            int sock = ::socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
            if (sock < 0)
                continue;

            int yes = 1;
            ::setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

            struct timeval tv
            {
            };
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            struct linger lg
            {
            };
            lg.l_onoff = 1;
            lg.l_linger = 0;
            ::setsockopt(sock, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

            if (::connect(sock, entry->ai_addr, entry->ai_addrlen) == 0)
            {
                connected = true;
                ::shutdown(sock, SHUT_RDWR);
                ::close(sock);
                break;
            }

            ::close(sock);
        }

        freeaddrinfo(info);

        if (connected)
        {
            WLog_INFO(TAG, "Port %" PRIu16 " is reachable on host %s", port, host.c_str());
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            return true;
        }

        std::this_thread::sleep_for(kReadinessPollInterval);
    }

    WLog_ERR(TAG, "Timed out waiting for port %" PRIu16 " on host %s", port, host.c_str());
    return false;
}

Json::Value BuildCreatePayload(const std::string& containerName, const std::string& username,
                               const std::string& image)
{
    auto& config = vdi::Config();

    Json::Value root(Json::objectValue);
    root["name"] = containerName;
    root["hostname"] = containerName;
    root["image"] = image;

    //Json::Value securityOpts(Json::arrayValue);
    //securityOpts.append("label=disable");
    //root["security_opt"] = securityOpts;

    Json::Value caps(Json::arrayValue);
    caps.append("SYS_ADMIN");
    caps.append("NET_ADMIN");
    caps.append("SYS_PTRACE");
    caps.append("AUDIT_CONTROL");
    caps.append("SYS_NICE");
    root["cap_add"] = caps;

    Json::Value devices(Json::arrayValue);
    std::unordered_set<std::string> appendedDevices;

    auto appendDevice = [&devices, &appendedDevices](const std::string& path) {
        if (path.empty())
            return;
        if (!appendedDevices.insert(path).second)
            return;
        Json::Value device(Json::objectValue);
        device["path"] = path;
        devices.append(device);
    };

    appendDevice("/dev/fuse");

    const auto driRenderDevices = config.DriRenderDevices();
    for (const auto& device : driRenderDevices)
        appendDevice(device);

    const auto driCardDevices = config.DriCardDevices();
    for (const auto& device : driCardDevices)
        appendDevice(device);

    const bool nvidiaEnabled = config.NvidiaGpuEnabled();
    Json::Value env(Json::objectValue);
    if (nvidiaEnabled)
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

    // appendMount("/etc/vdi", "/etc/vdi", true);
    appendMount(config.PasswdPath(), "/etc/passwd", true);
    appendMount(config.GroupPath(), "/etc/group", true);
    appendMount(config.ShadowPath(), "/etc/shadow", true);
    appendMount(config.HomePath(), "/home", false);

    const auto resourceLimits = config.ResourceLimitsForUser(username);
    if (!resourceLimits.empty())
    {
        Json::Value resource_limits(Json::objectValue);
        for (const auto& entry : resourceLimits)
        {
            Json::Value limit(Json::objectValue);
            limit["limit"] = static_cast<Json::Int64>(entry.second);
            resource_limits[entry.first] = limit;
        }
        root["resource_limits"] = resource_limits;
    }

    //Passthrough cgroup namespapce
    //appendMount("/sys/fs/cgroup", "/sys/fs/cgroup", false);
    //Json::Value cgroupns(Json::objectValue);
    //cgroupns["nsmode"] = "host";
    //root["cgroupns"] = cgroupns;

    //Json::Value ipcns(Json::objectValue);
    //ipcns["nsmode"] = "host";
    //root["ipcns"] = ipcns;
    
    //Add a PTY for OpenRC
    root["terminal"] = true;

    root["systemd"] = "always";

    const auto customMounts = config.CustomMounts();
    for (const auto& mount : customMounts)
        appendMount(mount.source, mount.destination, mount.readOnly);

    if (nvidiaEnabled)
    {
        const std::string base = "/dev/nvidia" + std::to_string(config.NvidiaGpuSlot());
        const std::array<std::string, 6> nvidiaDevices = {
            "/dev/nvidia-caps", base, "/dev/nvidiactl", "/dev/nvidia-modeset",
            "/dev/nvidia-uvm", "/dev/nvidia-uvm-tools"};

        for (const auto& dev : nvidiaDevices)
        {
            appendDevice(dev);
        }
    }

    root["devices"] = devices;
    root["mounts"] = mounts;

    //Json::Value command(Json::arrayValue);
    //command.append("/sbin/init");
    //root["command"] = command;

    return root;
}

bool CreateContainerInternal(const std::string& containerName, const std::string& username,
                             bool allowBuild = true)
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

    WLog_INFO(TAG, "Creating container %s with payload: %s", containerName.c_str(),
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
            WLog_ERR(TAG, "Failed to create container, HTTP code: %ld", httpCode);
            if (httpCode == 404)
                missingImage = true;
        }
    }
    else
    {
        WLog_ERR(TAG, "Failed to create container: %s", curl_easy_strerror(res));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (!success && missingImage)
    {
        if (hasCustomImage)
        {
            WLog_ERR(TAG,
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

    WLog_INFO(TAG, "Starting container: %s", containerName.c_str());

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
            WLog_ERR(TAG, "Failed to start container, HTTP code: %ld", httpCode);
    }
    else
    {
        WLog_ERR(TAG, "Failed to start container: %s", curl_easy_strerror(res));
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
        WLog_ERR(TAG, "Failed to parse container JSON info: %s", errs.c_str());
        return {};
    }

    const auto& networks = root["NetworkSettings"]["Networks"];
    if (!networks.isObject())
    {
        WLog_ERR(TAG, "No network information available for container.");
        return {};
    }

    for (const auto& name : networks.getMemberNames())
    {
        const auto& network = networks[name];
        const std::string ip = network["IPAddress"].asString();
        if (!ip.empty())
        {
            WLog_INFO(TAG, "Found IP: %s", ip.c_str());
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
            WLog_ERR(TAG, "Failed to create container for user %s", username.c_str());
            return {};
        }
    }

    if (!ContainerRunningInternal(containerName))
    {
        if (!StartContainerInternal(containerName))
        {
            WLog_ERR(TAG, "Failed to start container %s", containerName.c_str());
            return {};
        }
    }

    // bool compositorReady = WaitForProcessInternal(containerName, "/usr/bin/gnome-shell");
    // compositorReady &= WaitForProcessInternal(containerName,
    //                                           "/usr/libexec/gnome-remote-desktop-daemon --headless");
    // if (!compositorReady)
    //     WLog_WARN(TAG, "GNOME compositor not ready in container %s", containerName.c_str());

    const std::string ip = GetContainerIpInternal(containerName);
    if (ip.empty())
    {
        WLog_ERR(TAG, "Failed to retrieve IP for container %s", containerName.c_str());
        return {};
    }

    if (!WaitForTcpPort(ip, kRdpPort))
    {
        WLog_ERR(TAG, "RDP port %" PRIu16 " not ready on host %s", kRdpPort, ip.c_str());
        return {};
    }

    return ip;
}

} // namespace vdi
