#include "vdi_container_manager.h"

#include "vdi_broker_config.h"
#include "vdi_logging.h"

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
        VDI_LOG_ERROR(TAG, "Tar entry name too long: %s", tarName.c_str());
        return false;
    }

    if (!WriteOctal(header.mode, sizeof(header.mode), mode) ||
        !WriteOctal(header.uid, sizeof(header.uid), 0) ||
        !WriteOctal(header.gid, sizeof(header.gid), 0) ||
        !WriteOctal(header.size, sizeof(header.size), size) ||
        !WriteOctal(header.mtime, sizeof(header.mtime), mtime))
    {
        VDI_LOG_ERROR(TAG, "Failed to encode tar header fields for entry: %s", tarName.c_str());
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
        VDI_LOG_ERROR(TAG, "Failed to stat file for tar entry: %s (%s)",
                 sourcePath.string().c_str(), ec.message().c_str());
        return false;
    }

    if (!WriteTarHeader(tarStream, tarName, '0', fileSize, 0644, mtime))
        return false;

    std::ifstream input(sourcePath, std::ios::binary);
    if (!input)
    {
        VDI_LOG_ERROR(TAG, "Failed to open file for tar entry: %s", sourcePath.string().c_str());
        return false;
    }

    std::array<char, 8192> buffer{};
    while (input.read(buffer.data(), buffer.size()))
        tarStream.write(buffer.data(), buffer.size());
    if (input.gcount() > 0)
        tarStream.write(buffer.data(), input.gcount());

    if (!tarStream)
    {
        VDI_LOG_ERROR(TAG, "Failed while writing tar contents for: %s", tarName.c_str());
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
        VDI_LOG_ERROR(TAG, "Failed to create temporary build context: %s", tarPath.string().c_str());
        return false;
    }

    const std::uint64_t now = static_cast<std::uint64_t>(std::time(nullptr));

    std::error_code ec;
    if (!std::filesystem::exists(contextDir, ec))
    {
        VDI_LOG_ERROR(TAG, "Build context directory missing: %s", contextDir.string().c_str());
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
            VDI_LOG_ERROR(TAG, "Failed to resolve relative path for tar entry: %s (%s)",
                     it->path().string().c_str(), ec.message().c_str());
            return false;
        }

        std::string tarName = relative.generic_string();
        if (tarName.empty())
            continue;

        if (it->is_symlink())
        {
            VDI_LOG_WARN(TAG, "Symlinks are not supported in build context: %s",
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
            VDI_LOG_ERROR(TAG, "Unsupported file type in build context: %s",
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
        VDI_LOG_ERROR(TAG, "Dockerfile path not configured; unable to build image %s", image.c_str());
        return false;
    }

    std::filesystem::path dockerfile(dockerfilePath);
    if (!std::filesystem::exists(dockerfile))
    {
        VDI_LOG_ERROR(TAG, "Dockerfile not found at %s", dockerfilePath.c_str());
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
        VDI_LOG_ERROR(TAG, "Failed to resolve Dockerfile relative path: %s", ex.what());
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
        VDI_LOG_ERROR(TAG, "Failed to resolve temporary directory for build context: %s", ex.what());
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
        VDI_LOG_ERROR(TAG, "Failed to stat build context archive: %s", ec.message().c_str());
        return false;
    }

    CurlReadContext readContext{};
    readContext.stream.open(tarPath, std::ios::binary);
    if (!readContext.stream)
    {
        VDI_LOG_ERROR(TAG, "Failed to open build context archive for upload: %s", tarPath.string().c_str());
        return false;
    }

    CURL* curl = curl_easy_init();
    if (!curl)
    {
        VDI_LOG_ERROR(TAG, "Failed to initialise curl for Podman image build");
        return false;
    }

    std::unique_ptr<char, decltype(&curl_free)> escapedImage(
        curl_easy_escape(curl, image.c_str(), static_cast<int>(image.size())), curl_free);
    if (!escapedImage)
    {
        VDI_LOG_ERROR(TAG, "Failed to escape image name for Podman request");
        curl_easy_cleanup(curl);
        return false;
    }

    std::unique_ptr<char, decltype(&curl_free)> escapedDockerfile(
        curl_easy_escape(curl, dockerfileName.c_str(), static_cast<int>(dockerfileName.size())), curl_free);
    if (!escapedDockerfile)
    {
        VDI_LOG_ERROR(TAG, "Failed to escape Dockerfile path for Podman request");
        curl_easy_cleanup(curl);
        return false;
    }

    std::string url = kPodmanBuildEndpoint;
    url += "?t=";
    url += escapedImage.get();
    url += "&dockerfile=";
    url += escapedDockerfile.get();

    VDI_LOG_INFO(TAG, "Building Podman image '%s' using Dockerfile %s via Podman API", image.c_str(),
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
        VDI_LOG_ERROR(TAG, "Podman image build failed: %s", curl_easy_strerror(res));
        return false;
    }

    if (httpCode >= 400)
    {
        VDI_LOG_ERROR(TAG, "Podman image build returned HTTP status %ld", httpCode);
        return false;
    }

    VDI_LOG_INFO(TAG, "Successfully built Podman image '%s'", image.c_str());
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

bool ContainerExistsInternal(const std::string& containerName)
{
    const std::string payload = GetContainerInfo(containerName, "/json");
    if (payload.empty())
        VDI_LOG_INFO(TAG, "Container does not exist: %s", containerName.c_str());
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
        VDI_LOG_ERROR(TAG, "Failed to parse container info: %s", errs.c_str());
        return false;
    }

    const auto status = root["State"]["Status"].asString();
    return status == "running";
}

bool WaitForProcessInternal(const std::string& containerName, const std::string& processName)
{
    VDI_LOG_INFO(TAG, "Waiting for <%s> in container: %s", processName.c_str(), containerName.c_str());

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
            VDI_LOG_ERROR(TAG, "Error parsing JSON: %s", errs.c_str());
            return false;
        }

        const auto& processes = root["Processes"];
        if (!processes.isArray())
        {
            VDI_LOG_ERROR(TAG, "Invalid JSON: 'Processes' missing or not array");
            return false;
        }

        for (const auto& process : processes)
        {
            if (matchesProcess(process))
                return true;
        }

        std::this_thread::sleep_for(kReadinessPollInterval);
    }

    VDI_LOG_WARN(TAG, "Process <%s> not detected in container %s after %d attempts",
              processName.c_str(), containerName.c_str(), kProcessCheckAttempts);
    return false;
}

bool WaitForTcpPort(const std::string& host, std::uint16_t port)
{
    VDI_LOG_INFO(TAG, "Waiting for TCP port %" PRIu16 " on host %s", port, host.c_str());

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
            VDI_LOG_ERROR(TAG, "Failed to resolve address %s for port check: %s", host.c_str(),
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
            VDI_LOG_INFO(TAG, "Port %" PRIu16 " is reachable on host %s", port, host.c_str());
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            return true;
        }

        std::this_thread::sleep_for(kReadinessPollInterval);
    }

    VDI_LOG_ERROR(TAG, "Timed out waiting for port %" PRIu16 " on host %s", port, host.c_str());
    return false;
}

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

Json::Value BuildCreatePayload(const std::string& containerName, const std::string& username,
                               const std::string& image)
{
    auto& config = vdi::Config();
    ContainerPayloadBuilder builder(containerName, username, image, config);
    return builder.Build();
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
        VDI_LOG_ERROR(TAG, "Failed to parse container JSON info: %s", errs.c_str());
        return {};
    }

    const auto& networks = root["NetworkSettings"]["Networks"];
    if (!networks.isObject())
    {
        VDI_LOG_ERROR(TAG, "No network information available for container.");
        return {};
    }

    for (const auto& name : networks.getMemberNames())
    {
        const auto& network = networks[name];
        const std::string ip = network["IPAddress"].asString();
        if (!ip.empty())
        {
            VDI_LOG_INFO(TAG, "Found IP: %s", ip.c_str());
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
	vdi::logging::ScopedLogUser scopedUser(username);
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
            VDI_LOG_ERROR(TAG, "Failed to create container for user %s", username.c_str());
            return {};
        }
    }

    if (!ContainerRunningInternal(containerName))
    {
        if (!StartContainerInternal(containerName))
        {
            VDI_LOG_ERROR(TAG, "Failed to start container %s", containerName.c_str());
            return {};
        }
    }

    // bool compositorReady = WaitForProcessInternal(containerName, "/usr/bin/gnome-shell");
    // compositorReady &= WaitForProcessInternal(containerName,
    //                                           "/usr/libexec/gnome-remote-desktop-daemon --headless");
    // if (!compositorReady)
    //     VDI_LOG_WARN(TAG, "GNOME compositor not ready in container %s", containerName.c_str());

    const std::string ip = GetContainerIpInternal(containerName);
    if (ip.empty())
    {
        VDI_LOG_ERROR(TAG, "Failed to retrieve IP for container %s", containerName.c_str());
        return {};
    }

    if (!WaitForTcpPort(ip, kRdpPort))
    {
        VDI_LOG_ERROR(TAG, "RDP port %" PRIu16 " not ready on host %s", kRdpPort, ip.c_str());
        return {};
    }

    return ip;
}

} // namespace vdi
