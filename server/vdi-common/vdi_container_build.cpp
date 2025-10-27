#include "vdi_container_manager_internal.h"
#include "vdi_container_manager_constants.h"
#include "vdi_logging.h"

#include <curl/curl.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>
#include <ctime>

#define TAG MODULE_TAG("vdi-container-manager")

namespace vdi
{
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
        VDI_LOG_ERROR(TAG, "Failed to open build context archive for upload: %s",
                      tarPath.string().c_str());
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
        curl_easy_escape(curl, dockerfileName.c_str(), static_cast<int>(dockerfileName.size())),
        curl_free);
    if (!escapedDockerfile)
    {
        VDI_LOG_ERROR(TAG, "Failed to escape Dockerfile path for Podman request");
        curl_easy_cleanup(curl);
        return false;
    }

    std::string url(kPodmanBuildEndpoint);
    url += "?t=";
    url += escapedImage.get();
    url += "&dockerfile=";
    url += escapedDockerfile.get();

    VDI_LOG_INFO(TAG, "Building Podman image '%s' using Dockerfile %s via Podman API",
                 image.c_str(), dockerfilePath.c_str());

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

} // namespace vdi
