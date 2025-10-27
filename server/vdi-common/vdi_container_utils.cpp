#include "vdi_container_manager_internal.h"
#include "vdi_container_manager.h"
#include "vdi_container_manager_constants.h"
#include "vdi_logging.h"

#include <json/json.h>

#include <algorithm>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#define TAG MODULE_TAG("vdi-container-manager")

namespace vdi
{

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    const auto total = size * nmemb;
    auto* buffer = static_cast<std::string*>(userp);
    buffer->append(static_cast<const char*>(contents), total);
    return total;
}

std::string TrimWhitespace(const std::string& value)
{
    const auto start = value.find_first_not_of(" \t\r\n");
    if (start == std::string::npos)
        return {};

    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(start, end - start + 1);
}

std::string JoinCommand(const std::vector<std::string>& command)
{
    std::ostringstream stream;
    bool first = true;
    for (const auto& argument : command)
    {
        if (!first)
            stream << ' ';
        stream << argument;
        first = false;
    }
    return stream.str();
}

std::string SanitizeForLog(const std::string& input, size_t maxLength)
{
    std::string sanitized;
    sanitized.reserve(std::min(input.size(), maxLength));

    size_t produced = 0;
    for (unsigned char ch : input)
    {
        if (produced >= maxLength)
            break;

        if (ch >= 32 && ch <= 126)
        {
            sanitized.push_back(static_cast<char>(ch));
            ++produced;
        }
        else
        {
            if (produced + 4 > maxLength)
                break;
            constexpr char hexDigits[] = "0123456789ABCDEF";
            sanitized.append("\\x");
            sanitized.push_back(hexDigits[(ch >> 4) & 0x0F]);
            sanitized.push_back(hexDigits[ch & 0x0F]);
            produced += 4;
        }
    }

    return sanitized;
}

std::optional<std::string> ExtractLatestSessionJson(const std::string& output)
{
    try
    {
        const std::regex pattern{std::string(kSessionJsonPattern)};
        std::smatch match;
        std::optional<std::string> latest;
        auto begin = output.cbegin();
        while (std::regex_search(begin, output.cend(), match, pattern))
        {
            latest = match.str();
            begin = match.suffix().first;
        }
        return latest;
    }
    catch (const std::regex_error& ex)
    {
        VDI_LOG_ERROR(TAG, "Session credential regex failed: %s", ex.what());
        return std::nullopt;
    }
}

std::string ParsePodmanErrorResponse(const std::string& response)
{
    if (response.empty())
        return "empty response body";

    std::string trimmed = TrimWhitespace(response);
    if (trimmed.empty())
        return "empty response body";

    Json::Value errorJson;
    Json::CharReaderBuilder readerBuilder;
    std::string errs;
    std::istringstream stream(trimmed);
    if (Json::parseFromStream(readerBuilder, stream, &errorJson, &errs) && errorJson.isObject())
    {
        std::string message;
        std::string cause;
        if (errorJson.isMember("message") && errorJson["message"].isString())
            message = errorJson["message"].asString();
        if (errorJson.isMember("cause") && errorJson["cause"].isString())
            cause = errorJson["cause"].asString();

        if (!message.empty() || !cause.empty())
        {
            std::string details = message;
            if (!cause.empty())
            {
                if (!details.empty())
                    details.append("; ");
                details.append("cause: ");
                details.append(cause);
            }

            if (!details.empty())
                return details;
        }
    }

    return std::string{"raw="} + SanitizeForLog(trimmed);
}

bool ParseContainerConnectionInfo(const std::string& json, ContainerConnectionInfo& info,
                                  std::string* errorMessage)
{
    info = {};

    const std::string trimmed = TrimWhitespace(json);
    if (trimmed.empty())
    {
        if (errorMessage)
            *errorMessage = "empty payload";
        return false;
    }

    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errs;
    std::istringstream stream(trimmed);
    if (!Json::parseFromStream(builder, stream, &root, &errs))
    {
        if (errorMessage)
            *errorMessage = "invalid JSON response";
        return false;
    }

    info.ip = root.get("ip", "").asString();
    info.username = root.get("username", "").asString();
    info.password = root.get("password", "").asString();

    if (info.ip.empty())
    {
        if (errorMessage)
            *errorMessage = "missing ip field";
        return false;
    }

    return true;
}

} // namespace vdi
