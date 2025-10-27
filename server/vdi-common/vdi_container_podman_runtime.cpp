#include "vdi_container_manager_internal.h"
#include "vdi_container_manager_constants.h"
#include "vdi_logging.h"

#include <curl/curl.h>

#include <chrono>
#include <cstdint>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <json/json.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define TAG MODULE_TAG("vdi-container-manager")

namespace vdi
{


bool ExecuteCommandInContainer(const std::string& containerName,
                               const std::vector<std::string>& command, std::string& output)
{
    output.clear();

    if (command.empty())
    {
        VDI_LOG_ERROR(TAG, "Cannot execute empty command in container %s", containerName.c_str());
        return false;
    }

    CURL* curl = curl_easy_init();
    if (!curl)
        return false;

    Json::Value commandArray(Json::arrayValue);
    for (const auto& argument : command)
        commandArray.append(argument);

    Json::Value execRequest(Json::objectValue);
    execRequest["command"] = commandArray;
    execRequest["Command"] = commandArray;
    execRequest["Cmd"] = commandArray;
    execRequest["AttachStdout"] = true;
    execRequest["AttachStderr"] = true;
    execRequest["Detach"] = false;
    execRequest["Tty"] = false;

    Json::StreamWriterBuilder writerBuilder;
    writerBuilder["indentation"] = "";
    const std::string commandString = JoinCommand(command);
    const std::string body = Json::writeString(writerBuilder, execRequest);

    std::string response;
    const std::string execCreateUrl = BuildUrl(containerName, "/exec");

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, kPodmanSocket);
    curl_easy_setopt(curl, CURLOPT_URL, execCreateUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
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
        VDI_LOG_ERROR(TAG, "Failed to create exec for '%s' in container %s: %s",
                      commandString.c_str(), containerName.c_str(), curl_easy_strerror(res));
        return false;
    }

    if (httpCode >= 400)
    {
        std::string errorDetails = ParsePodmanErrorResponse(response);
        VDI_LOG_ERROR(TAG, "HTTP error %ld while creating exec for '%s' in container %s: %s",
                      httpCode, commandString.c_str(), containerName.c_str(), errorDetails.c_str());
        return false;
    }

    Json::Value createResponse;
    Json::CharReaderBuilder readerBuilder;
    std::string errs;
    std::istringstream responseStream(response);

    if (!Json::parseFromStream(readerBuilder, responseStream, &createResponse, &errs))
    {
        VDI_LOG_ERROR(TAG, "Failed to parse exec create response for '%s' in container %s: %s",
                      commandString.c_str(), containerName.c_str(), errs.c_str());
        return false;
    }

    const std::string execId = createResponse["Id"].asString();
    if (execId.empty())
    {
        VDI_LOG_ERROR(TAG, "Podman exec create response missing Id for '%s' in container %s",
                      commandString.c_str(), containerName.c_str());
        return false;
    }

    CURL* startCurl = curl_easy_init();
    if (!startCurl)
    {
        VDI_LOG_ERROR(TAG, "Failed to allocate CURL handle to start exec '%s' in container %s",
                      commandString.c_str(), containerName.c_str());
        return false;
    }

    Json::Value startRequest(Json::objectValue);
    startRequest["Detach"] = false;
    startRequest["Tty"] = false;

    const std::string startBody = Json::writeString(writerBuilder, startRequest);
    std::string execOutput;

    struct curl_slist* startHeaders = nullptr;
    startHeaders = curl_slist_append(startHeaders, "Content-Type: application/json");

    const std::string execStartUrl = kPodmanExecBase + execId + "/start";
    curl_easy_setopt(startCurl, CURLOPT_UNIX_SOCKET_PATH, kPodmanSocket);
    curl_easy_setopt(startCurl, CURLOPT_URL, execStartUrl.c_str());
    curl_easy_setopt(startCurl, CURLOPT_POSTFIELDS, startBody.c_str());
    curl_easy_setopt(startCurl, CURLOPT_POSTFIELDSIZE, static_cast<long>(startBody.size()));
    curl_easy_setopt(startCurl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(startCurl, CURLOPT_WRITEDATA, &execOutput);
    curl_easy_setopt(startCurl, CURLOPT_HTTPHEADER, startHeaders);

    const CURLcode startRes = curl_easy_perform(startCurl);
    long startHttpCode = 0;
    if (startRes == CURLE_OK)
        curl_easy_getinfo(startCurl, CURLINFO_RESPONSE_CODE, &startHttpCode);

    if (startHeaders)
        curl_slist_free_all(startHeaders);

    curl_easy_cleanup(startCurl);

    if (startRes != CURLE_OK)
    {
        VDI_LOG_ERROR(TAG, "Failed to run '%s' in container %s: %s", commandString.c_str(),
                      containerName.c_str(), curl_easy_strerror(startRes));
        return false;
    }

    if (startHttpCode >= 400)
    {
        std::string errorDetails = ParsePodmanErrorResponse(execOutput);
        VDI_LOG_ERROR(TAG, "HTTP error %ld while running '%s' in container %s: %s", startHttpCode,
                      commandString.c_str(), containerName.c_str(), errorDetails.c_str());
        return false;
    }

    output = TrimWhitespace(execOutput);
    return true;
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


bool WaitForContainerPortWithSs(const std::string& containerName, std::uint16_t port)
{
    VDI_LOG_INFO(TAG, "Waiting for TCP port %" PRIu16 " inside container %s using ss", port,
                 containerName.c_str());

    const auto deadline = std::chrono::steady_clock::now() + kPortReadyTimeout;
    const std::string portFilter = ":" + std::to_string(port);
    const std::vector<std::string> command = {"ss", "-H", "-ltn", "sport", "=", portFilter};

    while (std::chrono::steady_clock::now() < deadline)
    {
        std::string execOutput;
        if (!ExecuteCommandInContainer(containerName, command, execOutput))
        {
            VDI_LOG_ERROR(TAG, "Failed to run 'ss' inside container %s while checking port %" PRIu16,
                          containerName.c_str(), port);
            return false;
        }

        if (!execOutput.empty() && execOutput.find("LISTEN") != std::string::npos)
        {
            VDI_LOG_INFO(TAG, "Port %" PRIu16 " is listening inside container %s", port,
                         containerName.c_str());
            return true;
        }

        std::this_thread::sleep_for(kReadinessPollInterval);
    }

    VDI_LOG_WARN(TAG, "Port %" PRIu16 " did not start listening inside container %s before timeout",
                 port, containerName.c_str());
    return false;
}


std::string GetContainerIpInternal(const std::string& containerName)
{
    const std::string grepCommand = std::string("grep -oE '") + kSessionJsonPattern + "' " +
                                    kSessionLogPath + " | tail -n 1";
    const std::vector<std::string> command = {"sh", "-c", grepCommand};

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    std::optional<std::string> latestJson;
    std::string lastOutput;

    while (std::chrono::steady_clock::now() <= deadline)
    {
        std::string execOutput;
        if (!ExecuteCommandInContainer(containerName, command, execOutput))
        {
            VDI_LOG_ERROR(TAG,
                          "Failed to read %s inside container %s while searching for session credentials",
                          kSessionLogPath, containerName.c_str());
            return {};
        }

        lastOutput = std::move(execOutput);
        latestJson = ExtractLatestSessionJson(lastOutput);
        if (latestJson && !latestJson->empty())
            break;

        if (std::chrono::steady_clock::now() > deadline)
            break;

        std::this_thread::sleep_for(kReadinessPollInterval);
    }

    if (!latestJson || latestJson->empty())
    {
        const std::string sanitized = SanitizeForLog(lastOutput);
        VDI_LOG_ERROR(TAG,
                      "No session credentials matching pattern found in %s for container %s after waiting up to 30s (output preview='%s')",
                      kSessionLogPath, containerName.c_str(), sanitized.c_str());
        return {};
    }

    const std::string jsonPayload = TrimWhitespace(*latestJson);
    if (jsonPayload.empty())
    {
        const std::string sanitized = SanitizeForLog(*latestJson);
        VDI_LOG_ERROR(TAG,
                      "Matched session credential string was empty after trimming in container %s (preview='%s')",
                      containerName.c_str(), sanitized.c_str());
        return {};
    }

    Json::Value connectionInfo;
    Json::CharReaderBuilder readerBuilder;
    std::string errs;
    std::istringstream jsonStream(jsonPayload);

    if (!Json::parseFromStream(readerBuilder, jsonStream, &connectionInfo, &errs))
    {
        const std::string sanitized = SanitizeForLog(jsonPayload);
        VDI_LOG_ERROR(TAG,
                      "Failed to parse session credentials from %s in container %s: %s (payload length=%zu, preview='%s')",
                      kSessionLogPath, containerName.c_str(), errs.c_str(), jsonPayload.size(),
                      sanitized.c_str());
        return {};
    }

    auto ensureField = [&](const char* field) -> bool {
        if (!connectionInfo.isMember(field) || !connectionInfo[field].isString() ||
            connectionInfo[field].asString().empty())
        {
            VDI_LOG_ERROR(TAG,
                          "Session credential field '%s' missing in %s for container %s (payload length=%zu)",
                          field, kSessionLogPath, containerName.c_str(), jsonPayload.size());
            return false;
        }
        return true;
    };

    if (!ensureField("ip") || !ensureField("username") || !ensureField("password"))
        return {};

    const std::string ipValue = connectionInfo["ip"].asString();
    const std::string userValue = connectionInfo["username"].asString();
    VDI_LOG_INFO(TAG, "Retrieved container connection info for %s (ip: %s, user: %s)",
                 containerName.c_str(), ipValue.c_str(), userValue.c_str());
    return jsonPayload;
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

} // namespace vdi
