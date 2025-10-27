#pragma once

#include "vdi_broker_config.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <json/json.h>

namespace vdi
{

std::string TrimWhitespace(const std::string& value);
std::string JoinCommand(const std::vector<std::string>& command);
std::string SanitizeForLog(const std::string& input, size_t maxLength = 256);
std::optional<std::string> ExtractLatestSessionJson(const std::string& input);
std::string ParsePodmanErrorResponse(const std::string& responseBody);
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
bool ExecuteCommandInContainer(const std::string& containerName,
                               const std::vector<std::string>& command, std::string& output);
std::string BuildUrl(const std::string& containerName, const std::string& endpoint);
bool EnsurePodmanNetwork(VdiBrokerConfig& config);
bool ContainerExistsInternal(const std::string& containerName);
bool ContainerRunningInternal(const std::string& containerName);
std::string GetContainerInfo(const std::string& containerName, const std::string& endpoint);
bool CreateContainerInternal(const std::string& containerName, const std::string& username,
                             bool allowBuild = true);
bool StartContainerInternal(const std::string& containerName);
std::string GetContainerIpInternal(const std::string& containerName);
bool WaitForContainerPortWithSs(const std::string& containerName, std::uint16_t port);
bool WaitForProcessInternal(const std::string& containerName, const std::string& processName);
Json::Value BuildCreatePayload(const std::string& containerName, const std::string& username,
                               const std::string& image);
bool BuildImageFromDockerfile(const std::string& imageName, const std::string& dockerfilePath);
const char* PodmanModeToString(VdiBrokerConfig::PodmanNetworkMode mode);

} // namespace vdi
