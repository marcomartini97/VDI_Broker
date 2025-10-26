#pragma once

#include <string>

namespace vdi
{
struct ContainerConnectionInfo
{
    std::string ip;
    std::string username;
    std::string password;
};

std::string ManageContainer(const std::string& username, const std::string& containerPrefix = "vdi-");
bool ParseContainerConnectionInfo(const std::string& json, ContainerConnectionInfo& info,
                                  std::string* errorMessage = nullptr);

} // namespace vdi
