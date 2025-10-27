#pragma once

#include <string>

namespace vdi
{
class VdiBrokerConfig;

bool ParseBrokerConfigYaml(const std::string& content, VdiBrokerConfig& config);

} // namespace vdi
