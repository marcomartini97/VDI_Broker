#pragma once

#include <cstdint>
#include <string>

namespace vdi::proxy
{
struct ProxyOptions
{
	std::string bindAddress = "0.0.0.0";
	std::uint16_t port = 3389;
	std::string configPath;
	std::string certificatePath;
	std::string privateKeyPath;
};

} // namespace vdi::proxy
