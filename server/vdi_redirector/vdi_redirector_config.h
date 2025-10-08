#pragma once

#include <cstdint>
#include <string>

namespace redirector
{
/**
 * Encapsulates command line options that configure the redirector listener.
 */
struct RedirectorOptions
{
	std::string bindAddress = "0.0.0.0";
	std::uint16_t port = 3389;
	std::string configPath;
	std::string certificatePath;
	std::string privateKeyPath;
	bool useRoutingToken = true;
};

} // namespace redirector
