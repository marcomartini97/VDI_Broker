#include "vdi_redirector_config.h"
#include "vdi_redirector_constants.h"
#include "vdi_redirector_server.h"
#include "vdi_logging.h"
#include "vdi_broker_config.h"
#include "vdi_redirector_utils.h"

#include <winpr/winsock.h>

#include <atomic>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

#define TAG MODULE_TAG("vdi_redirector")

namespace redirector
{

void print_usage(const char* program)
{
	std::cout << "Usage: " << program << " [options]\n"
	          << "  --bind <address>        Bind address (default 0.0.0.0)\n"
	          << "  --port <port>           Listening port (default 3389)\n"
	          << "  --config <path>         Broker configuration file\n"
	          << "  --certificate <path>    Server certificate (PEM)\n"
	          << "  --private-key <path>    Server private key (PEM)\n"
	          << "  --routing-token         Enable routing token load-balance info\n"
	          << "  --vortice               Enable Vortice broker integration\n"
	          << "  --vortice-endpoint <endpoint>  Vortice endpoint (unix:/path or tcp:host:port)\n"
	          << "  --help                  Show this help message\n";
}

bool parse_arguments(int argc, char** argv, RedirectorOptions& options)
{
	for (int i = 1; i < argc; ++i)
	{
		const std::string arg = argv[i];
		if (arg == "--help")
		{
			print_usage(argv[0]);
			return false;
		}
		if (arg == "--bind")
		{
			if (i + 1 >= argc)
				return false;
			options.bindAddress = argv[++i];
		}
		else if (arg == "--port")
		{
			if (i + 1 >= argc)
				return false;
			const char* portStr = argv[++i];
			char* end = nullptr;
			const long port = std::strtol(portStr, &end, 10);
			if (!end || *end != '\0' || port < 1 || port > UINT16_MAX)
			{
				std::cerr << "Invalid port value: " << portStr << '\n';
				return false;
			}
			options.port = static_cast<std::uint16_t>(port);
		}
		else if (arg == "--config")
		{
			if (i + 1 >= argc)
				return false;
			options.configPath = argv[++i];
		}
		else if (arg == "--certificate")
		{
			if (i + 1 >= argc)
				return false;
			options.certificatePath = argv[++i];
		}
		else if (arg == "--private-key")
		{
			if (i + 1 >= argc)
				return false;
			options.privateKeyPath = argv[++i];
		}
		else if (arg == "--routing-token")
		{
			options.useRoutingToken = true;
		}
		else if (arg == "--vortice")
		{
			options.enableVortice = true;
		}
		else if (arg == "--vortice-endpoint")
		{
			if (i + 1 >= argc)
				return false;
			options.vorticeEndpoint = argv[++i];
			options.enableVortice = true;
		}
		else
		{
			std::cerr << "Unknown argument: " << arg << '\n';
			print_usage(argv[0]);
			return false;
		}
	}

	if (options.certificatePath.empty() || options.privateKeyPath.empty())
	{
		std::cerr << "Both --certificate and --private-key must be provided\n";
		return false;
	}

	if (options.enableVortice)
	{
		vdi::vortice::Endpoint endpoint{};
		if (!vdi::vortice::ParseEndpoint(options.vorticeEndpoint, endpoint))
		{
			std::cerr << "Invalid --vortice-endpoint value: " << options.vorticeEndpoint << '\n';
			return false;
		}
	}

	return true;
}

std::atomic<RedirectorServer*> g_activeServer{ nullptr };

void handle_signal(int)
{
	auto* server = g_activeServer.load();
	if (server)
		server->Stop();
}

int run(int argc, char** argv)
{
	RedirectorOptions options;
	if (!parse_arguments(argc, argv, options))
		return EXIT_FAILURE;

	if (!options.configPath.empty())
		vdi::Config().SetConfigPath(options.configPath);

	const bool refreshed = vdi::Config().Refresh();
	const bool reloaded = vdi::Config().ConsumeReloadedFlag();
	vdi_log_refresh_outcome(refreshed, reloaded);

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		VDI_LOG_ERROR(TAG, "WSAStartup failed");
		return EXIT_FAILURE;
	}

    RedirectorServer server;
    if (!server.Initialize(options))
    {
        WSACleanup();
        return EXIT_FAILURE;
    }

	g_activeServer.store(&server);
	std::signal(SIGINT, handle_signal);
	std::signal(SIGTERM, handle_signal);

    server.Run();

    g_activeServer.store(nullptr);
    WSACleanup();
    VDI_LOG_INFO(TAG, "VDI redirector stopped");
    return EXIT_SUCCESS;
}

} // namespace redirector

int main(int argc, char** argv)
{
	return redirector::run(argc, argv);
}
