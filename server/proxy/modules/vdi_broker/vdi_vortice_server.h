#pragma once

#include "vdi_vortice_protocol.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace vdi
{
namespace broker
{

#if defined(_WIN32)

class VorticeServer
{
public:
	VorticeServer(std::string endpoint, std::string proxyHost, std::uint16_t proxyPort)
	{
		(void)endpoint;
		(void)proxyHost;
		(void)proxyPort;
	}

	bool Start()
	{
		return false;
	}

	void Stop() {}

	bool Ready() const
	{
		return false;
	}

	struct PendingRedirect
	{
		std::string username;
		std::string password;
		std::string targetHost;
		std::uint16_t targetPort = 0;
		std::string rdpUsername;
		std::string rdpPassword;
		std::chrono::steady_clock::time_point created;
	};

	std::optional<PendingRedirect> ConsumeMatch(const std::string&, const std::string&)
	{
		return std::nullopt;
	}
};

#else

class VorticeServer
{
public:
	VorticeServer(std::string endpoint, std::string proxyHost, std::uint16_t proxyPort);
	~VorticeServer();

	bool Start();
	void Stop();
	bool Ready() const;

	struct PendingRedirect
	{
		std::string username;
		std::string password;
		std::string targetHost;
		std::uint16_t targetPort = 0;
		std::string rdpUsername;
		std::string rdpPassword;
		std::chrono::steady_clock::time_point created;
	};

	std::optional<PendingRedirect> ConsumeMatch(const std::string& username,
	                                            const std::string& password);

private:
	void WorkerLoop();
	bool SetupSocket();
	bool SetupUnixSocket(const std::string& path);
	bool SetupTcpSocket(const std::string& host, std::uint16_t port);
	void CloseSockets();
	bool HandleNewConnection(int clientFd);
	bool PerformHandshake(int clientFd);
	void ResetHandshake();
	void AddPending(const vdi::vortice::RedirectMessage& message);
	void CleanupExpiredLocked();

	std::string endpointString_;
	vdi::vortice::Endpoint endpoint_{};
	bool endpointValid_ = false;
	std::string proxyHost_;
	std::uint16_t proxyPort_;
	std::atomic_bool running_{ false };
	std::atomic_bool ready_{ false };
	int serverFd_ = -1;
	int clientFd_ = -1;
	std::thread worker_;
	std::mutex clientMutex_;
	std::mutex pendingMutex_;
	std::vector<PendingRedirect> pending_;
	std::chrono::seconds retention_{ 120 };
};

#endif

} // namespace broker
} // namespace vdi

