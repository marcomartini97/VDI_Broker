#include "vdi_vortice_server.h"

#if !defined(_WIN32)

#include "vdi_logging.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <arpa/inet.h>

#define TAG MODULE_TAG("vortice_server")

namespace vdi
{
namespace broker
{

VorticeServer::VorticeServer(std::string endpoint, std::string proxyHost, std::uint16_t proxyPort)
    : endpointString_(std::move(endpoint)),
      proxyHost_(std::move(proxyHost)),
      proxyPort_(proxyPort)
{
	endpointValid_ = vdi::vortice::ParseEndpoint(endpointString_, endpoint_);
	if (!endpointValid_)
	{
		VDI_LOG_ERROR(TAG, "Invalid Vortice endpoint '%s'", endpointString_.c_str());
	}
}

VorticeServer::~VorticeServer()
{
	Stop();
}

bool VorticeServer::Start()
{
	if (running_.exchange(true))
		return true;

	if (!endpointValid_)
	{
		running_.store(false);
		return false;
	}

	if (!SetupSocket())
	{
		running_.store(false);
		return false;
	}

	try
	{
		worker_ = std::thread(&VorticeServer::WorkerLoop, this);
	}
	catch (const std::exception& ex)
	{
		VDI_LOG_ERROR(TAG, "Failed to start Vortice server thread: %s", ex.what());
		CloseSockets();
		running_.store(false);
		return false;
	}

	return true;
}

void VorticeServer::Stop()
{
	if (!running_.exchange(false))
		return;

	CloseSockets();
	if (worker_.joinable())
		worker_.join();
	ResetHandshake();
}

bool VorticeServer::Ready() const
{
	return ready_.load(std::memory_order_acquire);
}

std::optional<VorticeServer::PendingRedirect> VorticeServer::ConsumeMatch(
    const std::string& username, const std::string& password)
{
	std::lock_guard<std::mutex> lock(pendingMutex_);
	CleanupExpiredLocked();

	for (auto it = pending_.begin(); it != pending_.end(); ++it)
	{
		if (it->username == username && it->password == password)
		{
			PendingRedirect match = *it;
			pending_.erase(it);
			return match;
		}
	}

	return std::nullopt;
}

void VorticeServer::CleanupExpiredLocked()
{
	const auto now = std::chrono::steady_clock::now();
	pending_.erase(std::remove_if(pending_.begin(), pending_.end(), [&](const PendingRedirect& entry) {
		              return (now - entry.created) > retention_;
	              }),
	               pending_.end());
}

void VorticeServer::WorkerLoop()
{
	while (running_.load(std::memory_order_acquire))
	{
		sockaddr_storage addr = {};
		socklen_t len = sizeof(addr);
		int client = ::accept(serverFd_, reinterpret_cast<sockaddr*>(&addr), &len);
		if (client < 0)
		{
			if (!running_.load(std::memory_order_acquire))
				break;
			if (errno == EINTR)
				continue;
			VDI_LOG_WARN(TAG, "Accept on Vortice endpoint failed: %s", strerror(errno));
			continue;
		}

		if (!HandleNewConnection(client))
		{
			::close(client);
			continue;
		}

		while (running_.load(std::memory_order_acquire))
		{
			vdi::vortice::Message inbound;
			if (!vdi::vortice::ReceiveMessage(client, inbound))
				break;

			if (inbound.type == vdi::vortice::MessageType::Redirect)
			{
				AddPending(inbound.redirect);

				vdi::vortice::Message ack;
				ack.type = vdi::vortice::MessageType::Ack;
				ack.ack.success = true;
				(void)vdi::vortice::SendMessage(client, ack);

				continue;
			}

			if (inbound.type == vdi::vortice::MessageType::Ack)
			{
				if (!inbound.ack.success && !inbound.ack.error.empty())
					VDI_LOG_WARN(TAG, "Received Vortice error from redirector: %s",
					             inbound.ack.error.c_str());
				continue;
			}

			VDI_LOG_WARN(TAG, "Unexpected Vortice message type %d", static_cast<int>(inbound.type));
		}

		ResetHandshake();
	}
}

bool VorticeServer::SetupSocket()
{
	if (endpoint_.type == vdi::vortice::EndpointType::Unix)
		return SetupUnixSocket(endpoint_.path);
	return SetupTcpSocket(endpoint_.host, endpoint_.port);
}

bool VorticeServer::SetupUnixSocket(const std::string& path)
{
	serverFd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
	if (serverFd_ < 0)
	{
		VDI_LOG_ERROR(TAG, "Unable to create Vortice UNIX socket: %s", strerror(errno));
		return false;
	}

	sockaddr_un addr = {};
	addr.sun_family = AF_UNIX;
	if (path.size() >= sizeof(addr.sun_path))
	{
		VDI_LOG_ERROR(TAG, "Vortice socket path '%s' too long", path.c_str());
		CloseSockets();
		return false;
	}

	std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
	::unlink(addr.sun_path);

	if (::bind(serverFd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
	{
		VDI_LOG_ERROR(TAG, "Failed to bind Vortice UNIX socket %s: %s", path.c_str(),
		              strerror(errno));
		CloseSockets();
		return false;
	}

	if (::listen(serverFd_, 4) < 0)
	{
		VDI_LOG_ERROR(TAG, "Failed to listen on Vortice UNIX socket %s: %s", path.c_str(),
		              strerror(errno));
		CloseSockets();
		return false;
	}

	VDI_LOG_INFO(TAG, "Listening for Vortice redirector on %s", path.c_str());
	return true;
}

bool VorticeServer::SetupTcpSocket(const std::string& host, std::uint16_t port)
{
	serverFd_ = ::socket(AF_INET, SOCK_STREAM, 0);
	if (serverFd_ < 0)
	{
		VDI_LOG_ERROR(TAG, "Unable to create Vortice TCP socket: %s", strerror(errno));
		return false;
	}

	sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	std::string bindHost = host;
	if (bindHost.empty() || bindHost == "*")
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
	else if (inet_pton(AF_INET, bindHost.c_str(), &addr.sin_addr) != 1)
	{
		VDI_LOG_ERROR(TAG, "Invalid Vortice TCP bind address '%s'", bindHost.c_str());
		CloseSockets();
		return false;
	}

	int opt = 1;
	setsockopt(serverFd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	if (::bind(serverFd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
	{
		VDI_LOG_ERROR(TAG, "Failed to bind Vortice TCP %s:%u (%s)", bindHost.c_str(),
		              static_cast<unsigned>(port), strerror(errno));
		CloseSockets();
		return false;
	}

	if (::listen(serverFd_, 4) < 0)
	{
		VDI_LOG_ERROR(TAG, "Failed to listen on Vortice TCP %s:%u (%s)", bindHost.c_str(),
		              static_cast<unsigned>(port), strerror(errno));
		CloseSockets();
		return false;
	}

	VDI_LOG_INFO(TAG, "Listening for Vortice redirector on %s:%u", bindHost.c_str(),
	             static_cast<unsigned>(port));
	return true;
}

void VorticeServer::CloseSockets()
{
	if (serverFd_ >= 0)
	{
		::shutdown(serverFd_, SHUT_RDWR);
		::close(serverFd_);
		serverFd_ = -1;

		if (endpoint_.type == vdi::vortice::EndpointType::Unix && !endpoint_.path.empty())
			::unlink(endpoint_.path.c_str());
	}

	std::lock_guard<std::mutex> lock(clientMutex_);
	if (clientFd_ >= 0)
	{
		::close(clientFd_);
		clientFd_ = -1;
	}
}

bool VorticeServer::HandleNewConnection(int clientFd)
{
	{
		std::lock_guard<std::mutex> lock(clientMutex_);
		if (clientFd_ >= 0)
		{
			::close(clientFd_);
			clientFd_ = -1;
		}
		clientFd_ = clientFd;
	}

	if (!PerformHandshake(clientFd))
	{
		ResetHandshake();
		return false;
	}

	return true;
}

bool VorticeServer::PerformHandshake(int clientFd)
{
	vdi::vortice::Message hello;
	if (!vdi::vortice::ReceiveMessage(clientFd, hello))
		return false;

	if (hello.type != vdi::vortice::MessageType::Hello || hello.hello.role != "redirector")
	{
		VDI_LOG_WARN(TAG, "Unexpected Vortice handshake message");
		return false;
	}

	vdi::vortice::Message response;
	response.type = vdi::vortice::MessageType::HelloResponse;
	response.helloResponse.role = "broker";
	response.helloResponse.proxyHost = proxyHost_;
	response.helloResponse.proxyPort = proxyPort_;
	if (!vdi::vortice::SendMessage(clientFd, response))
		return false;

	vdi::vortice::Message ack;
	if (!vdi::vortice::ReceiveMessage(clientFd, ack))
		return false;
	if (ack.type != vdi::vortice::MessageType::Ack)
	{
		VDI_LOG_WARN(TAG, "Expected Vortice handshake ack, received type %d",
		             static_cast<int>(ack.type));
		return false;
	}
	if (!ack.ack.success && !ack.ack.error.empty())
		VDI_LOG_WARN(TAG, "Redirector reported handshake error: %s", ack.ack.error.c_str());

	ready_.store(true, std::memory_order_release);
	VDI_LOG_INFO(TAG, "Redirector connected to Vortice endpoint (%s)",
	             vdi::vortice::EndpointToString(endpoint_).c_str());
	return true;
}

void VorticeServer::ResetHandshake()
{
	ready_.store(false, std::memory_order_release);
	{
		std::lock_guard<std::mutex> lock(clientMutex_);
		if (clientFd_ >= 0)
		{
			::close(clientFd_);
			clientFd_ = -1;
		}
	}
}

void VorticeServer::AddPending(const vdi::vortice::RedirectMessage& message)
{
	PendingRedirect entry;
	entry.username = message.username;
	entry.password = message.password;
	entry.targetHost = message.targetHost;
	entry.targetPort = message.targetPort;
	entry.rdpUsername = message.targetUsername;
	entry.rdpPassword = message.targetPassword;
	entry.created = std::chrono::steady_clock::now();

	std::lock_guard<std::mutex> lock(pendingMutex_);
	CleanupExpiredLocked();
	pending_.push_back(std::move(entry));
}

} // namespace broker
} // namespace vdi

#endif // !_WIN32
