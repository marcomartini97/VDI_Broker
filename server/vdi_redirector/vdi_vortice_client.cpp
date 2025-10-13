#include "vdi_vortice_client.h"

#include "vdi_logging.h"

#include <cerrno>
#include <cstring>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <arpa/inet.h>

#define TAG MODULE_TAG("vortice_client")

namespace redirector
{

VorticeClient::VorticeClient(std::string endpoint) : endpointString_(std::move(endpoint))
{
	endpointValid_ = vdi::vortice::ParseEndpoint(endpointString_, endpoint_);
	if (!endpointValid_)
	{
		VDI_LOG_ERROR(TAG, "Invalid Vortice endpoint '%s'", endpointString_.c_str());
	}
}

VorticeClient::~VorticeClient()
{
	Stop();
}

bool VorticeClient::EnsureConnected()
{
	std::lock_guard<std::mutex> lock(mutex_);
	if (!endpointValid_)
		return false;
	if (ready_ && fd_ >= 0)
		return true;
	return ConnectLocked();
}

void VorticeClient::Stop()
{
	std::lock_guard<std::mutex> lock(mutex_);
	ResetLocked();
}

bool VorticeClient::Ready() const
{
	std::lock_guard<std::mutex> lock(mutex_);
	return ready_;
}

std::string VorticeClient::ProxyHost() const
{
	std::lock_guard<std::mutex> lock(mutex_);
	return proxyHost_;
}

std::uint16_t VorticeClient::ProxyPort() const
{
	std::lock_guard<std::mutex> lock(mutex_);
	return proxyPort_;
}

bool VorticeClient::SendRedirect(const vdi::vortice::RedirectMessage& message)
{
	std::lock_guard<std::mutex> lock(mutex_);
	if (!endpointValid_)
		return false;

	if (!ready_ || (fd_ < 0))
	{
		if (!ConnectLocked())
			return false;
	}

	vdi::vortice::Message outbound;
	outbound.type = vdi::vortice::MessageType::Redirect;
	outbound.redirect = message;

	if (!vdi::vortice::SendMessage(fd_, outbound))
	{
		VDI_LOG_WARN(TAG, "Failed to send Vortice redirect payload, disconnecting");
		ResetLocked();
		return false;
	}

	vdi::vortice::Message ack;
	if (!vdi::vortice::ReceiveMessage(fd_, ack))
	{
		VDI_LOG_WARN(TAG, "Failed to receive Vortice acknowledgment");
		ResetLocked();
		return false;
	}

	if (ack.type != vdi::vortice::MessageType::Ack || !ack.ack.success)
	{
		if (ack.type == vdi::vortice::MessageType::Ack && !ack.ack.error.empty())
			VDI_LOG_WARN(TAG, "Vortice server reported failure: %s", ack.ack.error.c_str());
		else
			VDI_LOG_WARN(TAG, "Unexpected Vortice response type %d", static_cast<int>(ack.type));
		ResetLocked();
		return false;
	}

	return true;
}

bool VorticeClient::ConnectLocked()
{
	ResetLocked();

	if (endpoint_.type == vdi::vortice::EndpointType::Unix)
	{
		if (!ConnectUnixLocked())
			return false;
	}
	else
	{
		if (!ConnectTcpLocked())
			return false;
	}

	if (!PerformHandshakeLocked())
	{
		ResetLocked();
		return false;
	}

	return true;
}

bool VorticeClient::ConnectUnixLocked()
{
	fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd_ < 0)
	{
		VDI_LOG_ERROR(TAG, "Unable to create Vortice UNIX socket: %s", strerror(errno));
		return false;
	}

	sockaddr_un addr = {};
	addr.sun_family = AF_UNIX;
	if (endpoint_.path.size() >= sizeof(addr.sun_path))
	{
		VDI_LOG_ERROR(TAG, "Vortice UNIX path '%s' too long", endpoint_.path.c_str());
		return false;
	}
	std::strncpy(addr.sun_path, endpoint_.path.c_str(), sizeof(addr.sun_path) - 1);

	if (::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
	{
		VDI_LOG_WARN(TAG, "Failed to connect to Vortice UNIX socket %s: %s", endpoint_.path.c_str(),
		             strerror(errno));
		return false;
	}

	return true;
}

bool VorticeClient::ConnectTcpLocked()
{
	fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
	if (fd_ < 0)
	{
		VDI_LOG_ERROR(TAG, "Unable to create Vortice TCP socket: %s", strerror(errno));
		return false;
	}

	addrinfo hints = {};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	const std::string portStr = std::to_string(endpoint_.port);
	addrinfo* res = nullptr;

	int rc = getaddrinfo(endpoint_.host.c_str(), portStr.c_str(), &hints, &res);
	if ((rc != 0) || !res)
	{
		VDI_LOG_ERROR(TAG, "Failed to resolve Vortice endpoint %s:%u (%s)", endpoint_.host.c_str(),
		              static_cast<unsigned int>(endpoint_.port), gai_strerror(rc));
		if (res)
			freeaddrinfo(res);
		return false;
	}

	bool connected = false;
	for (addrinfo* it = res; it; it = it->ai_next)
	{
		if (::connect(fd_, it->ai_addr, it->ai_addrlen) == 0)
		{
			connected = true;
			break;
		}
	}
	freeaddrinfo(res);

	if (!connected)
	{
		VDI_LOG_WARN(TAG, "Failed to connect to Vortice TCP %s:%u: %s", endpoint_.host.c_str(),
		             static_cast<unsigned int>(endpoint_.port), strerror(errno));
		return false;
	}

	return true;
}

bool VorticeClient::PerformHandshakeLocked()
{
	vdi::vortice::Message hello;
	hello.type = vdi::vortice::MessageType::Hello;
	hello.hello.role = "redirector";
	if (!vdi::vortice::SendMessage(fd_, hello))
	{
		VDI_LOG_WARN(TAG, "Failed to send Vortice hello");
		return false;
	}

	vdi::vortice::Message response;
	if (!vdi::vortice::ReceiveMessage(fd_, response))
	{
		VDI_LOG_WARN(TAG, "Failed to receive Vortice handshake response");
		return false;
	}

	if (response.type != vdi::vortice::MessageType::HelloResponse ||
	    response.helloResponse.role != "broker")
	{
		VDI_LOG_WARN(TAG, "Unexpected Vortice handshake payload");
		return false;
	}

	proxyHost_ = response.helloResponse.proxyHost;
	proxyPort_ = response.helloResponse.proxyPort;
	ready_ = true;

	vdi::vortice::Message ack;
	ack.type = vdi::vortice::MessageType::Ack;
	ack.ack.success = true;
	if (!vdi::vortice::SendMessage(fd_, ack))
	{
		VDI_LOG_WARN(TAG, "Failed to acknowledge Vortice handshake");
		return false;
	}

	VDI_LOG_INFO(TAG, "Connected to Vortice broker at %s", endpointString_.c_str());
	return true;
}

void VorticeClient::ResetLocked()
{
	if (fd_ >= 0)
	{
		::close(fd_);
		fd_ = -1;
	}
	ready_ = false;
	proxyHost_.clear();
	proxyPort_ = 0;
}

} // namespace redirector

