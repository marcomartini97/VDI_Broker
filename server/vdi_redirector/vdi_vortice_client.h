#pragma once

#include "vdi_vortice_protocol.h"

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>

namespace redirector
{

class VorticeClient
{
public:
	explicit VorticeClient(std::string endpoint);
	~VorticeClient();

	bool EnsureConnected();
	void Stop();

	bool Ready() const;
	std::string ProxyHost() const;
	std::uint16_t ProxyPort() const;

	bool SendRedirect(const vdi::vortice::RedirectMessage& message);

private:
	bool ConnectLocked();
	bool ConnectUnixLocked();
	bool ConnectTcpLocked();
	bool PerformHandshakeLocked();
	void ResetLocked();

	std::string endpointString_;
	vdi::vortice::Endpoint endpoint_{};
	bool endpointValid_ = false;

	int fd_ = -1;
	bool ready_ = false;
	std::string proxyHost_;
	std::uint16_t proxyPort_ = 0;

	mutable std::mutex mutex_;
};

} // namespace redirector

