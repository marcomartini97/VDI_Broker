#pragma once

#include "vdi_proxy_config.h"

#include <freerdp/server/proxy/proxy_server.h>

namespace vdi::proxy
{

class VdiProxyServer
{
public:
	VdiProxyServer();
	~VdiProxyServer();

	bool Initialize(const ProxyOptions& options);
	void Run();
	void Stop();

private:
	bool RegisterBuiltInModule();
	void Cleanup();

	ProxyOptions options_;
	proxyServer* server_ = nullptr;
};

} // namespace vdi::proxy
