#pragma once

#include "vdi_redirector_config.h"

#include "vdi_vortice_client.h"

#include <freerdp/listener.h>
#include <freerdp/peer.h>
#include <winpr/wtypes.h>

#include <atomic>
#include <memory>
#include <string>
#include <thread>

namespace redirector
{

/**
 * Hosts the front-end listener that validates users then redirects them.
 */
class RedirectorServer
{
public:
	RedirectorServer();
	~RedirectorServer();

	/**
	 * Prepare the listener using the provided options.
	 */
	bool Initialize(RedirectorOptions options);
	void Run();
	void Stop();

	const RedirectorOptions& Options() const;
	HANDLE StopEvent() const;

	static BOOL PeerAccepted(freerdp_listener* listener, freerdp_peer* peer);
	static DWORD WINAPI PeerThreadProc(LPVOID arg);
	static BOOL PeerPostConnect(freerdp_peer* peer);

private:
	bool StartConfigPolling();
	void StopConfigPolling();
	void ConfigPollingLoop();

	struct PeerHolder
	{
		freerdp_peer* peer = nullptr;
		bool contextInitialized = false;

		~PeerHolder();
	};

	struct PeerContext
	{
		RedirectorServer* server = nullptr;
	};

	RedirectorOptions options_;
	freerdp_listener* listener_ = nullptr;
	HANDLE stopEvent_ = nullptr;
	std::unique_ptr<VorticeClient> vorticeClient_;
	std::atomic_bool stopConfigPolling_{ true };
	std::thread configPollingThread_;
};

} // namespace redirector
