#include "vdi_redirector_server.h"

#include "vdi_broker_config.h"
#include "vdi_container_manager.h"
#include "vdi_logging.h"
#include "vdi_redirector_constants.h"
#include "vdi_redirector_utils.h"
#include "vdi_redirector_server_helpers.h"
#include "vdi_status_display.h"

#include <freerdp/freerdp.h>
#include <freerdp/peer.h>
#include <freerdp/redirection.h>
#include <freerdp/settings.h>
#include <freerdp/update.h>
#include <freerdp/crypto/certificate.h>
#include <freerdp/crypto/privatekey.h>
#include <freerdp/constants.h>
#include <freerdp/channels/channels.h>
#include <freerdp/channels/wtsvc.h>

#include <winpr/synch.h>
#include <winpr/ssl.h>
#include <winpr/string.h>
#include <winpr/wtypes.h>
#include <winpr/wtsapi.h>
#include <winpr/winsock.h>

#include <arpa/inet.h>
#include <cstring>
#include <inttypes.h>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <sys/socket.h>

#define TAG MODULE_TAG("vdi_redirector")

namespace redirector
{


RedirectorServer::RedirectorServer() = default;

RedirectorServer::~RedirectorServer()
{
    Stop();
    vorticeClient_.reset();
    if (listener_)
    {
        freerdp_listener_free(listener_);
        listener_ = nullptr;
    }
    if (stopEvent_)
    {
        CloseHandle(stopEvent_);
        stopEvent_ = nullptr;
    }
}

bool RedirectorServer::Initialize(RedirectorOptions options)
{
    options_ = std::move(options);
	stopEvent_ = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	if (!stopEvent_)
	{
		VDI_LOG_ERROR(TAG, "Failed to create stop event");
		return false;
	}

	listener_ = freerdp_listener_new();
	if (!listener_)
	{
		VDI_LOG_ERROR(TAG, "Failed to allocate FreeRDP listener");
		return false;
	}

	listener_->info = this;
	listener_->PeerAccepted = PeerAccepted;

	if (options_.enableVortice)
	{
		vorticeClient_ = std::make_unique<VorticeClient>(options_.vorticeEndpoint);
		if (vorticeClient_ && !vorticeClient_->EnsureConnected())
		{
			VDI_LOG_WARN(TAG, "Unable to connect to Vortice broker immediately; retrying on demand");
		}
	}
	return true;
}

void RedirectorServer::Run()
{
	// Spin up the FreeRDP listener and multiplex events until Stop() is signaled.
	if (!listener_)
		return;

	WTSRegisterWtsApiFunctionTable(FreeRDP_InitWtsApi());
	winpr_InitializeSSL(WINPR_SSL_INIT_DEFAULT);

	const char* bindAddress = options_.bindAddress.empty() ? nullptr : options_.bindAddress.c_str();

	if (!listener_->Open(listener_, bindAddress, options_.port))
	{
		VDI_LOG_ERROR(TAG, "Failed to open listener on %s:%" PRIu16,
		              bindAddress ? bindAddress : "0.0.0.0", options_.port);
		return;
	}

	VDI_LOG_INFO(TAG, "Listening on %s:%" PRIu16, bindAddress ? bindAddress : "0.0.0.0",
	             options_.port);

	HANDLE handles[MAXIMUM_WAIT_OBJECTS] = { 0 };

	while (WaitForSingleObject(stopEvent_, 0) == WAIT_TIMEOUT)
	{
		DWORD count = listener_->GetEventHandles(listener_, handles, ARRAYSIZE(handles) - 1);
		if ((count == 0) || (count >= ARRAYSIZE(handles)))
		{
			VDI_LOG_ERROR(TAG, "Failed to get listener event handles");
			break;
		}

		handles[count++] = stopEvent_;

		const DWORD status = WaitForMultipleObjects(count, handles, FALSE, 1000);
		if (status == WAIT_FAILED)
		{
			VDI_LOG_ERROR(TAG, "WaitForMultipleObjects failed (%" PRIu32 ")", GetLastError());
			break;
		}

		if (WaitForSingleObject(stopEvent_, 0) != WAIT_TIMEOUT)
			break;

		if (!listener_->CheckFileDescriptor(listener_))
		{
			VDI_LOG_ERROR(TAG, "Listener file descriptor check failed");
			break;
		}
	}

	listener_->Close(listener_);
}

void RedirectorServer::Stop()
{
	if (stopEvent_)
		SetEvent(stopEvent_);
	if (vorticeClient_)
		vorticeClient_->Stop();
}

const RedirectorOptions& RedirectorServer::Options() const
{
	return options_;
}

HANDLE RedirectorServer::StopEvent() const
{
	return stopEvent_;
}

BOOL RedirectorServer::PeerAccepted(freerdp_listener* listener, freerdp_peer* peer)
{
	if (!listener || !peer)
		return FALSE;

	auto* server = static_cast<RedirectorServer*>(listener->info);
	if (!server)
		return FALSE;

    auto context = std::make_unique<PeerContext>();
    context->server = server;
	peer->ContextExtra = context.get();

	// Hand the socket off to a worker thread so the accept loop stays responsive.
	HANDLE thread = CreateThread(nullptr, 0, PeerThreadProc, peer, 0, nullptr);
	if (!thread)
	{
		peer->ContextExtra = nullptr;
		freerdp_peer_free(peer);
		return FALSE;
	}

	context.release();
	CloseHandle(thread);
	return TRUE;
}

DWORD WINAPI RedirectorServer::PeerThreadProc(LPVOID arg)
{
	// Per-connection thread: set up TLS/credentials, then wait for post-connect.
	auto* peer = static_cast<freerdp_peer*>(arg);
	if (!peer)
		return 0;

	std::unique_ptr<PeerContext> ctx(static_cast<PeerContext*>(peer->ContextExtra));
	if (!ctx || !ctx->server)
	{
		freerdp_peer_free(peer);
		return 0;
	}

	RedirectorServer* server = ctx->server;
	peer->ContextExtra = ctx.get();

	PeerHolder peerGuard{ peer };

	if (!freerdp_peer_context_new(peer))
	{
		VDI_LOG_ERROR(TAG, "Failed to create peer context");
		peer->ContextExtra = nullptr;
		return 0;
	}
	peerGuard.contextInitialized = true;

	rdpSettings* settings = peer->context->settings;
	if (!settings)
	{
		VDI_LOG_ERROR(TAG, "Peer settings unavailable");
		peer->ContextExtra = nullptr;
		return 0;
	}

	if (!freerdp_settings_set_bool(settings, FreeRDP_RdpSecurity, TRUE) ||
	    !freerdp_settings_set_bool(settings, FreeRDP_TlsSecurity, TRUE) ||
	    !freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, FALSE) ||
	    !freerdp_settings_set_bool(settings, FreeRDP_RdstlsSecurity, FALSE) ||
	    !freerdp_settings_set_uint32(settings, FreeRDP_EncryptionLevel,
	                                 ENCRYPTION_LEVEL_CLIENT_COMPATIBLE))
	{
		VDI_LOG_ERROR(TAG, "Failed to configure peer security settings");
		peer->ContextExtra = nullptr;
		return 0;
	}
	(void)freerdp_settings_set_uint32(settings, FreeRDP_PointerCacheSize, 128);
	(void)freerdp_settings_set_uint32(settings, FreeRDP_ColorPointerCacheSize, 128);
	(void)freerdp_settings_set_uint32(settings, FreeRDP_PointerCacheSize, 128);
	(void)freerdp_settings_set_uint32(settings, FreeRDP_ColorPointerCacheSize, 128);

	std::unique_ptr<rdpPrivateKey, decltype(&freerdp_key_free)> keyHolder(nullptr,
	                                                                     freerdp_key_free);
	keyHolder.reset(freerdp_key_new_from_file_enc(server->Options().privateKeyPath.c_str(), nullptr));
	if (!keyHolder)
	{
		VDI_LOG_ERROR(TAG, "Failed to load private key: %s",
		              server->Options().privateKeyPath.c_str());
		peer->ContextExtra = nullptr;
		return 0;
	}
	if (!freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerRsaKey, keyHolder.get(), 1))
	{
		VDI_LOG_ERROR(TAG, "Failed to assign private key to settings");
		peer->ContextExtra = nullptr;
		return 0;
	}
	keyHolder.release();

	std::unique_ptr<rdpCertificate, decltype(&freerdp_certificate_free)> certHolder(
	    nullptr, freerdp_certificate_free);
	certHolder.reset(
	    freerdp_certificate_new_from_file(server->Options().certificatePath.c_str()));
	if (!certHolder)
	{
		VDI_LOG_ERROR(TAG, "Failed to load certificate: %s",
		              server->Options().certificatePath.c_str());
		peer->ContextExtra = nullptr;
		return 0;
	}
	if (!freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerCertificate,
	                                      certHolder.get(), 1))
	{
		VDI_LOG_ERROR(TAG, "Failed to assign certificate to settings");
		peer->ContextExtra = nullptr;
		return 0;
	}
	certHolder.release();

	peer->PostConnect = PeerPostConnect;

	HANDLE handles[MAXIMUM_WAIT_OBJECTS] = { 0 };

	while (WaitForSingleObject(server->StopEvent(), 0) == WAIT_TIMEOUT)
	{
		DWORD count = peer->GetEventHandles(peer, handles, ARRAYSIZE(handles) - 1);
		if ((count == 0) || (count >= ARRAYSIZE(handles)))
		{
			VDI_LOG_ERROR(TAG, "Failed to get peer event handles");
			break;
		}

		handles[count++] = server->StopEvent();

		const DWORD status = WaitForMultipleObjects(count, handles, FALSE, 100);
		if (status == WAIT_FAILED)
		{
			VDI_LOG_ERROR(TAG, "WaitForMultipleObjects for peer failed (%" PRIu32 ")",
			              GetLastError());
			break;
		}

		if (WaitForSingleObject(server->StopEvent(), 0) != WAIT_TIMEOUT)
			break;

		if (!peer->CheckFileDescriptor(peer))
		{
			VDI_LOG_INFO(TAG, "Peer file descriptor closed");
			break;
		}
	}

	peer->ContextExtra = nullptr;
	ctx.reset();
	return 0;
}

BOOL RedirectorServer::PeerPostConnect(freerdp_peer* peer)
{
	if (!peer)
		return FALSE;

	// Validate inbound credentials, provision the user's container, then redirect.
	auto* ctx = static_cast<PeerContext*>(peer->ContextExtra);
	if (!ctx || !ctx->server || !peer->context || !peer->context->settings)
	{
		VDI_LOG_ERROR(TAG, "Peer context unavailable for post-connect handling");
		return FALSE;
	}

	RedirectorServer* server = ctx->server;

	rdpSettings* settings = peer->context->settings;
	const char* rawUser = freerdp_settings_get_string(settings, FreeRDP_Username);
	const char* rawPassword = freerdp_settings_get_string(settings, FreeRDP_Password);

	if (!rawUser || std::string_view(rawUser).empty())
	{
		VDI_LOG_ERROR(TAG, "Received empty username from client");
		return FALSE;
	}

	if (!rawPassword || std::string_view(rawPassword).empty())
	{
		VDI_LOG_ERROR(TAG, "Received empty password from client");
		return FALSE;
	}

	const ParsedUsername parsed = split_username(rawUser);
	if (parsed.user.empty())
	{
		VDI_LOG_ERROR(TAG, "Refusing authentication with empty username");
		return FALSE;
	}

	vdi::logging::ScopedLogUser scopedUser(parsed.user);

	auto& configuration = vdi::Config();
	const bool refreshed = configuration.Refresh();
	const bool reloaded = configuration.ConsumeReloadedFlag();
	vdi_log_refresh_outcome(refreshed, reloaded);

	// Present a provisioning overlay only if the client negotiated fast-path updates.
	vdi::StatusDisplay statusDisplay;
	const bool clientFastPath =
	    freerdp_settings_get_bool(settings, FreeRDP_FastPathOutput) ? true : false;
	const UINT32 clientMaxRequest =
	    freerdp_settings_get_uint32(settings, FreeRDP_MultifragMaxRequestSize);
	if (clientFastPath && (clientMaxRequest != 0))
	{
		statusDisplay.Initialize(peer, settings, configuration.RedirectorBackgroundImage(),
		                         configuration.RedirectorBackgroundColor());
	}
	if (statusDisplay.Ready())
		statusDisplay.ShowMessage("Authenticating user...");

	if (!vdi_auth(parsed.user, rawPassword))
	{
		if (statusDisplay.Ready())
			statusDisplay.ShowMessage("Authentication failed");
		VDI_LOG_ERROR(TAG, "PAM authentication failed for user %s", parsed.user.c_str());
		return FALSE;
	}

	VDI_LOG_INFO(TAG, "Client requested user: %s", rawUser);
	VDI_LOG_INFO(TAG, "PAM-authenticated user %s; delegating session auth to container",
	             parsed.user.c_str());

	const std::string containerPrefix = build_container_prefix(parsed.suffix);
	// Ask the broker to ensure the user's container is available and expose its address.
	if (statusDisplay.Ready())
	{
		statusDisplay.ShowMessage("Provisioning session for " + parsed.user + "...");
	}
	const std::string containerDetails = vdi::ManageContainer(parsed.user, containerPrefix);
	if (containerDetails.empty())
	{
		if (statusDisplay.Ready())
			statusDisplay.ShowMessage("Provisioning session failed");
		VDI_LOG_ERROR(TAG, "Failed to allocate container for user %s", parsed.user.c_str());
		return FALSE;
	}

	vdi::ContainerConnectionInfo containerInfo;
	std::string containerParseError;
	if (!vdi::ParseContainerConnectionInfo(containerDetails, containerInfo, &containerParseError))
	{
		if (statusDisplay.Ready())
			statusDisplay.ShowMessage("Provisioning session failed");
		if (containerParseError.empty())
			VDI_LOG_ERROR(TAG, "Failed to parse container details for user %s",
			              parsed.user.c_str());
		else
			VDI_LOG_ERROR(TAG, "Failed to parse container details for user %s: %s",
			              parsed.user.c_str(), containerParseError.c_str());
		return FALSE;
	}

	const std::string& ip = containerInfo.ip;

	RdpCredentials containerCreds;
	containerCreds.username = containerInfo.username;
	containerCreds.password = containerInfo.password;

	bool usedFallbackCreds = false;
	if (containerCreds.username.empty() || containerCreds.password.empty())
	{
		const RdpCredentials fallbackCreds = load_rdp_credentials();
		if (containerCreds.username.empty())
		{
			containerCreds.username = fallbackCreds.username;
			usedFallbackCreds = true;
		}
		if (containerCreds.password.empty())
		{
			containerCreds.password = fallbackCreds.password;
			usedFallbackCreds = true;
		}
	}

	if (usedFallbackCreds)
	{
		VDI_LOG_WARN(TAG,
		             "Container script missing credentials; using configured fallback for user %s",
		             parsed.user.c_str());
	}
	else {
		VDI_LOG_INFO(TAG, "Container script credentials: %s, %s\n", containerCreds.username.c_str(), containerCreds.password.c_str());
	}

	bool useVortice = false;
	std::string proxyHost;
	std::uint16_t proxyPort = 0;
	if (server->options_.enableVortice && server->vorticeClient_)
	{
		if (server->vorticeClient_->EnsureConnected())
		{
			proxyHost = server->vorticeClient_->ProxyHost();
			proxyPort = server->vorticeClient_->ProxyPort();
			if (!proxyHost.empty() && proxyPort != 0)
			{
				vdi::vortice::RedirectMessage redirect{};
				redirect.username = rawUser;
				redirect.password = rawPassword;
				redirect.targetHost = ip;
				redirect.targetPort = kContainerPort;
				redirect.targetUsername = containerCreds.username;
				redirect.targetPassword = containerCreds.password;

				if (server->vorticeClient_->SendRedirect(redirect))
				{
					useVortice = true;
					if (statusDisplay.Ready())
						statusDisplay.ShowMessage("Routing session through proxy...");
				}
				else
				{
					VDI_LOG_WARN(TAG,
					             "Vortice broker unavailable or rejected redirect; using local session");
					if (statusDisplay.Ready())
						statusDisplay.ShowMessage("Proxy unavailable, using local session...");
				}
			}
		}
		else
		{
			VDI_LOG_WARN(TAG, "Unable to reach Vortice broker; using local session instead");
		}
	}

	if (useVortice)
	{
		if (!freerdp_settings_set_string(settings, FreeRDP_ServerHostname, proxyHost.c_str()))
			return FALSE;
		(void)freerdp_settings_set_uint32(settings, FreeRDP_ServerPort, proxyPort);

		if (!send_redirection(peer, proxyHost, nullptr, nullptr))
		{
			if (statusDisplay.Ready())
				statusDisplay.ShowMessage("Unable to route session through proxy");
			return FALSE;
		}

		if (statusDisplay.Ready())
			statusDisplay.ShowMessage("Redirecting via proxy...");

		const std::string clientIp = resolve_client_ip(peer);
		const char* client = clientIp.empty() ? "<unknown>" : clientIp.c_str();
		VDI_LOG_INFO(TAG,
		             "Proxy redirect for user %s (client %s) via %s:%" PRIu16
		             " targeting container %s:%" PRIu16,
		             parsed.user.c_str(), client, proxyHost.c_str(), proxyPort, ip.c_str(),
		             kContainerPort);
		return TRUE;
	}

	std::optional<std::string> routingToken;
	if (server->Options().useRoutingToken)
	{
		if (statusDisplay.Ready())
			statusDisplay.ShowMessage("Preparing secure connection...");
		// Encode the eventual container endpoint so the client reconnects straight to it.
		routingToken = build_routing_token(ip, kContainerPort);
		if (!routingToken)
		{
			VDI_LOG_WARN(TAG, "Failed to build routing token for %s:%" PRIu16, ip.c_str(),
			             kContainerPort);
		}
	}
	else if (statusDisplay.Ready())
	{
		statusDisplay.ShowMessage("Connecting to remote desktop...");
	}

	if (!freerdp_settings_set_string(settings, FreeRDP_ServerHostname, ip.c_str()))
		return FALSE;
	(void)freerdp_settings_set_uint32(settings, FreeRDP_ServerPort, kContainerPort);

	const std::string* routingTokenPtr = routingToken ? &*routingToken : nullptr;
	if (!send_redirection(peer, ip, &containerCreds, routingTokenPtr))
	{
		if (statusDisplay.Ready())
			statusDisplay.ShowMessage("Unable to start remote desktop session");
		return FALSE;
	}

	if (statusDisplay.Ready())
		statusDisplay.ShowMessage("Launching remote desktop...");

	const std::string clientIp = resolve_client_ip(peer);
	const char* client = clientIp.empty() ? "<unknown>" : clientIp.c_str();

	std::string tokenForLog;
	if (routingToken)
	{
		tokenForLog = *routingToken;
		while (!tokenForLog.empty() &&
		       (tokenForLog.back() == '\r' || tokenForLog.back() == '\n'))
			tokenForLog.pop_back();
	}

	if (routingToken)
	{
		VDI_LOG_INFO(TAG,
		             "Redirected user %s (client %s) to %s:%" PRIu16 " with token %s",
		             parsed.user.c_str(), client, ip.c_str(), kContainerPort, tokenForLog.c_str());
	}
	else
	{
		VDI_LOG_INFO(TAG, "Redirected user %s (client %s) to %s:%" PRIu16, parsed.user.c_str(),
		             client, ip.c_str(), kContainerPort);
	}

	//if (peer->Disconnect)
	//	peer->Disconnect(peer);
	//if (peer->Close)
	//	peer->Close(peer);
	return TRUE;
}

RedirectorServer::PeerHolder::~PeerHolder()
{
	if (!peer)
		return;
	if (contextInitialized)
		freerdp_peer_context_free(peer);
	freerdp_peer_free(peer);
}

} // namespace redirector
