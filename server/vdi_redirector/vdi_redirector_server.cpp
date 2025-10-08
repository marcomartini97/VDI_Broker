#include "vdi_redirector_server.h"

#include "vdi_broker_config.h"
#include "vdi_container_manager.h"
#include "vdi_logging.h"
#include "vdi_redirector_constants.h"
#include "vdi_redirector_utils.h"
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

namespace
{
// Helper to derive a textual representation for the connected client.
std::string resolve_client_ip(freerdp_peer* peer)
{
	if (peer && peer->hostname && *peer->hostname)
		return std::string(peer->hostname);
	if (!peer)
		return {};

	sockaddr_in addr{};
	socklen_t len = sizeof(addr);
	if (getpeername(peer->sockfd, reinterpret_cast<sockaddr*>(&addr), &len) != 0)
		return {};
	char buffer[INET_ADDRSTRLEN] = {};
	if (!inet_ntop(AF_INET, &addr.sin_addr, buffer, sizeof(buffer)))
		return {};
	return std::string(buffer);
}

constexpr uint16_t reverse_bytes16(uint16_t value)
{
	return static_cast<uint16_t>(((value & 0x00FFu) << 8) | ((value & 0xFF00u) >> 8));
}

// Encode the target IP and port into the MS load-balancer cookie format.
std::optional<std::string> build_routing_token(const std::string& ip, std::uint16_t port)
{
	in_addr addr{};
	if (inet_pton(AF_INET, ip.c_str(), &addr) != 1)
		return std::nullopt;

	std::uint8_t octets[sizeof(addr.s_addr)] = { 0 };
	std::memcpy(octets, &addr.s_addr, sizeof(octets));

	uint32_t ipToken = (static_cast<uint32_t>(octets[3]) << 24) |
	                         (static_cast<uint32_t>(octets[2]) << 16) |
	                         (static_cast<uint32_t>(octets[1]) << 8) |
	                         static_cast<uint32_t>(octets[0]);

	const uint16_t portToken = reverse_bytes16(port);

	std::ostringstream osstoken;
	osstoken << "Cookie: msts=" << ipToken << "." << portToken << ".0000\r\n";
	return osstoken.str();
}


// Helper: convert UTF-8 credentials into the UTF-16 payload expected by redirection PDUs.
BOOL redirection_set_password_option(rdpRedirection* redirection, const std::string& password)
{
	size_t wcharLen = 0;
	WCHAR* wide = ConvertUtf8ToWCharAlloc(password.c_str(), &wcharLen);
	if (!wide)
	{
		VDI_LOG_ERROR(TAG, "Failed to convert password to UTF-16 for redirection");
		return FALSE;
	}

	const size_t bytes = (wcharLen + 1) * sizeof(WCHAR);
	const BOOL ok = redirection_set_byte_option(redirection, LB_PASSWORD,
	                                            reinterpret_cast<const BYTE*>(wide), bytes);
	free(wide);
	return ok;
}

// Populate and send the server redirection PDU that tells the client to reconnect elsewhere.
BOOL send_redirection(freerdp_peer* peer, const std::string& targetAddress,
                      const RdpCredentials* credentials, const std::string* routingToken)
{
	rdpRedirection* redirection = redirection_new();
	if (!redirection)
		return FALSE;

	BOOL success = TRUE;
	do
	{
		UINT32 flags = LB_TARGET_NET_ADDRESS;
		if (credentials)
			flags |= LB_USERNAME | LB_PASSWORD | LB_DOMAIN;
		if (routingToken && !routingToken->empty())
			flags |= LB_LOAD_BALANCE_INFO;
		if (!redirection_set_flags(redirection, flags))
		{
			success = FALSE;
			break;
		}
		if (!redirection_set_string_option(redirection, LB_TARGET_NET_ADDRESS, targetAddress.c_str()))
		{
			success = FALSE;
			break;
		}
		if (credentials)
		{
			if (!redirection_set_string_option(redirection, LB_USERNAME,
			                                   credentials->username.c_str()))
			{
				success = FALSE;
				break;
			}
			if (!redirection_set_password_option(redirection, credentials->password))
			{
				success = FALSE;
				break;
			}
			if (!redirection_set_string_option(redirection, LB_DOMAIN, "None"))
			{
				success = FALSE;
				break;
			}
		}
		if (routingToken && !routingToken->empty())
		{
			if (!redirection_set_byte_option(redirection, LB_LOAD_BALANCE_INFO,
			                                   reinterpret_cast<const BYTE*>(routingToken->c_str()),
			                                   routingToken->size()))
			{
				success = FALSE;
				break;
			}
		}

		UINT32 missingFlags = 0;
		if (!redirection_settings_are_valid(redirection, &missingFlags))
		{
			VDI_LOG_ERROR(TAG, "Redirection settings invalid (missing flags=0x%08" PRIX32 ")",
			              missingFlags);
			success = FALSE;
			break;
		}

		if (!peer->SendServerRedirection(peer, redirection))
		{
			VDI_LOG_ERROR(TAG, "Failed to send redirection PDU");
			success = FALSE;
			break;
		}
	} while (0);

	redirection_free(redirection);
	return success;
}

} // namespace

RedirectorServer::RedirectorServer() = default;

RedirectorServer::~RedirectorServer()
{
    Stop();
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
	StatusDisplay statusDisplay;
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
	const std::string ip = vdi::ManageContainer(parsed.user, containerPrefix);
	if (ip.empty())
	{
		if (statusDisplay.Ready())
			statusDisplay.ShowMessage("Provisioning session failed");
		VDI_LOG_ERROR(TAG, "Failed to allocate container for user %s", parsed.user.c_str());
		return FALSE;
	}

	const RdpCredentials containerCreds = load_rdp_credentials();

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

	if (peer->Disconnect)
		peer->Disconnect(peer);
	if (peer->Close)
		peer->Close(peer);
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
