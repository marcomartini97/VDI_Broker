#include "vdi_proxy_server.h"

#include "vdi_proxy_constants.h"
#include "vdi_proxy_utils.h"

#include "vdi_broker_config.h"
#include "vdi_container_manager.h"
#include "vdi_logging.h"

#include <freerdp/api.h>
#include <freerdp/crypto/crypto.h>
#include <freerdp/server/proxy/proxy_config.h>
#include <freerdp/server/proxy/proxy_context.h>
#include <freerdp/server/proxy/proxy_modules_api.h>
#include <freerdp/server/proxy/proxy_server.h>
#include <freerdp/settings.h>

#include <winpr/assert.h>
#include <winpr/crt.h>
#include <winpr/ini.h>
#include <winpr/wtypes.h>
#include <winpr/wlog.h>

#include <inttypes.h>
#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>

#define TAG MODULE_TAG("vdi_proxy")

using vdi::proxy::ParsedUsername;
using vdi::proxy::RdpCredentials;
using vdi::proxy::build_container_prefix;
using vdi::proxy::load_rdp_credentials;
using vdi::proxy::split_username;
using vdi::proxy::vdi_auth;
namespace vdi::proxy
{

namespace
{

proxyConfig* create_proxy_config(const ProxyOptions& options)
{
	auto* config = static_cast<proxyConfig*>(calloc(1, sizeof(proxyConfig)));
	if (!config)
		return nullptr;

	config->Host = _strdup(options.bindAddress.c_str());
	if (!config->Host)
		goto fail;
	config->Port = options.port;

	config->FixedTarget = TRUE;
	config->TargetHost = _strdup("127.0.0.1"); //Fake address, overrided later
	config->TargetPort = 3389;
	config->GFX = TRUE;
	config->DisplayControl = TRUE;
	config->Clipboard = TRUE;
	config->AudioOutput = TRUE;
	config->AudioInput = TRUE;
	config->RemoteApp = TRUE;
	config->DeviceRedirection = TRUE;
	config->VideoRedirection = TRUE;
	config->CameraRedirection = TRUE;
	config->PassthroughIsBlacklist = FALSE;

	config->Keyboard = TRUE;
	config->Mouse = TRUE;
	config->Multitouch = TRUE;

	config->ServerTlsSecurity = TRUE;
	config->ServerRdpSecurity = FALSE;
	config->ServerNlaSecurity = FALSE;

	config->ClientTlsSecurity = TRUE;
	config->ClientRdpSecurity = FALSE;
	config->ClientNlaSecurity = TRUE;
	config->ClientAllowFallbackToTls = FALSE;
	config->TargetTlsSecLevel = 1; // Accept any certificate (for self-signed certs in containers)

	config->Modules = nullptr;
	config->ModulesCount = 0;
	config->RequiredPlugins = nullptr;
	config->RequiredPluginsCount = 0;

	config->ini = IniFile_New();
	if (!config->ini)
		goto fail;

	if (!options.certificatePath.empty())
	{
		config->CertificateFile = _strdup(options.certificatePath.c_str());
		if (!config->CertificateFile)
			goto fail;

		size_t pemLength = 0;
		config->CertificatePEM = crypto_read_pem(config->CertificateFile, &pemLength);
		if (!config->CertificatePEM)
			goto fail;
		config->CertificatePEMLength = pemLength + 1;
	}

	if (!options.privateKeyPath.empty())
	{
		config->PrivateKeyFile = _strdup(options.privateKeyPath.c_str());
		if (!config->PrivateKeyFile)
			goto fail;

		size_t keyLength = 0;
		config->PrivateKeyPEM = crypto_read_pem(config->PrivateKeyFile, &keyLength);
		if (!config->PrivateKeyPEM)
			goto fail;
		config->PrivateKeyPEMLength = keyLength + 1;
	}

	return config;

fail:
	pf_server_config_free(config);
	return nullptr;
}

BOOL vdi_proxy_client_pre_connect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_UNUSED(plugin);
	WINPR_UNUSED(custom);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(pdata->pc);

	rdpSettings* settings = pdata->pc->context.settings;
	WINPR_ASSERT(settings);

	const RdpCredentials creds = load_rdp_credentials();
	if (!freerdp_settings_set_string(settings, FreeRDP_Username, creds.username.c_str()))
		return FALSE;
	if (!freerdp_settings_set_string(settings, FreeRDP_Password, creds.password.c_str()))
		return FALSE;
	if (!freerdp_settings_set_string(settings, FreeRDP_Domain, ""))
		return FALSE;
	VDI_LOG_INFO(TAG, "Set container credentials user=%s", creds.username.c_str());

	rdpSettings* server_settings = pdata->ps->context.settings;
	const char* rawUser = freerdp_settings_get_string(server_settings, FreeRDP_Username);
	const char* rawPassword = freerdp_settings_get_string(server_settings, FreeRDP_Password);
	if (!rawUser || !rawPassword || std::string_view(rawUser).empty())
	{
		VDI_LOG_ERROR(TAG, "Missing credentials from incoming connection");
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

	if (!vdi_auth(parsed.user, rawPassword))
	{
		VDI_LOG_ERROR(TAG, "PAM authentication failed for user %s", parsed.user.c_str());
		return FALSE;
	}

	const std::string containerPrefix = build_container_prefix(parsed.suffix);
	const std::string ip = ManageContainer(parsed.user, containerPrefix);
	if (ip.empty())
	{
		VDI_LOG_ERROR(TAG, "Failed to allocate container for user %s", parsed.user.c_str());
		return FALSE;
	}

	VDI_LOG_INFO(TAG, "Proxying user %s to %s:%" PRIu16, parsed.user.c_str(), ip.c_str(),
	             kContainerPort);

	if (!freerdp_settings_set_string(settings, FreeRDP_ServerHostname, ip.c_str()))
		return FALSE;
	if (!freerdp_settings_set_uint32(settings, FreeRDP_ServerPort, 3389))
		return FALSE;


	return TRUE;
}

BOOL vdi_proxy_module_entry(proxyPluginsManager* manager, void* userdata)
{
	WINPR_UNUSED(userdata);
	WINPR_ASSERT(manager);

	proxyPlugin plugin = {};
	plugin.name = "vdi-proxy-inline";
	plugin.description = "VDI proxy inline container integration";
	plugin.ClientPreConnect = vdi_proxy_client_pre_connect;
	//plugin.ServerFetchTargetAddr = vdi_proxy_server_fetch_target;

	if (!manager->RegisterPlugin(manager, &plugin))
		return FALSE;

	return TRUE;
}

} // namespace

VdiProxyServer::VdiProxyServer() = default;

VdiProxyServer::~VdiProxyServer()
{
	Cleanup();
}

bool VdiProxyServer::Initialize(const ProxyOptions& options)
{
	options_ = options;

	std::unique_ptr<proxyConfig, decltype(&pf_server_config_free)> config(create_proxy_config(options),
	                                                                      pf_server_config_free);
	if (!config)
	{
		VDI_LOG_ERROR(TAG, "Failed to build proxy configuration");
		return false;
	}

	server_ = pf_server_new(config.get());
	if (!server_)
	{
		VDI_LOG_ERROR(TAG, "Failed to create proxy server");
		return false;
	}

	if (!RegisterBuiltInModule())
	{
		Cleanup();
		return false;
	}

	if (!pf_server_start(server_))
	{
		VDI_LOG_ERROR(TAG, "Failed to start proxy listener");
		Cleanup();
		return false;
	}

	return true;
}

bool VdiProxyServer::RegisterBuiltInModule()
{
	if (!server_)
		return false;

	if (!pf_server_add_module(server_, vdi_proxy_module_entry, nullptr))
		return false;

	return true;
}

void VdiProxyServer::Run()
{
	if (!server_)
		return;

	if (!pf_server_run(server_))
		VDI_LOG_ERROR(TAG, "Proxy server terminated with errors");
}

void VdiProxyServer::Stop()
{
	if (server_)
		pf_server_stop(server_);
}

void VdiProxyServer::Cleanup()
{
	if (server_)
	{
		pf_server_free(server_);
		server_ = nullptr;
	}
}

} // namespace vdi::proxy
