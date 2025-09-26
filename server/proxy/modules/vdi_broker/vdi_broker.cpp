/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Proxy Server Demo C++ Module
 *
 * Copyright 2019 Kobi Mizrachi <kmizrachi18@gmail.com>
 * Copyright 2021 Armin Novak <anovak@thincast.com>
 * Copyright 2021 Thincast Technologies GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "freerdp/server/proxy/proxy_context.h"

#include <iostream>
#include <string>
#include <cctype>
#include <cstdint>
#include <inttypes.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <freerdp/api.h>
#include <freerdp/scancode.h>
#include <freerdp/server/proxy/proxy_config.h>
#include <freerdp/server/proxy/proxy_modules_api.h>
#include <sys/time.h>

#include "vdi_broker_config.h"
#include "vdi_container_manager.h"

#define TAG MODULE_TAG("vdi_broker")
static constexpr char plugin_name[] = "vdi-broker";
static constexpr char plugin_desc[] =
    "Intercepts RDP Authentication and forwards the connection to an RDP Enabled Container";
static constexpr char kConfigPathKey[] = "config_path";
static constexpr char kDefaultPamServiceName[] = "vdi-broker";

namespace
{
std::string build_container_prefix(const std::string& suffix)
{
    if (suffix.empty())
        return "vdi-";

    std::string sanitized;
    sanitized.reserve(suffix.size());
    for (const char ch : suffix)
    {
        const unsigned char uch = static_cast<unsigned char>(ch);
        if (std::isalnum(uch) || ch == '_' || ch == '-')
            sanitized.push_back(static_cast<char>(std::tolower(uch)));
        else
            sanitized.push_back('_');
    }

    if (sanitized.empty())
        return "vdi-";

    return std::string("vdi_") + sanitized + "-";
}
} // namespace


// Set Nla Security to login
static BOOL vdi_server_session_started(proxyPlugin* plugin, proxyData* pdata, void* custom) {
	auto settings = pdata->ps->context.settings;
	freerdp_settings_set_bool (settings, FreeRDP_RdpSecurity, FALSE);
	freerdp_settings_set_bool (settings, FreeRDP_TlsSecurity, TRUE);
	freerdp_settings_set_bool (settings, FreeRDP_NlaSecurity, TRUE);
	freerdp_settings_set_bool (settings, FreeRDP_RdstlsSecurity, TRUE);
	return TRUE;
}


void vdi_log_configuration_state(bool refreshed)
{
	auto& configuration = vdi::Config();
	const std::string configPath = configuration.ConfigPath();
	const std::string podmanImage = configuration.PodmanImage();
	const std::string driDevice = configuration.DriDevice();
	const std::string homePath = configuration.HomePath();
	const std::string shadowPath = configuration.ShadowPath();
	const std::string groupPath = configuration.GroupPath();
	const std::string passwdPath = configuration.PasswdPath();
	const std::string pamPath = configuration.PamPath();
	const std::string dockerfilePath = configuration.DockerfilePath();
	const std::string pamService = configuration.PamServiceName();
	const std::string rdpUsername = configuration.RdpUsername();
	const std::string rdpPassword = configuration.RdpPassword();
	const std::size_t userImageOverrides = configuration.UserImageCount();
	const std::size_t customMounts = configuration.CustomMountCount();
	const bool nvidiaEnabled = configuration.NvidiaGpuEnabled();
	const std::uint32_t nvidiaSlot = configuration.NvidiaGpuSlot();

	const char* configPathStr = configPath.empty() ? "<defaults>" : configPath.c_str();
	const char* dockerfileStr = dockerfilePath.empty() ? "<unset>" : dockerfilePath.c_str();
	const char* rdpPasswordStr = rdpPassword.empty() ? "<unset>" : "<redacted>";

	if (!refreshed)
		WLog_WARN(TAG, "Failed to refresh VDI broker configuration at %s; using defaults",
		         configPathStr);

	WLog_INFO(TAG, "VDI broker configuration loaded");
	WLog_INFO(TAG, "  config_path   : %s", configPathStr);
	WLog_INFO(TAG, "  podman_image  : %s", podmanImage.c_str());
	WLog_INFO(TAG, "  user_images   : %" PRIu64 " overrides",
	          static_cast<std::uint64_t>(userImageOverrides));
	WLog_INFO(TAG, "  custom_mounts : %" PRIu64 " entries",
	          static_cast<std::uint64_t>(customMounts));
	WLog_INFO(TAG, "  nvidia_gpu    : %s", nvidiaEnabled ? "enabled" : "disabled");
	if (nvidiaEnabled)
		WLog_INFO(TAG, "  nvidia_slot   : %" PRIu32, nvidiaSlot);
	WLog_INFO(TAG, "  dri_device    : %s", driDevice.c_str());
	WLog_INFO(TAG, "  home_path     : %s", homePath.c_str());
	WLog_INFO(TAG, "  shadow_path   : %s", shadowPath.c_str());
	WLog_INFO(TAG, "  group_path    : %s", groupPath.c_str());
	WLog_INFO(TAG, "  passwd_path   : %s", passwdPath.c_str());
	WLog_INFO(TAG, "  pam_path      : %s", pamPath.c_str());
	WLog_INFO(TAG, "  pam_service   : %s", pamService.c_str());
	WLog_INFO(TAG, "  dockerfile    : %s", dockerfileStr);
	WLog_INFO(TAG, "  rdp_username  : %s", rdpUsername.c_str());
	WLog_INFO(TAG, "  rdp_password  : %s", rdpPasswordStr);
}

void vdi_log_refresh_outcome(bool refreshed, bool reloaded)
{
	if (reloaded)
	{
		vdi_log_configuration_state(refreshed);
		return;
	}

	if (!refreshed)
	{
		auto& configuration = vdi::Config();
		const std::string configPath = configuration.ConfigPath();
		const char* configPathStr = configPath.empty() ? "<defaults>" : configPath.c_str();
		WLog_WARN(TAG, "Failed to refresh VDI broker configuration at %s; using defaults",
		         configPathStr);
	}
}

static void vdi_refresh_configuration(proxyData* pdata)
{
	auto& configuration = vdi::Config();

	if (pdata && pdata->config)
	{
		const char* path = pf_config_get(pdata->config, plugin_name, kConfigPathKey);
		if (path && *path)
		{
			const std::string currentPath = configuration.ConfigPath();
			const bool changed = currentPath != path;
			configuration.SetConfigPath(path);
			const bool refreshed = configuration.Refresh();
			const bool reloaded = configuration.ConsumeReloadedFlag();
			if (changed || reloaded || !refreshed)
				vdi_log_refresh_outcome(refreshed, reloaded);
			return;
		}
	}

	const bool refreshed = configuration.Refresh();
	const bool reloaded = configuration.ConsumeReloadedFlag();
	vdi_log_refresh_outcome(refreshed, reloaded);
}

static void vdi_initialize_configuration(const proxyConfig* config)
{
	if (!config)
		return;

	auto& configuration = vdi::Config();
	const char* path = pf_config_get(config, plugin_name, kConfigPathKey);
	if (path && *path)
		configuration.SetConfigPath(path);
}



struct vdi_custom_data
{
	proxyPluginsManager* mgr;
	int somesetting;
};

static BOOL vdi_plugin_unload(proxyPlugin* plugin)
{
	WINPR_ASSERT(plugin);

	std::cout << "C++ vdi plugin: unloading..." << std::endl;

	/* Here we have to free up our custom data storage. */
	if (plugin)
		delete static_cast<struct vdi_custom_data*>(plugin->custom);

	return TRUE;
}

static BOOL vdi_client_init_connect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(custom);
	auto settings = pdata->pc->context.settings;

	freerdp_settings_set_bool (settings, FreeRDP_RdpSecurity, FALSE);
	freerdp_settings_set_bool (settings, FreeRDP_TlsSecurity, FALSE);
	freerdp_settings_set_bool (settings, FreeRDP_NlaSecurity, TRUE);


	WLog_INFO(TAG, "called");
	return TRUE;
}

// Structure to hold the password
struct pam_conv_data {
    const char* password;
};


// PAM conversation function
static int pam_conversation(int num_msg, const struct pam_message** msg,
                            struct pam_response** resp, void* appdata_ptr) {
    if (num_msg <= 0) {
        return PAM_CONV_ERR;
    }

    pam_conv_data* conv_data = static_cast<pam_conv_data*>(appdata_ptr);
    struct pam_response* responses = (struct pam_response*)calloc(num_msg, sizeof(struct pam_response));
    if (responses == nullptr) {
        return PAM_CONV_ERR;
    }

    for (int i = 0; i < num_msg; ++i) {
        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
                // Provide the password
                responses[i].resp = strdup(conv_data->password);
                responses[i].resp_retcode = 0;
                break;
            case PAM_PROMPT_ECHO_ON:
                // Handle cases where echo is allowed (not used here)
                responses[i].resp = nullptr;
                responses[i].resp_retcode = 0;
                break;
            case PAM_ERROR_MSG:
                std::cerr << "PAM Error Message: " << msg[i]->msg << std::endl;
                responses[i].resp = nullptr;
                responses[i].resp_retcode = 0;
                break;
            case PAM_TEXT_INFO:
                std::cout << "PAM Info: " << msg[i]->msg << std::endl;
                responses[i].resp = nullptr;
                responses[i].resp_retcode = 0;
                break;
            default:
                free(responses);
                return PAM_CONV_ERR;
        }
    }

    *resp = responses;
    return PAM_SUCCESS;
}




// Function to authenticate user via PAM
bool vdi_auth(const std::string& username, const std::string& password) {
    pam_handle_t* pamh = nullptr;
    struct pam_conv conv;
    pam_conv_data conv_data = { password.c_str() };

    conv.conv = pam_conversation;
    conv.appdata_ptr = &conv_data;

	auto& configuration = vdi::Config();
	const bool refreshedConfig = configuration.Refresh();
	const bool reloadedConfig = configuration.ConsumeReloadedFlag();
	vdi_log_refresh_outcome(refreshedConfig, reloadedConfig);

	std::string pamService = configuration.PamServiceName();
    if (pamService.empty())
        pamService.assign(kDefaultPamServiceName);

    // Start PAM transaction
    int retval = pam_start(pamService.c_str(), username.c_str(), &conv, &pamh);
    if (retval != PAM_SUCCESS) {
        std::cerr << "pam_start failed: " << pam_strerror(pamh, retval) << std::endl;
        return false;
    }

    // Authenticate the user
    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS) {
        std::cerr << "pam_authenticate failed: " << pam_strerror(pamh, retval) << std::endl;
        pam_end(pamh, retval);
        return false;
    }

    // Check account status
    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) {
        std::cerr << "pam_acct_mgmt failed: " << pam_strerror(pamh, retval) << std::endl;
        pam_end(pamh, retval);
        return false;
    }

    // End PAM transaction
    retval = pam_end(pamh, PAM_SUCCESS);
    if (retval != PAM_SUCCESS) {
        std::cerr << "pam_end failed: " << pam_strerror(pamh, retval) << std::endl;
        return false;
    }

    return true;
}

static BOOL vdi_client_pre_connect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(pdata->pc);
	WINPR_ASSERT(custom);

        //Set target to another thing
	auto settings = pdata->pc->context.settings;
	const char* uname = freerdp_settings_get_string(settings, FreeRDP_Username);
	const char* passw = freerdp_settings_get_string(settings, FreeRDP_Password);

	if(uname == nullptr)
		return FALSE;
	if(passw == nullptr)
		return FALSE;

	std::string username = uname;
	std::string password = passw;

	vdi_refresh_configuration(pdata);

	WLog_INFO(TAG, "Username full: %s", username.c_str());

	auto hashPos = username.find('#');
	std::string containerSuffix;
	if ((hashPos != std::string::npos) && (hashPos + 1 < username.size()))
		containerSuffix = username.substr(hashPos + 1);

	std::string user = (hashPos == std::string::npos) ? username : username.substr(0, hashPos);

	if(!vdi_auth(user, password)) {
		return FALSE;
	}
	WLog_INFO(TAG, "Username: %s", username.c_str());
	const std::string containerPrefix = build_container_prefix(containerSuffix);
	const std::string requestedContainer = containerPrefix + user;
	WLog_INFO(TAG, "Requesting container: %s", requestedContainer.c_str());
	std::string ip = vdi::ManageContainer(user, containerPrefix);
	if (!ip.empty())
	{
		WLog_INFO(TAG, "Setting target address: %s", ip.c_str());
		auto& configuration = vdi::Config();
		const bool refreshedConfig = configuration.Refresh();
		const bool reloadedConfig = configuration.ConsumeReloadedFlag();
		vdi_log_refresh_outcome(refreshedConfig, reloadedConfig);
		const std::string rdpUsername =
		    configuration.RdpUsername().empty() ? "rdp" : configuration.RdpUsername();
		const std::string rdpPassword =
		    configuration.RdpPassword().empty() ? "rdp" : configuration.RdpPassword();
		freerdp_settings_set_string(settings, FreeRDP_ServerHostname, ip.c_str());
		freerdp_settings_set_uint32(settings, FreeRDP_ServerPort, 3389);
		freerdp_settings_set_string(settings, FreeRDP_Username, rdpUsername.c_str());
		freerdp_settings_set_string(settings, FreeRDP_Password, rdpPassword.c_str());
		freerdp_settings_set_string(settings, FreeRDP_Domain, "None");
	}

	return TRUE;
}


void printDelayBetweenCalls() {
    // Declare a static variable to hold the last time the function was called
    static struct timeval lastTime = {0, 0};

    // Get the current time
    struct timeval currentTime;
    gettimeofday(&currentTime, NULL);

    // Check if the function has been called before
    if (lastTime.tv_sec != 0 || lastTime.tv_usec != 0) {
        // Calculate the delay in microseconds
        long seconds = currentTime.tv_sec - lastTime.tv_sec;
        long microseconds = currentTime.tv_usec - lastTime.tv_usec;
        long totalMicroseconds = (seconds * 1000) + microseconds;

        printf("Time delay between calls: %ld microseconds\n", totalMicroseconds);
    } else {
        // If this is the first call, print a message indicating so
        printf("This is the first time the function is being called.\n");
    }

    // Update the lastTime variable with the current time
    lastTime = currentTime;
}

#ifdef __cplusplus
extern "C"
{
#endif
	FREERDP_API BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager, void* userdata);
#ifdef __cplusplus
}
#endif

void vdi_broker_proxy_module_entry_point(){}

BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager, void* userdata)
{
	struct vdi_custom_data* custom = nullptr;
	proxyPlugin plugin = {};

	const proxyConfig* initialConfig = static_cast<const proxyConfig*>(userdata);
	vdi_initialize_configuration(initialConfig);
	auto& configuration = vdi::Config();
	const bool refreshed = configuration.Refresh();
	const bool reloaded = configuration.ConsumeReloadedFlag();

	plugin.name = plugin_name;
	plugin.description = plugin_desc;
	plugin.PluginUnload = vdi_plugin_unload;
	plugin.ClientInitConnect = vdi_client_init_connect;
	plugin.ClientPreConnect = vdi_client_pre_connect;

	custom = new (struct vdi_custom_data);
	if (!custom)
		return FALSE;

	custom->mgr = plugins_manager;
	custom->somesetting = 42;

	plugin.custom = custom;

	vdi_log_refresh_outcome(refreshed, reloaded);

	return plugins_manager->RegisterPlugin(plugins_manager, &plugin);
}
