#include "vdi_redirector_utils.h"

#include "vdi_broker_config.h"
#include "vdi_logging.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <inttypes.h>
#include <string>
#include <vector>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#define TAG MODULE_TAG("vdi_redirector")
static constexpr char kDefaultPamServiceName[] = "vdi-broker";

ParsedUsername split_username(const std::string& username)
{
	ParsedUsername parsed{};
	const auto hashPos = username.find('#');
	if (hashPos == std::string::npos)
	{
		parsed.user = username;
		return parsed;
	}

	parsed.user = username.substr(0, hashPos);
	if (hashPos + 1 < username.size())
		parsed.suffix = username.substr(hashPos + 1);

	return parsed;
}

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

RdpCredentials load_rdp_credentials()
{
	auto& configuration = vdi::Config();
	const bool refreshedConfig = configuration.Refresh();
	const bool reloadedConfig = configuration.ConsumeReloadedFlag();
	vdi_log_refresh_outcome(refreshedConfig, reloadedConfig);

	RdpCredentials creds{};
	creds.username = configuration.RdpUsername().empty() ? "rdp" : configuration.RdpUsername();
	creds.password = configuration.RdpPassword().empty() ? "rdp" : configuration.RdpPassword();
	return creds;
}

void vdi_log_configuration_state(bool refreshed)
{
	auto& configuration = vdi::Config();
	const std::string configPath = configuration.ConfigPath();
	const std::string podmanImage = configuration.PodmanImage();
	const auto driRenderDevices = configuration.DriRenderDevices();
	const auto driCardDevices = configuration.DriCardDevices();
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
	const auto globalResourceLimits = configuration.GlobalResourceLimits();
	const std::size_t perUserResourceLimitOverrides = configuration.ResourceLimitUserCount();
	const std::string redirectorBackgroundImage = configuration.RedirectorBackgroundImage();
	const std::uint32_t redirectorBackgroundColor = configuration.RedirectorBackgroundColor();
	const std::uint8_t bgRed = static_cast<std::uint8_t>((redirectorBackgroundColor >> 16) & 0xFF);
	const std::uint8_t bgGreen = static_cast<std::uint8_t>((redirectorBackgroundColor >> 8) & 0xFF);
	const std::uint8_t bgBlue = static_cast<std::uint8_t>(redirectorBackgroundColor & 0xFF);
	char colorBuffer[8] = {};
	std::snprintf(colorBuffer, sizeof(colorBuffer), "#%02X%02X%02X", bgRed, bgGreen, bgBlue);

	const char* configPathStr = configPath.empty() ? "<defaults>" : configPath.c_str();
	const char* dockerfileStr = dockerfilePath.empty() ? "<unset>" : dockerfilePath.c_str();
	const char* rdpPasswordStr = rdpPassword.empty() ? "<unset>" : "<redacted>";

	if (!refreshed)
		VDI_LOG_WARN(TAG, "Failed to refresh VDI broker configuration at %s; using defaults",
		             configPathStr);

	VDI_LOG_INFO(TAG, "VDI broker configuration loaded");
	VDI_LOG_INFO(TAG, "  config_path   : %s", configPathStr);
	VDI_LOG_INFO(TAG, "  podman_image  : %s", podmanImage.c_str());
	VDI_LOG_INFO(TAG, "  user_images   : %" PRIu64 " overrides",
	             static_cast<std::uint64_t>(userImageOverrides));
	VDI_LOG_INFO(TAG, "  custom_mounts : %" PRIu64 " entries",
	             static_cast<std::uint64_t>(customMounts));
	VDI_LOG_INFO(TAG, "  nvidia_gpu    : %s", nvidiaEnabled ? "enabled" : "disabled");
	if (nvidiaEnabled)
		VDI_LOG_INFO(TAG, "  nvidia_slot   : %" PRIu32, nvidiaSlot);
	VDI_LOG_INFO(TAG, "  resource_limits: %" PRIu64 " global entries; %" PRIu64
	                 " per-user overrides",
	             static_cast<std::uint64_t>(globalResourceLimits.size()),
	             static_cast<std::uint64_t>(perUserResourceLimitOverrides));
	const char* firstRenderDevice =
	    driRenderDevices.empty() ? "<unset>" : driRenderDevices.front().c_str();
	const char* firstCardDevice =
	    driCardDevices.empty() ? "<unset>" : driCardDevices.front().c_str();
	VDI_LOG_INFO(TAG, "  dri_render    : %" PRIu64 " entries (first: %s)",
	             static_cast<std::uint64_t>(driRenderDevices.size()), firstRenderDevice);
	VDI_LOG_INFO(TAG, "  dri_cards     : %" PRIu64 " entries (first: %s)",
	             static_cast<std::uint64_t>(driCardDevices.size()), firstCardDevice);
	VDI_LOG_INFO(TAG, "  home_path     : %s", homePath.c_str());
	VDI_LOG_INFO(TAG, "  shadow_path   : %s", shadowPath.c_str());
	VDI_LOG_INFO(TAG, "  group_path    : %s", groupPath.c_str());
	VDI_LOG_INFO(TAG, "  passwd_path   : %s", passwdPath.c_str());
	VDI_LOG_INFO(TAG, "  pam_path      : %s", pamPath.c_str());
	VDI_LOG_INFO(TAG, "  pam_service   : %s", pamService.c_str());
	VDI_LOG_INFO(TAG, "  dockerfile    : %s", dockerfileStr);
	const char* bgImageStr = redirectorBackgroundImage.empty() ? "<unset>" : redirectorBackgroundImage.c_str();
	VDI_LOG_INFO(TAG, "  redirector_bg : %s (color %s)", bgImageStr, colorBuffer);
	VDI_LOG_INFO(TAG, "  rdp_username  : %s", rdpUsername.c_str());
	VDI_LOG_INFO(TAG, "  rdp_password  : %s", rdpPasswordStr);
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
		VDI_LOG_WARN(TAG, "Failed to refresh VDI broker configuration at %s; using defaults",
		             configPathStr);
	}
}

struct pam_conv_data
{
	const char* password;
};

static int pam_conversation(int num_msg, const struct pam_message** msg, struct pam_response** resp,
                            void* appdata_ptr)
{
	if (num_msg <= 0)
		return PAM_CONV_ERR;

	auto* conv_data = static_cast<pam_conv_data*>(appdata_ptr);
	struct pam_response* responses =
	    static_cast<pam_response*>(calloc(static_cast<size_t>(num_msg), sizeof(pam_response)));
	if (!responses)
		return PAM_CONV_ERR;

	for (int i = 0; i < num_msg; ++i)
	{
		switch (msg[i]->msg_style)
		{
			case PAM_PROMPT_ECHO_OFF:
				responses[i].resp = conv_data->password ? strdup(conv_data->password) : nullptr;
				responses[i].resp_retcode = 0;
				break;
			case PAM_PROMPT_ECHO_ON:
				responses[i].resp = nullptr;
				responses[i].resp_retcode = 0;
				break;
			case PAM_ERROR_MSG:
				VDI_LOG_WARN(TAG, "PAM Error Message: %s", msg[i]->msg ? msg[i]->msg : "<null>");
				responses[i].resp = nullptr;
				responses[i].resp_retcode = 0;
				break;
			case PAM_TEXT_INFO:
				VDI_LOG_INFO(TAG, "PAM Info: %s", msg[i]->msg ? msg[i]->msg : "<null>");
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

bool vdi_auth(const std::string& username, const std::string& password)
{
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

	int retval = pam_start(pamService.c_str(), username.c_str(), &conv, &pamh);
	if (retval != PAM_SUCCESS)
	{
		VDI_LOG_ERROR(TAG, "pam_start failed: %s", pam_strerror(pamh, retval));
		return false;
	}

	retval = pam_authenticate(pamh, 0);
	if (retval != PAM_SUCCESS)
	{
		VDI_LOG_ERROR(TAG, "pam_authenticate failed: %s", pam_strerror(pamh, retval));
		pam_end(pamh, retval);
		return false;
	}

	retval = pam_acct_mgmt(pamh, 0);
	if (retval != PAM_SUCCESS)
	{
		VDI_LOG_ERROR(TAG, "pam_acct_mgmt failed: %s", pam_strerror(pamh, retval));
		pam_end(pamh, retval);
		return false;
	}

	retval = pam_end(pamh, PAM_SUCCESS);
	if (retval != PAM_SUCCESS)
	{
		VDI_LOG_ERROR(TAG, "pam_end failed: %s", pam_strerror(pamh, retval));
		return false;
	}

	return true;
}
