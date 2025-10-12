#include "vdi_proxy_utils.h"

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

#define TAG MODULE_TAG("vdi_proxy")
static constexpr char kDefaultPamServiceName[] = "vdi-broker";

namespace vdi::proxy
{

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

} // namespace vdi::proxy
