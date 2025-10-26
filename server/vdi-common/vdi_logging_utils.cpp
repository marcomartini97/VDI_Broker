#include "vdi_logging.h"

#include "vdi_broker_config.h"

#include <inttypes.h>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#define TAG MODULE_TAG("config")

namespace
{
const char* PodmanModeToString(vdi::VdiBrokerConfig::PodmanNetworkMode mode)
{
	switch (mode)
	{
		case vdi::VdiBrokerConfig::PodmanNetworkMode::MacVlan:
			return "macvlan";
		case vdi::VdiBrokerConfig::PodmanNetworkMode::BridgeUnmanaged:
			return "bridge-unmanaged";
		case vdi::VdiBrokerConfig::PodmanNetworkMode::Bridge:
			return "bridge";
		case vdi::VdiBrokerConfig::PodmanNetworkMode::None:
		default:
			return "disabled";
	}
}
} // namespace

void vdi_log_configuration_state(bool refreshed)
{
	auto& configuration = vdi::Config();
	const std::string configPath = configuration.ConfigPath();
	const std::string podmanImage = configuration.PodmanImage();
	const auto networkMode = configuration.ActivePodmanNetworkMode();
	const std::string networkName = configuration.PodmanNetworkName();
	const std::string networkInterface = configuration.PodmanNetworkInterface();
	const std::string networkParent = configuration.PodmanNetworkParentInterface();
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
	VDI_LOG_INFO(TAG, "  network_mode  : %s", PodmanModeToString(networkMode));
	if (networkMode != vdi::VdiBrokerConfig::PodmanNetworkMode::None)
	{
		const char* nameStr = networkName.empty() ? "<unset>" : networkName.c_str();
		const char* ifaceStr = networkInterface.empty() ? "<default>" : networkInterface.c_str();
		VDI_LOG_INFO(TAG, "  network_name  : %s", nameStr);
		VDI_LOG_INFO(TAG, "  network_if    : %s", ifaceStr);
		if (!networkParent.empty())
			VDI_LOG_INFO(TAG, "  network_parent: %s", networkParent.c_str());
	}
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
