#include "vdi_container_manager.h"

#include "vdi_broker_config.h"
#include "vdi_container_manager_constants.h"
#include "vdi_container_manager_internal.h"
#include "vdi_logging.h"

#include <inttypes.h>
#include <string>

#define TAG MODULE_TAG("vdi-container-manager")

namespace vdi
{

std::string ManageContainer(const std::string& username, const std::string& containerPrefix)
{
    vdi::logging::ScopedLogUser scopedUser(username);
    auto& configuration = Config();
    const bool refreshed = configuration.Refresh();
    const bool reloaded = configuration.ConsumeReloadedFlag();
    if (reloaded || !refreshed)
        vdi_log_refresh_outcome(refreshed, reloaded);

    const std::string prefix = containerPrefix.empty() ? std::string("vdi-") : containerPrefix;
    const std::string containerName = prefix + username;

    if (!EnsurePodmanNetwork(configuration))
    {
        VDI_LOG_ERROR(TAG, "Unable to ensure Podman network for container %s",
                      containerName.c_str());
        return {};
    }

    if (!ContainerExistsInternal(containerName))
    {
        if (!CreateContainerInternal(containerName, username))
        {
            VDI_LOG_ERROR(TAG, "Failed to create container for user %s", username.c_str());
            return {};
        }
    }

    if (!ContainerRunningInternal(containerName))
    {
        if (!StartContainerInternal(containerName))
        {
            VDI_LOG_ERROR(TAG, "Failed to start container %s", containerName.c_str());
            return {};
        }
    }

    const std::string connectionDetails = GetContainerIpInternal(containerName);
    if (connectionDetails.empty())
    {
        VDI_LOG_ERROR(TAG, "Failed to retrieve IP for container %s", containerName.c_str());
        return {};
    }

    ContainerConnectionInfo connectionInfo;
    std::string parseError;
    if (!ParseContainerConnectionInfo(connectionDetails, connectionInfo, &parseError))
    {
        if (parseError.empty())
            VDI_LOG_ERROR(TAG, "Failed to parse container connection details for %s",
                          containerName.c_str());
        else
            VDI_LOG_ERROR(TAG, "Failed to parse container connection details for %s: %s",
                          containerName.c_str(), parseError.c_str());
        return {};
    }

    if (!WaitForContainerPortWithSs(containerName, kRdpPort))
    {
        VDI_LOG_ERROR(TAG, "RDP port %" PRIu16 " not ready inside container %s (ip: %s)",
                      kRdpPort, containerName.c_str(), connectionInfo.ip.c_str());
        return {};
    }

    return TrimWhitespace(connectionDetails);
}

} // namespace vdi
