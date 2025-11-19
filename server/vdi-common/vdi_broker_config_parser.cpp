#include "vdi_broker_config_parser.h"
#include "vdi_broker_config_parser_internal.h"

#include "vdi_broker_config.h"

#include <cctype>
#include <limits>
#include <sstream>

namespace vdi
{

ConfigYamlParser::ConfigYamlParser(VdiBrokerConfig& config) : config_(config)
{
}

bool ConfigYamlParser::Parse(const std::string& content)
{
    std::istringstream stream(content);
    std::string line;
    while (std::getline(stream, line))
        ProcessLine(line);

    FlushPending();
    if (macVlanParentRequired_)
    {
        config_.podmanNetworkMode_ = VdiBrokerConfig::PodmanNetworkMode::Bridge;
        macVlanParentRequired_ = false;
    }
    if (config_.podmanNetworkMode_ == VdiBrokerConfig::PodmanNetworkMode::MacVlan)
    {
        if (config_.podmanNetworkParentInterface_.empty())
            config_.podmanNetworkMode_ = VdiBrokerConfig::PodmanNetworkMode::Bridge;
    }
    config_.pamServiceName_ = config_.ResolvePamService(config_.pamPath_);
    return true;
}

void ConfigYamlParser::ProcessLine(const std::string& line)
{
    const std::string trimmed = VdiBrokerConfig::Trim(line);
    if (trimmed.empty() || trimmed[0] == '#')
        return;

    const bool isTopLevel =
        !line.empty() && !std::isspace(static_cast<unsigned char>(line.front()));

    if (isTopLevel)
        ResetBlocksForTopLevel(trimmed);

    if (HandleBlockLine(trimmed, isTopLevel))
        return;

    ProcessTopLevelLine(trimmed);
}

void ConfigYamlParser::ResetBlocksForTopLevel(const std::string& trimmed)
{
    if (trimmed.empty())
        return;

    const bool isBlockContinuation = trimmed[0] == '-';

    if (inUserImagesBlock_ && !isBlockContinuation)
    {
        FlushUserImage();
        inUserImagesBlock_ = false;
    }

    if (inCustomMountsBlock_ && !isBlockContinuation)
    {
        FlushCustomMount();
        inCustomMountsBlock_ = false;
    }

    if (inDriRenderDevicesBlock_ && !isBlockContinuation)
        inDriRenderDevicesBlock_ = false;

    if (inDriCardDevicesBlock_ && !isBlockContinuation)
        inDriCardDevicesBlock_ = false;

    if (inResourceLimitsBlock_ && !isBlockContinuation)
    {
        if (resourceSection_ == ResourceSection::Users)
            FlushResourceLimitUser();
        inResourceLimitsBlock_ = false;
        resourceSection_ = ResourceSection::None;
    }

    if (inNetworkBlock_ && !isBlockContinuation)
    {
        inNetworkBlock_ = false;
        if (macVlanParentRequired_)
        {
            config_.podmanNetworkMode_ = VdiBrokerConfig::PodmanNetworkMode::Bridge;
            macVlanParentRequired_ = false;
        }
    }
}

void ConfigYamlParser::ProcessTopLevelLine(const std::string& trimmed)
{
    const auto pos = trimmed.find(':');
    if (pos == std::string::npos)
        return;

    const std::string key = VdiBrokerConfig::Trim(trimmed.substr(0, pos));
    const std::string value = RemoveCommentAndStrip(trimmed.substr(pos + 1));
    HandleTopLevelEntry(key, value);
}

void ConfigYamlParser::HandleTopLevelEntry(const std::string& key, const std::string& value)
{
    const std::string normalized = VdiBrokerConfig::ToLower(key);

    if (normalized == "podman_image")
    {
        if (!value.empty())
            config_.podmanImage_ = value;
        return;
    }

    if (normalized == "network")
    {
        if (ShouldStartBlock(value))
        {
            StartNetworkBlock();
        }
        else
        {
            const std::string lower = VdiBrokerConfig::ToLower(value);
            if (lower == "none" || lower == "disabled" || IsFalsy(value))
            {
                config_.podmanNetworkMode_ = VdiBrokerConfig::PodmanNetworkMode::None;
                macVlanParentRequired_ = false;
            }
            else if (lower == "macvlan")
            {
                config_.podmanNetworkMode_ = VdiBrokerConfig::PodmanNetworkMode::MacVlan;
                macVlanParentRequired_ = config_.podmanNetworkParentInterface_.empty();
            }
            else if (IsBridgeUnmanagedToken(value))
            {
                config_.podmanNetworkMode_ = VdiBrokerConfig::PodmanNetworkMode::BridgeUnmanaged;
                macVlanParentRequired_ = false;
            }
            else
            {
                config_.podmanNetworkMode_ = VdiBrokerConfig::PodmanNetworkMode::Bridge;
                macVlanParentRequired_ = false;
            }
        }
        return;
    }

    if (normalized == "user_images" || normalized == "custom_user_images")
    {
        config_.userImages_.clear();
        if (ShouldStartBlock(value))
            StartUserImagesBlock();
        else
            inUserImagesBlock_ = false;
        return;
    }

    if (normalized == "custom_mounts" || normalized == "additional_mounts")
    {
        config_.customMounts_.clear();
        if (ShouldStartBlock(value))
            StartCustomMountsBlock();
        else
            inCustomMountsBlock_ = false;
        return;
    }

    if (normalized == "resource_limits" || normalized == "limits")
    {
        FlushResourceLimitUser();
        if (ShouldStartBlock(value))
            StartResourceLimitsBlock();
        else
        {
            inResourceLimitsBlock_ = false;
            resourceSection_ = ResourceSection::None;
        }
        return;
    }

    if (normalized == "dri_render_devices" || normalized == "dri_render_nodes")
    {
        config_.driRenderDevices_.clear();
        if (ShouldStartBlock(value))
        {
            StartDriRenderDevicesBlock();
        }
        else
        {
            inDriRenderDevicesBlock_ = false;
            ParseInlineDeviceList(value, config_.driRenderDevices_);
        }
        return;
    }

    if (normalized == "dri_card_devices" || normalized == "dri_cards")
    {
        config_.driCardDevices_.clear();
        if (ShouldStartBlock(value))
        {
            StartDriCardDevicesBlock();
        }
        else
        {
            inDriCardDevicesBlock_ = false;
            ParseInlineDeviceList(value, config_.driCardDevices_);
        }
        return;
    }

    if (normalized == "dri_device" || normalized == "dri_render_device")
    {
        config_.driRenderDevices_.clear();
        inDriRenderDevicesBlock_ = false;
        ParseInlineDeviceList(value, config_.driRenderDevices_);
        return;
    }

    if (normalized == "nvidia_gpu" || normalized == "use_nvidia_gpu" ||
        normalized == "enable_nvidia_gpu")
    {
        if (IsTruthy(value))
            config_.nvidiaGpuEnabled_ = true;
        else if (IsFalsy(value))
            config_.nvidiaGpuEnabled_ = false;
        return;
    }

    if (normalized == "nvidia_gpu_slot" || normalized == "nvidia_gpu_index" ||
        normalized == "nvidia_slot")
    {
        if (!value.empty())
        {
            try
            {
                const unsigned long parsed = std::stoul(value);
                if (parsed <= std::numeric_limits<std::uint32_t>::max())
                    config_.nvidiaGpuSlot_ = static_cast<std::uint32_t>(parsed);
            }
            catch (...)
            {
            }
        }
        return;
    }

    if (normalized == "home_path" || normalized == "home_directory_path" ||
        normalized == "home_dir")
    {
        if (!value.empty())
            config_.homePath_ = value;
        return;
    }

    if (normalized == "shadow_path")
    {
        if (!value.empty())
            config_.shadowPath_ = value;
        return;
    }

    if (normalized == "group_path")
    {
        if (!value.empty())
            config_.groupPath_ = value;
        return;
    }

    if (normalized == "passwd_path" || normalized == "password_path")
    {
        if (!value.empty())
            config_.passwdPath_ = value;
        return;
    }

    if (normalized == "pam_path" || normalized == "pam_config_path")
    {
        if (!value.empty())
        {
            config_.pamPath_ = value;
            config_.pamServiceName_ = config_.ResolvePamService(config_.pamPath_);
        }
        return;
    }

    if (normalized == "dockerfile_path")
    {
        config_.dockerfilePath_ = value;
        return;
    }

    if (normalized == "rdp_username")
    {
        if (!value.empty())
            config_.rdpUsername_ = value;
        return;
    }

    if (normalized == "rdp_password")
    {
        if (!value.empty())
            config_.rdpPassword_ = value;
        return;
    }

    if (normalized == "rdp_auth_override" || normalized == "rdp_authentication_override")
    {
        if (IsTruthy(value))
            config_.rdpAuthOverride_ = true;
        else if (IsFalsy(value))
            config_.rdpAuthOverride_ = false;
        return;
    }

    if (normalized == "redirector_background_image")
    {
        config_.redirectorBackgroundImage_ = VdiBrokerConfig::StripQuotes(value);
        return;
    }

    if (normalized == "redirector_background_color")
    {
        config_.redirectorBackgroundColorBgrx_ =
            VdiBrokerConfig::ParseColorBgrx(value, config_.redirectorBackgroundColorBgrx_);
        return;
    }
}

void ConfigYamlParser::StartUserImagesBlock()
{
    inUserImagesBlock_ = true;
    currentUser_.clear();
    currentImage_.clear();
}

void ConfigYamlParser::StartCustomMountsBlock()
{
    inCustomMountsBlock_ = true;
    currentMountSource_.clear();
    currentMountDestination_.clear();
    currentMountReadOnly_ = false;
}

void ConfigYamlParser::StartResourceLimitsBlock()
{
    inResourceLimitsBlock_ = true;
    resourceSection_ = ResourceSection::None;
}

void ConfigYamlParser::StartResourceLimitsUsersSection()
{
    FlushResourceLimitUser();
    resourceSection_ = ResourceSection::Users;
}

void ConfigYamlParser::StartResourceLimitsGlobalSection()
{
    resourceSection_ = ResourceSection::Global;
}

void ConfigYamlParser::StartDriRenderDevicesBlock()
{
    inDriRenderDevicesBlock_ = true;
}

void ConfigYamlParser::StartDriCardDevicesBlock()
{
    inDriCardDevicesBlock_ = true;
}

void ConfigYamlParser::StartNetworkBlock()
{
    inNetworkBlock_ = true;
    macVlanParentRequired_ = false;
}

void ConfigYamlParser::FlushUserImage()
{
    if (!currentUser_.empty() && !currentImage_.empty())
        config_.userImages_[VdiBrokerConfig::ToLower(currentUser_)] = currentImage_;

    currentUser_.clear();
    currentImage_.clear();
}

void ConfigYamlParser::FlushCustomMount()
{
    if (!currentMountSource_.empty() && !currentMountDestination_.empty())
        config_.customMounts_.push_back({currentMountSource_, currentMountDestination_,
                                         currentMountReadOnly_});

    currentMountSource_.clear();
    currentMountDestination_.clear();
    currentMountReadOnly_ = false;
}

void ConfigYamlParser::FlushResourceLimitUser()
{
    if (!currentResourceLimitUser_.empty() && !currentUserResourceLimits_.empty())
        config_.userResourceLimits_[VdiBrokerConfig::ToLower(currentResourceLimitUser_)] =
            currentUserResourceLimits_;

    currentResourceLimitUser_.clear();
    currentUserResourceLimits_.clear();
}

void ConfigYamlParser::FlushPending()
{
    FlushUserImage();
    FlushCustomMount();
    FlushResourceLimitUser();
}

bool ParseBrokerConfigYaml(const std::string& content, VdiBrokerConfig& config)
{
    ConfigYamlParser parser(config);
    return parser.Parse(content);
}

} // namespace vdi
