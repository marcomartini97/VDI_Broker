#include "vdi_broker_config_parser_internal.h"

#include "vdi_broker_config.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <string>
#include <utility>

namespace vdi
{

bool ConfigYamlParser::HandleBlockLine(const std::string& trimmed, bool isTopLevel)
{
    if (inNetworkBlock_ && !isTopLevel)
        return ProcessNetworkLine(trimmed);

    if (inDriRenderDevicesBlock_ && !isTopLevel)
        return ProcessDriDevicesLine(trimmed, config_.driRenderDevices_);

    if (inDriCardDevicesBlock_ && !isTopLevel)
        return ProcessDriDevicesLine(trimmed, config_.driCardDevices_);

    if (inResourceLimitsBlock_ && !isTopLevel)
        return ProcessResourceLimitsLine(trimmed);

    if (inUserImagesBlock_)
        return ProcessUserImagesLine(trimmed);

    if (inCustomMountsBlock_)
        return ProcessCustomMountsLine(trimmed);

    return false;
}

bool ConfigYamlParser::ProcessResourceLimitsLine(const std::string& trimmed)
{
    if (resourceSection_ == ResourceSection::Users)
        return ProcessUserResourceLimitLine(trimmed);

    if (resourceSection_ == ResourceSection::Global)
        return ProcessGlobalResourceLimitLine(trimmed);

    if (!trimmed.empty() && trimmed.back() == ':')
    {
        const std::string key =
            VdiBrokerConfig::ToLower(VdiBrokerConfig::Trim(trimmed.substr(0, trimmed.size() - 1)));
        if (key == "global")
        {
            StartResourceLimitsGlobalSection();
            return true;
        }
        if (key == "users" || key == "per_user" || key == "per-user")
        {
            StartResourceLimitsUsersSection();
            return true;
        }
    }

    const auto pos = trimmed.find(':');
    if (pos != std::string::npos)
    {
        const std::string key =
            VdiBrokerConfig::ToLower(VdiBrokerConfig::Trim(trimmed.substr(0, pos)));
        const std::string value = RemoveCommentAndStrip(trimmed.substr(pos + 1));

        if (key == "global" && value.empty())
        {
            StartResourceLimitsGlobalSection();
            return true;
        }
        if ((key == "users" || key == "per_user" || key == "per-user") && value.empty())
        {
            StartResourceLimitsUsersSection();
            return true;
        }
    }

    return true;
}

bool ConfigYamlParser::ProcessUserResourceLimitLine(std::string trimmed)
{
    if (trimmed.empty())
        return true;

    if (trimmed[0] == '-')
    {
        FlushResourceLimitUser();
        trimmed = VdiBrokerConfig::Trim(trimmed.substr(1));
        if (trimmed.empty())
            return true;
    }

    const auto pos = trimmed.find(':');
    if (pos == std::string::npos)
        return true;

    const std::string key =
        VdiBrokerConfig::ToLower(VdiBrokerConfig::Trim(trimmed.substr(0, pos)));
    const std::string value = RemoveCommentAndStrip(trimmed.substr(pos + 1));

    if (key == "user" || key == "username")
    {
        FlushResourceLimitUser();
        currentResourceLimitUser_ = value;
    }
    else if (!value.empty())
    {
        try
        {
            const long long parsed = std::stoll(value);
            currentUserResourceLimits_[key] = static_cast<std::int64_t>(parsed);
        }
        catch (...)
        {
        }
    }

    return true;
}

bool ConfigYamlParser::ProcessGlobalResourceLimitLine(const std::string& trimmed)
{
    const auto pos = trimmed.find(':');
    if (pos == std::string::npos)
        return true;

    const std::string key =
        VdiBrokerConfig::ToLower(VdiBrokerConfig::Trim(trimmed.substr(0, pos)));
    const std::string value = RemoveCommentAndStrip(trimmed.substr(pos + 1));

    if (value.empty())
        return true;

    try
    {
        const long long parsed = std::stoll(value);
        config_.globalResourceLimits_[key] = static_cast<std::int64_t>(parsed);
    }
    catch (...)
    {
    }

    return true;
}

bool ConfigYamlParser::ProcessUserImagesLine(std::string trimmed)
{
    if (trimmed.empty())
        return true;

    if (trimmed[0] == '-')
    {
        FlushUserImage();
        trimmed = VdiBrokerConfig::Trim(trimmed.substr(1));
        if (trimmed.empty())
            return true;
    }

    const auto pos = trimmed.find(':');
    if (pos == std::string::npos)
        return true;

    const std::string key =
        VdiBrokerConfig::ToLower(VdiBrokerConfig::Trim(trimmed.substr(0, pos)));
    const std::string value = RemoveCommentAndStrip(trimmed.substr(pos + 1));

    if (key == "user" || key == "username")
        currentUser_ = value;
    else if (key == "image" || key == "podman_image")
        currentImage_ = value;

    return true;
}

bool ConfigYamlParser::ProcessCustomMountsLine(std::string trimmed)
{
    if (trimmed.empty())
        return true;

    if (trimmed[0] == '-')
    {
        FlushCustomMount();
        trimmed = VdiBrokerConfig::Trim(trimmed.substr(1));
        if (trimmed.empty())
            return true;
    }

    const auto pos = trimmed.find(':');
    if (pos == std::string::npos)
        return true;

    const std::string key =
        VdiBrokerConfig::ToLower(VdiBrokerConfig::Trim(trimmed.substr(0, pos)));
    const std::string value = RemoveCommentAndStrip(trimmed.substr(pos + 1));

    if (key == "source" || key == "host" || key == "src")
        currentMountSource_ = value;
    else if (key == "destination" || key == "target" || key == "container" ||
             key == "dest")
        currentMountDestination_ = value;
    else if (key == "read_only" || key == "readonly" || key == "read-only" || key == "ro")
        currentMountReadOnly_ = IsTruthy(value);

    return true;
}

bool ConfigYamlParser::ProcessDriDevicesLine(std::string trimmed, std::vector<std::string>& target)
{
    if (!trimmed.empty() && trimmed[0] == '-')
        trimmed = VdiBrokerConfig::Trim(trimmed.substr(1));

    const std::string value = RemoveCommentAndStrip(trimmed);
    AppendDeviceEntry(target, value);
    return true;
}

bool ConfigYamlParser::ProcessNetworkLine(std::string trimmed)
{
    if (trimmed.empty())
        return true;

    if (trimmed[0] == '-')
        trimmed = VdiBrokerConfig::Trim(trimmed.substr(1));

    if (trimmed.empty())
        return true;

    if (trimmed.back() == ':')
        return true;

    const auto pos = trimmed.find(':');
    if (pos == std::string::npos)
        return true;

    const std::string key =
        VdiBrokerConfig::ToLower(VdiBrokerConfig::Trim(trimmed.substr(0, pos)));
    const std::string value = RemoveCommentAndStrip(trimmed.substr(pos + 1));

    if (key == "name")
    {
        if (!value.empty())
            config_.podmanNetworkName_ = value;
        return true;
    }

    if (key == "interface_name" || key == "network_interface" || key == "container_interface")
    {
        config_.podmanNetworkInterface_ = value;
        return true;
    }

    if (key == "type" || key == "mode")
    {
        const std::string lower = VdiBrokerConfig::ToLower(value);
        if (lower == "none" || lower == "disabled")
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
        return true;
    }

    if (key == "parent" || key == "master" || key == "master_interface")
    {
        config_.podmanNetworkParentInterface_ = value;
        if (config_.podmanNetworkMode_ == VdiBrokerConfig::PodmanNetworkMode::MacVlan)
            macVlanParentRequired_ = config_.podmanNetworkParentInterface_.empty();
        return true;
    }

    return true;
}

bool ConfigYamlParser::ShouldStartBlock(const std::string& value)
{
    return value.empty() || value == "|";
}
std::string ConfigYamlParser::RemoveCommentAndStrip(const std::string& value)
{
    std::string result = VdiBrokerConfig::Trim(value);
    const auto commentPos = result.find('#');
    if (commentPos != std::string::npos)
        result = VdiBrokerConfig::Trim(result.substr(0, commentPos));
    return VdiBrokerConfig::StripQuotes(result);
}

bool ConfigYamlParser::IsTruthy(const std::string& value)
{
    const std::string lower = VdiBrokerConfig::ToLower(value);
    return lower == "true" || lower == "1" || lower == "yes" || lower == "on";
}

bool ConfigYamlParser::IsFalsy(const std::string& value)
{
    const std::string lower = VdiBrokerConfig::ToLower(value);
    return lower == "false" || lower == "0" || lower == "no" || lower == "off";
}

bool ConfigYamlParser::IsBridgeUnmanagedToken(const std::string& value)
{
    const std::string lower = VdiBrokerConfig::ToLower(value);
    return lower == "bridge-unmanaged" || lower == "bridge_unmanaged" ||
           lower == "bridge unmanaged" || lower == "unmanaged" || lower == "bridgeunmanaged";
}

void ConfigYamlParser::AppendDeviceEntry(std::vector<std::string>& target,
                                         const std::string& value)
{
    if (value.empty())
        return;

    if (std::find(target.begin(), target.end(), value) != target.end())
        return;

    target.push_back(value);
}

void ConfigYamlParser::ParseInlineDeviceList(const std::string& content,
                                             std::vector<std::string>& target)
{
    if (content.empty())
        return;

    std::string normalized = VdiBrokerConfig::Trim(content);
    if (normalized.empty())
        return;

    if (normalized.front() == '[' && normalized.back() == ']')
        normalized = normalized.substr(1, normalized.size() - 2);

    std::stringstream stream(normalized);
    std::string token;
    bool parsedAny = false;
    while (std::getline(stream, token, ','))
    {
        const std::string candidate = VdiBrokerConfig::Trim(token);
        if (candidate.empty())
            continue;
        AppendDeviceEntry(target, candidate);
        parsedAny = true;
    }

    if (!parsedAny)
        AppendDeviceEntry(target, normalized);
}

} // namespace vdi
