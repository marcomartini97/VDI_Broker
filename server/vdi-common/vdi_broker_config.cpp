#include "vdi_broker_config.h"

#include "vdi_broker_config_parser.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <limits>

namespace
{
constexpr char kDefaultConfigPath[] = "/etc/vdi/vdi_broker.yaml";
constexpr char kEnvConfigPath[] = "VDI_BROKER_CONFIG";
constexpr char kDefaultPamService[] = "vdi-broker";
} // namespace

namespace vdi
{

VdiBrokerConfig& VdiBrokerConfig::Instance()
{
    static VdiBrokerConfig instance;
    return instance;
}

VdiBrokerConfig::VdiBrokerConfig()
    : configPath_(), podmanImage_(), homePath_(), shadowPath_(), groupPath_(),
      passwdPath_(), pamPath_(), pamServiceName_(kDefaultPamService), dockerfilePath_(),
      rdpUsername_(), rdpPassword_(), rdpAuthOverride_(false), userImages_(),
      nvidiaGpuEnabled_(false), nvidiaGpuSlot_(0), customMounts_(), driRenderDevices_(),
      driCardDevices_(), globalResourceLimits_(), userResourceLimits_(),
      redirectorBackgroundImage_(), redirectorBackgroundColorBgrx_(0),
      hasLastWrite_(false), loaded_(false), reloaded_(false)
{
    const char* env = std::getenv(kEnvConfigPath);
    if (env && *env)
        configPath_ = env;
    else
        configPath_ = kDefaultConfigPath;

    ApplyDefaultsUnlocked();
}

void VdiBrokerConfig::SetConfigPath(const std::string& path)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (path.empty() || path == configPath_)
        return;

    configPath_ = path;
    hasLastWrite_ = false;
    loaded_ = false;
}

std::string VdiBrokerConfig::ConfigPath() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return configPath_;
}

bool VdiBrokerConfig::Refresh()
{
    std::lock_guard<std::mutex> lock(mutex_);
    bool reloaded = false;

    if (!loaded_)
    {
        ApplyDefaultsUnlocked();
        reloaded = true;
    }

    if (configPath_.empty())
    {
        loaded_ = true;
        hasLastWrite_ = false;
        reloaded_ = reloaded;
        return true;
    }

    std::error_code ec;
    const auto writeTime = std::filesystem::last_write_time(configPath_, ec);
    if (ec)
    {
        if (!loaded_)
        {
            ApplyDefaultsUnlocked();
            reloaded = true;
        }
        hasLastWrite_ = false;
        reloaded_ = reloaded;
        return false;
    }

    if (!hasLastWrite_ || writeTime != lastWrite_ || !loaded_)
    {
        if (!LoadFromFileUnlocked(configPath_))
        {
            ApplyDefaultsUnlocked();
            hasLastWrite_ = false;
            loaded_ = true;
            reloaded_ = true;
            return false;
        }
        lastWrite_ = writeTime;
        hasLastWrite_ = true;
        loaded_ = true;
        reloaded = true;
    }

    reloaded_ = reloaded;
    return true;
}

std::string VdiBrokerConfig::PodmanImage() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return podmanImage_;
}

std::vector<std::string> VdiBrokerConfig::DriRenderDevices() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return driRenderDevices_;
}

std::vector<std::string> VdiBrokerConfig::DriCardDevices() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return driCardDevices_;
}

std::string VdiBrokerConfig::HomePath() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return homePath_;
}

std::string VdiBrokerConfig::ShadowPath() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return shadowPath_;
}

std::string VdiBrokerConfig::GroupPath() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return groupPath_;
}

std::string VdiBrokerConfig::PasswdPath() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return passwdPath_;
}

std::string VdiBrokerConfig::PamPath() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return pamPath_;
}

std::string VdiBrokerConfig::PamServiceName() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return pamServiceName_;
}

std::string VdiBrokerConfig::DockerfilePath() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return dockerfilePath_;
}

std::string VdiBrokerConfig::RdpUsername() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return rdpUsername_;
}

std::string VdiBrokerConfig::RdpPassword() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return rdpPassword_;
}

bool VdiBrokerConfig::RdpAuthOverrideEnabled() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return rdpAuthOverride_;
}

std::string VdiBrokerConfig::RedirectorBackgroundImage() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return redirectorBackgroundImage_;
}

std::uint32_t VdiBrokerConfig::RedirectorBackgroundColor() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return redirectorBackgroundColorBgrx_;
}

std::string VdiBrokerConfig::PodmanImageForUser(const std::string& username) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    const std::string normalized = ToLower(username);
    const auto it = userImages_.find(normalized);
    if (it != userImages_.end())
        return it->second;
    return podmanImage_;
}

bool VdiBrokerConfig::HasUserImage(const std::string& username) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return userImages_.find(ToLower(username)) != userImages_.end();
}

std::size_t VdiBrokerConfig::UserImageCount() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return userImages_.size();
}

bool VdiBrokerConfig::NvidiaGpuEnabled() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return nvidiaGpuEnabled_;
}

std::uint32_t VdiBrokerConfig::NvidiaGpuSlot() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return nvidiaGpuSlot_;
}

std::vector<VdiBrokerConfig::Mount> VdiBrokerConfig::CustomMounts() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return customMounts_;
}

std::size_t VdiBrokerConfig::CustomMountCount() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return customMounts_.size();
}

bool VdiBrokerConfig::ConsumeReloadedFlag()
{
    std::lock_guard<std::mutex> lock(mutex_);
    const bool value = reloaded_;
    reloaded_ = false;
    return value;
}

void VdiBrokerConfig::ApplyDefaultsUnlocked()
{
    podmanImage_ = "vdi-gnome";
    homePath_ = "/home";
    shadowPath_ = "/etc/shadow";
    groupPath_ = "/etc/group";
    passwdPath_ = "/etc/passwd";
    pamPath_ = "/etc/pam.d/vdi-broker";
    pamServiceName_ = ResolvePamService(pamPath_);
    dockerfilePath_.clear();
    rdpUsername_ = "rdp";
    rdpPassword_ = "rdp";
    rdpAuthOverride_ = false;
    userImages_.clear();
    nvidiaGpuEnabled_ = false;
    nvidiaGpuSlot_ = 0;
    customMounts_.clear();
    driRenderDevices_.clear();
    driCardDevices_.clear();
    globalResourceLimits_.clear();
    globalResourceLimits_["pids"] = 0;
    userResourceLimits_.clear();
    redirectorBackgroundImage_.clear();
    redirectorBackgroundColorBgrx_ = 0x001D4ED8u;
    podmanNetworkMode_ = PodmanNetworkMode::Bridge;
    podmanNetworkName_ = "vortice-network";
    podmanNetworkInterface_ = "vortice0";
    podmanNetworkParentInterface_.clear();
}

bool VdiBrokerConfig::LoadFromFileUnlocked(const std::string& path)
{
    std::ifstream stream(path);
    if (!stream.is_open())
    {
        std::cerr << "Unable to open configuration file: " << path << std::endl;
        return false;
    }

    std::stringstream buffer;
    buffer << stream.rdbuf();

    ApplyDefaultsUnlocked();

    if (!ParseYamlContentUnlocked(buffer.str()))
        return false;

    return true;
}

bool VdiBrokerConfig::ParseYamlContentUnlocked(const std::string& content)
{
    return ParseBrokerConfigYaml(content, *this);
}

std::unordered_map<std::string, std::int64_t> VdiBrokerConfig::GlobalResourceLimits() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return globalResourceLimits_;
}

std::unordered_map<std::string, std::int64_t>
VdiBrokerConfig::ResourceLimitsForUser(const std::string& username) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_map<std::string, std::int64_t> limits = globalResourceLimits_;
    if (!username.empty())
    {
        const std::string normalized = ToLower(username);
        const auto it = userResourceLimits_.find(normalized);
        if (it != userResourceLimits_.end())
        {
            for (const auto& entry : it->second)
                limits[entry.first] = entry.second;
        }
    }
    return limits;
}

std::size_t VdiBrokerConfig::ResourceLimitUserCount() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return userResourceLimits_.size();
}

VdiBrokerConfig::PodmanNetworkMode VdiBrokerConfig::ActivePodmanNetworkMode() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    switch (podmanNetworkMode_)
    {
        case PodmanNetworkMode::None:
            return PodmanNetworkMode::None;
        case PodmanNetworkMode::MacVlan:
            return podmanNetworkParentInterface_.empty() ? PodmanNetworkMode::Bridge
                                                         : PodmanNetworkMode::MacVlan;
        case PodmanNetworkMode::BridgeUnmanaged:
            return PodmanNetworkMode::BridgeUnmanaged;
        case PodmanNetworkMode::Bridge:
        default:
            return PodmanNetworkMode::Bridge;
    }
}

std::string VdiBrokerConfig::PodmanNetworkName() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return podmanNetworkName_;
}

std::string VdiBrokerConfig::PodmanNetworkInterface() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return podmanNetworkInterface_;
}

std::string VdiBrokerConfig::PodmanNetworkParentInterface() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return podmanNetworkParentInterface_;
}

std::string VdiBrokerConfig::ResolvePamService(const std::string& pamPath) const
{
    if (pamPath.empty())
        return kDefaultPamService;

    std::filesystem::path path(pamPath);
    const std::string name = path.filename().string();
    if (name.empty())
        return kDefaultPamService;
    return name;
}

std::string VdiBrokerConfig::Trim(const std::string& value)
{
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string VdiBrokerConfig::StripQuotes(const std::string& value)
{
    if (value.size() >= 2)
    {
        const char front = value.front();
        const char back = value.back();
        if ((front == '"' && back == '"') || (front == '\'' && back == '\''))
            return value.substr(1, value.size() - 2);
    }
    return value;
}

std::string VdiBrokerConfig::ToLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::uint32_t VdiBrokerConfig::ParseColorBgrx(const std::string& value, std::uint32_t fallback)
{
    std::string trimmed = Trim(StripQuotes(value));
    if (trimmed.empty())
        return fallback;

    int base = 10;
    if (trimmed.rfind("0x", 0) == 0 || trimmed.rfind("0X", 0) == 0)
    {
        base = 16;
        trimmed = trimmed.substr(2);
    }
    else if (!trimmed.empty() && trimmed.front() == '#')
    {
        base = 16;
        trimmed = trimmed.substr(1);
    }

    try
    {
        unsigned long parsed = std::stoul(trimmed, nullptr, base);
        if (base == 10 && parsed <= 255UL)
        {
            const std::uint8_t component = static_cast<std::uint8_t>(parsed & 0xFFu);
            return static_cast<std::uint32_t>(component) |
                   (static_cast<std::uint32_t>(component) << 8) |
                   (static_cast<std::uint32_t>(component) << 16);
        }

        parsed = std::min(parsed, 0xFFFFFFul);
        const std::uint8_t r = static_cast<std::uint8_t>((parsed >> 16) & 0xFFu);
        const std::uint8_t g = static_cast<std::uint8_t>((parsed >> 8) & 0xFFu);
        const std::uint8_t b = static_cast<std::uint8_t>(parsed & 0xFFu);
        return static_cast<std::uint32_t>(b) | (static_cast<std::uint32_t>(g) << 8) |
               (static_cast<std::uint32_t>(r) << 16);
    }
    catch (...)
    {
        return fallback;
    }
}

VdiBrokerConfig& Config()
{
    return VdiBrokerConfig::Instance();
}

} // namespace vdi
