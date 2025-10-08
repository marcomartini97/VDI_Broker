#include "vdi_broker_config.h"

#include "vdi_logging.h"

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
class ConfigYamlParser
{
public:
    explicit ConfigYamlParser(VdiBrokerConfig& config);

    bool Parse(const std::string& content);

private:
    enum class ResourceSection
    {
        None,
        Global,
        Users
    };

    void ProcessLine(const std::string& line);
    void ResetBlocksForTopLevel(const std::string& trimmed);
    bool HandleBlockLine(const std::string& trimmed, bool isTopLevel);
    bool ProcessResourceLimitsLine(const std::string& trimmed);
    bool ProcessUserResourceLimitLine(std::string trimmed);
    bool ProcessGlobalResourceLimitLine(const std::string& trimmed);
    bool ProcessUserImagesLine(std::string trimmed);
    bool ProcessCustomMountsLine(std::string trimmed);
    bool ProcessDriDevicesLine(std::string trimmed, std::vector<std::string>& target);
    void ProcessTopLevelLine(const std::string& trimmed);
    void HandleTopLevelEntry(const std::string& key, const std::string& value);
    void StartUserImagesBlock();
    void StartCustomMountsBlock();
    void StartResourceLimitsBlock();
    void StartResourceLimitsUsersSection();
    void StartResourceLimitsGlobalSection();
    void StartDriRenderDevicesBlock();
    void StartDriCardDevicesBlock();
    void FlushUserImage();
    void FlushCustomMount();
    void FlushResourceLimitUser();
    void FlushPending();

    static bool ShouldStartBlock(const std::string& value);
    static std::string RemoveCommentAndStrip(const std::string& value);
    static bool IsTruthy(const std::string& value);
    static bool IsFalsy(const std::string& value);
    static void AppendDeviceEntry(std::vector<std::string>& target, const std::string& value);
    static void ParseInlineDeviceList(const std::string& content, std::vector<std::string>& target);

    VdiBrokerConfig& config_;
    bool inUserImagesBlock_ = false;
    bool inCustomMountsBlock_ = false;
    bool inResourceLimitsBlock_ = false;
    bool inDriRenderDevicesBlock_ = false;
    bool inDriCardDevicesBlock_ = false;
    ResourceSection resourceSection_ = ResourceSection::None;
    std::string currentUser_;
    std::string currentImage_;
    std::string currentMountSource_;
    std::string currentMountDestination_;
    bool currentMountReadOnly_ = false;
    std::string currentResourceLimitUser_;
    std::unordered_map<std::string, std::int64_t> currentUserResourceLimits_;
};

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
}

bool ConfigYamlParser::HandleBlockLine(const std::string& trimmed, bool isTopLevel)
{
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

VdiBrokerConfig& VdiBrokerConfig::Instance()
{
    static VdiBrokerConfig instance;
    return instance;
}

VdiBrokerConfig::VdiBrokerConfig()
    : configPath_(), podmanImage_(), homePath_(), shadowPath_(), groupPath_(),
      passwdPath_(), pamPath_(), pamServiceName_(kDefaultPamService), dockerfilePath_(),
      rdpUsername_(), rdpPassword_(), userImages_(), nvidiaGpuEnabled_(false),
      nvidiaGpuSlot_(0), customMounts_(), driRenderDevices_(), driCardDevices_(),
      globalResourceLimits_(), userResourceLimits_(), redirectorBackgroundImage_(),
      redirectorBackgroundColorBgrx_(0),
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
    ConfigYamlParser parser(*this);
    return parser.Parse(content);
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
