#include "vdi_broker_config.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

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
    : configPath_(), podmanImage_(), driDevice_(), homePath_(), shadowPath_(), groupPath_(),
      passwdPath_(), pamPath_(), pamServiceName_(kDefaultPamService), dockerfilePath_(),
      rdpUsername_(), rdpPassword_(), hasLastWrite_(false), loaded_(false), reloaded_(false)
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

std::string VdiBrokerConfig::DriDevice() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return driDevice_;
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
    driDevice_ = "/dev/dri/renderD128";
    homePath_ = "/home";
    shadowPath_ = "/etc/shadow";
    groupPath_ = "/etc/group";
    passwdPath_ = "/etc/passwd";
    pamPath_ = "/etc/pam.d/vdi-broker";
    pamServiceName_ = ResolvePamService(pamPath_);
    dockerfilePath_.clear();
    rdpUsername_ = "rdp";
    rdpPassword_ = "rdp";
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
    std::istringstream stream(content);
    std::string line;

    while (std::getline(stream, line))
    {
        std::string trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#')
            continue;

        const auto pos = trimmed.find(':');
        if (pos == std::string::npos)
            continue;

        std::string key = Trim(trimmed.substr(0, pos));
        std::string value = Trim(trimmed.substr(pos + 1));

        const auto comment = value.find('#');
        if (comment != std::string::npos)
            value = Trim(value.substr(0, comment));

        value = StripQuotes(value);
        const std::string normalized = ToLower(key);

        if (normalized == "podman_image")
        {
            if (!value.empty())
                podmanImage_ = value;
        }
        else if (normalized == "dri_device" || normalized == "dri_render_device")
        {
            if (!value.empty())
                driDevice_ = value;
        }
        else if (normalized == "home_path" || normalized == "home_directory_path" ||
                 normalized == "home_dir")
        {
            if (!value.empty())
                homePath_ = value;
        }
        else if (normalized == "shadow_path")
        {
            if (!value.empty())
                shadowPath_ = value;
        }
        else if (normalized == "group_path")
        {
            if (!value.empty())
                groupPath_ = value;
        }
        else if (normalized == "passwd_path" || normalized == "password_path")
        {
            if (!value.empty())
                passwdPath_ = value;
        }
        else if (normalized == "pam_path" || normalized == "pam_config_path")
        {
            if (!value.empty())
            {
                pamPath_ = value;
                pamServiceName_ = ResolvePamService(pamPath_);
            }
        }
        else if (normalized == "dockerfile_path")
        {
            dockerfilePath_ = value;
        }
        else if (normalized == "rdp_username")
        {
            if (!value.empty())
                rdpUsername_ = value;
        }
        else if (normalized == "rdp_password")
        {
            if (!value.empty())
                rdpPassword_ = value;
        }
    }

    pamServiceName_ = ResolvePamService(pamPath_);
    return true;
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

VdiBrokerConfig& Config()
{
    return VdiBrokerConfig::Instance();
}

} // namespace vdi
