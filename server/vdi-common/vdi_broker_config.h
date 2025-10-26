#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace vdi
{
class ConfigYamlParser;

class VdiBrokerConfig
{
public:
    struct Mount
    {
        std::string source;
        std::string destination;
        bool readOnly;
    };

    enum class PodmanNetworkMode
    {
        None,
        Bridge,
        BridgeUnmanaged,
        MacVlan
    };

    static VdiBrokerConfig& Instance();

    void SetConfigPath(const std::string& path);
    std::string ConfigPath() const;

    bool Refresh();
    bool ConsumeReloadedFlag();

    std::string PodmanImage() const;
    std::vector<std::string> DriRenderDevices() const;
    std::vector<std::string> DriCardDevices() const;
    std::string HomePath() const;
    std::string ShadowPath() const;
    std::string GroupPath() const;
    std::string PasswdPath() const;
    std::string PamPath() const;
    std::string PamServiceName() const;
    std::string DockerfilePath() const;
    std::string RdpUsername() const;
    std::string RdpPassword() const;
    std::string RedirectorBackgroundImage() const;
    std::uint32_t RedirectorBackgroundColor() const;
    std::string PodmanImageForUser(const std::string& username) const;
    bool HasUserImage(const std::string& username) const;
    std::size_t UserImageCount() const;
    bool NvidiaGpuEnabled() const;
    std::uint32_t NvidiaGpuSlot() const;
    std::vector<Mount> CustomMounts() const;
    std::size_t CustomMountCount() const;
    std::unordered_map<std::string, std::int64_t> GlobalResourceLimits() const;
    std::unordered_map<std::string, std::int64_t>
    ResourceLimitsForUser(const std::string& username) const;
    std::size_t ResourceLimitUserCount() const;
    PodmanNetworkMode ActivePodmanNetworkMode() const;
    std::string PodmanNetworkName() const;
    std::string PodmanNetworkInterface() const;
    std::string PodmanNetworkParentInterface() const;

private:
    VdiBrokerConfig();
    VdiBrokerConfig(const VdiBrokerConfig&) = delete;
    VdiBrokerConfig& operator=(const VdiBrokerConfig&) = delete;

    friend class ConfigYamlParser;

    void ApplyDefaultsUnlocked();
    bool LoadFromFileUnlocked(const std::string& path);
    bool ParseYamlContentUnlocked(const std::string& content);
    std::string ResolvePamService(const std::string& pamPath) const;

    static std::string Trim(const std::string& value);
    static std::string StripQuotes(const std::string& value);
    static std::string ToLower(std::string value);
    static std::uint32_t ParseColorBgrx(const std::string& value, std::uint32_t fallback);

    mutable std::mutex mutex_;
    std::string configPath_;
    std::string podmanImage_;
    std::string homePath_;
    std::string shadowPath_;
    std::string groupPath_;
    std::string passwdPath_;
    std::string pamPath_;
    std::string pamServiceName_;
    std::string dockerfilePath_;
    std::string rdpUsername_;
    std::string rdpPassword_;
    std::unordered_map<std::string, std::string> userImages_;
    bool nvidiaGpuEnabled_;
    std::uint32_t nvidiaGpuSlot_;
    std::vector<Mount> customMounts_;
    std::vector<std::string> driRenderDevices_;
    std::vector<std::string> driCardDevices_;
    std::unordered_map<std::string, std::int64_t> globalResourceLimits_;
    std::unordered_map<std::string, std::unordered_map<std::string, std::int64_t>>
        userResourceLimits_;
    std::string redirectorBackgroundImage_;
    std::uint32_t redirectorBackgroundColorBgrx_;
    PodmanNetworkMode podmanNetworkMode_;
    std::string podmanNetworkName_;
    std::string podmanNetworkInterface_;
    std::string podmanNetworkParentInterface_;
    std::filesystem::file_time_type lastWrite_;
    bool hasLastWrite_;
    bool loaded_;
    bool reloaded_;
};

VdiBrokerConfig& Config();

} // namespace vdi
