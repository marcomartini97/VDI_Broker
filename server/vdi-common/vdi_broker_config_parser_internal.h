#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace vdi
{
class VdiBrokerConfig;

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
    bool ProcessNetworkLine(std::string trimmed);
    void ProcessTopLevelLine(const std::string& trimmed);
    void HandleTopLevelEntry(const std::string& key, const std::string& value);
    void StartUserImagesBlock();
    void StartCustomMountsBlock();
    void StartResourceLimitsBlock();
    void StartResourceLimitsUsersSection();
    void StartResourceLimitsGlobalSection();
    void StartDriRenderDevicesBlock();
    void StartDriCardDevicesBlock();
    void StartNetworkBlock();
    void FlushUserImage();
    void FlushCustomMount();
    void FlushResourceLimitUser();
    void FlushPending();

    static bool ShouldStartBlock(const std::string& value);
    static std::string RemoveCommentAndStrip(const std::string& value);
    static bool IsTruthy(const std::string& value);
    static bool IsFalsy(const std::string& value);
    static bool IsBridgeUnmanagedToken(const std::string& value);
    static void AppendDeviceEntry(std::vector<std::string>& target, const std::string& value);
    static void ParseInlineDeviceList(const std::string& content, std::vector<std::string>& target);

    VdiBrokerConfig& config_;
    bool inUserImagesBlock_ = false;
    bool inCustomMountsBlock_ = false;
    bool inResourceLimitsBlock_ = false;
    bool inDriRenderDevicesBlock_ = false;
    bool inDriCardDevicesBlock_ = false;
    bool inNetworkBlock_ = false;
    bool macVlanParentRequired_ = false;
    ResourceSection resourceSection_ = ResourceSection::None;
    std::string currentUser_;
    std::string currentImage_;
    std::string currentMountSource_;
    std::string currentMountDestination_;
    bool currentMountReadOnly_ = false;
    std::string currentResourceLimitUser_;
    std::unordered_map<std::string, std::int64_t> currentUserResourceLimits_;
};

} // namespace vdi
