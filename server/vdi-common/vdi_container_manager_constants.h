#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace vdi
{
inline constexpr char kPodmanSocket[] = "/var/run/podman/podman.sock";
inline const std::string kPodmanApiBase = "http://d/v5.3.0/libpod/containers/";
inline const std::string kPodmanExecBase = "http://d/v5.3.0/libpod/exec/";
inline const std::string kPodmanBuildEndpoint = "http://d/v5.3.0/libpod/build";
inline constexpr char kSessionLogPath[] = "/var/log/vortice/gnome-vdi-session.log";
inline constexpr char kSessionJsonPattern[] =
    R"(\{"ip":"[^"]+","username":"[^"]+","password":"[^"]+"\})";
inline constexpr int kProcessCheckAttempts = 20;
inline constexpr std::chrono::seconds kReadinessPollInterval{1};
inline constexpr std::chrono::seconds kPortReadyTimeout{30};
inline constexpr std::uint16_t kRdpPort = 3389;
} // namespace vdi
