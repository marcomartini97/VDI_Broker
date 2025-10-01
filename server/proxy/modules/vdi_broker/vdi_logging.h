#pragma once

#include <chrono>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

#include <winpr/wlog.h>

namespace vdi
{
namespace logging
{
enum class LogLevel
{
	Info,
	Warn,
	Error
};

inline std::string& CurrentUserStorage()
{
	thread_local std::string currentUser = "system";
	return currentUser;
}

inline void SetCurrentUser(std::string user)
{
	if (user.empty())
		user = "system";
	CurrentUserStorage() = std::move(user);
}

inline std::string GetCurrentUser()
{
	return CurrentUserStorage();
}

class ScopedLogUser
{
public:
	explicit ScopedLogUser(std::string user) : previous_(GetCurrentUser())
	{
		SetCurrentUser(std::move(user));
	}

	~ScopedLogUser()
	{
		SetCurrentUser(std::move(previous_));
	}

private:
	std::string previous_;
};

inline std::string SanitizeForFile(std::string value)
{
	if (value.empty())
		return "system";

	for (char& ch : value)
	{
		if (!(std::isalnum(static_cast<unsigned char>(ch)) || ch == '-' || ch == '_'))
			ch = '_';
	}

	return value;
}

inline std::string MakeTimestamp()
{
	const auto now = std::chrono::system_clock::now();
	const auto time = std::chrono::system_clock::to_time_t(now);
	std::tm tm{};
	#if defined(_WIN32)
	localtime_s(&tm, &time);
	#else
	localtime_r(&time, &tm);
	#endif

	std::ostringstream oss;
	oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
	return oss.str();
}

inline const char* LevelString(LogLevel level)
{
	switch (level)
	{
		case LogLevel::Info:
			return "INFO";
		case LogLevel::Warn:
			return "WARN";
		case LogLevel::Error:
			return "ERROR";
	}
	return "UNKNOWN";
}

inline void AppendLogsToFiles(const std::string& user, LogLevel level, const std::string& message)
{
	static std::mutex logMutex;
	std::lock_guard<std::mutex> lock(logMutex);

	const std::filesystem::path root{"/var/log/vdi-broker"};
	const std::filesystem::path globalLog = root / "connections.log";
	const std::filesystem::path userLog = root /
	                                     ("session_" + SanitizeForFile(user) + ".log");

	std::error_code ec;
	std::filesystem::create_directories(root, ec);

	const std::string timestamp = MakeTimestamp();
	const std::string line = timestamp + " [" + LevelString(level) + "] [user=" + user + "] " +
	                         message + '\n';

	std::ofstream globalStream(globalLog, std::ios::app);
	if (globalStream.is_open())
		globalStream << line;

	std::ofstream userStream(userLog, std::ios::app);
	if (userStream.is_open())
		userStream << line;
}

inline std::string FormatMessage(const char* fmt, va_list args)
{
	va_list copy;
	va_copy(copy, args);
	const int needed = std::vsnprintf(nullptr, 0, fmt, copy);
	va_end(copy);
	if (needed <= 0)
		return {};

	std::string buffer(static_cast<size_t>(needed) + 1, '\0');
	std::vsnprintf(buffer.data(), buffer.size(), fmt, args);
	buffer.resize(static_cast<size_t>(needed));
	return buffer;
}

inline void LogMessage(const char* tag, LogLevel level, const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	const std::string formatted = FormatMessage(fmt, args);
	va_end(args);

	const std::string user = GetCurrentUser();
	const std::string finalMessage = "[user=" + user + "] " + formatted;

	switch (level)
	{
		case LogLevel::Info:
			WLog_INFO(tag, "%s", finalMessage.c_str());
			break;
		case LogLevel::Warn:
			WLog_WARN(tag, "%s", finalMessage.c_str());
			break;
		case LogLevel::Error:
			WLog_ERR(tag, "%s", finalMessage.c_str());
			break;
	}

	AppendLogsToFiles(user, level, formatted);
}

} // namespace logging
} // namespace vdi

#define VDI_LOG_INFO(tag, fmt, ...) \
	::vdi::logging::LogMessage(tag, ::vdi::logging::LogLevel::Info, fmt, ##__VA_ARGS__)

#define VDI_LOG_WARN(tag, fmt, ...) \
	::vdi::logging::LogMessage(tag, ::vdi::logging::LogLevel::Warn, fmt, ##__VA_ARGS__)

#define VDI_LOG_ERROR(tag, fmt, ...) \
	::vdi::logging::LogMessage(tag, ::vdi::logging::LogLevel::Error, fmt, ##__VA_ARGS__)
