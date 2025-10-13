#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace vdi
{
namespace vortice
{

constexpr const char* kDefaultSocketPath = "/tmp/vortice.sock";
constexpr const char* kDefaultEndpoint = "unix:/tmp/vortice.sock";

enum class EndpointType
{
	Unix,
	Tcp
};

struct Endpoint
{
	EndpointType type = EndpointType::Unix;
	std::string path;
	std::string host;
	std::uint16_t port = 0;
};

enum class MessageType
{
	Hello,
	HelloResponse,
	Redirect,
	Ack,
	Unknown
};

struct HelloMessage
{
	std::string role;
};

struct HelloResponseMessage
{
	std::string role;
	std::string proxyHost;
	std::uint16_t proxyPort = 0;
};

struct RedirectMessage
{
	std::string username;
	std::string password;
	std::string targetHost;
	std::uint16_t targetPort = 0;
	std::string targetUsername;
	std::string targetPassword;
};

struct AckMessage
{
	bool success = false;
	std::string error;
};

struct Message
{
	MessageType type = MessageType::Unknown;
	HelloMessage hello;
	HelloResponseMessage helloResponse;
	RedirectMessage redirect;
	AckMessage ack;
};

bool EncodeMessage(const Message& message, std::string& encoded);
bool DecodeMessage(const std::string& encoded, Message& message);

bool SendMessage(int fd, const Message& message);
bool ReceiveMessage(int fd, Message& message, std::size_t maxPayload = 16384);

bool ParseEndpoint(const std::string& value, Endpoint& endpoint);
std::string EndpointToString(const Endpoint& endpoint);

} // namespace vortice
} // namespace vdi
