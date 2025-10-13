#include "vdi_vortice_protocol.h"

#include "vdi_logging.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <string_view>
#include <unordered_map>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <arpa/inet.h>

namespace vdi
{
namespace vortice
{
namespace
{

std::string json_escape(std::string_view value)
{
	std::string escaped;
	escaped.reserve(value.size());
	for (unsigned char ch : value)
	{
		switch (ch)
		{
			case '\\':
				escaped.append("\\\\");
				break;
			case '"':
				escaped.append("\\\"");
				break;
			case '\b':
				escaped.append("\\b");
				break;
			case '\f':
				escaped.append("\\f");
				break;
			case '\n':
				escaped.append("\\n");
				break;
			case '\r':
				escaped.append("\\r");
				break;
			case '\t':
				escaped.append("\\t");
				break;
			default:
				if (ch < 0x20)
				{
					static constexpr char hex[] = "0123456789abcdef";
					escaped.append("\\u00");
					escaped.push_back(hex[(ch >> 4) & 0x0F]);
					escaped.push_back(hex[ch & 0x0F]);
				}
				else
				{
					escaped.push_back(static_cast<char>(ch));
				}
				break;
		}
	}
	return escaped;
}

bool parse_hex_digit(char ch, int& value)
{
	if (ch >= '0' && ch <= '9')
	{
		value = ch - '0';
		return true;
	}
	if (ch >= 'a' && ch <= 'f')
	{
		value = 10 + (ch - 'a');
		return true;
	}
	if (ch >= 'A' && ch <= 'F')
	{
		value = 10 + (ch - 'A');
		return true;
	}
	return false;
}

bool json_unescape(std::string_view value, std::string& out)
{
	out.clear();
	out.reserve(value.size());

	for (size_t i = 0; i < value.size(); ++i)
	{
		char ch = value[i];
		if (ch != '\\')
		{
			out.push_back(ch);
			continue;
		}

		if (++i >= value.size())
			return false;

		ch = value[i];
		switch (ch)
		{
			case '\\':
			case '"':
			case '/':
				out.push_back(ch);
				break;
			case 'b':
				out.push_back('\b');
				break;
			case 'f':
				out.push_back('\f');
				break;
			case 'n':
				out.push_back('\n');
				break;
			case 'r':
				out.push_back('\r');
				break;
			case 't':
				out.push_back('\t');
				break;
			case 'u':
			{
				if (i + 4 >= value.size())
					return false;
				int accum = 0;
				for (size_t j = 0; j < 4; ++j)
				{
					int digit = 0;
					if (!parse_hex_digit(value[i + 1 + j], digit))
						return false;
					accum = (accum << 4) | digit;
				}
				i += 4;
				if (accum <= 0x7F)
				{
					out.push_back(static_cast<char>(accum));
				}
				else
				{
					// Only basic multilingual plane handling required for our use-case.
					char utf8[4] = { 0 };
					std::size_t count = 0;
					if (accum <= 0x7FF)
					{
						utf8[0] = static_cast<char>(0xC0 | ((accum >> 6) & 0x1F));
						utf8[1] = static_cast<char>(0x80 | (accum & 0x3F));
						count = 2;
					}
					else
					{
						utf8[0] = static_cast<char>(0xE0 | ((accum >> 12) & 0x0F));
						utf8[1] = static_cast<char>(0x80 | ((accum >> 6) & 0x3F));
						utf8[2] = static_cast<char>(0x80 | (accum & 0x3F));
						count = 3;
					}
					out.append(utf8, utf8 + count);
				}
				break;
			}
			default:
				return false;
		}
	}
	return true;
}

void skip_whitespace(const std::string& json, size_t& pos)
{
	while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])))
		++pos;
}

bool parse_string_token(const std::string& json, size_t& pos, std::string& value)
{
	if (pos >= json.size() || json[pos] != '"')
		return false;

	++pos;
	size_t start = pos;
	std::string raw;

	while (pos < json.size())
	{
		char ch = json[pos];
		if (ch == '\\')
		{
			if (pos + 1 >= json.size())
				return false;
			pos += 2;
			continue;
		}
		if (ch == '"')
		{
			raw.assign(json.begin() + static_cast<std::ptrdiff_t>(start),
			           json.begin() + static_cast<std::ptrdiff_t>(pos));
			++pos;
			return json_unescape(raw, value);
		}
		++pos;
	}
	return false;
}

bool parse_number_token(const std::string& json, size_t& pos, std::uint32_t& value)
{
	size_t start = pos;
	while (pos < json.size() &&
	       (std::isdigit(static_cast<unsigned char>(json[pos])) || json[pos] == '+'))
	{
		++pos;
	}
	if (start == pos)
		return false;

	const std::string token = json.substr(start, pos - start);
	try
	{
		value = static_cast<std::uint32_t>(std::stoul(token));
	}
	catch (const std::exception&)
	{
		return false;
	}
	return true;
}

bool parse_boolean_token(const std::string& json, size_t& pos, bool& value)
{
	static constexpr std::string_view kTrue = "true";
	static constexpr std::string_view kFalse = "false";

	if (json.compare(pos, kTrue.size(), kTrue.data(), kTrue.size()) == 0)
	{
		value = true;
		pos += kTrue.size();
		return true;
	}
	if (json.compare(pos, kFalse.size(), kFalse.data(), kFalse.size()) == 0)
	{
		value = false;
		pos += kFalse.size();
		return true;
	}
	return false;
}

struct ParsedObject
{
	std::unordered_map<std::string, std::string> strings;
	std::unordered_map<std::string, std::uint32_t> numbers;
	std::unordered_map<std::string, bool> booleans;
};

bool parse_json_object(const std::string& json, ParsedObject& result)
{
	size_t pos = 0;
	skip_whitespace(json, pos);
	if (pos >= json.size() || json[pos] != '{')
		return false;
	++pos;

	while (true)
	{
		skip_whitespace(json, pos);
		if (pos >= json.size())
			return false;
		if (json[pos] == '}')
		{
			++pos;
			break;
		}

		std::string key;
		if (!parse_string_token(json, pos, key))
			return false;
		skip_whitespace(json, pos);
		if (pos >= json.size() || json[pos] != ':')
			return false;
		++pos;
		skip_whitespace(json, pos);
		if (pos >= json.size())
			return false;

		if (json[pos] == '"')
		{
			std::string value;
			if (!parse_string_token(json, pos, value))
				return false;
			result.strings.emplace(std::move(key), std::move(value));
		}
		else if (std::isdigit(static_cast<unsigned char>(json[pos])) || json[pos] == '+')
		{
			std::uint32_t number = 0;
			if (!parse_number_token(json, pos, number))
				return false;
			result.numbers.emplace(std::move(key), number);
		}
		else if (json[pos] == 't' || json[pos] == 'f')
		{
			bool boolean = false;
			if (!parse_boolean_token(json, pos, boolean))
				return false;
			result.booleans.emplace(std::move(key), boolean);
		}
		else
		{
			return false;
		}

		skip_whitespace(json, pos);
		if (pos >= json.size())
			return false;
		if (json[pos] == ',')
		{
			++pos;
			continue;
		}
		if (json[pos] == '}')
		{
			++pos;
			break;
		}
		return false;
	}

	skip_whitespace(json, pos);
	return pos == json.size();
}

bool send_all(int fd, const void* buffer, std::size_t length)
{
	const auto* data = static_cast<const std::uint8_t*>(buffer);
	std::size_t total = 0;
	while (total < length)
	{
		ssize_t sent = ::send(fd, data + total, length - total, 0);
		if (sent < 0)
		{
			if (errno == EINTR)
				continue;
			return false;
		}
		if (sent == 0)
			return false;
		total += static_cast<std::size_t>(sent);
	}
	return true;
}

bool recv_all(int fd, void* buffer, std::size_t length)
{
	auto* data = static_cast<std::uint8_t*>(buffer);
	std::size_t total = 0;
	while (total < length)
	{
		ssize_t received = ::recv(fd, data + total, length - total, 0);
		if (received < 0)
		{
			if (errno == EINTR)
				continue;
			return false;
		}
		if (received == 0)
			return false;
		total += static_cast<std::size_t>(received);
	}
	return true;
}

} // namespace

bool EncodeMessage(const Message& message, std::string& encoded)
{
	switch (message.type)
	{
		case MessageType::Hello:
			encoded = "{\"type\":\"hello\",\"role\":\"" + json_escape(message.hello.role) + "\"}";
			return true;
		case MessageType::HelloResponse:
		{
			encoded = "{\"type\":\"hello_response\",\"role\":\"" +
			          json_escape(message.helloResponse.role) + "\",\"proxy_ip\":\"" +
			          json_escape(message.helloResponse.proxyHost) + "\",\"proxy_port\":" +
			          std::to_string(message.helloResponse.proxyPort) + "}";
			return true;
		}
		case MessageType::Redirect:
		{
			encoded =
			    "{\"type\":\"redirect\",\"username\":\"" + json_escape(message.redirect.username) +
			    "\",\"password\":\"" + json_escape(message.redirect.password) +
			    "\",\"target_ip\":\"" + json_escape(message.redirect.targetHost) +
			    "\",\"target_port\":" + std::to_string(message.redirect.targetPort) +
			    ",\"rdp_username\":\"" + json_escape(message.redirect.targetUsername) +
			    "\",\"rdp_password\":\"" + json_escape(message.redirect.targetPassword) + "\"}";
			return true;
		}
		case MessageType::Ack:
		{
			encoded = "{\"type\":\"ack\",\"success\":" + std::string(message.ack.success ? "true" : "false");
			if (!message.ack.error.empty())
				encoded += ",\"error\":\"" + json_escape(message.ack.error) + "\"";
			encoded += "}";
			return true;
		}
		case MessageType::Unknown:
			return false;
	}

	return false;
}

bool DecodeMessage(const std::string& encoded, Message& message)
{
	ParsedObject obj;
	if (!parse_json_object(encoded, obj))
		return false;

	auto typeIt = obj.strings.find("type");
	if (typeIt == obj.strings.end())
		return false;

	const std::string& type = typeIt->second;
	if (type == "hello")
	{
		message.type = MessageType::Hello;
		auto roleIt = obj.strings.find("role");
		if (roleIt == obj.strings.end())
			return false;
		message.hello.role = roleIt->second;
		return true;
	}
	if (type == "hello_response")
	{
		message.type = MessageType::HelloResponse;
		auto roleIt = obj.strings.find("role");
		auto hostIt = obj.strings.find("proxy_ip");
		auto portIt = obj.numbers.find("proxy_port");
		if (roleIt == obj.strings.end() || hostIt == obj.strings.end() || portIt == obj.numbers.end())
			return false;
		message.helloResponse.role = roleIt->second;
		message.helloResponse.proxyHost = hostIt->second;
		message.helloResponse.proxyPort = static_cast<std::uint16_t>(portIt->second);
		return true;
	}
	if (type == "redirect")
	{
		message.type = MessageType::Redirect;
		auto userIt = obj.strings.find("username");
		auto passIt = obj.strings.find("password");
		auto hostIt = obj.strings.find("target_ip");
		auto portIt = obj.numbers.find("target_port");
		auto rdpUserIt = obj.strings.find("rdp_username");
		auto rdpPassIt = obj.strings.find("rdp_password");
		if (userIt == obj.strings.end() || passIt == obj.strings.end() || hostIt == obj.strings.end() ||
		    portIt == obj.numbers.end() || rdpUserIt == obj.strings.end() ||
		    rdpPassIt == obj.strings.end())
		{
			return false;
		}
		message.redirect.username = userIt->second;
		message.redirect.password = passIt->second;
		message.redirect.targetHost = hostIt->second;
		message.redirect.targetPort = static_cast<std::uint16_t>(portIt->second);
		message.redirect.targetUsername = rdpUserIt->second;
		message.redirect.targetPassword = rdpPassIt->second;
		return true;
	}
	if (type == "ack")
	{
		message.type = MessageType::Ack;
		bool success = false;
		auto successIt = obj.booleans.find("success");
		if (successIt == obj.booleans.end())
			return false;
		message.ack.success = successIt->second;
		auto errorIt = obj.strings.find("error");
		message.ack.error = (errorIt != obj.strings.end()) ? errorIt->second : std::string();
		return true;
	}

	message.type = MessageType::Unknown;
	return false;
}

bool SendMessage(int fd, const Message& message)
{
	std::string payload;
	if (!EncodeMessage(message, payload))
		return false;

	const std::uint32_t length = static_cast<std::uint32_t>(payload.size());
	const std::uint32_t header = htonl(length);

	if (!send_all(fd, &header, sizeof(header)))
		return false;
	return send_all(fd, payload.data(), payload.size());
}

bool ReceiveMessage(int fd, Message& message, std::size_t maxPayload)
{
	std::uint32_t header = 0;
	if (!recv_all(fd, &header, sizeof(header)))
		return false;

	const std::uint32_t length = ntohl(header);
	if (length == 0 || length > maxPayload)
		return false;

	std::string payload(length, '\0');
	if (!recv_all(fd, payload.data(), length))
		return false;

	return DecodeMessage(payload, message);
}

bool ParseEndpoint(const std::string& value, Endpoint& endpoint)
{
	endpoint = Endpoint{};
	if (value.empty())
		return false;

	std::string working = value;
	auto to_lower = [](char ch) { return static_cast<char>(std::tolower(static_cast<unsigned char>(ch))); };
	auto starts_with_case = [&](std::string_view prefix) {
		if (working.size() < prefix.size())
			return false;
		for (size_t i = 0; i < prefix.size(); ++i)
		{
			if (to_lower(working[i]) != prefix[i])
				return false;
		}
		return true;
	};

	bool indicatedTcp = false;
	bool indicatedUnix = false;

	if (starts_with_case("tcp://"))
	{
		working.erase(0, 6);
		indicatedTcp = true;
	}
	else if (starts_with_case("tcp:"))
	{
		working.erase(0, 4);
		indicatedTcp = true;
	}

	if (starts_with_case("unix://"))
	{
		working.erase(0, 7);
		indicatedUnix = true;
	}
	else if (starts_with_case("unix:"))
	{
		working.erase(0, 5);
		indicatedUnix = true;
	}

	if (indicatedTcp)
		endpoint.type = EndpointType::Tcp;
	else if (indicatedUnix)
		endpoint.type = EndpointType::Unix;
	else if (value.find('/') != std::string::npos)
		endpoint.type = EndpointType::Unix;
	else if (value.rfind("tcp", 0) == 0)
		endpoint.type = EndpointType::Tcp;
	else
	{
		// Guess based on colon count.
		endpoint.type = (value.find(':') != std::string::npos) ? EndpointType::Tcp : EndpointType::Unix;
	}

	if (endpoint.type == EndpointType::Unix)
	{
		std::string path = indicatedUnix ? working : value;
		if (path.empty())
			return false;
		endpoint.path = path;
		return true;
	}

	// TCP parsing
	std::string tcpSpec = indicatedTcp ? working : value;
	const auto colonPos = tcpSpec.rfind(':');
	if (colonPos == std::string::npos || colonPos == 0 || colonPos + 1 >= tcpSpec.size())
		return false;

	std::string host = tcpSpec.substr(0, colonPos);
	std::string portStr = tcpSpec.substr(colonPos + 1);
	if (host.empty())
		host = "0.0.0.0";

	std::uint32_t port = 0;
	try
	{
		port = static_cast<std::uint32_t>(std::stoul(portStr));
	}
	catch (const std::exception&)
	{
		return false;
	}

	if (port == 0 || port > 65535)
		return false;

	endpoint.type = EndpointType::Tcp;
	endpoint.host = host;
	endpoint.port = static_cast<std::uint16_t>(port);
	return true;
}

std::string EndpointToString(const Endpoint& endpoint)
{
	if (endpoint.type == EndpointType::Unix)
	{
		return std::string("unix:") + endpoint.path;
	}
	return "tcp:" + endpoint.host + ":" + std::to_string(endpoint.port);
}

} // namespace vortice
} // namespace vdi
