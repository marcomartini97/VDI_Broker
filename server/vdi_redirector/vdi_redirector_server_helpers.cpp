#include "vdi_redirector_server_helpers.h"

#include "vdi_logging.h"

#include <freerdp/channels/channels.h>
#include <freerdp/redirection.h>

#include <arpa/inet.h>
#include <cstring>
#include <inttypes.h>
#include <sstream>

#define TAG MODULE_TAG("vdi_redirector")

namespace redirector
{
namespace
{
constexpr uint16_t reverse_bytes16(uint16_t value)
{
	return static_cast<uint16_t>(((value & 0x00FFu) << 8) | ((value & 0xFF00u) >> 8));
}
} // namespace

std::string resolve_client_ip(freerdp_peer* peer)
{
	if (peer && peer->hostname && *peer->hostname)
		return std::string(peer->hostname);
	if (!peer)
		return {};

	sockaddr_in addr{};
	socklen_t len = sizeof(addr);
	if (getpeername(peer->sockfd, reinterpret_cast<sockaddr*>(&addr), &len) != 0)
		return {};
	char buffer[INET_ADDRSTRLEN] = {};
	if (!inet_ntop(AF_INET, &addr.sin_addr, buffer, sizeof(buffer)))
		return {};
	return std::string(buffer);
}

std::optional<std::string> build_routing_token(const std::string& ip, std::uint16_t port)
{
	in_addr addr{};
	if (inet_pton(AF_INET, ip.c_str(), &addr) != 1)
		return std::nullopt;

	std::uint8_t octets[sizeof(addr.s_addr)] = { 0 };
	std::memcpy(octets, &addr.s_addr, sizeof(octets));

	uint32_t ipToken = (static_cast<uint32_t>(octets[3]) << 24) |
	                   (static_cast<uint32_t>(octets[2]) << 16) |
	                   (static_cast<uint32_t>(octets[1]) << 8) |
	                   static_cast<uint32_t>(octets[0]);

	const uint16_t portToken = reverse_bytes16(port);

	std::ostringstream osstoken;
	osstoken << "Cookie: msts=" << ipToken << "." << portToken << ".0000";
	return osstoken.str();
}

BOOL redirection_set_password_option(rdpRedirection* redirection, const std::string& password)
{
	size_t wcharLen = 0;
	WCHAR* wide = ConvertUtf8ToWCharAlloc(password.c_str(), &wcharLen);
	if (!wide)
	{
		VDI_LOG_ERROR(TAG, "Failed to convert password to UTF-16 for redirection");
		return FALSE;
	}

	const size_t bytes = (wcharLen + 1) * sizeof(WCHAR);
	const BOOL ok = redirection_set_byte_option(redirection, LB_PASSWORD,
	                                            reinterpret_cast<const BYTE*>(wide), bytes);
	free(wide);
	return ok;
}

BOOL send_redirection(freerdp_peer* peer, const std::string& targetAddress,
                      const RdpCredentials* credentials, const std::string* routingToken)
{
	rdpRedirection* redirection = redirection_new();
	if (!redirection)
		return FALSE;

	BOOL success = TRUE;
	do
	{
		UINT32 flags = 0;
		flags |= LB_TARGET_NET_ADDRESS;
		if (routingToken && !routingToken->empty())
			flags |= LB_LOAD_BALANCE_INFO;

		if (credentials)
			flags |= LB_USERNAME | LB_PASSWORD | LB_DOMAIN;
		if (!redirection_set_flags(redirection, flags))
		{
			success = FALSE;
			break;
		}
		if (flags & LB_TARGET_NET_ADDRESS)
		{
			if (!redirection_set_string_option(redirection, LB_TARGET_NET_ADDRESS, targetAddress.c_str()))
			{
				success = FALSE;
				break;
			}
		}
		if (credentials)
		{
			if (!redirection_set_string_option(redirection, LB_USERNAME,
			                                   credentials->username.c_str()))
			{
				success = FALSE;
				break;
			}
			if (!redirection_set_password_option(redirection, credentials->password))
			{
				success = FALSE;
				break;
			}
			if (!redirection_set_string_option(redirection, LB_DOMAIN, "None"))
			{
				success = FALSE;
				break;
			}
		}
		if (routingToken && !routingToken->empty())
		{
			if (!redirection_set_byte_option(redirection, LB_LOAD_BALANCE_INFO,
			                                 reinterpret_cast<const BYTE*>(routingToken->c_str()),
			                                 routingToken->size()))
			{
				success = FALSE;
				break;
			}
		}

		UINT32 missingFlags = 0;
		if (!redirection_settings_are_valid(redirection, &missingFlags))
		{
			VDI_LOG_ERROR(TAG, "Redirection settings invalid (missing flags=0x%08" PRIX32 ")",
			              missingFlags);
			success = FALSE;
			break;
		}

		if (!peer->SendServerRedirection(peer, redirection))
		{
			VDI_LOG_ERROR(TAG, "Failed to send redirection PDU");
			success = FALSE;
			break;
		}
	} while (0);

	redirection_free(redirection);
	return success;
}

} // namespace redirector
