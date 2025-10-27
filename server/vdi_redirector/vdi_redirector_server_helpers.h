#pragma once

#include "vdi_redirector_utils.h"

#include <freerdp/peer.h>

#include <cstdint>
#include <optional>
#include <string>

struct rdp_redirection;
typedef struct rdp_redirection rdpRedirection;

namespace redirector
{

std::string resolve_client_ip(freerdp_peer* peer);
std::optional<std::string> build_routing_token(const std::string& ip, std::uint16_t port);
BOOL redirection_set_password_option(rdpRedirection* redirection, const std::string& password);
BOOL send_redirection(freerdp_peer* peer, const std::string& targetAddress,
                      const RdpCredentials* credentials, const std::string* routingToken);

} // namespace redirector
