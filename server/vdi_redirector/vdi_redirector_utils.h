#pragma once

#include <string>

struct ParsedUsername
{
	std::string user;
	std::string suffix;
};

struct RdpCredentials
{
	std::string username;
	std::string password;
};

ParsedUsername split_username(const std::string& username);
std::string build_container_prefix(const std::string& suffix);
RdpCredentials load_rdp_credentials();
void vdi_log_configuration_state(bool refreshed);
void vdi_log_refresh_outcome(bool refreshed, bool reloaded);
bool vdi_auth(const std::string& username, const std::string& password);
