/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Proxy Server Demo C++ Module
 *
 * Copyright 2019 Kobi Mizrachi <kmizrachi18@gmail.com>
 * Copyright 2021 Armin Novak <anovak@thincast.com>
 * Copyright 2021 Thincast Technologies GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "freerdp/server/proxy/proxy_context.h"

#include <iostream>
#include <string>
#include <curl/curl.h>
#include <unistd.h>
#include <json/json.h>


#include <freerdp/api.h>
#include <freerdp/scancode.h>
#include <freerdp/server/proxy/proxy_modules_api.h>
#include <sys/time.h>

#define TAG MODULE_TAG("vdi_broker")

/* Container Management Part */


// Path to the Podman UNIX socket
const char* PODMAN_SOCKET = "/var/run/podman/podman.sock";

// Callback function to capture CURL response data
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Function to get container information via Podman RESTful API
std::string get_container_info(const std::string& container_name) {
    CURL* curl;
    CURLcode res;
    std::string response;

    curl = curl_easy_init();
    if (curl) {
        std::string url = "http://d/v1.0.0/libpod/containers/" + container_name + "/json";

        curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, PODMAN_SOCKET);
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

        // Set up the write callback to capture response data
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        // Perform the request
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "Failed to get container info: " << curl_easy_strerror(res) << std::endl;
            response.clear();
        }

        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        if (http_code == 404) {
            response.clear(); // Container does not exist
        } else if (http_code >= 400) {
            std::cerr << "HTTP error code: " << http_code << std::endl;
            response.clear();
        }

    	std::clog << "Get Container info - http code: " << http_code << std::endl << "Response: " << res << std::endl; 

        curl_easy_cleanup(curl);
    }
    return response;
}

// Check if the container exists
bool container_exists(const std::string& container_name) {
    std::string info = get_container_info(container_name);
    if(info.empty()){
	    std::clog << "Container doesn't exist: Create it" << std::endl;
    }
    return !info.empty();
}

// Check if the container is running
bool container_running(const std::string& container_name) {
    std::string info = get_container_info(container_name);
    if (info.empty()) {
        return false;
    }

    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(info, root)) {
        std::cerr << "Failed to parse container JSON info." << std::endl;
        return false;
    }

    std::string status = root["State"]["Status"].asString();
    std::clog << "Container status:" << status << std::endl;
    return status == "running";
}

// Start the container using Podman RESTful API
bool start_container(const std::string& container_name) {
    CURL* curl;
    CURLcode res;
    bool success = false;
    std::clog << "Starting container: " << container_name << std::endl;

    curl = curl_easy_init();
    if (curl) {
        std::string url = "http://d/v1.0.0/libpod/containers/" + container_name + "/start";

        curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, PODMAN_SOCKET);
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);

        // Perform the request
        res = curl_easy_perform(curl);

        if (res == CURLE_OK) {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

            if (http_code >= 200 && http_code < 300) {
                success = true;
            } else {
                std::cerr << "Failed to start container, HTTP code: " << http_code << std::endl;
            }
        } else {
            std::cerr << "Failed to start container: " << curl_easy_strerror(res) << std::endl;
        }


        curl_easy_cleanup(curl);
    }
    return success;
}

// Get the container's IP address
std::string get_container_ip(const std::string& container_name) {
    std::string info = get_container_info(container_name);
    if (info.empty()) {
        return "";
    }

    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(info, root)) {
        std::cerr << "Failed to parse container JSON info." << std::endl;
        return "";
    }

    //Note this only works with podman default network
    const Json::Value& networks = root["NetworkSettings"]["Networks"];
    if (!networks.isObject()) {
        std::cerr << "No network information available." << std::endl;
        return "";
    }

    for (const auto& network_name : networks.getMemberNames()) {
        const Json::Value& network = networks[network_name];
        std::string ip = network["IPAddress"].asString();
        if (!ip.empty()) {
	    std::clog << "Found IP: " << ip << std::endl;
            return ip;
        }
    }
    return "";
}

// Main function to manage the container
std::string manage_container(const std::string& username, const std::string& container_prefix= "weston-") {
    if (!container_exists(container_prefix + username)) {
        // Create container using compose, suppose we're in the same directory as the compose file
        std::string command = "env USERNAME=" + username + " podman-compose up -d";
        int result = system(command.c_str());
        if (result != 0) {
            std::cerr << "Failed to create container using compose." << std::endl;
            return "";
        }
    } else {
        if (!container_running(container_prefix + username)) {
            // Start the container
            if (!start_container(container_prefix + username)) {
                std::cerr << "Failed to start the container." << std::endl;
                return "";
            }
        }
    }

    // Wait for the container to fully start
    sleep(2);

    // Get the container's IP address
    std::string ip = get_container_ip(container_prefix + username);
    if (ip.empty()) {
        std::cerr << "Failed to retrieve the container's IP address." << std::endl;
    }
    return ip;
}

struct demo_custom_data
{
	proxyPluginsManager* mgr;
	int somesetting;
};

static constexpr char plugin_name[] = "vdi-broker";
static constexpr char plugin_desc[] = "Intercepts RDP Authentication and forwards the connection to an RDP Enabled Container";

static BOOL demo_plugin_unload(proxyPlugin* plugin)
{
	WINPR_ASSERT(plugin);

	std::cout << "C++ demo plugin: unloading..." << std::endl;

	/* Here we have to free up our custom data storage. */
	if (plugin)
		delete static_cast<struct demo_custom_data*>(plugin->custom);

	return TRUE;
}

static BOOL demo_client_init_connect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(custom);

	WLog_INFO(TAG, "called");
	return TRUE;
}

static BOOL demo_client_uninit_connect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(custom);

	WLog_INFO(TAG, "called");
	return TRUE;
}

static BOOL demo_client_pre_connect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(pdata->pc);
	WINPR_ASSERT(custom);

        //Set target to another thing
	auto settings = pdata->pc->context.settings;
	auto username = freerdp_settings_get_string(settings, FreeRDP_Username);
	WLog_INFO(TAG, "User: %s", username);
	auto ip = manage_container(username).c_str();
	WLog_INFO(TAG, "Setting target address: %s", ip);
	freerdp_settings_set_string(settings, FreeRDP_ServerHostname, ip);
	if(!freerdp_settings_get_string(settings, FreeRDP_Username))
		freerdp_settings_set_string(settings, FreeRDP_Username, "None");
	if(!freerdp_settings_get_string(settings, FreeRDP_Password))
		freerdp_settings_set_string(settings, FreeRDP_Password, "None");
	if(!freerdp_settings_get_string(settings, FreeRDP_Domain))
		freerdp_settings_set_string(settings, FreeRDP_Domain, "None");


	WLog_INFO(TAG, "called");
	return TRUE;
}

static BOOL demo_client_post_connect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(custom);

	WLog_INFO(TAG, "called");


	return TRUE;
}

static BOOL demo_client_post_disconnect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(custom);

	WLog_INFO(TAG, "called");
	return TRUE;
}

static BOOL demo_client_x509_certificate(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(custom);

	WLog_INFO(TAG, "called");
	return TRUE;
}

static BOOL demo_client_login_failure(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(custom);

	WLog_INFO(TAG, "called");
	return TRUE;
}

static BOOL demo_client_end_paint(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(custom);

	WLog_INFO(TAG, "called");
	return TRUE;
}

static BOOL demo_client_redirect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(custom);

	WLog_INFO(TAG, "called");
	return TRUE;
}

static BOOL demo_server_post_connect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(pdata->pc);
	WINPR_ASSERT(custom);



	WLog_INFO(TAG, "called");
	return TRUE;
}

static BOOL demo_server_peer_activate(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(custom);

	WLog_INFO(TAG, "called");
	return TRUE;
}

static BOOL demo_server_channels_init(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(custom);

	WLog_INFO(TAG, "called");
	return TRUE;
}

static BOOL demo_server_channels_free(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(custom);

	WLog_INFO(TAG, "called");
	return TRUE;
}

static BOOL demo_server_session_end(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(custom);

	WLog_INFO(TAG, "called");
	return TRUE;
}

static BOOL demo_filter_keyboard_event(proxyPlugin* plugin, proxyData* pdata, void* param)
{
	proxyPluginsManager* mgr = nullptr;
	auto event_data = static_cast<const proxyKeyboardEventInfo*>(param);

	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(event_data);

	mgr = plugin->mgr;
	WINPR_ASSERT(mgr);

	if (event_data == nullptr)
		return FALSE;

	if (event_data->rdp_scan_code == RDP_SCANCODE_KEY_B)
	{
		/* user typed 'B', that means bye :) */
		std::cout << "C++ demo plugin: aborting connection" << std::endl;
		mgr->AbortConnect(mgr, pdata);
	}

	return TRUE;
}

static BOOL demo_filter_unicode_event(proxyPlugin* plugin, proxyData* pdata, void* param)
{
	proxyPluginsManager* mgr = nullptr;
	auto event_data = static_cast<const proxyUnicodeEventInfo*>(param);

	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(event_data);

	mgr = plugin->mgr;
	WINPR_ASSERT(mgr);

	if (event_data == nullptr)
		return FALSE;

	if (event_data->code == 'b')
	{
		/* user typed 'B', that means bye :) */
		std::cout << "C++ demo plugin: aborting connection" << std::endl;
		mgr->AbortConnect(mgr, pdata);
	}

	return TRUE;
}

void printDelayBetweenCalls() {
    // Declare a static variable to hold the last time the function was called
    static struct timeval lastTime = {0, 0};

    // Get the current time
    struct timeval currentTime;
    gettimeofday(&currentTime, NULL);

    // Check if the function has been called before
    if (lastTime.tv_sec != 0 || lastTime.tv_usec != 0) {
        // Calculate the delay in microseconds
        long seconds = currentTime.tv_sec - lastTime.tv_sec;
        long microseconds = currentTime.tv_usec - lastTime.tv_usec;
        long totalMicroseconds = (seconds * 1000) + microseconds;

        printf("Time delay between calls: %ld microseconds\n", totalMicroseconds);
    } else {
        // If this is the first call, print a message indicating so
        printf("This is the first time the function is being called.\n");
    }

    // Update the lastTime variable with the current time
    lastTime = currentTime;
}


static BOOL demo_mouse_event(proxyPlugin* plugin, proxyData* pdata, void* param)
{
	auto event_data = static_cast<const proxyMouseEventInfo*>(param);

	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(event_data);

	WLog_INFO(TAG, "called %p", event_data);
	printDelayBetweenCalls();
	return TRUE;
}

static BOOL demo_mouse_ex_event(proxyPlugin* plugin, proxyData* pdata, void* param)
{
	auto event_data = static_cast<const proxyMouseExEventInfo*>(param);

	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(event_data);

	WLog_INFO(TAG, "called %p", event_data);
	return TRUE;
}

static BOOL demo_client_channel_data(proxyPlugin* plugin, proxyData* pdata, void* param)
{
	const auto* channel = static_cast<const proxyChannelDataEventInfo*>(param);

	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(channel);

	WLog_INFO(TAG, "%s [0x%04" PRIx16 "] got %" PRIuz, channel->channel_name, channel->channel_id,
	          channel->data_len);
	return TRUE;
}

static BOOL demo_server_channel_data(proxyPlugin* plugin, proxyData* pdata, void* param)
{
	const auto* channel = static_cast<const proxyChannelDataEventInfo*>(param);

	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(channel);

	WLog_WARN(TAG, "%s [0x%04" PRIx16 "] got %" PRIuz, channel->channel_name, channel->channel_id,
	          channel->data_len);
	return TRUE;
}

static BOOL demo_dynamic_channel_create(proxyPlugin* plugin, proxyData* pdata, void* param)
{
	const auto* channel = static_cast<const proxyChannelDataEventInfo*>(param);

	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(channel);

	WLog_WARN(TAG, "%s [0x%04" PRIx16 "]", channel->channel_name, channel->channel_id);
	return TRUE;
}

static BOOL demo_server_fetch_target_addr(proxyPlugin* plugin, proxyData* pdata, void* param)
{
	auto event_data = static_cast<const proxyFetchTargetEventInfo*>(param);

	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(event_data);

	WLog_INFO(TAG, "called %p", event_data);

	return TRUE;
}

static BOOL demo_server_peer_logon(proxyPlugin* plugin, proxyData* pdata, void* param)
{
	auto info = static_cast<const proxyServerPeerLogon*>(param);
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(info);
	WINPR_ASSERT(info->identity);



	WLog_INFO(TAG, "%d", info->automatic);
	return TRUE;
}

static BOOL demo_dyn_channel_intercept_list(proxyPlugin* plugin, proxyData* pdata, void* arg)
{
	auto data = static_cast<proxyChannelToInterceptData*>(arg);

	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(data);

	WLog_INFO(TAG, "%s: %p", __func__, data);
	return TRUE;
}

static BOOL demo_static_channel_intercept_list(proxyPlugin* plugin, proxyData* pdata, void* arg)
{
	auto data = static_cast<proxyChannelToInterceptData*>(arg);

	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(data);

	WLog_INFO(TAG, "%s: %p", __func__, data);
	return TRUE;
}

static BOOL demo_dyn_channel_intercept(proxyPlugin* plugin, proxyData* pdata, void* arg)
{
	auto data = static_cast<proxyDynChannelInterceptData*>(arg);

	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(data);

	WLog_INFO(TAG, "%s: %p", __func__, data);
	return TRUE;
}

#ifdef __cplusplus
extern "C"
{
#endif
	FREERDP_API BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager, void* userdata);
#ifdef __cplusplus
}
#endif

BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager, void* userdata)
{
	struct demo_custom_data* custom = nullptr;
	proxyPlugin plugin = {};

	plugin.name = plugin_name;
	plugin.description = plugin_desc;
	plugin.PluginUnload = demo_plugin_unload;
	//plugin.ClientInitConnect = demo_client_init_connect;
	//plugin.ClientUninitConnect = demo_client_uninit_connect;
	plugin.ClientPreConnect = demo_client_pre_connect;
	//plugin.ClientPostConnect = demo_client_post_connect;
	//plugin.ClientPostDisconnect = demo_client_post_disconnect;
	//plugin.ClientX509Certificate = demo_client_x509_certificate;
	//plugin.ClientLoginFailure = demo_client_login_failure;
	//plugin.ClientEndPaint = demo_client_end_paint;
	//plugin.ClientRedirect = demo_client_redirect;
	//plugin.ServerPostConnect = demo_server_post_connect;
	//plugin.ServerPeerActivate = demo_server_peer_activate;
	//plugin.ServerChannelsInit = demo_server_channels_init;
	//plugin.ServerChannelsFree = demo_server_channels_free;
	//plugin.ServerSessionEnd = demo_server_session_end;
	//plugin.KeyboardEvent = demo_filter_keyboard_event;
	//plugin.UnicodeEvent = demo_filter_unicode_event;
	//plugin.MouseEvent = demo_mouse_event;
	//plugin.MouseExEvent = demo_mouse_ex_event;
	//plugin.ClientChannelData = demo_client_channel_data;
	//plugin.ServerChannelData = demo_server_channel_data;
	//plugin.DynamicChannelCreate = demo_dynamic_channel_create;
	//plugin.ServerFetchTargetAddr = demo_server_fetch_target_addr;
	//plugin.ServerPeerLogon = demo_server_peer_logon;

	plugin.StaticChannelToIntercept = demo_static_channel_intercept_list;
	plugin.DynChannelToIntercept = demo_dyn_channel_intercept_list;
	plugin.DynChannelIntercept = demo_dyn_channel_intercept;

	plugin.userdata = userdata;

	custom = new (struct demo_custom_data);
	if (!custom)
		return FALSE;

	custom->mgr = plugins_manager;
	custom->somesetting = 42;

	plugin.custom = custom;
	plugin.userdata = userdata;

	return plugins_manager->RegisterPlugin(plugins_manager, &plugin);
}
