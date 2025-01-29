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
#include <thread>
#include <curl/curl.h>
#include <unistd.h>
#include <json/json.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <freerdp/api.h>
#include <freerdp/scancode.h>
#include <freerdp/server/proxy/proxy_modules_api.h>
#include <sys/time.h>

#define TAG MODULE_TAG("vdi_broker")
#define PODMAN_IMAGE "vdi-gnome"
#define CONTAINER_PREFIX "vdi-"


// Set Nla Security to login
static BOOL vdi_server_session_started(proxyPlugin* plugin, proxyData* pdata, void* custom) {
	auto settings = pdata->ps->context.settings;
	freerdp_settings_set_bool (settings, FreeRDP_RdpSecurity, FALSE);
	freerdp_settings_set_bool (settings, FreeRDP_TlsSecurity, TRUE);
	freerdp_settings_set_bool (settings, FreeRDP_NlaSecurity, TRUE);
	freerdp_settings_set_bool (settings, FreeRDP_RdstlsSecurity, TRUE);
	return TRUE;
}


/* Container Management Part */


// Path to the Podman UNIX socket
const char* PODMAN_SOCKET = "/var/run/podman/podman.sock";

// Callback function to capture CURL response data
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Function to get container information via Podman RESTful API
std::string get_container_info(const std::string& container_name, const std::string& endpoint = "/json") {
    CURL* curl;
    CURLcode res;
    std::string response;

    curl = curl_easy_init();
    if (curl) {
        std::string url = "http://d/v5.3.0/libpod/containers/" + container_name + endpoint;

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

    	//std::clog << "Get Container info - http code: " << http_code << std::endl << "Response: " << res << std::endl; 

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
    //std::clog << "Container status:" << status << std::endl;
    return status == "running";
}

bool wait_for_process(const std::string& container_name, const std::string& process_name) {
    std::clog << "Waiting for <" << process_name  << "> to be active in container: " << container_name << std::endl;

    bool is_compositor_active = false;
    int count = 0;
    while (!is_compositor_active && count < 10) {
    	auto response = get_container_info(container_name, "/top");
    	//Check if compositor is running (hard coded string)
    	auto searchValue = process_name;


    	// Parse the JSON string
    	Json::Value root;
    	Json::CharReaderBuilder builder;
    	std::string errs;

    	std::istringstream s(response);
    	if (!Json::parseFromStream(builder, s, &root, &errs)) {
    		std::cerr << "Error parsing JSON: " << errs << std::endl;
    		return false;
    	}

    	// Check if the "Processes" key exists and is an array
    	if (!root.isMember("Processes") || !root["Processes"].isArray()) {
    		std::cerr << "Invalid JSON: 'Processes' key is missing or not an array" << std::endl;
    		return false;
    	}

    	// Iterate through the "Processes" array
    	for (const auto &process : root["Processes"]) {
    		if (!process.isArray()) {
    			continue; // Ensure each process is an array
    		}

    		// Check if the last element in the process array matches the searchValue
    		if (process[process.size() - 1].asString() == searchValue) {
    			is_compositor_active = true;
    		}
    	}


        if (!is_compositor_active) {
            std::this_thread::sleep_for(std::chrono::seconds(2)); // Wait before retrying
        }
	count++;
    }

    std::this_thread::sleep_for(std::chrono::seconds(2)); // Wait before returning true 
    return is_compositor_active;
}


// Start the container using Podman RESTful API
bool start_container(const std::string& container_name) {
	CURL* curl;
	CURLcode res;
	bool success = false;
	std::clog << "Starting container: " << container_name << std::endl;

	curl = curl_easy_init();
	if (curl) {
		std::string url = "http://d/v5.3.0/libpod/containers/" + container_name + "/start";
		std::string start_command = R"({"name": ")" + container_name + R"("})";

		struct curl_slist* headers = nullptr;
		headers = curl_slist_append(headers, "Content-Type: application/json");

		curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, PODMAN_SOCKET);
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, start_command.c_str());

		// Perform the request to start the container
		res = curl_easy_perform(curl);

		if (res == CURLE_OK) {
			long http_code = 0;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

			if (http_code >= 200 && http_code < 300) {
				success = true;
				std::clog << "Container started successfully." << std::endl;
			} else {
				std::cerr << "Failed to start container, HTTP code: " << http_code << std::endl;
			}
		} else {
			std::cerr << "Failed to start container: " << curl_easy_strerror(res) << std::endl;
		}

		curl_slist_free_all(headers);
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


bool create_container(const std::string& container_name, const std::string& username) {
    CURL* curl;
    CURLcode res;
    bool success = false;
    std::clog << "Creating container: " << container_name << std::endl;
    curl = curl_easy_init();
    if (curl) {
        std::string url = "http://d/v5.3.0/libpod/containers/create";
    	//Note: Change image: accordingly, TODO: do it dynamically on a config file or something similar
    	std::string create_command = "{\"name\": \"" + container_name + "\","
				     "\"hostname\": \"" + container_name + "\","
    				     R"(
				     "image": ")" + PODMAN_IMAGE + R"(",
				     "cap_add": [
				         "SYS_ADMIN",
				         "NET_ADMIN",
				         "SYS_PTRACE",
				         "AUDIT_CONTROL"
				     ],
				     "devices": [
				         { "path": "/dev/fuse" },
				         { "path": "/dev/nvidia0" },
				         { "path": "/dev/nvidiactl" },
				         { "path": "/dev/nvidia-uvm" },
				         { "path": "/dev/dri/renderD128" }
				     ],
				     "env": {
				         "XDG_RUNTIME_DIR": "/tmp",
				         "GSK_RENDERER": "ngl"
				     },
				     "mounts": [
				         { "Source": "/etc/vdi", "Destination": "/etc/vdi", "Type": "bind", "ReadOnly": true },
				         { "Source": "/etc/passwd", "Destination": "/etc/passwd", "Type": "bind", "ReadOnly": true },
				         { "Source": "/etc/group", "Destination": "/etc/group", "Type": "bind", "ReadOnly": true },
				         { "Source": "/etc/shadow", "Destination": "/etc/shadow", "Type": "bind", "ReadOnly": true },
				         { "Source": "/home", "Destination": "/home", "Type": "bind" }
				     ],
				     "command": ["/usr/sbin/init"]
				     })";

        std::clog << "Create string: : " << create_command << std::endl;

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, PODMAN_SOCKET);
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, create_command.c_str());

        // Perform the request to create the container
        res = curl_easy_perform(curl);

        if (res == CURLE_OK) {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

            if (http_code >= 200 && http_code < 300) {
                success = true;
                std::clog << "Container created successfully." << std::endl;
            } else {
                std::cerr << "Failed to create container, HTTP code: " << http_code << std::endl;
            }
        } else {
            std::cerr << "Failed to create container: " << curl_easy_strerror(res) << std::endl;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    return success;
}


// Main function to manage the container
std::string manage_container(const std::string& username, const std::string& container_prefix= CONTAINER_PREFIX) {
    if (!container_exists(container_prefix + username)) {
        // Create container
    	create_container(container_prefix + username, username);
    }

    if (!container_running(container_prefix + username)) {
        // Start the container
        if (!start_container(container_prefix + username)) {
            std::cerr << "Failed to start the container." << std::endl;
            return "";
        }
    }

    // Wait for weston to be up
    wait_for_process(container_prefix + username, "/usr/bin/gnome-shell");
    wait_for_process(container_prefix + username, "/usr/libexec/gnome-remote-desktop-daemon --headless");

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
	auto settings = pdata->pc->context.settings;

	freerdp_settings_set_bool (settings, FreeRDP_RdpSecurity, FALSE);
	freerdp_settings_set_bool (settings, FreeRDP_TlsSecurity, FALSE);
	freerdp_settings_set_bool (settings, FreeRDP_NlaSecurity, TRUE);


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

// Structure to hold the password
struct pam_conv_data {
    const char* password;
};


// PAM conversation function
static int pam_conversation(int num_msg, const struct pam_message** msg,
                            struct pam_response** resp, void* appdata_ptr) {
    if (num_msg <= 0) {
        return PAM_CONV_ERR;
    }

    pam_conv_data* conv_data = static_cast<pam_conv_data*>(appdata_ptr);
    struct pam_response* responses = (struct pam_response*)calloc(num_msg, sizeof(struct pam_response));
    if (responses == nullptr) {
        return PAM_CONV_ERR;
    }

    for (int i = 0; i < num_msg; ++i) {
        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
                // Provide the password
                responses[i].resp = strdup(conv_data->password);
                responses[i].resp_retcode = 0;
                break;
            case PAM_PROMPT_ECHO_ON:
                // Handle cases where echo is allowed (not used here)
                responses[i].resp = nullptr;
                responses[i].resp_retcode = 0;
                break;
            case PAM_ERROR_MSG:
                std::cerr << "PAM Error Message: " << msg[i]->msg << std::endl;
                responses[i].resp = nullptr;
                responses[i].resp_retcode = 0;
                break;
            case PAM_TEXT_INFO:
                std::cout << "PAM Info: " << msg[i]->msg << std::endl;
                responses[i].resp = nullptr;
                responses[i].resp_retcode = 0;
                break;
            default:
                free(responses);
                return PAM_CONV_ERR;
        }
    }

    *resp = responses;
    return PAM_SUCCESS;
}




// Function to authenticate user via PAM
bool vdi_auth(const std::string& username, const std::string& password) {
    pam_handle_t* pamh = nullptr;
    struct pam_conv conv;
    pam_conv_data conv_data = { password.c_str() };

    conv.conv = pam_conversation;
    conv.appdata_ptr = &conv_data;

    // Start PAM transaction
    int retval = pam_start("vdi-broker", username.c_str(), &conv, &pamh);
    if (retval != PAM_SUCCESS) {
        std::cerr << "pam_start failed: " << pam_strerror(pamh, retval) << std::endl;
        return false;
    }

    // Authenticate the user
    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS) {
        std::cerr << "pam_authenticate failed: " << pam_strerror(pamh, retval) << std::endl;
        pam_end(pamh, retval);
        return false;
    }

    // Check account status
    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) {
        std::cerr << "pam_acct_mgmt failed: " << pam_strerror(pamh, retval) << std::endl;
        pam_end(pamh, retval);
        return false;
    }

    // End PAM transaction
    retval = pam_end(pamh, PAM_SUCCESS);
    if (retval != PAM_SUCCESS) {
        std::cerr << "pam_end failed: " << pam_strerror(pamh, retval) << std::endl;
        return false;
    }

    return true;
}

static BOOL demo_client_pre_connect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(pdata->pc);
	WINPR_ASSERT(custom);

        //Set target to another thing
	auto settings = pdata->pc->context.settings;
	const char* uname = freerdp_settings_get_string(settings, FreeRDP_Username);
	const char* passw = freerdp_settings_get_string(settings, FreeRDP_Password);

	if(uname == nullptr)
		return FALSE;
	if(passw == nullptr)
		return FALSE;

	std::string username = uname;
	std::string password = passw;

	WLog_INFO(TAG, "Username full: %s", username.c_str());

	//Set Default Codec
	//freerdp_settings_set_bool(settings, FreeRDP_NSCodec, true);
	// Otherwise find the position of '#', then set RFX if found
	auto hashPos = username.find('#');

	if (hashPos != std::string::npos) { // Check if '#' is present
		// Extract the part after '#'
		auto codec = username.substr(hashPos + 1);

		if (!codec.empty()) {
			if(codec.compare("rfx") == 0) {
				freerdp_settings_set_bool(settings, FreeRDP_RemoteFxCodec, true);
				WLog_INFO(TAG, "USING CODEC RFX");
			}
		}
	}

	auto user = username.substr(0, hashPos);

	//WLog_INFO(TAG, "USING CODEC NSC");
	if(!vdi_auth(user, password)) {
		return FALSE;
	}
	WLog_INFO(TAG, "Username: %s", username.c_str());
	auto ip = manage_container(user).c_str();
	if(ip != "") {
		WLog_INFO(TAG, "Setting target address: %s", ip);
		//Hardcoded password for now, set the same for grd in container
		freerdp_settings_set_string(settings, FreeRDP_ServerHostname, ip);
		freerdp_settings_set_string(settings, FreeRDP_Username, "rdp");
		freerdp_settings_set_string(settings, FreeRDP_Password, "rdp");
		freerdp_settings_set_string(settings, FreeRDP_Domain, "None");
	}

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
	plugin.ClientInitConnect = demo_client_init_connect;
	//plugin.ClientUninitConnect = demo_client_uninit_connect;
	plugin.ClientPreConnect = demo_client_pre_connect;
	plugin.ServerSessionStarted = vdi_server_session_started;
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
