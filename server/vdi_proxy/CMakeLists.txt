cmake_minimum_required(VERSION 3.13)

if(NOT FREERDP_DEFAULT_PROJECT_VERSION)
	set(FREERDP_DEFAULT_PROJECT_VERSION "1.0.0.0")
endif()

project(vdi-proxy
	VERSION ${FREERDP_DEFAULT_PROJECT_VERSION}
	LANGUAGES CXX
)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake)
include(CommonConfigOptions)
include(CXXCompilerFlags)
include(GNUInstallDirs)

# Find libcurl
find_package(CURL REQUIRED)
if(NOT CURL_FOUND)
	message(FATAL_ERROR "libcurl not found")
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)

# Find PAM libraries using pkg-config
pkg_check_modules(PAM REQUIRED pam pam_misc)
if(NOT PAM_FOUND)
    message(FATAL_ERROR "PAM libraries (libpam and libpam_misc) not found")
endif()

set(SRCS
	vdi_proxy.cpp
	vdi_proxy_server.cpp
	vdi_proxy_utils.cpp
)

AddTargetWithResourceFile(${PROJECT_NAME} TRUE "${PROJECT_VERSION}" SRCS FALSE)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)

target_include_directories(${PROJECT_NAME}
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}
		${JSONCPP_INCLUDE_DIRS}
		${PAM_INCLUDE_DIRS}
		${CMAKE_CURRENT_SOURCE_DIR}/../vdi-common
)

target_link_libraries(${PROJECT_NAME}
	PRIVATE
		winpr
		vdi-common
		CURL::libcurl
		${JSONCPP_LIBRARIES}
		${PAM_LIBRARIES}
		freerdp-server
		freerdp
		freerdp-server-proxy
)

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../vdi-common/vdi_broker.sample.yaml
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/freerdp)
