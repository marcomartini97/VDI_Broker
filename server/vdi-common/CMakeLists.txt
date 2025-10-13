cmake_minimum_required(VERSION 3.13)

project(vdi-common LANGUAGES CXX)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake)
include(CommonConfigOptions)
include(CXXCompilerFlags)

find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)

pkg_check_modules(PAM REQUIRED pam pam_misc)

add_library(vdi-common STATIC
	vdi_broker_config.cpp
	vdi_container_manager.cpp
	vdi_logging_utils.cpp
	vdi_status_display.cpp
	vdi_vortice_protocol.cpp
)

target_compile_features(vdi-common PUBLIC cxx_std_17)

target_include_directories(vdi-common
	PUBLIC
		${CMAKE_CURRENT_SOURCE_DIR}
		${JSONCPP_INCLUDE_DIRS}
		${PAM_INCLUDE_DIRS}
)

target_link_libraries(vdi-common
	PUBLIC
		winpr
		CURL::libcurl
		${JSONCPP_LIBRARIES}
		${PAM_LIBRARIES}
)
