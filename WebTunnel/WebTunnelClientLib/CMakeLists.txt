# Sources
file(GLOB SRCS_G "src/*.cpp")
POCO_SOURCES_AUTO(SRCS ${SRCS_G})

# Headers
file(GLOB_RECURSE HDRS_G "include/*.h")
POCO_HEADERS_AUTO(SRCS ${HDRS_G})

# Version Resource
if(MSVC AND BUILD_SHARED_LIBS)
	source_group("Resources" FILES ${PROJECT_SOURCE_DIR}/DLLVersion.rc)
	list(APPEND SRCS ${PROJECT_SOURCE_DIR}/DLLVersion.rc)
endif()

if(WEBTUNNELCLIENTLIB_MODULE)
  set(WEBTUNNELCLIENTLIB_TYPE MODULE)
	set(CMAKE_DEBUG_POSTFIX "" CACHE STRING "Set Debug library postfix" FORCE)
	set(CMAKE_RELEASE_POSTFIX "" CACHE STRING "Set Release library postfix" FORCE)
	set(CMAKE_MINSIZEREL_POSTFIX "" CACHE STRING "Set MinSizeRel library postfix" FORCE)
	set(CMAKE_RELWITHDEBINFO_POSTFIX "" CACHE STRING "Set RelWithDebInfo library postfix" FORCE)
else()
	if(WEBTUNNELCLIENTLIB_SHARED)
		set(WEBTUNNELCLIENTLIB_TYPE SHARED)
	else()
		if (BUILD_SHARED_LIBS)
			set(WEBTUNNELCLIENTLIB_TYPE SHARED)
		else()
			set(WEBTUNNELCLIENTLIB_TYPE STATIC)
		endif()
	endif()
endif()

add_library(WebTunnelClientLib ${WEBTUNNELCLIENTLIB_TYPE} ${SRCS})
set_target_properties(WebTunnelClientLib
  PROPERTIES
  OUTPUT_NAME WebTunnelClient
  DEFINE_SYMBOL WebTunnelClient_EXPORTS
)

if (MSVC AND BUILD_SHARED_LIBS)
	target_compile_definitions(WebTunnelClientLib PRIVATE WebTunnelClient_EXPORTS)
endif()

if(ENABLE_NETSSL_WIN)
	target_compile_definitions(WebTunnelClientLib PUBLIC WEBTUNNEL_ENABLE_TLS=1)
	target_link_libraries(WebTunnelClientLib Poco::NetSSLWin)
else()
	find_package(OpenSSL)
	if(OPENSSL_FOUND)
		if(ENABLE_NETSSL)
			target_include_directories(WebTunnelClientLib PUBLIC "${OPENSSL_INCLUDE_DIR}")
			target_compile_definitions(WebTunnelClientLib PUBLIC WEBTUNNEL_ENABLE_TLS=1)
			target_link_libraries(WebTunnelClientLib Poco::NetSSL Poco::Crypto ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
		endif()
	endif()
endif()

target_link_libraries(WebTunnelClientLib Poco::WebTunnel Poco::Util Poco::Net Poco::Foundation)

target_include_directories(WebTunnelClientLib
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

POCO_INSTALL(WebTunnelClientLib)
POCO_GENERATE_PACKAGE(WebTunnelClientLib)
