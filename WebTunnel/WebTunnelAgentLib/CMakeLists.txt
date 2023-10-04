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

if(WEBTUNNELAGENTLIB_MODULE)
	set(WEBTUNNELAGENTLIB_TYPE MODULE)
	set(CMAKE_DEBUG_POSTFIX "" CACHE STRING "Set Debug library postfix" FORCE)
	set(CMAKE_RELEASE_POSTFIX "" CACHE STRING "Set Release library postfix" FORCE)
	set(CMAKE_MINSIZEREL_POSTFIX "" CACHE STRING "Set MinSizeRel library postfix" FORCE)
	set(CMAKE_RELWITHDEBINFO_POSTFIX "" CACHE STRING "Set RelWithDebInfo library postfix" FORCE)
else()
	if(WEBTUNNELAGENTLIB_SHARED)
		set(WEBTUNNELAGENTLIB_TYPE SHARED)
	else()
		if (BUILD_SHARED_LIBS)
			set(WEBTUNNELAGENTLIB_TYPE SHARED)
		else()
			set(WEBTUNNELAGENTLIB_TYPE STATIC)
		endif()
	endif()
endif()

add_library(WebTunnelAgentLib ${WEBTUNNELAGENTLIB_TYPE} ${SRCS})

if(NOT ${WEBTUNNELAGENTLIB_TYPE} STREQUAL "STATIC")
	target_compile_definitions(WebTunnelAgentLib PUBLIC WebTunnelAgent_DLL)
endif()

set_target_properties(WebTunnelAgentLib
  PROPERTIES
  OUTPUT_NAME WebTunnelAgent
  DEFINE_SYMBOL WebTunnelAgent_EXPORTS
)

if(ENABLE_NETSSL_WIN)
	target_compile_definitions(WebTunnelAgentLib PRIVATE WEBTUNNEL_ENABLE_TLS=1)
	target_link_libraries(WebTunnelAgentLib Poco::NetSSLWin)
else()
	find_package(OpenSSL)
	if(OPENSSL_FOUND)
		if(ENABLE_NETSSL)
			target_include_directories(WebTunnelAgentLib PUBLIC "${OPENSSL_INCLUDE_DIR}")
			target_compile_definitions(WebTunnelAgentLib PRIVATE WEBTUNNEL_ENABLE_TLS=1)
			target_link_libraries(WebTunnelAgentLib Poco::NetSSL Poco::Crypto ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
		endif()
	endif()
endif()

target_link_libraries(WebTunnelAgentLib Poco::WebTunnel Poco::Util Poco::Net Poco::Foundation)

target_include_directories(WebTunnelAgentLib
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

POCO_INSTALL(WebTunnelAgentLib)
POCO_GENERATE_PACKAGE(WebTunnelAgentLib)
