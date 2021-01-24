set(APP_NAME "WebTunnelSSH")

set(LOCAL_SRCS "")
aux_source_directory(src LOCAL_SRCS)

add_executable(${APP_NAME} ${LOCAL_SRCS})

if(ENABLE_NETSSL_WIN)
	target_compile_definitions(${APP_NAME} PUBLIC WEBTUNNEL_ENABLE_TLS=1)
	target_link_libraries(${APP_NAME} PocoNetSSLWin)
else()
find_package(OpenSSL)
if(OPENSSL_FOUND)
if(ENABLE_NETSSL)
	target_include_directories(${APP_NAME} PUBLIC "${OPENSSL_INCLUDE_DIR}")
	target_compile_definitions(${APP_NAME} PUBLIC WEBTUNNEL_ENABLE_TLS=1)
	target_link_libraries(${APP_NAME} Poco::NetSSL Poco::Crypto ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
endif()
endif()
endif()

target_link_libraries(${APP_NAME} Poco::WebTunnel Poco::Util Poco::Net Poco::Foundation)

install(
	TARGETS "${APP_NAME}" EXPORT "${APP_NAME}Targets"
	RUNTIME DESTINATION bin
)
