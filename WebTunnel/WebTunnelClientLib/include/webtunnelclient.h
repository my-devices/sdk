/*
// webtunnelclient.h
//
// The WebTunnel Client C API
//
// Copyright (c) 2020-2023, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// SPDX-License-Identifier:	BSL-1.0
*/


#ifndef WebTunnelClient_INCLUDED
#define WebTunnelClient_INCLUDED


/*
// The following block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the WebTunnelClient_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// WebTunnelClient_API functions as being imported from a DLL, wheras this DLL sees symbols
// defined with this macro as being exported.
*/
#if defined(_WIN32) && defined(WebTunnelClient_DLL)
	#if defined(WebTunnelClient_EXPORTS)
		#define WebTunnelClient_API __declspec(dllexport)
	#else
		#define WebTunnelClient_API __declspec(dllimport)
	#endif
#endif


#if !defined(WebTunnelClient_API)
	#define WebTunnelClient_API
#endif


/*
// Automatically link WebTunnelClientCAPI library.
*/
#if defined(_MSC_VER) && defined(WebTunnelClient_DLL)
	#if !defined(WebTunnelClient_EXPORTS)
		#if defined(_DEBUG)
			#pragma comment(lib, "WebTunnelClientd.lib")
		#else
			#pragma comment(lib, "WebTunnelClient.lib")
		#endif
	#endif
#endif


/*
// Client API
*/
typedef enum webtunnel_client_result
{
	webtunnel_client_result_ok = 0,
	webtunnel_client_result_error = 1,
	webtunnel_client_result_not_supported = 2
} webtunnel_client_result;


typedef enum webtunnel_client_tls_version
{
	webtunnel_client_tls_1_0 = 0,
	webtunnel_client_tls_1_1 = 1,
	webtunnel_client_tls_1_2 = 2,
	webtunnel_client_tls_1_3 = 3
} webtunnel_client_tls_version;


typedef void* webtunnel_client;


#ifdef __cplusplus
extern "C" {
#endif


/*
// webtunnel_client_init
//
// Initialize webtunnel client library.
//
// Must be called before any other functions.
// Returns webunnel_client_result_ok if successful, or
// webtunnel_client_result_error otherwise.
*/
int WebTunnelClient_API webtunnel_client_init(void);


/*
// webtunnel_client_cleanup
//
// Cleanup webtunnel client library.
//
// Should be called when the library is no longer being used
// to cleanup internal state and resources.
*/
void WebTunnelClient_API webtunnel_client_cleanup(void);


/*
// webtunnel_client_configure_timeouts
//
// Configure timeouts for WebTunnel connections.
//
// All timeouts are in seconds.
//
// connect_timeout is the timeout for setting up the initial HTTP connection
// to the reflector server.
//
// remote_timeout specifies the timeout of the tunnel connection to the reflector service.
// If no data has been received for this period, the client will send a PING
// message to the server. If the server does not reply to the PING, the connection
// will be closed.
//
// local_timeout specifies the timeout of the local socket connection.
// If no data has been received for this period, the connection will be closed.
//
// returns webtunnel_client_result_ok if all went well, otherwise webtunnel_client_result_error.
*/
int WebTunnelClient_API webtunnel_client_configure_timeouts(int connect_timeout, int remote_timeout, int local_timeout);


/*
// webtunnel_client_configure_tls
//
// Sets up SSL/TLS parameters for the connection to the
// reflector server.
//
// If accept_unknown_cert is true, any server certificate, even without
// a valid chain, will be accepted.
//
// If extended_verification is true, extended certificate verification
// will be performed, which means that the certificate must contain the
// fully qualified domain name of the reflector server.
//
// A list of ciphers can be given in ciphers, using OpenSSL syntax
// (e.g., "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"). Can be NULL to use
// the default.
//
// ca_location contains the path to the file or directory containing
// the CA/root certificates. Can be NULL to use the built-in root
// certificates.
//
// minimum_protocol specifies the minimum TLS protocol version (see webtunnel_client_tls_version).
//
// Returns webtunnel_client_result_ok if successful, or webtunnel_client_result_error if an error
// occured, or webtunnel_client_result_not_supported if no SSL/TLS support is available.
*/
int WebTunnelClient_API webtunnel_client_configure_tls(bool accept_unknown_cert, bool extended_verification, const char* ciphers, const char* ca_location, int minimum_protocol);


/*
// webtunnel_client_configure_proxy
//
// Sets up parameters for connecting through a proxy server.
//
// If enable_proxy is true, the connection to the Remote Manager server
// will be attempted through a proxy server.
//
// proxy_host contains the proxy server host name or IP address.
//
// proxy_port contains the port number of the proxy server.
//
// proxy_username contains the username for authenticating against the
// proxy server. If NULL, no authentication will be performed.
//
// proxy_password contains the password for authenticating against the
// proxy server. If NULL, no authentication will be performed.
//
// Returns webtunnel_client_result_ok if successful, or webtunnel_client_result_error if an error
// occured.
*/
int WebTunnelClient_API webtunnel_client_configure_proxy(bool enable_proxy, const char* proxy_host, unsigned short proxy_port, const char* proxy_username, const char* proxy_password);


/*
// webtunnel_client_create
//
// Creates a tunnel connection from the given local_port to remote_port on
// the remote machine, using the reflector server as intermediary.
//
// If local_port is 0, a suitable port number will be chosen automatically.
// The port number can be obtained by calling webtunnel_client_local_port().
//
// remote_uri contains the URI of the remote machine, using the http
// or https URI scheme.
// Example: "https://0a72da53-9de5-44c8-9adf-f3d916304be6.my-devices.net"
//
// username and password are used for authentication against the reflector
// server.
//
// local_addr can be NULL (defaults to 127.0.0.1) or a string containing
// an IP address or host name ("localhost").
//
// Returns NULL in case of an error.
*/
webtunnel_client WebTunnelClient_API webtunnel_client_create(const char* local_addr, unsigned short local_port, unsigned short remote_port, const char* remote_uri, const char* username, const char* password);


/*
// webtunnel_client_create_jwt
//
// Creates a tunnel connection from the given local_port to remote_port on
// the remote machine, using the reflector server as intermediary.
//
// If local_port is 0, a suitable port number will be chosen automatically.
// The port number can be obtained by calling webtunnel_client_local_port().
//
// remote_uri contains the URI of the remote machine, using the http
// or https URI scheme.
// Example: " https://0a72da53-9de5-44c8-9adf-f3d916304be6.my-devices.net"
//
// A JSON Web Token (JWT) is used for authentication against the reflector
// server.
//
// Returns NULL in case of an error.
*/
webtunnel_client WebTunnelClient_API webtunnel_client_create_jwt(const char* local_addr, unsigned short local_port, unsigned short remote_port, const char* remote_uri, const char* jwt);


/*
// webtunnel_client_destroy
//
// Closes the given web tunnel connection.
*/
void WebTunnelClient_API webtunnel_client_destroy(webtunnel_client wt);


/*
// webtunnel_client_get_local_port
//
// Returns the local port number for forwarding
// connections.
*/
unsigned short WebTunnelClient_API webtunnel_client_get_local_port(webtunnel_client wt);


/*
// webtunnel_client_get_last_error_text
//
// Returns a text describing the last encountered error.
// Can be NULL if no descriptive text is available.
*/
const char WebTunnelClient_API * webtunnel_client_get_last_error_text(void);


#ifdef __cplusplus
}
#endif


#endif /* WebTunnelClient_INCLUDED */
