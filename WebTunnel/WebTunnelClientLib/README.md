# macchina.io REMOTE Client Library (*libWebTunnelClient*)

`libWebTunnelClient` provides a C API for creating a tunnel connection from
a local TCP port to a port on a remote device connected to macchina.io REMOTE.
This is what the [`remote-client`](../WebTunnelClient/README.md) is doing,
but provided as a library for easy inclusion into applications (not written in C++).
C++ applications can also use the `Poco::WebTunnel::LocalPortForwarder` class
in the `WebTunnel` library.

Please see the [webtunnelclient.h](include/webtunnelclient.h) header file for
a description of the available types and functions.

Basic usage:
  - `webtunnel_client_init()` must be called before any other functions.
  - `webtunnel_client_cleanup()` must be called as last function when the library
    is no longer used in the program, to clean up internal state and resources.
  - `webtunnel_client_configure_timeouts()` and `webtunnel_client_configure_tls()` are used
    for basic configuration of connection timeouts and TLS parameters.
  - `webtunnel_client_create()` is used to create a tunnel from a local port to a 
    remote port on a device connected to a macchina.io REMOTE server.
    The function sets up a local TCP socket, to which the application can
    then connect. Any data sent over the connection will be tunneled to the remote device.
  - `webtunnel_client_create_jwt()` can be used instead of `webtunnel_client_create()` if a token
    (JWT) should be used for authentication.
  - `webtunnel_client_destroy()` stops the local TCP server for the tunnel connection.
  
