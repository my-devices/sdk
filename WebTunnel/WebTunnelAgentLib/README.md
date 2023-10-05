# macchina.io REMOTE Agent Library (*libWebTunnelAgent*)

`libWebTunnelAgent` provides a C API for connecting a device to a macchina.io REMOTE server.
This is what the [`WebTunnelAgent`](../WebTunnelAgent/README.md) program does,
but provided as a library for easy inclusion into applications (not written in C++).
C++ applications can also use the `Poco::WebTunnel::RemotePortForwarder` class
in the `WebTunnel` library directly.

Please see the [webtunnelagent.h](include/webtunnelagent.h) header file for
a description of the available types and functions.

Basic usage:
  - `webtunnel_agent_init()` must be called before any other functions.
  - `webtunnel_agent_cleanup()` must be called as last function when the library
    is no longer used in the program, to clean up internal state and resources.
  - `webtunnel_agent_configure_timeouts()` and `webtunnel_agent_configure_tls()` are used
    for basic configuration of connection timeouts and TLS parameters.
  - `webtunnel_agent_create()` is used to create a tunnel from the device to a macchina.io REMOTE server.
  - `webtunnel_agent_destroy()` stops the local TCP server for the tunnel connection.
  