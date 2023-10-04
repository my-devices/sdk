# macchina.io REMOTE Agent Library (*libWebTunnelAgent*)

`libWebTunnelAgent` provides a C API for connecting a device to a macchina.io REMOTE server.
This is what the [`WebTunnelAgent`](../WebTunnelAgent/README.md) is doing,
but provided as a library for easy inclusion into applications (not written in C++).
C++ applications can also use the `Poco::WebTunnel::RemotePortForwarder` class
in the `WebTunnel` library.

Please see the [webtunnelagent.h](include/webtunnelagent.h) header file for
a description of the available types and functions.

Basic usage:
  - `webtunnelagent_init()` must be called before any other functions.
  - `webtunnelagent_cleanup()` must be called as last function when the library
    is no longer used in the program, to clean up internal state and resources.
  - `webtunnelagent_create()` is used to create a connection from to a macchina.io REMOTE server.
  - `webtunnelagent_destroy()` stops the local TCP server for the tunnel connection.
  