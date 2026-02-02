# macchina.io REMOTE SDK Changes


## Release 2.4.0 (2026-02-02)

- WebTunnelAgent: allow specifying a designated OpenVPN port number in the
  list of forwarded ports in the configuration file (`webtunnel.vpnPort`).
- Fixed a build error with GCC 15.
- Improved network error handling.
- Upgraded libraries.


## Release 2.3.2 (2025-05-05)

- Fixed an issue where a connection refused error would not be detected on
  macOS or BSD when connecting to a server. Instead, the connect operation
  would time out.
- Improved error reporting.
- Optimized network code.


## Release 2.3.1 (2025-04-15)

- Fixed an issue in WebTunnelAgent/RemotePortForwarder where in rare cases automatic
  reconnect would not be triggered if the connection to the server was interrupted
  (e.g., by a server restart).


## Release 2.3.0 (2025-04-05)

- Fixed a compile error on macOS Sequoia 15.4 by upgrading the bundled zlib library.


## Release 2.2.0 (2025-03-17)

- Fixed an issue with high CPU usage during SSL/TLS negotiations.
- Improved internal connection error handling.


## Release 2.1.1 (2025-03-11)

- Fixed an issue in WebTunnelAgent/RemotePortForwarder: closing the WebTunnel connection
  leads to a high number of error messages with some load balancers.


## Release 2.1.0 (2025-02-17)

- Fixed an issue that could lead to excessive memory usage.


## Release 2.0.0 (2025-01-28)

- The WebTunnel protocol implementation has been changed to use non-blocking sockets.
- Connecting to local web servers over HTTPS (TLS) now works reliably.
- Applications now support a --version command-line parameter.


## Release 1.17.2 (2024-02-01)

- Fixed a multithreading issue with OpenSSL that would cause random connection drops in
  client connections (`remote-client`, `remote-ssh`, etc.).


## Release 1.17.0 (2023-10-27)

- added macchina.io REMOTE Agent Library (libWebTunnelAgent), which provides a C interface to macchina.io REMOTE agent (`WebTunnelAgent`) features for integration into applications that cannot use the C++ implementation
- clients (`remote-client`, `remote-ssh`, etc.) can now use a user-specific default configuration file (`~/.remote-client.properties` for all clients, or `~/.remote.ssh.properties`, etc. for specific clients)
- the macchina.io REMOTE username and passwords for the clients can be specified via environment variables `REMOTE_USERNAME` and `REMOTE_PASSWORD` to avoid having to enter every time
- `remote-ssh`, `remote-scp` and `remote-sftp` support the `-i` option to pass an identify file (private key)
- upgraded bundled POCO C++ Libraries to 1.11.8


## Release 1.16.0 (2023-08-31)

- added macchina.io REMOTE Client Library (libWebTunnelClient), which provides a C interface to macchina.io REMOTE client features for integration into applications that cannot use the C++ implementation
- added support for building on iOS and Android
- upgraded bundled POCO C++ Libraries to 1.11.7


## Release 1.15.0 (2023-01-30)

- Fixed a race condition (#12) that could lead to random connection failures when connecting to a VNC or SSH server.
- Minor improvements
- Upgraded POCO C++ Libraries to 1.11.6.
