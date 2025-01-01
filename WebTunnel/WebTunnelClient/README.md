# macchina.io REMOTE Client (remote-client)

`remote-client` is a command-line program that sets up a tunnel for a TCP connection from your
local machine (e.g., your PC, Mac, etc.) to a device connected to the macchina.io
REMOTE.

Note that in contrast to `WebTunnelAgent`, which typically runs on an embedded or IoT
device, `remote-client` runs on a PC or Mac that you want to connect to the
device. You'll have to build the [macchina.io REMOTE SDK](../../README.md)
for your machine to get the `remote-client` program.

In addition to `remote-client`, there are also more specialized command-line client
programs for specific protocols:

  - [`remote-ssh`](../WebTunnelSSH/README.md): This is a variant of `remote-client` that first
    creates a tunnel connection from your local machine (Windows, macOS or Linux) to the remote device,
    then launches a SSH client using that tunnel connection.
  - [`remote-scp`](../WebTunnelSCP/README.md): This is a variant of `remote-client` that first
    creates a tunnel connection from your local machine (Windows, macOS or Linux) to the remote device,
    then launches a SCP (Secure/SSH File Copy) client (`scp`) using that tunnel connection.
  - [`remote-sftp`](../WebTunnelSFTP/README.md): This is a variant of `remote-client` that first
    creates a tunnel connection from your local machine (Windows, macOS or Linux) to the remote device,
    then launches a SFTP (Secure/SSH File Transfer Protocol) client using that tunnel connection.
  - [`remote-vnc`](../WebTunnelVNC/README.md): This is a variant of `remote-client` that first
    creates a tunnel connection from your local machine (Windows, macOS or Linux) to a remote device
    running a VNC (Virtual Network Computing) server, then launches a VNC remote desktop client using
    that tunnel connection.
  - [`remote-rdp`](../WebTunnelRDP/README.md): This is a variant of `remote-client` that first
    creates a tunnel connection from your local machine (Windows, macOS) to a remote Windows device
    (which must have the remote desktop feature enabled), then launches a Microsoft Remote Desktop (RDP)
    client using that tunnel connection.

## Running remote-client

`remote-client` usually does not need a configuration file, most parameters can be passed
via command-line arguments. Some settings can be set using a configuration file
(see the `WebTunnelAgent` [documentation](../WebTunnelAgent/README.md#configuration-file-format) for more
information on configuration files). Also, see the [Configuration](#configuration) section below. 

At startup, `remote-client` will look for a configuration file `.remote-client.properties` 
in the current user's home directory, and read it if it's present.

To run `remote-client`, you'll need to specify the URL of the remote device to connect
to (e.g. https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io), as well as
the remote port number - the port number on the device you want to connect to, and the
local port number - the port number on your machine that will be forwarded to the device's
remote port.

For example, to forward the SSH port (22) of an embedded Linux device to your local
machine (port 2222), run:

```
remote-client https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io -R 22 -L 2222
```

If running on Windows, the parameters must be passed Windows-style:

```
remote-client https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io /remote 22 /local 2222
```

`remote-client` will prompt for your macchina.io REMOTE username and password.
When no longer needed, the tunnel can be terminated by typing `CTRL-C`.

The macchina.io REMOTE username and password can also be supplied via environment
variables `REMOTE_USERNAME` and `REMOTE_PASSWORD`, or via the configuration file.

You can now start your SSH client and connect it to port 2222 on your local machine
in order to open an SSH session to your device:

```
ssh pi@localhost -p 2222
```

Note that `pi` in `pi@localhost` actually refers to the `pi` account on the
remote device, not your local machine.

The [`WebTunnelSSH`](../WebTunnelSSH/README.md) program also included in the
SDK simplifies these steps for SSH access to a device, by setting up the tunnel
and then launching the SSH client with correct parameters.

`remote-client` can also run a command after setting up the tunnel, instead of just
waiting. To do so, use the `--command` (short `-C`, or `/command` on Windows) option
to specify the command. Arguments for the command can be specified at the end of the
command-line, separated by `--`. Example:

```
remote-client https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io -R 22 -L 2222 -C ssh -- -p 22 localhost
```

Given command to execute, `remote-client` will terminate as soon as the specified program has
terminated as well.

Like `WebTunnelAgent`, `remote-client` can be used as a daemon or Windows service.
Please see the [`WebTunnelAgent` documentation](../WebTunnelAgent/README.md) for more information.

You can also run `remote-client` without command-line options (or with `--help`
or `/help` on Windows) to see a help screen with available command-line options.

## Connecting Trough a HTTP Proxy

In some environments it may be required to connect to the macchina.io REMOTE server
via a HTTP proxy. This can be done by providing the address of the proxy server
on the command-line (`--proxy`, `-P` for short, or `/proxy` on Windows), or by providing the
proxy server and optionally credentials for the proxy server in a configuration file 
(see below).

Below is an example for specifying a proxy server on the command-line:

```
remote-client https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io -R 22 -L 2222 -P http://proxy.nowhere.com:8080
```

## Configuration

`remote-client` can optionally read settings from a configuration file. A configuration file
can be specified on the command-line with the `--config-file` (or `/config-file` on Windows) option.
Also, specific configuration options can also be set with the `--define` (or `/define`) option.

At startup, `remote-client` will also look for a configuration file named `.remote-client.properties`
in the user's home directory and read it if it is present. If that file is not present,
`remote-client` will attempt to read a configuration file named `remote-client.properties` located
in the same directory as the `remote-client` executable, or a parent directory.

Please refer to the [`WebTunnelAgent`](../WebTunnelAgent/README.md#configuration-file-format)
documentation for the configuration file format.

The following settings can be provided via a configuration file:

### Credentials

  - `remote.username`: The username for the macchina.io REMOTE server.
  - `remote.password`: The password for the macchina.io REMOTE server.
  - `remote.token`: A token (JSON Web Token) for authenticating against the macchina.io REMOTE server.
    If a token is given, username and password are not required. NOTE: A token is supported
    by `remote-client` only, not any of the other client programs like `remote-ssh`.

Credentials specified in command-line arguments or via environment variables 
(`REMOTE_USERNAME`, `REMOTE_PASSWORD`) will override those in a configuration file.

When storing credentials in the configuration file, make sure to keep your configuration
file secure. From a security perspective it's recommended to not store the credentials
in a file in clear-text.

### SSL/TLS Configuration

Please refer to the [`WebTunnelAgent`](../WebTunnelAgent/README.md#ssltls-configuration)
documentation for SSL/TLS configuration settings.

### HTTP Proxy Configuration

Please refer to the [`WebTunnelAgent`](../WebTunnelAgent/README.md#http-configuration)
documentation for configuring a HTTP proxy, including proxy credentials.

### Logging

Please refer to the [`WebTunnelAgent`](../WebTunnelAgent/README.md#logging)
documentation for configuring logging.
