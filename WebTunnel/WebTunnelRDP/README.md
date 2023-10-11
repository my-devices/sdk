# macchina.io REMOTE RDP Client Wrapper (remote-rdp)

`remote-rdp` is a command-line program that sets up a tunnel for a Microsoft Remote Desktop connection from your
local machine (e.g., your PC, Mac, etc.) to a device connected to the macchina.io
REMOTE, and then launches the Microsoft Remote Desktop client to open a RDP session.

Note that in contrast to `WebTunnelAgent`, which typically runs on an embedded or IoT
device, `remote-rdp`, like `remote-client` and `WebTunnelSSH`, runs on a PC or Mac that you want to connect to the
device. You'll have to build the [macchina.io REMOTE SDK](../../README.md)
for your machine to get the `remote-rdp` program.

## Running remote-rdp

`remote-rdp` usually does not need a configuration file, most parameters can be passed
via command-line arguments. Some settings can be set using a configuration file
(see the `remote-client` [documentation](../WebTunnelClient/README.md) for more
information on configuration files). 

At startup, `remote-rdp` will look for a configuration file named 
`.remote-rdp.properties` or `.remote-client.properties`
in the current user's home directory, and read it if it's present. 

To run `remote-rdp`, you'll need to specify the URL of the remote device to connect
to (e.g. https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io).

```
remote-rdp https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io
```

`remote-rdp` will prompt for your macchina.io REMOTE username and password and
then launch the Remote Desktop client with correct parameters for host and port number.

The macchina.io REMOTE username and password can also be supplied via environment
variables `REMOTE_USERNAME` and `REMOTE_PASSWORD`, or via a configuration file.

The following RDP clients are used:

  - `mstsc.exe` on Windows
  - [`Microsoft Remote Desktop.app`](https://apps.apple.com/us/app/microsoft-remote-desktop/id1295203466) on macOS (launched via a temporarily created `.rdp` file)
  - [`xfreerdp`](https://www.freerdp.com) on Linux and other Unix platforms

Like [`remote-client`](../WebTunnelClient/README.md), `remote-rdp` can also connect through a 
[proxy server](../WebTunnelClient/README.md#connecting-trough-a-http-proxy).

### Command-Line Arguments Help

You can run `remote-rdp` without command-line options (or with `--help`
or `/help` on Windows) to see a help screen with available command-line options.
