# macchina.io REMOTE RDP Client Wrapper (WebTunnelRDP)

`WebTunnelRDP` is a command-line program that sets up a tunnel for a Microsoft Remote Desktop connection from your
local machine (e.g., your PC, Mac, etc.) to a device connected to the macchina.io
REMOTE, and then launches the Microsoft Remote Desktop client to open a RDP session.

Note that in contrast to `WebTunnelAgent`, which typically runs on an embedded or IoT
device, `WebTunnelRDP`, like `WebTunnelClient` and `WebTunnelSSH`, runs on a PC or Mac that you want to connect to the
device. You'll have to build the [macchina.io REMOTE SDK](../../README.md)
for your machine to get the `WebTunnelRDP` program.

## Running WebTunnelRDP

`WebTunnelRDP` does not need a configuration file, all parameters can be passed
via command-line arguments. Some settings can also be set using a configuration file
(see the `WebTunnelAgent` [documentation](../WebTunnelAgent/README.md) for more
information on configuration files), but in most cases no configuration file is needed.

To run `WebTunnelRDP`, you'll need to specify the URL of the remote device to connect
to (e.g. https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net).

```
WebTunnelRDP https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net
```

`WebTunnelRDP` will prompt for your macchina.io REMOTE username and password and
then launch the Remote Desktop client with correct parameters for host and port number.


### Command-Line Arguments Help

You can run `WebTunnelRDP` without command-line options (or with `--help`
or `/help` on Windows) to see a help screen with available command-line options.
