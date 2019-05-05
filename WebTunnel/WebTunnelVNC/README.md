# macchina.io Remote Manager VNC Client Wrapper (WebTunnelVNC)

`WebTunnelVNC` is a command-line program that sets up a tunnel for a VNC remote desktop connection from your
local machine (e.g., your PC, Mac, etc.) to a device connected to the macchina.io
Remote Manager, and then launches a VNC client to open a VNC session.

Note: Remote Manager has a built-in web-based VNC viewer, so `WebTunnelVNC` only
needs to be used if the web-based VNC viewer does not work with a specific device
or cannot be used for other reasons.

Note that in contrast to `WebTunnelAgent`, which typically runs on an embedded or IoT
device, `WebTunnelVNC`, like `WebTunnelClient` and `WebTunnelSSH`, runs on a PC or Mac that you want to connect to the
device. You'll have to build the [macchina.io Remote Manager SDK](../../README.md)
for your machine to get the `WebTunnelVNC` program.

## Running WebTunnelVNC

`WebTunnelVNC` does not need a configuration file, all parameters can be passed
via command-line arguments. Some settings can also be set using a configuration file
(see the `WebTunnelAgent` [documentation](../WebTunnelAgent/README.md) for more
information on configuration files), but in most cases no configuration file is needed.

To run `WebTunnelVNC`, you'll need to specify the URL of the remote device to connect
to (e.g. https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net).

```
WebTunnelVNC https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net
```

`WebTunnelVNC` will prompt for your Remote Manager username and password and
then launch the VNC client with correct parameters for host, port number and
remote user name.

On macOS, `WebTunnelVNC` will launch the built-in macOS Screen Sharing client.
On other platforms, `WebTunnelVNC` will attempt to launch an executable
named `vncviewer`, which must be in the executable search path.


### Specifying the VNC Viewer Executable to Use

The name of the VNC viewer executable can be changed by setting the
`vncviewer.executable` configuration property, which can be done via a
command-line parameter:

```
WebTunnelVNC https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net -Dvncviewer.executable=myvncviewer
```

Or, on Windows:

```
WebTunnelVNC https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net /define:vncviewer.executable=myvncviewer
```


### Command-Line Arguments Help

You can run `WebTunnelVNC` without command-line options (or with `--help`
or `/help` on Windows) to see a help screen with available command-line options.
