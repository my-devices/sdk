# macchina.io REMOTE VNC Client Wrapper (remote-vnc)

`remote-vnc` is a command-line program that sets up a tunnel for a VNC remote desktop connection from your
local machine (e.g., your PC, Mac, etc.) to a device connected to the macchina.io
REMOTE, and then launches a VNC client to open a VNC session.

Note: macchina.io REMOTE has a built-in web-based VNC viewer, so `remote-vnc` only
needs to be used if the web-based VNC viewer does not work with a specific device
or cannot be used for other reasons.

Note that in contrast to `WebTunnelAgent`, which typically runs on an embedded or IoT
device, `remote-vnc`, like `remote-client` and `WebTunnelSSH`, runs on a PC or Mac that you want to connect to the
device. You'll have to build the [macchina.io REMOTE SDK](../../README.md)
for your machine to get the `remote-vnc` program.

## Running remote-vnc

`remote-vnc` usually does not need a configuration file, most parameters can be passed
via command-line arguments. Some settings can be set using a configuration file
(see the `remote-client` [documentation](../WebTunnelClient/README.md) for more
information on configuration files). 

At startup, `remote-vnc` will look for a configuration file named 
`.remote-vnc.properties` or `.remote-client.properties`
in the current user's home directory, and read it if it's present. 

To run `remote-vnc`, you'll need to specify the URL of the remote device to connect
to (e.g. https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io).

```
remote-vnc https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io
```

`remote-vnc` will prompt for your macchina.io REMOTE username and password and
then launch the VNC client with correct parameters for host, port number and
remote user name.

The macchina.io REMOTE username and password can also be supplied via environment
variables `REMOTE_USERNAME` and `REMOTE_PASSWORD`, or via a configuration file.

Like [`remote-client`](../WebTunnelClient/README.md), `remote-vnc` can also connect through a 
[proxy server](../WebTunnelClient/README.md#connecting-trough-a-http-proxy).

On macOS, `remote-vnc` will launch the built-in macOS Screen Sharing client.
On other platforms, `remote-vnc` will attempt to launch an executable
named `vncviewer`, which must be in the executable search path.


### Specifying the VNC Viewer Executable to Use

The name of the VNC viewer executable can be changed by setting the
`vncviewer.executable` configuration property, which can be done via a
command-line parameter:

```
remote-vnc https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io -Dvncviewer.executable=myvncviewer
```

Or, on Windows:

```
remote-vnc https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io /define:vncviewer.executable=myvncviewer
```


### Command-Line Arguments Help

You can run `remote-vnc` without command-line options (or with `--help`
or `/help` on Windows) to see a help screen with available command-line options.
