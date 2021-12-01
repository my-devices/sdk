# macchina.io REMOTE SFTP Client Wrapper (WebTunnelSFTP)

`WebTunnelSFTP` is a command-line program that sets up a tunnel for a SFTP
(Secure/SSH File Transfer Protocol) connection from your local machine
(e.g., your PC, Mac, etc.) to a device connected to the macchina.io
REMOTE, and then launches an SFTP client to open an SFTP session.

Note that in contrast to `WebTunnelAgent`, which typically runs on an embedded or IoT
device, `WebTunnelSFTP`, like `WebTunnelClient`, runs on a PC or Mac that you want to connect
to the device. You'll have to build the [macchina.io REMOTE SDK](../../README.md)
for your machine to get the `WebTunnelSFTP` program.

## Running WebTunnelSFTP

`WebTunnelSFTP` does not need a configuration file, all parameters can be passed
via command-line arguments. Some settings can also be set using a configuration file
(see the `WebTunnelAgent` [documentation](../WebTunnelAgent/README.md) for more
information on configuration files), but in most cases no configuration file is needed.

To run `WebTunnelSFTP`, you'll need to specify the URL of the remote device to connect
to (e.g. https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net), as well as the
user name to connect to.

```
WebTunnelSFTP -l pi https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net
```

If running on Windows, the parameters must be passed Windows-style:

```
WebTunnelSFTP /l pi https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net
```

Furthermore, on Windows, `WebTunnelSFTP` first looks for `sftp.exe`, which is
available in newer releases of Windows 10. If no SFTP client executable could be found,
and also no executable has been configured (using the `sftp.executable` configuration property
or `/sftp-client` command-line argument), an error message is printed and
`WebTunnelSFTP` exits.

`WebTunnelSFTP` will prompt for your macchina.io REMOTE username and password and
then launch the SFTP client with correct parameters for host, port number and
remote user name.

### Command-Line Arguments Help

You can run `WebTunnelSFTP` without command-line options (or with `--help`
or `/help` on Windows) to see a help screen with available command-line options.
