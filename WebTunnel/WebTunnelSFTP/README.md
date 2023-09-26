# macchina.io REMOTE SFTP Client Wrapper (remote-sftp)

`remote-sftp` is a command-line program that sets up a tunnel for a SFTP
(Secure/SSH File Transfer Protocol) connection from your local machine
(e.g., your PC, Mac, etc.) to a device connected to the macchina.io
REMOTE, and then launches an SFTP client to open an SFTP session.

Note that in contrast to `WebTunnelAgent`, which typically runs on an embedded or IoT
device, `remote-sftp`, like `remote-client`, runs on a PC or Mac that you want to connect
to the device. You'll have to build the [macchina.io REMOTE SDK](../../README.md)
for your machine to get the `remote-sftp` program.

## Running remote-sftp

`remote-sftp` does not need a configuration file, all parameters can be passed
via command-line arguments. Some settings can also be set using a configuration file
(see the `WebTunnelAgent` [documentation](../WebTunnelAgent/README.md) for more
information on configuration files), but in most cases no configuration file is needed.

To run `remote-sftp`, you'll need to specify the URL of the remote device to connect
to (e.g. https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io), as well as the
user name to connect to.

```
remote-sftp -l pi https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io
```

If running on Windows, the parameters must be passed Windows-style:

```
remote-sftp /l pi https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io
```

It's also possible to specify remote username and the remote device address in a single
argument:

```
remote-sftp pi@8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io
```

On Windows, `remote-sftp` first looks for `sftp.exe`, which is available in newer
releases of Windows 10 as an optional install. If no SFTP client executable could be found,
and also no executable has been configured (using the `sftp.executable` configuration property
or `/sftp-client` command-line argument), an error message is printed and
`remote-sftp` exits.

`remote-sftp` will prompt for your macchina.io REMOTE username and password and
then launch the SFTP client with correct parameters for host, port number and
remote user name.

The macchina.io REMOTE username and password can also be supplied via environment
variables `REMOTE_USERNAME` and `REMOTE_PASSWORD`.

### Passing Options to the SFTP Client

`remote-sftp` can pass command-line options to the SFTP client. SFTP command-line arguments
are given on the `remote-sftp` command-line, separated with a `--`. For example, to use
a private key for authentication:

```
remote-sftp -l pi https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io -- -i ~/.ssh/mysecret
```

On Windows, the `--` is not required.

### Command-Line Arguments Help

You can run `remote-sftp` without command-line options (or with `--help`
or `/help` on Windows) to see a help screen with available command-line options.
