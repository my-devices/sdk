# macchina.io REMOTE SCP Client Wrapper (remote-scp)

`remote-scp` is a command-line program that sets up a tunnel for a SCP
(SSH/Secure File Copy) connection from your local machine
(e.g., your PC, Mac, etc.) to a device connected to the macchina.io
REMOTE, and then launches an SCP client to open copy a file.

Note that in contrast to `WebTunnelAgent`, which typically runs on an embedded or IoT
device, `remote-scp`, like `remote-client`, runs on a PC or Mac that you want to connect
to the device. You'll have to build the [macchina.io REMOTE SDK](../../README.md)
for your machine to get the `remote-scp` program.

## Running remote-scp

`remote-scp` does not need a configuration file, all parameters can be passed
via command-line arguments. Some settings can also be set using a configuration file
(see the `WebTunnelAgent` [documentation](../WebTunnelAgent/README.md) for more
information on configuration files), but in most cases no configuration file is needed.

To run `remote-scp`, you'll need to specify the macchina.io REMOTE fully-qualified
host name of the remote device to connect to (e.g. 8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io),
as well as the SSH login to connect with.

To copy a file (`file.txt`) from the remote device (`8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io`)
to the local machine's current directory (`.`), using remote SSH login `pi`:
```
remote-scp pi@8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io:file.txt .
```

To copy a file (`file.txt`) from the local machine to the home directory on the remote device
(`8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io`), using remote SSH login `pi`:
```
remote-scp file.txt pi@8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io:
```

`remote-scp` will prompt for your macchina.io REMOTE username and password, set-up
the tunnel connection and then launch the `scp` client program with correct parameters
for host, port number and remote user name.

The macchina.io REMOTE username and password can also be supplied via environment
variables `REMOTE_USERNAME` and `REMOTE_PASSWORD`.

### Passing Options to the SCP Client

`remote-scp` can pass command-line options to the SCP client. SCP command-line arguments
are given on the `remote-scp` command-line, separated with a `--`. For example, to use
a private key for authentication:

```
remote-scp -- -i ~/.ssh/mysecret pi@8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io:file.txt .
```

On Windows, the `--` is not required.

### Command-Line Arguments Help

You can run `remote-scp` without command-line options (or with `--help`
or `/help` on Windows) to see a help screen with available command-line options.
