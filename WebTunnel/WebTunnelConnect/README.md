# macchina.io REMOTE Connect (remote-connect)

`remote-connect` is a command-line program that sets up a TCP connection from your
local machine (e.g., your PC, Mac, etc.) to a device connected to the macchina.io
REMOTE. The connection is then exposed via standard input/output. This enables 
`remote-connect` to be used in a similar way to `netcat` (`nc`).

Additionally, `remote-connect` can be used with the `ProxyCommand` configuration
directive of OpenSSH, enabling an alternative way of connecting to a remote device
via SSH in addition to the `remote-ssh` command.

## Running remote-connect

`remote-connect` usually does not need a configuration file, most parameters can be passed
via command-line arguments. Some settings can be set using a configuration file
(see the `remote-client` [documentation](../WebTunnelClient/README.md) for more
information on configuration files). 

At startup, `remote-connect` will look for a configuration file named 
`.remote-connect.properties` or `.remote-client.properties`
in the current user's home directory, and read it if it's present. 

To run `remote-connect`, you'll need to specify the host name of the remote device to connect
to, as well as the port number, e.g. 8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io:22.

Username and password for the macchina.io REMOTE server must be either passed via command-line 
options, via a configuration file, or via environment variables 
`REMOTE_USERNAME` and `REMOTE_PASSWORD`. 
`remote-connect` will not prompt for username and password, and will fail to connect if 
username and password are not specified.

Example:

```
remote-connect -u johndoe -p s3cr3t 8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io:80
```

The above command connects to port 80 (web server) of the target device. It's then possible
to send a HTTP request to the device via standard input.

### Using remote-connect with OpenSSH

The OpenSSH `ProxyCommand` can be used to have the OpenSSL client connect via `remote-connect`.
This has some advantages over the `remote-ssh` program. Most importantly, other programs that
use `ssh` to connect to a device can now be used with remote devices via macchina.io REMOTE,
by providing a `ProxyCommand` configuration directive, either on the command-line or via
the OpenSSH configuration file (`~/.ssh/config`).

#### Command Line

```
export REMOTE_USERNAME=johndoe
export REMOTE_PASSWORD=s3cr3t
ssh -o 'ProxyCommand remote-connect 8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io:80' pi@8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io
```

#### Configuration File

`~/.ssh/config`:
```
Host 188d3d96-b14e-4804-a6c6-4407af5108a3.remote.macchina.io
  ProxyCommand remote-connect -u johndue -p s3cr3t 188d3d96-b14e-4804-a6c6-4407af5108a3.remote.macchina.io:22
```

SSH Command:
```
ssh pi@188d3d96-b14e-4804-a6c6-4407af5108a3.remote.macchina.io
```

### Command-Line Arguments Help

You can run `remote-connect` without command-line options (or with `--help`
or `/help` on Windows) to see a help screen with available command-line options.
