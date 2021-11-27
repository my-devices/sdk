# macchina.io REMOTE SSH Client Wrapper (WebTunnelSSH)

`WebTunnelSSH` is a command-line program that sets up a tunnel for a SSH connection from your
local machine (e.g., your PC, Mac, etc.) to a device connected to the macchina.io
REMOTE, and then launches an SSH client to open an SSH session.

Note that in contrast to `WebTunnelAgent`, which typically runs on an embedded or IoT
device, `WebTunnelSSH`, like `WebTunnelClient`, runs on a PC or Mac that you want to connect to the
device. You'll have to build the [macchina.io REMOTE SDK](../../README.md)
for your machine to get the `WebTunnelSSH` program.

## Running WebTunnelSSH

`WebTunnelSSH` does not need a configuration file, all parameters can be passed
via command-line arguments. Some settings can also be set using a configuration file
(see the `WebTunnelAgent` [documentation](../WebTunnelAgent/README.md) for more
information on configuration files), but in most cases no configuration file is needed.

To run `WebTunnelSSH`, you'll need to specify the URL of the remote device to connect
to (e.g. https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net), as well as the
user name to connect to.

```
WebTunnelSSH -l pi https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net
```

If running on Windows, the parameters must be passed Windows-style:

```
WebTunnelSSH /l pi https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net
```

Furthermore, on Windows, `WebTunnelSSH` first looks for `ssh.exe`, which is
available in newer releases of Windows 10. If `ssh.exe` cannot be found in the
executables search path (`PATH` environment variable), `WebTunnelSSH` looks
for `putty.exe`. If no SSH client executable could be found, and also no
executable has been configured (using the `ssh.executable` configuration property
or `/ssh-client` command-line argument), an error message is printed and
`WebTunnelSSH` exits.

`WebTunnelSSH` will prompt for your macchina.io REMOTE username and password and
then launch the SSH client with correct parameters for host, port number and
remote user name.

### Using WebTunnelSSH for Transferring Files Using SCP

On platforms supporting the `scp` program for secure file transfers, `WebTunnelSSH`
can also be used to launch `scp` instead of `ssh`.

To copy a file `file.txt` to the remote system using `scp`.

```
WebTunnelSSH --scp https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net file.txt pi@localhost:file.txt
```

or, on Windows 10 (with SSH):

```
WebTunnelSSH /scp https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net file.txt pi@localhost:file.txt
```

Note that the remote host name must be specified as `localhost` in this case, as
`scp` actually connects to a local port that is forwarded by `WebTunnelSSH` to the
remote device.

### Passing Options to the SSH Client

`WebTunnelSSH` can pass command-line options to the SSH client. SSH command-line arguments
are given on the `WebTunnelSSH` command-line, separated with a `--`. For example, to use
a private key for authentication:

```
WebTunnelSSH -l pi https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net -- -i ~/.ssh/mysecret
```

### Passing a Command or Script to the SSH Client

`WebTunnelSSH` can pass a command for the remote system to `ssh`.
To do so, specify the command using the `--command` (short: `-m`; Windows: `/command`) option.
The given command will be passed to `ssh` after the extra options and the hostname:

```
WebTunnelSSH -l pi -m "ls -l" https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net
```

This can also be used to run a script (via pipe of redirection of stdin).
However, in this case, the macchina.io REMOTE username and password must be passed as
command-line arguments, and `bash` or another shell must be specified as command to execute via `ssh`:

```
WebTunnelSSH -l pi -u rmuser -p rmpasswd -m bash https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net <script.sh
```

### Command-Line Arguments Help

You can run `WebTunnelSSH` without command-line options (or with `--help`
or `/help` on Windows) to see a help screen with available command-line options.
