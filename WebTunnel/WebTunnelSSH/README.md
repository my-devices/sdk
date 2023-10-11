# macchina.io REMOTE SSH Client Wrapper (remote-ssh)

`remote-ssh` is a command-line program that sets up a tunnel for a SSH connection from your
local machine (e.g., your PC, Mac, etc.) to a device connected to the macchina.io
REMOTE, and then launches an SSH client to open an SSH session.

Note that in contrast to `WebTunnelAgent`, which typically runs on an embedded or IoT
device, `remote-ssh`, like `remote-client`, runs on a PC or Mac that you want to connect to the
device. You'll have to build the [macchina.io REMOTE SDK](../../README.md)
for your machine to get the `remote-ssh` program.

## Running remote-ssh

`remote-ssh` usually does not need a configuration file, most parameters can be passed
via command-line arguments. Some settings can be set using a configuration file
(see the `remote-client` [documentation](../WebTunnelClient/README.md) for more
information on configuration files). 

At startup, `remote-ssh` will look for a configuration file named 
`.remote-ssh.properties` or `.remote-client.properties`
in the current user's home directory, and read it if it's present. 

To run `remote-ssh`, you'll need to specify the URL of the remote device to connect
to (e.g. https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io), as well as the
user name to connect to.

```
remote-ssh -l pi https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io
```

If running on Windows, the parameters must be passed Windows-style:

```
remote-ssh /l pi https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io
```

It is also possible to specify remote username and remote device address in one argument:

```
remote-ssh pi@8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io
```

On Windows, `remote-ssh` first looks for `ssh.exe`, which is
available in newer releases of Windows 10 as an
[optional install](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse).
If `ssh.exe` cannot be found in the executables search path (`PATH` environment variable),
`remote-ssh` looks for `putty.exe`. If no SSH client executable could be found, and also
no executable has been configured (using the `ssh.executable` configuration property
or `/ssh-client` command-line argument), an error message is printed and
`remote-ssh` exits.

`remote-ssh` will prompt for your macchina.io REMOTE username and password and
then launch the SSH client with correct parameters for host, port number and
remote SSH login name.

The macchina.io REMOTE username and password can also be supplied via environment
variables `REMOTE_USERNAME` and `REMOTE_PASSWORD`, or via a configuration file.

Like [`remote-client`](../WebTunnelClient/README.md), `remote-ssh` can also connect through a 
[proxy server](../WebTunnelClient/READMD.md#connecting-trough-a-http-proxy).

### Disabling Host Fingerprint Checking and Authenticity Warning

When connecting via SSH to a remote host with `remote-ssh`, the `ssh` client will
usually warn you that the authenticity of the remote host can't be established, and
will prompt you to continue. This can be annoying, especially since `remote-ssh`
normally uses an ephemeral (random) port number that `ssh` connects to. Therefore
you will also end up with lots of entries in your `known_hosts` file.
This can be disabled by adding the following section to the `ssh` configuration
file (usually located in `~/.ssh/config`):

```
Host localhost
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel QUIET
```

The above settings will disable validation of the remote host key and prevent warnings
when `ssh` connects to `localhost`, as it does when invoked from `remote-ssh`.
It also prevents `ssh` from writing an entry to the `known_hosts` file.

### Using remote-ssh for Transferring Files Using SCP

On platforms supporting the `scp` program for secure file transfers, `remote-ssh`
can also be used to launch `scp` instead of `ssh`.

However, there's also a separate [`remote-scp`](../WebTunnelSCP/README.md)
client program which is a bit easier to use.

To copy a file `file.txt` to the remote system using `scp` with `remote-ssh`:

```
remote-ssh --scp https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io file.txt pi@localhost:file.txt
```

or, on Windows 10 (with SSH):

```
remote-ssh /scp https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io file.txt pi@localhost:file.txt
```

Note that the remote host name must be specified as `localhost` in this case, as
`scp` actually connects to a local port that is forwarded by `remote-ssh` to the
remote device.

### Passing Options to the SSH Client

`remote-ssh` can pass command-line options to the SSH client. SSH command-line arguments
are given on the `remote-ssh` command-line, separated with a `--`. For example, to use
a private key for authentication:

```
remote-ssh -l pi https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io -- -i ~/.ssh/mysecret
```

### Passing a Command or Script to the SSH Client

`remote-ssh` can pass a command for the remote system to `ssh`.
To do so, specify the command using the `--command` (short: `-m`; Windows: `/command`) option.
The given command will be passed to `ssh` after the extra options and the hostname:

```
remote-ssh -l pi -m "ls -l" https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io
```

This can also be used to run a script (via pipe of redirection of stdin).
However, in this case, the macchina.io REMOTE username and password must be passed as
command-line arguments, and `bash` or another shell must be specified as command to execute via `ssh`:

```
remote-ssh -l pi -u rmuser -p rmpasswd -m bash https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io <script.sh
```

### Command-Line Arguments Help

You can run `remote-ssh` without command-line options (or with `--help`
or `/help` on Windows) to see a help screen with available command-line options.
