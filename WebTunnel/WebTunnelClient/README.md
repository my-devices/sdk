# macchina.io Remote Manager Client (WebTunnelClient)

`WebTunnelClient` is a command-line program that sets up a tunnel for a TCP connection from your
local machine (e.g., your PC, Mac, etc.) to a device connected to the macchina.io
Remote Manager.

Note that in contrast to `WebTunnelAgent`, which typically runs on an embedded or IoT
device, `WebTunnelClient` runs on a PC or Mac that you want to connect to the
device. You'll have to build the [macchina.io Remote Manager SDK](../../README.md)
for your machine to get the `WebTunnelClient` program.

## Running WebTunnelClient

`WebTunnelClient` does not need a configuration file, all parameters can be passed
via command-line arguments. Some settings can also be set using a configuration file
(see the `WebTunnelAgent` [documentation](../WebTunnelAgent/README.md) for more
information on configuration files), but in most cases no configuration file is needed.

To run `WebTunnelClient`, you'll need to specify the URL of the remote device to connect
to (e.g. https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net), as well as
the remote port number - the port number on the device you want to connect to, and the
local port number - the port number on your machine that will be forwarded to the device's
remote port.

For example, to forward the SSH port (22) of an embedded Linux device to your local
machine (port 2222), run:

```
WebTunnelClient https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net -R 22 -L 2222
```

If running on Windows, the parameters must be passed Windows-style:

```
WebTunnelClient https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net /remote 22 /local 2222
```

`WebTunnelClient` will prompt for your Remote Manager username and password.
When no longer needed, the tunnel can be terminated by typing `CTRL-C`.

You can now start your SSH client and connect it to port 2222 on your local machine
in order to open an SSH session to your device:

```
ssh pi@localhost -p 2222
```

Note that `pi` in `pi@localhost` actually refers to the `pi` account on the
remote device, not your local machine.

The [`WebTunnelSSH`](../WebTunnelSSH/README.md) program also included in the
SDK simplifies these steps for SSH access to a device, by setting up the tunnel
and then launching the SSH client with correct parameters.

`WebTunnelClient` can also run a command after setting up the tunnel, instead of just
waiting. To do so, use the `--command` (short `-C`, or `/command` on Windows) option
to specify the command. Arguments for the command can be specified at the end of the
command-line, separated by `--`. Example:

```
WebTunnelClient https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net -R 22 -L 2222 -C ssh -- -p 22 localhost
```

Given command to execute, `WebTunnelClient` will terminate as soon as the specified program has
terminated as well.

Like `WebTunnelAgent`, `WebTunnelClient` can be used as a daemon or Windows service.
Please see the [`WebTunnelAgent` documentation](../WebTunnelAgent/README.md) for more information.

You can also run `WebTunnelClient` without command-line options (or with `--help`
or `/help` on Windows) to see a help screen with available command-line options.
