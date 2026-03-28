# macchina.io REMOTE Login (remote-login)

`remote-login` is a command-line program that obtains an OAuth 2.0 token (JWT) from
the macchina.io REMOTE server. The program will ask the user for their
username and password (unless these are provided via command-line parameters).

The program then uses the macchina.io REMOTE server API to request a token,
using the given credentials. If the user has two-factor authentication enabled
on the server, the program will also ask for a time-based one-time password (TOTP),
typically provided by an authenticator app like Authy or Google Authenticator.

The received token will then be stored in the file `.remote-credentials.properties`
in the user's home directory. If present, this file will be read by all macchina.io REMOTE
client programs (`remote-client`, `remote-ssh`, etc.) on startup, and the stored
token will be used for authentication against the macchina.io REMOTE server.

The main advantage of `remote-login` over using environment variables or
configuration files to store the credentials is that only the token is
stored on the local machine. The token has a limited validity, typically
24 hours, controlled through the macchina.io REMOTE server configuration.

## Running remote-login

At startup, `remote-login` will look for a configuration file named
`.remote-login.properties`  in the current user's home directory, and read it if it's present.

To request a token, run `remote-login` without parameters. The program will ask
for a username and password, and, if two-factor authentication has been enabled for
the user, will also ask for a time-based one-time password.

If no further command-line parameters or configuration files are given, `remote-login`
will use https://remote.macchina.io to obtain the token. To use a different server,
specify the `--reflector-uri` command-line parameter, e.g.:

```
remote-login --reflector-uri=https://remote.company.com
```

Alternatively, you can create a configuration file
(`.remote-login.properties` in the home directory) containing:

```
remote.reflectorURI = https://remote.company.com
```

To check the validity of an existing token, run:

```
remote-login --status
```

To clear the token (and delete the `.remote-credentials.properties` file), run:

```
remote-login --clear
```

### Command-Line Arguments Help

You can run `remote-login` without command-line options (or with `--help`
or `/help` on Windows) to see a help screen with available command-line options.

## Configuration

### SSL/TLS Configuration

Please refer to the [`WebTunnelAgent`](../WebTunnelAgent/README.md#ssltls-configuration)
documentation for SSL/TLS configuration settings.

### HTTP Proxy Configuration

Please refer to the [`WebTunnelAgent`](../WebTunnelAgent/README.md#http-configuration)
documentation for configuring a HTTP proxy, including proxy credentials.
