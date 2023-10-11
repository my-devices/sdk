# The macchina.io REMOTE SDK and Tools

## About macchina.io REMOTE

[macchina.io REMOTE](https://macchina.io/remote) provides secure remote access to connected devices
via HTTP or other TCP-based protocols and applications such as secure shell (SSH),
secure file transfer (SFTP), Virtual Network Computing (VNC) or remote desktop (RDP).
With macchina.io REMOTE, any network-connected device
running the macchina.io REMOTE Device Agent software (`WebTunnelAgent`, contained in this SDK)
can be securely accessed remotely over the internet from browsers, mobile apps, desktop,
server or cloud applications.

This even works if the device is behind a NAT router, firewall or proxy server.
The device becomes just another host on the internet, addressable via its own URL and
protected by the macchina.io REMOTE server against unauthorized or malicious access.
macchina.io REMOTE is a great solution for secure remote support and maintenance,
as well as for providing secure remote access to devices for end-users via web or
mobile apps.

Visit [macchina.io/remote](https://macchina.io/remote) to learn more and to register for a free account.
Specifically, see the [Getting Started](https://macchina.io/remote_signup.html) page and the
[Frequently Asked Questions](https://macchina.io/remote_faq.html) for
information on how to use this SDK and the included `WebTunnelAgent` executable.

There is also a [blog post](https://macchina.io/blog/?p=257) showing step-by-step instructions to connect a Raspberry Pi.


## About This SDK

The macchina.io REMOTE SDK is based on the
[POCO C++ Libraries](https://pocoproject.org). You may want to read README_POCO
as well as it contains important information regarding the directory structure
and the build system of the SDK.

The SDK contains the `WebTunnel` library, which implements the tunnel protocol used by macchina.io REMOTE.
Furthermore, the following executables are included:

  - [`WebTunnelAgent`](WebTunnel/WebTunnelAgent/README.md): This executable, also known as
    **macchina.io REMOTE Device Agent**, runs on the device and creates the secure tunnel between the device
    and the macchina.io REMOTE server. This is the most important component of the macchina.io REMOTE SDK.
  - [`remote-client`](WebTunnel/WebTunnelClient/README.md): This executable can run on a client machine
    (Windows, macOS or Linux) to create a secure tunnel from the client machine to the remote device, via
    the macchina.io REMOTE server. It is required for tunneling TCP-based protocols not directly supported by
    macchina.io REMOTE, such Modbus/TCP, OPC-UA, database connections, etc.
  - [`remote-ssh`](WebTunnel/WebTunnelSSH/README.md): This is a variant of `remote-client` that first
    creates a tunnel connection from your local machine (Windows, macOS or Linux) to the remote device,
    then launches a SSH client using that tunnel connection.
  - [`remote-scp`](WebTunnel/WebTunnelSCP/README.md): This is a variant of `remote-client` that first
    creates a tunnel connection from your local machine (Windows, macOS or Linux) to the remote device,
    then launches a SCP (Secure/SSH File Copy) client (`scp`) using that tunnel connection.
  - [`remote-sftp`](WebTunnel/WebTunnelSFTP/README.md): This is a variant of `remote-client` that first
    creates a tunnel connection from your local machine (Windows, macOS or Linux) to the remote device,
    then launches a SFTP (Secure/SSH File Transfer Protocol) client using that tunnel connection.
  - [`remote-vnc`](WebTunnel/WebTunnelVNC/README.md): This is a variant of `remote-client` that first
    creates a tunnel connection from your local machine (Windows, macOS or Linux) to a remote device
    running a VNC (Virtual Network Computing) server, then launches a VNC remote desktop client using
    that tunnel connection.
  - [`remote-rdp`](WebTunnel/WebTunnelRDP/README.md): This is a variant of `remote-client` that first
    creates a tunnel connection from your local machine (Windows, macOS) to a remote Windows device
    (which must have the remote desktop feature enabled), then launches a Microsoft Remote Desktop (RDP)
    client using that tunnel connection.

There is also [`WebTunnelClientLib`](WebTunnel/WebTunnelClientLib/README.md), which provides the
functionality of `remote-client` in a C API, suitable for integration into applications (not written in C++).

The macchina.io REMOTE SDK is licensed under the [Boost Software License](https://spdx.org/licenses/BSL-1.0).


## Pre-Built Executables

Pre-built executables for Windows, macOS and some Linux distributions
(including Raspberry Pi OS) are available from the [macchina.io website](https://macchina.io/remote_downloads.html).


## Easy Install from Source (Linux and macOS)

The easiest way to install the above mentioned executables on a Linux or macOS system
from source is to download and run the
[installer script](https://github.com/my-devices/agent-installer/blob/master/install.sh)
with the following command:

```
$ curl https://raw.githubusercontent.com/my-devices/agent-installer/master/install.sh | bash
```

The script should work on most Debian and RedHat-based Linux distributions including
Ubuntu and Raspberry Pi OS. On macOS, [Homebrew](https://brew.sh) must be installed.

The script will install all required dependencies, then get the sources from
GitHub and run the steps necessary (see below) to build and install the binaries in `/usr/local/bin/`.

If you do not want to or cannot run the installer script, please see the following
instructions.


## External Dependecies

### Libraries

The macchina.io REMOTE SDK requires OpenSSL 1.0 or newer
on Linux and macOS systems.
We recommend using OpenSSL version 1.1.1l or newer (including OpenSSL 3).

Most Unix/Linux systems already have OpenSSL preinstalled. If your system
does not have OpenSSL, please get it from <https://www.openssl.org> or
another source. You do not have to build OpenSSL yourself - a binary
distribution is fine. For example, via Debian APT:

```
$ apt-get install openssl libssl-dev
```

On macOS, the easiest way to install OpenSSL is via [Homebrew](https://brew.sh):

```
$ brew install openssl
```

On Windows, OpenSSL is optional. The default (with CMake) is to build using
Windows native SSL/TLS support. However, it's also possible to use OpenSSL instead.
The easiest way to install OpenSSL on Windows is to use a binary
(prebuild) release, for example the one from Shining Light
Productions that comes with a
[Windows installer](https://www.slproweb.com/products/Win32OpenSSL.html).

### Toolchain

A C++ compiler (C++14 or newer) is required to build the SDK and applications.
The system's default compiler (gcc on Linux, clang on macOS) should be fine on
reasonably recent systems.
On Windows, Visual C++ is recommended (any version from 2015 to 2019 will do).

[CMake](https://cmake.org) 3.2 (or newer) is the recommended way to build the SDK.

### Installing All Dependencies (Linux and macOS)

All dependencies can be installed with the following commands:

#### Debian Linux (including Ubuntu and Raspberry Pi OS)

```
$ sudo apt-get -y update && sudo apt-get -y install git g++ make cmake libssl-dev
```

#### RedHat Linux

```
$ sudo yum install -y git gcc-c++ make cmake3 openssl-devel
```

#### macOS (with Homebrew)

```
$ brew install cmake openssl
```

## Building with CMake (Linux, macOS, Windows)

[CMake](https://cmake.org) (version 3.2 or newer) is the recommended build system for
building the macchina.io REMOTE SDK.

```
$ git clone https://github.com/my-devices/sdk.git
$ cd sdk
$ mkdir cmake-build
$ cd cmake-build
$ cmake ..
$ cmake --build . --config Release
```

On macOS, it's necessary to tell CMake where to find the OpenSSL headers
and libraries by setting the `OPENSSL_ROOT_DIR` CMake variable.
For example, if OpenSSL 1.1.x has been installed with Homebrew,
the `cmake` invocation becomes:

```
$ cmake .. -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl
```

On an Apple Silicon Mac, Homebrew installs packages in `/opt/homebrew`,
so the command becomes:

```
$ cmake .. -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl
```

If you want to link statically with OpenSSL libraries (recommended on
macOS), add the `-DOPENSSL_USE_STATIC_LIBS=TRUE` option, e.g.:

```
$ cmake .. -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1 -DOPENSSL_USE_STATIC_LIBS=TRUE
```

Other common ways of building with CMake (e.g., `cmake-gui`) will also work.

There are also a number of project-specific CMake variables that can be changed,
e.g., to build with OpenSSL on Windows.


### Cross-Compiling

With a proper CMake toolchain file (specified via the `CMAKE_TOOLCHAIN_FILE` CMake variable),
the SDK can be cross-compiled for embedded Linux systems:

```
$ cmake .. -DCMAKE_TOOLCHAIN_FILE=/path/to/mytoolchain.cmake -DCMAKE_INSTALL_PREFIX=/path/to/target
```

If the cross-compiling toolchain does not contain OpenSSL, you'll also have to build
it prior to building this project. See [Cross Compiling with CMake](https://github.com/my-devices/sdk/wiki/Cross-Compiling-with-CMake)
for instructions.

Note: The resulting executables may contain debug information, which significantly
increases their size.
You should run `xxx-yyy-linux-strip` on the resulting executables to reduce their
size before deploying them to the device.

NOTE: See [README_iOS.md](README_iOS.md) for iOS builds 
and [README_Android.md](README_Android.md) for Android builds.

### Installing

The SDK can be optionally be installed by building the `install` target. However,
in most cases this is not necessary. The resulting executables in the `cmake-build/bin`
directory are statically linked per default and can be moved to any directory desired.

If required, the SDK header files and libraries can be installed with:

```
$ sudo cmake --build . --target install
```

The default install location is `/usr/local/` on Linux and macOS and
`C:\Program Files (x64)\` on Windows and can be overridden by setting
the `CMAKE_INSTALL_PREFIX` CMake variable.

_WARNING_: Be careful when installing to the default location if you also
have the POCO C++ Libraries installed there, as both install locations are
the same. If you need to install (e.g., in order to build the Remote
Manager Gateway), specify an appropriate `CMAKE_INSTALL_PREFIX`.


## Building on Linux and macOS with GNU Make

In addition to CMake, the GNU Make based build system from the
POCO C++ Libraries is also supported.

### The Easy Way

The easy way to build the SDK on Linux or macOS is to run the
`buildsdk.sh` script:

```
$ git clone https://github.com/my-devices/sdk.git
$ cd sdk
$ ./buildsdk.sh
```

It will make the necessary invocations of
the configure script and GNU make to build `WebTunnelAgent` and
the client command-line tools, along with the required libraries. With this
build, the required POCO libraries (`Foundation`, `Net`, `Util`, `WebTunnel`,
`Crypto` and `NetSSL_OpenSSL`) will be linked statically into the final
applications. If you don't want this, because you want to use other
parts of POCO in your project and link the shared libraries, you'll
have to run the necessary commands manually. You'll also have to
do a manual build if your target does not have OpenSSL.

The resulting executables will be located in the *bin* directory.

For cross-compiling for an embedded platform, pass the name of a
build configuration to the `buildsdk.sh` script. For example, to build
for Angstrom:

```
$ ./buildsdk.sh Angstrom
```

See the build/config directory for available build configurations. If
there's no build configuration that fits your target, you'll have to
create one yourself. This is best done by copying an existing one,
making the necessary changes (typically, changing the name of the
compiler and linker executables to match your particular toolchain,
and modifying compiler/linker settings if necessary).
Specify the name of your new build configuration in the call to `buildsdk.sh`.

For more information regarding the build system, see the POCO C++
Libraries documentation at <https://docs.pocoproject.org/>.

A final note: `buildsdk.sh` only builds the release configuration.
If you need a debug build, see below.


### Customizing The SDK Build

To customize the SDK build, invoke the configure script and GNU make
manually, as described in README_POCO.

```
$ ./configure --cflags=-DPOCO_UTIL_NO_XMLCONFIGURATION --no-tests --no-samples --static
$ make -s -j8 DEFAULT_TARGET=static_release
$ export POCO_BASE=`pwd`
$ cd WebTunnel/WebTunnelAgent
$ make -s DEFAULT_TARGET=shared_release
```

A few notes on the arguments:

  * `--cflags=-DPOCO_UTIL_NO_XMLCONFIGURATION` instructs the build system to omit support
    for XML configuration files. The result is that the PocoXML library does not
    need to be linked into the application, saving a few 100Ks of executable size.
  * `--no-tests` and `--no-samples` instruct the build system not to build the
    POCO sample applications and the testsuites.
  * `--static` instructs the build system to build static libraries.
  * `DEFAULT_TARGET=static_release` instructs the build system to only build
    the release configuration.
  * `DEFAULT_TARGET=shared_release` (in the second call to GNU make for building the
    `WebTunnelAgent` and command-line client executables) instructs the build system to
    link against the shared runtime libraries (C and C++ standard libraries, OpenSSL),
    but use the static POCO libraries (since only these are available).
  * `WEBTUNNEL_ENABLE_TLS=1` enables SSL/TLS support for WebTunnelAgent and
    the command-line client tools.

If your system does not have OpenSSL, run configure and GNU make as follows:

```
$ ./configure --cflags=-DPOCO_UTIL_NO_XMLCONFIGURATION --omit=Crypto,NetSSL_OpenSSL --no-tests --no-samples --static
$ make -s -j8 DEFAULT_TARGET=static_release
$ export POCO_BASE=`pwd`
$ cd WebTunnel/Agent
$ make -s WEBTUNNEL_DISABLE_TLS=1 DEFAULT_TARGET=shared_release
```

For a cross-build for an embedded target, you must specify the build configuration in the
call to `./configure` and the final call to GNU make.

```
$ ./configure --cflags=-DPOCO_UTIL_NO_XMLCONFIGURATION --no-tests --no-samples --static --config=Angstrom
$ make -s -j8 DEFAULT_TARGET=static_release
$ export POCO_BASE=`pwd`
$ cd WebTunnel/WebTunnelAgent
$ make -s POCO_CONFIG=Angstrom DEFAULT_TARGET=shared_release
```

