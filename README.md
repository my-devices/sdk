# The macchina.io Remote Manager SDK

## About macchina.io Remote Manager

[macchina.io Remote Manager](https://macchina.io) provides secure remote access to connected devices
via HTTP or other TCP-based protocols and applications such as secure shell (SSH) or
Virtual Network Computing (VNC). With macchina.io Remote Manager, any network-connected device
running the Remote Manager Agent software (*WebTunnelAgent*, contained in this SDK)
can be securely accessed remotely over the internet from browsers, mobile apps, desktop,
server or cloud applications.

This even works if the device is behind a NAT router, firewall or proxy server.
The device becomes just another host on the internet, addressable via its own URL and
protected by the Remote Manager server against unauthorized or malicious access.
macchina.io Remote Manager is a great solution for secure remote support and maintenance,
as well as for providing secure remote access to devices for end-users via web or
mobile apps.

Visit [macchina.io](https://macchina.io/remote.html) to learn more and to register for a free account.
Specifically, see the [Getting Started](https://macchina.io/remote_signup.html) page and the
[Frequently Asked Questions](https://macchina.io/remote_faq.html) for
information on how to use this SDK and the included *WebTunnelAgent* executable.

There is also a [blog post](https://macchina.io/blog/?p=257) showing step-by-step instructions to connect a Raspberry Pi.


## About This SDK

The macchina.io Remote Manager SDK is based on the
[POCO C++ Libraries](http://pocoproject.org). You may want to read README_POCO
as well as it contains important information regarding the directory structure
and the build system of the SDK.

The SDK contains the WebTunnel library, which implements the tunnel protocol used by Remote Manager.
Furthermore, the following executables are included:

  - [*WebTunnelAgent*](WebTunnel/WebTunnelAgent/README.md): This executable runs on the device and creates the secure tunnel between the device
    and the Remote Manager server. This is the most important component of the Remote Manager SDK.
  - [*WebTunnelClient*](WebTunnel/WebTunnelClient/README.md): This executable can run on a client PC to create a secure tunnel from the PC to the
    device, via the Remote Manager server. It is required for tunneling protocols like SSH or other TCP-based
    protocols not directly supported by the Remote Manager server.
  - [*WebTunnelSSH*](WebTunnel/WebTunnelSSH/README.md): This is a variant of WebTunnelClient that first creates a tunnel connection from your PC
    to the device, then launches a SSH client using that tunnel connection.
  - [*WebTunnelVNC*](WebTunnel/WebTunnelVNC/README.md): This is a variant of WebTunnelClient that first creates a tunnel connection from your PC to
    the device, then launches a VNC viewer using that tunnel connection.
  - [*WebTunnelRDP*](WebTunnel/WebTunnelRDP/README.md): This is a variant of WebTunnelClient that first creates a tunnel connection from your PC to
    the device, then launches the Microsoft Remote Desktop client using that tunnel connection.

The macchina.io Remote Manager SDK is licensed under the [Boost Software License](https://spdx.org/licenses/BSL-1.0).


## Easy Install (Linux and macOS)

The easiest way to install the above mentioned executables on a Linux or macOS system
from source is to download and run the
[installer script](https://github.com/my-devices/agent-installer/blob/master/install.sh)
with the following command:

```
$ curl https://raw.githubusercontent.com/my-devices/agent-installer/master/install.sh | bash
```

The script should work on most Debian and RedHat-based Linux distributions including
Ubuntu and Raspbian. On macOS, [Homebrew](https://brew.sh) must be installed.

The script will install all required dependencies, then get the sources from
GitHub and run the steps necessary (see below) to build and install the binaries in `/usr/local/bin/`.

If you do not want to or cannot run the installer script, please see the following
instructions.


## External Dependecies

### Libraries

The macchina.io Remote Manager SDK requires OpenSSL 1.0 or newer
on Linux and macOS systems.
We recommend using at least OpenSSL 1.0.2r or 1.1.1b.

Most Unix/Linux systems already have OpenSSL preinstalled. If your system
does not have OpenSSL, please get it from <http://www.openssl.org> or
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

A C++ compiler is required to build the SDK and applications. The system's default
compiler (gcc on Linux, clang on macOS) should be fine on reasonably recent systems.
On Windows, Visual C++ is recommended (any version from 2008 to 2019 will do).

[CMake](https://cmake.org) 3.2 (or newer) is the recommended way to build the SDK.


## Building with CMake (Linux, macOS, Windows)

[CMake](https://cmake.org) (version 3.2 or newer) is the recommended build system for
building the macchina.io Remote Manager SDK.

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
For example, if OpenSSL has been installed with Homebrew,
the `cmake` invocation becomes:

```
$ cmake .. -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl
```

If you want to link statically with OpenSSL libraries (recommended on
macOS), add the `-DOPENSSL_USE_STATIC_LIBS=TRUE` option, e.g.:

```
$ cmake .. -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl -DOPENSSL_USE_STATIC_LIBS=TRUE
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

Note: The resulting executables may contain debug information, which significantly
increases their size.
You should run `xxx-yyy-linux-strip` on the resulting executables to reduce their
size before deploying them to the device.


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
the configure script and GNU make to build WebTunnelAgent and
WebTunnelClient, along with the required libraries. With this
build, the required POCO libraries (Foundation, Net, Util, WebTunnel,
Crypto and NetSSL_OpenSSL) will be linked statically into the final
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
Libraries documentation at <http://pocoproject.org/docs>.

A final note: `buildsdk.sh` only builds the release configuration.
If you need a debug build, see below.


### Customizing The SDK Build

To customize the SDK build, invoke the configure script and GNU make
manually, as described in README_POCO.

```
$ ./configure --cflags=-DPOCO_UTIL_NO_XMLCONFIGURATION --no-tests --no-samples --static
$ make -s -j8 DEFAULT_TARGET=static_release
$ export POCO_BASE=`pwd`
$ cd WebTunnel/Agent
$ make -s DEFAULT_TARGET=shared_release
```

A few notes on the arguments:

  * `--cflags=-DPOCO_UTIL_NO_XMLCONFIGURATION` instructs the build system to omit support
    for XML configuration files. The result is that the PocoXML library does not
    need to be linked into the application, saving a few 100Ks of executable size.
  * `--no-tests and --no-samples` instruct the build system not to build the
    POCO sample applications and the testsuites.
  * `--static instructs` the build system to build static libraries.
  * `DEFAULT_TARGET=static_release` instructs the build system to only build
    the release configuration.
  * `DEFAULT_TARGET=shared_release` (in the second call to GNU make for building the
    WebTunnelAgent and WebTunnelClient executables) instructs the build system to
    link against the shared runtime libraries (C and C++ standard libraries, OpenSSL),
    but use the static POCO libraries (since only these are available).
  * `WEBTUNNEL_ENABLE_TLS=1` enables SSL/TLS support for WebTunnelAgent and
    WebTunnelClient.

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
$ cd WebTunnel/Agent
$ make -s POCO_CONFIG=Angstrom DEFAULT_TARGET=shared_release
```

