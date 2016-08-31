# The my-devices.net SDK

## About my-devices.net

[my-devices.net](http://www.my-devices.net) provides secure remote access to connected devices 
via HTTP or other TCP-based protocols and applications such as secure shell (SSH) or 
Virtual Network Computing (VNC). With my-devices.net, any network-connected device 
running the my-devices.net Agent software can be securely accessed remotely over the 
internet from browsers, mobile apps, desktop, server or cloud applications. 
This even works if the device is behind a NAT router, firewall or proxy server. 
The device becomes just another host on the internet, addressable via its own URL and 
protected by the my-devices.net server against unauthorized or malicious access. 
my-devices.net is a great solution for secure remote support and maintenance, 
as well as for providing secure remote access to devices for end-users via web or 
mobile apps.

Visit [my-devices.net](http://www.my-devices.net) to learn more and to register for a free account.
Specifically, see the [Getting Started](http://www.my-devices.net/getstarted.html) page for 
information on how to use this SDK and the included WebTunnelAgent executable.


## About this SDK

The my-devices.net Device SDK is based on the POCO C++ Libraries
<http://pocoproject.org>. Please read README_POCO first as it
contains important information regarding the directory structure
and the build system of the SDK.

The SDK contains the WebTunnel library, which implements the tunnel protocol used by my-devices.net.
Furthermore, the following executables are included:

  - *WebTunnelAgent*: This executable runs on the device and creates the secure tunnel between the device and the my-devices.net server. This is the most important component of the my-devices.net SDK.
  - *WebTunnelClient*: This executable can run on a client PC to create a secure tunnel from the PC to the device, via the my-devices.net server. It is required for tunneling protocols like SSH or other TCP-based protocols not directly supported by the my-devices.net server.
  - *WebTunnelSSH*: This is a variant of WebTunnelClient that first creates a tunnel connection from your PC to the device, then launches a SSH client using that tunnel connection.
  - *WebTunnelVNC*: This is a variant of WebTunnelVNC that first creates a tunnel connection from your PC to the device, then launches a VNC viewer using that tunnel connection.

The my-devices.net SDK is licensed under the [Boost Software License](https://spdx.org/licenses/BSL-1.0).


## External Dependecies

The my-devices.net Device SDK requires OpenSSL 0.9.8 or newer.
We recommend using at least OpenSSL 1.0.

Most Unix/Linux systems already have OpenSSL preinstalled. If your system 
does not have OpenSSL, please get it from <http://www.openssl.org> or 
another source. You do not have to build OpenSSL yourself - a binary 
distribution is fine (e.g., apt-get install openssl libssl-dev).

The easiest way to install OpenSSL on Windows is to use a binary 
(prebuild) release, for example the one from Shining Light 
Productions that comes with a Windows installer
<http://www.slproweb.com/products/Win32OpenSSL.html>. 
Depending on where you have installed the OpenSSL libraries, 
you might have to edit the build script (buildwin.cmd), or add the 
necessary paths to the INCLUDE and LIB environment variables.

On Unix/Linux/OS X, GNU make 3.80 or newer is required.


## Building on Linux and OS X

### The Easy Way

The easy way to build the SDK on Linux or OS X is to run the
buildsdk.sh script:

    ./buildsdk.sh

It will make the necessary invocations of
the configure script and GNU make to build WebTunnelAgent and
WebTunnelClient, along with the required libraries. With this
build, the required POCO libraries (Foundation, Net, Util, WebTunnel,
Crypto and NetSSL_OpenSSL) will be linked statically into the final
applications. If you don't want this, because you want to use other
parts of POCO in your project and link the shared libraries, you'll
have to run the necessary commands manually. You'll also have to
do a manual build if your target does not have OpenSSL.

For cross-compiling for an embedded platform, pass the name of a
build configuration to the buildsdk.sh script. For example, to build
for Angstrom:

    ./buildsdk.sh Angstrom

See the build/config directory for available build configurations. If
there's no build configuration that fits your target, you'll have to 
create one yourself. This is best done by copying an existing one,
making the necessary changes (typically, changing the name of the
compiler and linker executables to match your particular toolchain,
and modifying compiler/linker settings if necessary). 
Specify the name of your new build configuration in the call to buildsdk.sh.

For more information regarding the build system, see the POCO C++
Libraries documentation at <http://pocoproject.org/docs>.

A final note: buildsdk.sh only builds the release configuration.
If you need a debug build, see below.


### Customizing The SDK Build

To customize the SDK build, invoke the configure script and GNU make
manually, as described in README_POCO.

    ./configure --cflags=-DPOCO_UTIL_NO_XMLCONFIGURATION --no-tests --no-samples --static
    make -s -j8 DEFAULT_TARGET=static_release
    export POCO_BASE=`pwd`
    cd WebTunnel/Agent
    make -s DEFAULT_TARGET=shared_release

A few notes on the arguments:

  * --cflags=-DPOCO_UTIL_NO_XMLCONFIGURATION instructs the build system to omit support
    for XML configuration files. The result is that the PocoXML library does not
    need to be linked into the application, saving a few 100Ks of executable size.
  * --no-tests and --no-samples instruct the build system not to build the
    POCO sample applications and the testsuites.
  * --static instructs the build system to build static libraries.
  * DEFAULT_TARGET=static_release instructs the build system to only build
    the release configuration.
  * DEFAULT_TARGET=shared_release (in the second call to GNU make for building the
    WebTunnelAgent and WebTunnelClient executables) instructs the build system to
    link against the shared runtime libraries (C and C++ standard libraries, OpenSSL),
    but use the static POCO libraries (since only these are available).
  * WEBTUNNEL_ENABLE_TLS=1 enables SSL/TLS support for WebTunnelAgent and
    WebTunnelClient.
  
If your system does not have OpenSSL, run configure and GNU make as follows:

    ./configure --cflags=-DPOCO_UTIL_NO_XMLCONFIGURATION --omit=Crypto,NetSSL_OpenSSL --no-tests --no-samples --static
    make -s -j8 DEFAULT_TARGET=static_release
    export POCO_BASE=`pwd`
    cd WebTunnel/Agent
    make -s WEBTUNNEL_DISABLE_TLS=1 DEFAULT_TARGET=shared_release

For a cross-build for an embedded target, you must specify the build configuration in the
call to ./configure and the final call to GNU make. 

    ./configure --cflags=-DPOCO_UTIL_NO_XMLCONFIGURATION --no-tests --no-samples --static --config=Angstrom
    make -s -j8 DEFAULT_TARGET=static_release
    export POCO_BASE=`pwd`
    cd WebTunnel/Agent
    make -s POCO_CONFIG=Angstrom DEFAULT_TARGET=shared_release 


## Building on Windows

For Windows, you'll need Visual C++. Any version from 2008 to 2015 is fine.

The easiest way to build on Windows is to run one of the build_vsNNN.cmd scripts, depending on the
Visual Studio version you'll want to build with. For Visual Studio 2008, run build_vs90.cmd, for 
Visual Studio 2015 run buidl_vs140.cmd:

    build_vs140

You can also use the buildwin.cmd script for greater flexibility. Run it without arguments to see available options.
Also, see README_POCO for more information.
