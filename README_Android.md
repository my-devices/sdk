# Building the macchina.io REMOTE SDK for Android

The macchina.io REMOTE SDK can be built for Android with `cmake`.
The main use case is including the `WebTunnelClient` functionality
in an Android application - connecting to a TCP port on a remote
device through the macchina.io REMOTE server tunneling feature.

## Prerequisites

  - [Android NDK](https://developer.android.com/ndk)
    installed on Windows, macOS or Windows
  - [CMake](https://cmake.org) 3.19.5 or newer 
  - [Ninja](https://ninja-build.org)
  - OpenSSL 1.1.1 or 3.0.x compiled for Android

### Installing the Android NDK

On Windows and Linux, [download](https://developer.android.com/ndk/downloads) the 
`android-ndk-*.zip` file for your platform and unpack it in a directory of your choice.

On macOS, use [Homebrew](https://formulae.brew.sh/cask/android-ndk) to install the NDK:

```
$ brew install --cask android-ndk
```


### Installing CMake

**Windows**

Install CMake via the [installer](https://cmake.org/download/).

**Linux**

Install via package manager, e.g.:

```
$ sudo apt-get install cmake
```

**macOS**

Install via [Homebrew](https://brew.sh):

```
$ brew install cmake
```

### Installing Ninja

**Windows**

Download Ninja binary for Windows (`ninja-win.zip`) from GitHub [ninja-build/ninja](https://github.com/ninja-build/ninja/releases).

**Linux**

Install via package manager, e.g.:

```
$ sudo apt-get install ninja-build
```

**macOS**

Install via [Homebrew](https://brew.sh):

```
$ brew install ninja
```

### OpenSSL for Android

OpenSSL (version 1.1.1 or 3.0.x) must be built for Android, either into static or shared libraries.

Build scripts for creating static libraries (with position independent code)
for linking with a shared library, as well as the built libraries can be found in the 
[openss-_for_android](https://github.com/obiltschnig/openssl_for_android/)
project (forked from [217heidai/openssl_for_android](https://github.com/217heidai/openssl_for_android)).

## Building

### Download OpenSSL Libraries for Android

Note: the libraries must be downloaded separately for each target architecture.
In the following we only show `arm64` and `x86_64` (for the simulator).

```
$ curl -L https://github.com/obiltschnig/openssl_for_android/releases/download/3.0.8/OpenSSL_3.0.8_arm64-v8a.tar.gz | tar xz 
$ curl -L https://github.com/obiltschnig/openssl_for_android/releases/download/3.0.8/OpenSSL_3.0.8_x86_64.tar.gz | tar xz 
```

These two commands will download and extract the OpenSSL headers and static libraries
for `arm64` and `x86_64` into the following directory structure in the current working
directory:

  - openssl_3.0.8_arm64-v8a
    - include
    - lib
  - openssl_3.0.8_x86_64
    - include
    - lib
    
### Building the macchina.io REMOTE SDK for Android

```
$ git clone git@github.com:my-devices/sdk.git
$ cd sdk
$ cmake . -Bcmake-build-android-arm64-v8a -GNinja \
    -DCMAKE_SYSTEM_NAME=Android \
    -DCMAKE_SYSTEM_VERSION=21 \
    -DCMAKE_ANDROID_ARCH_ABI=arm64-v8a \
    -DCMAKE_INSTALL_PREFIX=`pwd`/cmake-install-android-arm64-v8a \
    -DCMAKE_ANDROID_NDK=/path/to/android-ndk \
    -DENABLE_WEBTUNNELAGENT=NO \
    -DENABLE_WEBTUNNELCLIENT=NO \
    -DENABLE_WEBTUNNELSSH=NO \
    -DENABLE_WEBTUNNELSCP=NO \
    -DENABLE_WEBTUNNELSFTP=NO \
    -DENABLE_WEBTUNNELVNC=NO \
    -DENABLE_WEBTUNNELRDP=NO \
    -DENABLE_WEBTUNNELCLIENTLIB=YES \
    -DOPENSSL_INCLUDE_DIR=`pwd`/../openssl_3.0.8_arm64-v8a/include \
    -DOPENSSL_CRYPTO_LIBRARY=`pwd`/../openssl_3.0.8_arm64-v8a/lib/libcrypto.a \
    -DOPENSSL_SSL_LIBRARY=`pwd`/../openssl_3.0.8_arm64-v8a/lib/libssl.a
$ cmake --build cmake-build-android-arm64-v8a && cmake --install cmake-build-android-arm64-v8a 
```

**Notes**

  - The above command only builds for a single target architecture (`arm64-v8a`).
    The commands need to be repeated for additional architectures (e.g., `x86_64` for the simulator),
    with `arm64-v8a` replaced with `x86_64` in the arguments.
  - The paths to the OpenSSL include directory and the `libssl` and `libcrypto` libraries
    are directly passed to CMake (`-DOPENSSL_INCLUDE_DIR=...`, `-DOPENSSL_CRYPTO_LIBRARY=...`,
    `-DOPENSSL_SSL_LIBRARY=...`), using the paths from the `openssl_for_android` script.
  - All command-line tools are disabled in the build.
  - Header files for the SDK are installed in `./cmake-install-android-arm64-v8a/include`, static 
    libraries are in `./cmake-install-android-arm64-v8a/lib`. You can of course changes these
    locations by modifying the respective CMake arguments (`CMAKE_INSTALL_PREFIX`).
  - The resulting static libraries must be linked to your Android native application. 
    The libraries are `libWebTunnelClient.a`, `libPocoWebTunnel.a`, 
    `libPocoNetSSL.a`, `libPocoCrypto.a`, `libPocoNet.a`, `libPocoUtil.a`, and `libPocoFoundation.a`.
    Furthermore, the OpenSSL libraries (`libcrypto.a` and `libssl.a`) must also be
    linked to the Android application.
  - See the [CMake documentation on cross-compiling for Android](https://cmake.org/cmake/help/v3.20/manual/cmake-toolchains.7.html#cross-compiling-for-android)
    for more information.

**Building WebTunnelClientLib as a Standalone Shared Library**

In some cases it may be useful to compile `libWebTunnelClient` as a standalone shared
library, e.g. for use with JNI or .NET P/Invoke. This can be done by passing the following
additional CMake definitions:

  - `-DWEBTUNNELCLIENTLIB_SHARED=YES`
  - `-DCMAKE_POSITION_INDEPENDENT_CODE=ON`
  
The resulting build commands therefore are:

```
$ git clone git@github.com:my-devices/sdk.git
$ cd sdk
$ cmake . -Bcmake-build-android-arm64-v8a -GNinja \
    -DCMAKE_SYSTEM_NAME=Android \
    -DCMAKE_SYSTEM_VERSION=21 \
    -DCMAKE_ANDROID_ARCH_ABI=arm64-v8a \
    -DCMAKE_INSTALL_PREFIX=`pwd`/cmake-install-android-arm64-v8a \
    -DCMAKE_ANDROID_NDK=/path/to/android-ndk \
    -DENABLE_WEBTUNNELAGENT=NO \
    -DENABLE_WEBTUNNELCLIENT=NO \
    -DENABLE_WEBTUNNELSSH=NO \
    -DENABLE_WEBTUNNELSCP=NO \
    -DENABLE_WEBTUNNELSFTP=NO \
    -DENABLE_WEBTUNNELVNC=NO \
    -DENABLE_WEBTUNNELRDP=NO \
    -DENABLE_WEBTUNNELCLIENTLIB=YES \
    -DWEBTUNNELCLIENTLIB_SHARED=YES \
    -DOPENSSL_INCLUDE_DIR=`pwd`/../openssl_3.0.8_arm64-v8a/include \
    -DOPENSSL_CRYPTO_LIBRARY=`pwd`/../openssl_3.0.8_arm64-v8a/lib/libcrypto.a \
    -DOPENSSL_SSL_LIBRARY=`pwd`/../openssl_3.0.8_arm64-v8a/lib/libssl.a
$ cmake --build cmake-build-android-arm64-v8a && cmake --install cmake-build-android-arm64-v8a 
```
