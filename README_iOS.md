# Building the macchina.io REMOTE SDK for iOS

The macchina.io REMOTE SDK can be built for iOS with `cmake`.
The main use case is including the `WebTunnelClient` functionality
in an iOS application - connecting to a TCP port on a remote
device through the macchina.io REMOTE server tunneling feature.

## Prerequisites

  - Xcode
  - `cmake` 3.19.5 or newer (installed via Homebrew)
  - OpenSSL 1.1.1 or 3.0.x compiled for iOS
  
CMake can be installed via [Homebrew](https://brew.sh):

```
$ brew install cmake
```

For cross-compiling OpenSSL for iOS, the scripts from
the [x2on/penSSL-for-iPhone](https://github.com/x2on/OpenSSL-for-iPhone)
project can be used.

## Building

### Building OpenSSL for iOS

```
$ git clone git@github.com:x2on/OpenSSL-for-iPhone.git
$ cd OpenSSL-for-iPhone
$ ./build-libssl.sh --deprecated       
$ cd ..
```

### Building the macchina.io REMOTE SDK for iOS

```
$ git clone git@github.com:my-devices/sdk.git
$ cd sdk
```

Note: iOS device and simulator use different SDKs. The SDK to use must be specified
during the build step. Therefore, separate builds (in different directories) 
for device and simulator are necessary.

#### Building for iOS Device

```
$ cmake . -Bcmake-build-iphoneos -GXcode \
    -DCMAKE_SYSTEM_NAME=iOS \
    "-DCMAKE_OSX_ARCHITECTURES=arm64" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0 \
    -DCMAKE_INSTALL_PREFIX=`pwd`/cmake-install-iphoneos \
    -DCMAKE_XCODE_ATTRIBUTE_ONLY_ACTIVE_ARCH=NO \
    -DENABLE_WEBTUNNELAGENT=NO \
    -DENABLE_WEBTUNNELCLIENT=NO \
    -DENABLE_WEBTUNNELSSH=NO \
    -DENABLE_WEBTUNNELSCP=NO \
    -DENABLE_WEBTUNNELSFTP=NO \
    -DENABLE_WEBTUNNELVNC=NO \
    -DENABLE_WEBTUNNELRDP=NO \
    -DENABLE_WEBTUNNELCLIENTLIB=YES \
    -DOPENSSL_INCLUDE_DIR=`pwd`/../OpenSSL-for-iPhone/include \
    -DOPENSSL_CRYPTO_LIBRARY=`pwd`/../OpenSSL-for-iPhone/lib/libcrypto-iOS.a \
    -DOPENSSL_SSL_LIBRARY=`pwd`/../OpenSSL-for-iPhone/lib/libssl-iOS.a
$ cmake --build cmake-build-iphoneos --config Release -- -sdk iphoneos16.2 && cmake --install cmake-build-iphoneos --config Release 
```

#### Building for iOS Simulator

```
$ cmake . -Bcmake-build-iphonesimulator -GXcode \
    -DCMAKE_SYSTEM_NAME=iOS \
    "-DCMAKE_OSX_ARCHITECTURES=arm64;x86_64" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0 \
    -DCMAKE_INSTALL_PREFIX=`pwd`/cmake-install-iphonesimulator \
    -DCMAKE_XCODE_ATTRIBUTE_ONLY_ACTIVE_ARCH=NO \
    -DCMAKE_IOS_INSTALL_COMBINED=YES \
    -DENABLE_WEBTUNNELAGENT=NO \
    -DENABLE_WEBTUNNELCLIENT=NO \
    -DENABLE_WEBTUNNELSSH=NO \
    -DENABLE_WEBTUNNELSCP=NO \
    -DENABLE_WEBTUNNELSFTP=NO \
    -DENABLE_WEBTUNNELVNC=NO \
    -DENABLE_WEBTUNNELRDP=NO \
    -DENABLE_WEBTUNNELCLIENTLIB=YES \
    -DOPENSSL_INCLUDE_DIR=`pwd`/../OpenSSL-for-iPhone/include \
    -DOPENSSL_CRYPTO_LIBRARY=`pwd`/../OpenSSL-for-iPhone/lib/libcrypto-iOS-Sim.a \
    -DOPENSSL_SSL_LIBRARY=`pwd`/../OpenSSL-for-iPhone/lib/libssl-iOS-Sim.a
$ cmake --build cmake-build-iphonesimulator --config Release -- -sdk iphonesimulator16.2 && cmake --install cmake-build-iphonesimulator --config Release 
```

**Notes**

  - The paths to the OpenSSL include directory and the `libssl` and `libcrypto` libraries
    are directly passed to CMake (`-DOPENSSL_INCLUDE_DIR=...`, `-DOPENSSL_CRYPTO_LIBRARY=...`,
    `-DOPENSSL_SSL_LIBRARY=...`), using the paths from the `OpenSSL-for-iPhone` script.
    The library names are different for device and simulator.
  - All command-line tools are disabled in the build as they cannot run on iOS anyway
    (and also CMake cannot build them, due to some missing iOS-specific definitions in
    their `CMakeLists`)
  - Header files for the SDK are installed in `./cmake-install-iphoneos/include`, static 
    libraries are in `./cmake-install-iphoneos/lib` (for the device build). 
    You can of course changes these locations by modifying the respective CMake arguments 
    (`CMAKE_INSTALL_PREFIX`).
  - The resulting static libraries must be linked to your iOS application in your
    app's Xcode project file. The libraries are `libWebTunnelClient.a`, `libPocoWebTunnel.a`, 
    `libPocoNetSSL.a`, `libPocoCrypto.a`, `libPocoNet.a`, `libPocoUtil.a`, and `libPocoFoundation.a`.
    Furthermore, the OpenSSL libraries (`libcrypto-iOS.a` and `libssl-iOS.a` for device,
    `libcrypto-iOS-Sim.a` and `libssl-iOS-Sim.a` for simulator) must also be
    linked to the iOS application.
  - The resulting libraries for the simulator will be "fat", including objects for both
    `arm64` and `x64_64` architectures. For the device, only `arm64` libraries are built.
  - See the [CMake documentation on cross-compiling for iOS](https://cmake.org/cmake/help/v3.20/manual/cmake-toolchains.7.html#cross-compiling-for-ios-tvos-or-watchos)
    for more information.
