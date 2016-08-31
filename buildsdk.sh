#! /bin/sh
#
# buildsdk.sh
#
# $Id: //poco/1.7/dist/my-devices-sdk/buildsdk.sh#1 $
#
# Build script for the my-devices.net Device SDK.
#

PARALLEL_BUILDS=4

config=""
if [ "$1" != "" ] ; then
	config="--config=$1"
fi

echo "Starting my-devices.net SDK build..."

export POCO_BASE=`pwd`
export POCO_CONFIG=$1

./configure --cflags=-DPOCO_UTIL_NO_XMLCONFIGURATION --cflags=-DPOCO_UTIL_NO_JSONCONFIGURATION --no-tests --no-samples --static $config
if [ $? -ne 0 ] ; then
	echo "Configure script failed. Exiting."
	exit 1
fi
make -s -j$PARALLEL_BUILDS DEFAULT_TARGET=static_release 
if [ $? -ne 0 ] ; then
	echo "POCO C++ Libraries build failed. Exiting."
	exit 1
fi

mkdir -p bin

for app in WebTunnelAgent WebTunnelClient WebTunnelSSH WebTunnelVNC; do
	echo "Building: $app"
	make -s DEFAULT_TARGET=shared_release -C WebTunnel/$app
	if [ $? -ne 0 ] ; then
		echo "SDK build failed."
		exit 1
	fi
	cp -R WebTunnel/$app/bin/* bin
done

echo ""
echo "my-devices.net SDK build is complete."
echo ""
