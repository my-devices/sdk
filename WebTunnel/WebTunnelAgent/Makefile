#
# Makefile
#
# $Id: //poco/1.7/WebTunnel/samples/WebTunnelAgent/Makefile#3 $
#
# Makefile for WebTunnelAgent
#

include $(POCO_BASE)/build/rules/global

ifndef WEBTUNNEL_DISABLE_TLS
CXXFLAGS += -DWEBTUNNEL_ENABLE_TLS
tlslibs = PocoNetSSL PocoCrypto
SYSLIBS += -lssl -lcrypto -lz -ldl
endif

objects = WebTunnelAgent

target         = WebTunnelAgent
target_version = 1
target_libs    = $(tlslibs) PocoWebTunnel PocoUtil PocoNet PocoXML PocoJSON PocoFoundation

include $(POCO_BASE)/build/rules/exec
