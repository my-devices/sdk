//
// RemotePortForwarder.h
//
// Library: WebTunnel
// Package: WebTunnel
// Module:  RemotePortForwarder
//
// Definition of the LocalPortForwarder class.
//
// Copyright (c) 2013, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef WebTunnel_RemotePortForwarder_INCLUDED
#define WebTunnel_RemotePortForwarder_INCLUDED


#include "Poco/WebTunnel/WebTunnel.h"
#include "Poco/WebTunnel/SocketDispatcher.h"
#include "Poco/WebTunnel/Protocol.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Net/WebSocket.h"
#include "Poco/SharedPtr.h"
#include "Poco/AutoPtr.h"
#include "Poco/RefCountedObject.h"
#include "Poco/Buffer.h"
#include "Poco/BasicEvent.h"
#include "Poco/Mutex.h"
#include "Poco/Logger.h"
#include <map>
#include <set>


namespace Poco {
namespace WebTunnel {


class WebTunnel_API SocketFactory: public Poco::RefCountedObject
	/// This class is used by RemotePortForwarder to create a StreamSocket
	/// for connecting to the target endpoint.
{
public:
	typedef Poco::AutoPtr<SocketFactory> Ptr;

	SocketFactory();
		/// Creates the SocketFactory.

	virtual ~SocketFactory();
		/// Destroys the SocketFactory.

	virtual Poco::Net::StreamSocket createSocket(const Poco::Net::SocketAddress& addr);
		/// Creates and connects a socket to the given address.
		/// If the socket cannot be connected within the given timeout,
		/// throws a Poco::TimeoutException.
		///
		/// The default implementation always creates a Poco::Net::StreamSocket.
};


class WebTunnel_API RemotePortForwarder
	/// This class forwards one or more ports to a remote host,
	/// using a shared web socket for tunneling the data.
{
public:
	enum CloseReason
	{
		RPF_CLOSE_GRACEFUL   = 0, /// Graceful shutdown, initiated by peer.
		RPF_CLOSE_UNEXPECTED = 1, /// Unexpected shutdown by peer.
		RPF_CLOSE_ERROR      = 2, /// Close due to socket exception.
		RPF_CLOSE_TIMEOUT    = 3, /// Close due to timeout.
	};

	Poco::BasicEvent<const int> webSocketClosed;
		/// Fired when the web socket has been closed.
		///
		/// The event argument will indicate the
		/// reason for the close. See the CloseReason
		/// enum for values and their meanings.

	RemotePortForwarder(SocketDispatcher& dispatcher, Poco::SharedPtr<Poco::Net::WebSocket> pWebSocket, const Poco::Net::IPAddress& host, const std::set<Poco::UInt16>& ports, Poco::Timespan remoteTimeout = Poco::Timespan(300, 0), SocketFactory::Ptr pSocketFactory = new SocketFactory);
		/// Creates the RemotePortForwarder, using the given socket dispatcher and web socket,
		/// which is used for tunneling data. Only the port numbers given in ports will
		/// be forwarded. The web socket must have already been connected to the
		/// reflector server.

	~RemotePortForwarder();
		/// Destroys the RemotePortForwarder and closes the web socket connection.

	void stop();
		/// Stops the RemotePortForwarder.

	void setLocalTimeout(const Poco::Timespan& timeout);
		/// Sets the timeout for the forwarded local ports.

	const Poco::Timespan& getLocalTimeout() const;
		/// Returns the timeout for the forwarded local ports.

	void setCloseTimeout(const Poco::Timespan& timeout);
		/// Sets the close timeout for the forwarded local ports.

	const Poco::Timespan& getCloseTimeout() const;
		/// Returns the close timeout for the forwarded local ports.

	void setConnectTimeout(const Poco::Timespan& timeout);
		/// Sets the timeout for connecting to local ports.

	const Poco::Timespan& getConnectTimeout() const;
		/// Returns the timeout for connecting to local ports.

	const Poco::Timespan& remoteTimeout() const;
		/// Returns the timeout for the remote connection.

	void setThrottleDelay(Poco::Timespan delay);
		/// Sets the upstream receive delay if throttling is necessary.

	Poco::Timespan getThrottleDelay() const;
		/// Returns the upstream receive delay if throttling is necessary.

	void setThrottleMaxPendingBytesToSend(std::size_t count);
		/// Sets the maximum number of pending bytes to send downstream (
		/// to the local device) before the upstream
		/// connection (to reflector) is throttled.

	std::size_t getThrottleMaxPendingBytesToSend() const;
		/// Returns the maximum number of pending bytes to send downstream (
		/// to the local device) before the upstream
		/// connection (to reflector) is throttled.

	void updateProperties(const std::map<std::string, std::string>& props);
		/// Transmits properties (key-value pairs) to the remote peer.

protected:
	bool wantMultiplex(SocketDispatcher& dispatcher);
	void multiplex(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket, Poco::UInt16 channel, Poco::Buffer<char>& buffer);
	void multiplexError(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket, Poco::UInt16 channel, Poco::Buffer<char>& buffer);
	void multiplexTimeout(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket, Poco::UInt16 channel, Poco::Buffer<char>& buffer);
	bool wantDemultiplex(SocketDispatcher& dispatcher);
	void demultiplex(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket, Poco::Buffer<char>& buffer);
	void demultiplexError(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket, Poco::Buffer<char>& buffer);
	void demultiplexTimeout(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket, Poco::Buffer<char>& buffer);
	void connect(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket, Poco::UInt16 channel);
	void connectError(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket, Poco::UInt16 channel);
	void connectTimeout(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket, Poco::UInt16 channel);
	void forwardData(const char* buffer, int size, Poco::UInt16 channel);
	void openChannel(Poco::UInt16 channel, Poco::UInt16 port);
	void shutdownSendChannel(Poco::UInt16 channel);
	void removeChannel(Poco::UInt16 channel);
	void sendResponse(Poco::UInt16 channel, Poco::UInt8 opcode, Poco::UInt16 errorCode);
	void closeWebSocket(CloseReason reason, bool active);
	int setChannelFlag(Poco::UInt16 channel, int flag);
	int getChannelFlags(Poco::UInt16 channel) const;

private:
	class TunnelMultiplexer: public SocketDispatcher::SocketHandler
	{
	public:
		TunnelMultiplexer(RemotePortForwarder& forwarder, Poco::UInt16 channel):
			_forwarder(forwarder),
			_channel(channel),
			_buffer(Protocol::WT_FRAME_MAX_SIZE + Protocol::WT_FRAME_HEADER_SIZE)
		{
		}

		bool wantRead(SocketDispatcher& dispatcher)
		{
			return _forwarder.wantMultiplex(dispatcher);
		}
	
		bool wantWrite(SocketDispatcher& dispatcher)
		{
			return false;
		}	

		void readable(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
		{
			_forwarder.multiplex(dispatcher, socket, _channel, _buffer);
		}

		void writable(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
		{
		}

		void exception(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
		{
			_forwarder.multiplexError(dispatcher, socket, _channel, _buffer);
		}

		void timeout(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
		{
			_forwarder.multiplexTimeout(dispatcher, socket, _channel, _buffer);
		}

	private:
		RemotePortForwarder& _forwarder;
		Poco::UInt16 _channel;
		Poco::Buffer<char> _buffer;
	};

	class TunnelDemultiplexer: public SocketDispatcher::SocketHandler
	{
	public:
		TunnelDemultiplexer(RemotePortForwarder& forwarder):
			_forwarder(forwarder),
			_buffer(Protocol::WT_FRAME_MAX_SIZE + Protocol::WT_FRAME_HEADER_SIZE)
		{
		}

		bool wantRead(SocketDispatcher& dispatcher)
		{
			return _forwarder.wantDemultiplex(dispatcher);
		}
	
		bool wantWrite(SocketDispatcher& dispatcher)
		{
			return false;
		}	

		void readable(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
		{
			_forwarder.demultiplex(dispatcher, socket, _buffer);
		}

		void writable(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
		{
		}

		void exception(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
		{
			_forwarder.demultiplexError(dispatcher, socket, _buffer);
		}

		void timeout(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
		{
			_forwarder.demultiplexTimeout(dispatcher, socket, _buffer);
		}

	private:
		RemotePortForwarder& _forwarder;
		Poco::Buffer<char> _buffer;
	};

	class TunnelConnector: public SocketDispatcher::SocketHandler
	{
	public:
		TunnelConnector(RemotePortForwarder& forwarder, Poco::UInt16 channel):
			_forwarder(forwarder),
			_channel(channel)
		{
		}

		bool wantRead(SocketDispatcher& dispatcher)
		{
			return false;
		}
	
		bool wantWrite(SocketDispatcher& dispatcher)
		{
			return true;
		}
	
		void readable(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
		{
		}

		void writable(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
		{
			_forwarder.connect(dispatcher, socket, _channel);
		}

		void exception(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
		{
			_forwarder.connectError(dispatcher, socket, _channel);
		}

		void timeout(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
		{
			_forwarder.connectTimeout(dispatcher, socket, _channel);
		}

	private:
		RemotePortForwarder& _forwarder;
		Poco::UInt16 _channel;
	};

	enum ConnectionFlags
	{
		CF_CLOSED_LOCAL  = 0x01,
		CF_CLOSED_REMOTE = 0x02
	};

	struct ChannelInfo
	{
		Poco::Net::StreamSocket socket;
		int flags = 0;
	};
	using ChannelMap = std::map<Poco::UInt16, ChannelInfo>;

	SocketDispatcher& _dispatcher;
	SocketFactory::Ptr _pSocketFactory;
	Poco::SharedPtr<Poco::Net::WebSocket> _pWebSocket;
	int _webSocketFlags = 0;
	Poco::Net::IPAddress _host;
	std::set<Poco::UInt16> _ports;
	ChannelMap _channelMap;
	Poco::Timespan _connectTimeout;
	Poco::Timespan _localTimeout;
	Poco::Timespan _closeTimeout;
	Poco::Timespan _remoteTimeout;
	Poco::Timespan _throttleDelay;
	std::size_t _throttleMaxPendingBytesToSend;
	Poco::Clock _lastSend;
	Poco::Clock _delayReceiveUntil;
	int _timeoutCount = 0;
	mutable Poco::FastMutex _mutex;
	Poco::Logger& _logger;

	RemotePortForwarder() = delete;
	RemotePortForwarder(const RemotePortForwarder&) = delete;
	RemotePortForwarder& operator = (const RemotePortForwarder&) = delete;

	friend class TunnelMultiplexer;
	friend class TunnelDemultiplexer;
};


} } // namespace Poco::WebTunnel


#endif // WebTunnel_RemotePortForwarder_INCLUDED
