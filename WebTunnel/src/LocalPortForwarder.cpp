//
// LocalPortForwarder.cpp
//
// Library: WebTunnel
// Package: WebTunnel
// Module:  LocalPortForwarder
//
// Copyright (c) 2013, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/WebTunnel/LocalPortForwarder.h"
#include "Poco/WebTunnel/SocketDispatcher.h"
#include "Poco/WebTunnel/Protocol.h"
#include "Poco/Net/TCPServerConnection.h"
#include "Poco/Net/TCPServerConnectionFactory.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/HTTPClientSession.h"
#include "Poco/Net/HTTPSessionFactory.h"
#include "Poco/Net/HTTPBasicCredentials.h"
#include "Poco/Net/NetException.h"
#include "Poco/NumberFormatter.h"
#include "Poco/NumberParser.h"
#include "Poco/Format.h"
#include "Poco/Buffer.h"


using namespace std::string_literals;


namespace Poco {
namespace WebTunnel {


//
// LocalPortForwarderConnection
//


class LocalPortForwarderConnection: public Poco::Net::TCPServerConnection
{
public:
	LocalPortForwarderConnection(const Poco::Net::StreamSocket& socket, LocalPortForwarder& forwarder):
		Poco::Net::TCPServerConnection(socket),
		_forwarder(forwarder)
	{
	}

	void run()
	{
		_forwarder.forward(socket());
	}

private:
	LocalPortForwarder& _forwarder;
};


//
// LocalPortForwarderConnectionFactory
//


class LocalPortForwarderConnectionFactory: public Poco::Net::TCPServerConnectionFactory
{
public:
	LocalPortForwarderConnectionFactory(LocalPortForwarder& forwarder):
		_forwarder(forwarder)
	{
	}

	Poco::Net::TCPServerConnection* createConnection(const Poco::Net::StreamSocket& socket)
	{
		return new LocalPortForwarderConnection(socket, _forwarder);
	}

private:
	LocalPortForwarder& _forwarder;
};


//
// WebSocketFactory
//


WebSocketFactory::WebSocketFactory()
{
}


WebSocketFactory::~WebSocketFactory()
{
}


//
// DefaultWebSocketFactory
//


DefaultWebSocketFactory::DefaultWebSocketFactory()
{
}


DefaultWebSocketFactory::DefaultWebSocketFactory(const std::string& username, const std::string& password, Poco::Timespan timeout):
	_username(username),
	_password(password),
	_timeout(timeout)
{
}


DefaultWebSocketFactory::~DefaultWebSocketFactory()
{
}


Poco::Net::WebSocket* DefaultWebSocketFactory::createWebSocket(const Poco::URI& uri, Poco::Net::HTTPRequest& request, Poco::Net::HTTPResponse& response)
{
	Poco::SharedPtr<Poco::Net::HTTPClientSession> pSession = Poco::Net::HTTPSessionFactory::defaultFactory().createClientSession(uri);
	pSession->setTimeout(_timeout);
	if (!_username.empty())
	{
		Poco::Net::HTTPBasicCredentials creds(_username, _password);
		creds.authenticate(request);
	}
	return new Poco::Net::WebSocket(*pSession, request, response);
}


//
// BasicSocketForwarder
//


class BasicSocketForwarder: public SocketDispatcher::SocketHandler
{
public:
	BasicSocketForwarder(LocalPortForwarder& lpf, Poco::SharedPtr<SocketDispatcher> pDispatcher):
		_lpf(lpf),
		_pDispatcher(pDispatcher),
		_buffer(Protocol::WT_FRAME_MAX_SIZE)
	{
	}

	void shutdown(Poco::Net::WebSocket& webSocket, Poco::UInt16 statusCode, Poco::Logger& logger)
	{
		try
		{
			char buffer[2];
			Poco::MemoryOutputStream ostr(buffer, sizeof(buffer));
			Poco::BinaryWriter writer(ostr, Poco::BinaryWriter::NETWORK_BYTE_ORDER);
			writer << static_cast<Poco::UInt16>(Poco::Net::WebSocket::WS_NORMAL_CLOSE);
			_pDispatcher->sendBytes(webSocket, buffer, sizeof(buffer), Poco::Net::WebSocket::FRAME_FLAG_FIN | Poco::Net::WebSocket::FRAME_OP_CLOSE);
			_pDispatcher->shutdownSend(webSocket);
		}
		catch (Poco::Exception& exc)
		{
			logger.debug("Error shutting down WebSocket: %s"s, exc.displayText());
		}
	}

	void notifyClientDisconnected(const Poco::Net::Socket& socket)
	{
		try
		{
			_lpf.clientDisconnected(&_lpf, socket.peerAddress());
		}
		catch (Poco::Exception&)
		{
		}
	}

protected:
	LocalPortForwarder& _lpf;
	Poco::SharedPtr<SocketDispatcher> _pDispatcher;
	Poco::Buffer<char> _buffer;
};


//
// SocketToWebSocketForwarder
//


class StreamSocketToWebSocketForwarder: public BasicSocketForwarder
{
public:
	StreamSocketToWebSocketForwarder(LocalPortForwarder& lpf, Poco::SharedPtr<SocketDispatcher> pDispatcher, Poco::SharedPtr<LocalPortForwarder::ConnectionPair> pConnectionPair):
		BasicSocketForwarder(lpf, pDispatcher),
		_pConnectionPair(pConnectionPair),
		_logger(Poco::Logger::get("WebTunnel.StreamSocketToWebSocketForwarder"s))
	{
	}

	bool wantRead(SocketDispatcher& dispatcher)
	{
		return dispatcher.countPendingSends(_pConnectionPair->webSocket) == 0;
	}

	bool wantWrite(SocketDispatcher& dispatcher)
	{
		return false;
	}

	void readable(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
	{
		poco_assert_dbg (socket == _pConnectionPair->streamSocket);

		int n;
		try
		{
			n = _pConnectionPair->streamSocket.receiveBytes(_buffer.begin(), static_cast<int>(_buffer.size()));
			if (n < 0) return;
		}
		catch (Poco::Net::ConnectionResetException& exc)
		{
			_logger.debug("Exception while receiving data from local socket: %s"s, exc.displayText());
			shutdown(_pConnectionPair->webSocket, Poco::Net::WebSocket::WS_UNEXPECTED_CONDITION, _logger);
			_pDispatcher->updateSocket(_pConnectionPair->webSocket, Poco::Net::PollSet::POLL_READ, _pConnectionPair->closeTimeout);
			_pConnectionPair->webSocketFlags |= LocalPortForwarder::CF_CLOSED_LOCAL;

			notifyClientDisconnected(_pConnectionPair->streamSocket);
			_pDispatcher->removeSocket(_pConnectionPair->streamSocket);
			_pConnectionPair->streamSocketFlags |= LocalPortForwarder::CF_ERROR;
			return;
		}
		catch (Poco::Exception& exc)
		{
			_logger.error("Exception while receiving data from local socket: %s"s, exc.displayText());
			shutdown(_pConnectionPair->webSocket, Poco::Net::WebSocket::WS_UNEXPECTED_CONDITION, _logger);
			_pDispatcher->updateSocket(_pConnectionPair->webSocket, Poco::Net::PollSet::POLL_READ, _pConnectionPair->closeTimeout);
			_pConnectionPair->webSocketFlags |= LocalPortForwarder::CF_CLOSED_LOCAL;

			notifyClientDisconnected(_pConnectionPair->streamSocket);
			_pDispatcher->removeSocket(_pConnectionPair->streamSocket);
			_pConnectionPair->streamSocketFlags |= LocalPortForwarder::CF_ERROR;
			return;
		}
		if (n > 0)
		{
			if (_pConnectionPair->webSocketFlags & LocalPortForwarder::CF_ERROR)
			{
				// Hard close local stream socket
				notifyClientDisconnected(_pConnectionPair->streamSocket);
				_pDispatcher->removeSocket(_pConnectionPair->streamSocket);
			}
			else
			{
				_pDispatcher->sendBytes(_pConnectionPair->webSocket, _buffer.begin(), n, Poco::Net::WebSocket::FRAME_BINARY);
			}
			return;
		}
		else
		{
			_logger.debug("Local connection (socket %?d) closed by peer."s, socket.impl()->sockfd());
			if (!(_pConnectionPair->webSocketFlags & LocalPortForwarder::CF_CLOSED_LOCAL))
			{
				_logger.debug("Shutting down remote WebSocket connection %?d."s, _pConnectionPair->webSocket.impl()->sockfd());
				shutdown(_pConnectionPair->webSocket, Poco::Net::WebSocket::WS_NORMAL_CLOSE, _logger);
				_pConnectionPair->webSocketFlags |= LocalPortForwarder::CF_CLOSED_LOCAL;
				_pDispatcher->updateSocket(_pConnectionPair->webSocket, Poco::Net::PollSet::POLL_READ, _pConnectionPair->closeTimeout);
				_pDispatcher->updateSocket(_pConnectionPair->streamSocket, 0);
			}
			_pConnectionPair->streamSocketFlags |= LocalPortForwarder::CF_CLOSED_REMOTE;
			if (_pConnectionPair->streamSocketFlags & LocalPortForwarder::CF_CLOSED_LOCAL)
			{
				notifyClientDisconnected(_pConnectionPair->streamSocket);
				_pDispatcher->removeSocket(_pConnectionPair->streamSocket);
			}
		}
	}

	void writable(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
	{
	}

	void exception(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket, const Poco::Exception* pException)
	{
		_pConnectionPair->streamSocketFlags |= LocalPortForwarder::CF_ERROR;
		if (!(_pConnectionPair->webSocketFlags & LocalPortForwarder::CF_CLOSED_LOCAL))
		{
			shutdown(_pConnectionPair->webSocket, Poco::Net::WebSocket::WS_UNEXPECTED_CONDITION, _logger);
			_pConnectionPair->webSocketFlags |= LocalPortForwarder::CF_CLOSED_LOCAL;
			_pDispatcher->updateSocket(_pConnectionPair->webSocket, Poco::Net::PollSet::POLL_READ, _pConnectionPair->closeTimeout);
		}
		notifyClientDisconnected(_pConnectionPair->streamSocket);
		_pDispatcher->removeSocket(_pConnectionPair->streamSocket);
	}

	void timeout(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
	{
		if (!(_pConnectionPair->webSocketFlags & LocalPortForwarder::CF_CLOSED_LOCAL))
		{
			shutdown(_pConnectionPair->webSocket, Poco::Net::WebSocket::WS_UNEXPECTED_CONDITION, _logger);
			_pConnectionPair->webSocketFlags |= LocalPortForwarder::CF_CLOSED_LOCAL;
			_pDispatcher->updateSocket(_pConnectionPair->webSocket, Poco::Net::PollSet::POLL_READ, _pConnectionPair->closeTimeout);
		}
		_pConnectionPair->streamSocket.shutdown();
		_pConnectionPair->streamSocketFlags |= LocalPortForwarder::CF_CLOSED_LOCAL;
	}

private:
	Poco::SharedPtr<LocalPortForwarder::ConnectionPair> _pConnectionPair;
	Poco::Logger& _logger;
};


//
// WebSocketToStreamSocketForwarder
//


class WebSocketToStreamSocketForwarder: public BasicSocketForwarder
{
public:
	WebSocketToStreamSocketForwarder(LocalPortForwarder& lpf, Poco::SharedPtr<SocketDispatcher> pDispatcher, Poco::SharedPtr<LocalPortForwarder::ConnectionPair> pConnectionPair):
		BasicSocketForwarder(lpf, pDispatcher),
		_pConnectionPair(pConnectionPair),
		_logger(Poco::Logger::get("WebTunnel.WebSocketToStreamSocketForwarder"s))
	{
	}

	bool wantRead(SocketDispatcher& dispatcher)
	{
		return dispatcher.countPendingSends(_pConnectionPair->streamSocket) == 0;
	}

	bool wantWrite(SocketDispatcher& dispatcher)
	{
		return false;
	}

	void readable(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
	{
		poco_assert_dbg (socket == _pConnectionPair->webSocket);

		int flags;
		int n;
		try
		{
			n = _pConnectionPair->webSocket.receiveFrame(_buffer.begin(), static_cast<int>(_buffer.size()), flags);
			if (n < 0) return;
		}
		catch (Poco::Exception& exc)
		{
			_logger.error("Exception while receiving frame from remote socket: %s"s, exc.displayText());
			_pDispatcher->removeSocket(_pConnectionPair->webSocket);
			if (!(_pConnectionPair->webSocketFlags & LocalPortForwarder::CF_CLOSED_LOCAL))
			{
				_logger.error("Exception while receiving data from remote socket: %s"s, exc.displayText());
				_pConnectionPair->webSocketFlags |= LocalPortForwarder::CF_ERROR;
			}
			else
			{
				_pConnectionPair->webSocketFlags |= LocalPortForwarder::CF_CLOSED_REMOTE;
			}

			if (!(_pConnectionPair->streamSocketFlags & LocalPortForwarder::CF_CLOSED_LOCAL))
			{
				_logger.debug("Shutting down stream socket due to error on WebSocket."s);
				_pConnectionPair->streamSocketFlags |= LocalPortForwarder::CF_CLOSED_LOCAL;
				try
				{
					_pDispatcher->shutdownSend(_pConnectionPair->streamSocket);
				}
				catch (Poco::Net::NetException&)
				{
					_pConnectionPair->streamSocketFlags |= LocalPortForwarder::CF_ERROR;
					notifyClientDisconnected(_pConnectionPair->streamSocket);
					_pDispatcher->removeSocket(_pConnectionPair->streamSocket);
				}
			}
			return;
		}
		if ((flags & Poco::Net::WebSocket::FRAME_OP_BITMASK) == Poco::Net::WebSocket::FRAME_OP_PONG)
		{
			_logger.debug("PONG received."s);
			_timeoutCount = 0;
			return;
		}
		if (n > 0 && (flags & Poco::Net::WebSocket::FRAME_OP_BITMASK) == Poco::Net::WebSocket::FRAME_OP_BINARY)
		{
			if (!(_pConnectionPair->streamSocketFlags & LocalPortForwarder::CF_ERROR))
			{
				_logger.debug("Forwarding data (%d bytes) to stream socket.", n);
				dispatcher.sendBytes(_pConnectionPair->streamSocket, _buffer.begin(), n, 0);
			}
		}
		else if (n == 0 || (flags & Poco::Net::WebSocket::FRAME_OP_BITMASK) == Poco::Net::WebSocket::FRAME_OP_CLOSE)
		{
			if (!(_pConnectionPair->streamSocketFlags & LocalPortForwarder::CF_CLOSED_LOCAL))
			{
				_logger.debug("Shutting down stream socket due to WebSocket closing."s);
				try
				{
					dispatcher.shutdownSend(_pConnectionPair->streamSocket);
					_pConnectionPair->streamSocketFlags |= LocalPortForwarder::CF_CLOSED_LOCAL;
					_pDispatcher->updateSocket(_pConnectionPair->streamSocket, Poco::Net::PollSet::POLL_READ, _pConnectionPair->closeTimeout);
				}
				catch (Poco::Net::NetException&)
				{
					_pConnectionPair->streamSocketFlags |= LocalPortForwarder::CF_ERROR;
					notifyClientDisconnected(_pConnectionPair->streamSocket);
					_pDispatcher->removeSocket(_pConnectionPair->streamSocket);
				}
			}
			if (n == 0)
			{
				if (_pConnectionPair->webSocketFlags & LocalPortForwarder::CF_CLOSED_LOCAL)
				{
					dispatcher.removeSocket(_pConnectionPair->webSocket);
				}
				else
				{
					if (!(_pConnectionPair->webSocketFlags & LocalPortForwarder::CF_CLOSED_REMOTE))
					{
						_logger.debug("WebSocket connection ungracefully closed by peer."s);
						try
						{
							dispatcher.shutdownSend(_pConnectionPair->webSocket);
						}
						catch (Poco::Net::NetException&)
						{
						}
					}
					dispatcher.removeSocket(_pConnectionPair->webSocket);
				}
			}
			else
			{
				_logger.debug("WebSocket connection gracefully closed by peer."s);
				_pConnectionPair->webSocketFlags |= LocalPortForwarder::CF_CLOSED_REMOTE;
				_pDispatcher->shutdownSend(_pConnectionPair->webSocket);
				_pConnectionPair->webSocketFlags |= LocalPortForwarder::CF_CLOSED_LOCAL;
				_pDispatcher->updateSocket(_pConnectionPair->webSocket, Poco::Net::PollSet::POLL_READ, _pConnectionPair->closeTimeout);
			}
		}
		else
		{
			_logger.debug("Ignoring unsupported frame type"s);
		}
	}

	void writable(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
	{
	}

	void exception(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket, const Poco::Exception* pException)
	{
		dispatcher.removeSocket(_pConnectionPair->webSocket);
		_pConnectionPair->webSocketFlags |= LocalPortForwarder::CF_ERROR;

		try
		{
			dispatcher.shutdownSend(_pConnectionPair->streamSocket);
			_pConnectionPair->streamSocketFlags |= LocalPortForwarder::CF_CLOSED_LOCAL;
			_pDispatcher->updateSocket(_pConnectionPair->streamSocket, Poco::Net::PollSet::POLL_READ, _pConnectionPair->closeTimeout);
		}
		catch (Poco::Net::NetException&)
		{
			_pConnectionPair->streamSocketFlags |= LocalPortForwarder::CF_ERROR;	
			notifyClientDisconnected(_pConnectionPair->streamSocket);		
			_pDispatcher->removeSocket(_pConnectionPair->streamSocket);
		}
	}

	void timeout(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
	{
		_logger.debug("Timeout reading from WebSocket (timeoutCount = %d)."s, _timeoutCount);
		if (_timeoutCount == 0)
		{
			_timeoutCount = 1;
			_logger.debug("Sending PING."s);
			dispatcher.sendBytes(_pConnectionPair->webSocket, 0, 0, Poco::Net::WebSocket::FRAME_FLAG_FIN | Poco::Net::WebSocket::FRAME_OP_PING);
		}
		else
		{
			dispatcher.removeSocket(_pConnectionPair->webSocket);
			_pConnectionPair->webSocketFlags |= LocalPortForwarder::CF_ERROR;

			try
			{
				dispatcher.shutdownSend(_pConnectionPair->streamSocket);
				_pConnectionPair->streamSocketFlags |= LocalPortForwarder::CF_CLOSED_LOCAL;
				_pDispatcher->updateSocket(_pConnectionPair->streamSocket, Poco::Net::PollSet::POLL_READ, _pConnectionPair->closeTimeout);
			}
			catch (Poco::Net::NetException&)
			{
				_pConnectionPair->streamSocketFlags |= LocalPortForwarder::CF_ERROR;
				notifyClientDisconnected(_pConnectionPair->streamSocket);
				_pDispatcher->removeSocket(_pConnectionPair->streamSocket);			
			}
		}
	}

private:
	Poco::SharedPtr<LocalPortForwarder::ConnectionPair> _pConnectionPair;
	int _timeoutCount = 0;
	Poco::Logger& _logger;
};


//
// LocalPortForwarder
//


const std::string LocalPortForwarder::SEC_WEBSOCKET_PROTOCOL("Sec-WebSocket-Protocol");
const std::string LocalPortForwarder::X_WEBTUNNEL_REMOTEPORT("X-WebTunnel-RemotePort");
const std::string LocalPortForwarder::X_WEBTUNNEL_KEEPALIVE("X-WebTunnel-KeepAlive");
const std::string LocalPortForwarder::WEBTUNNEL_PROTOCOL("com.appinf.webtunnel.client/1.0");


LocalPortForwarder::LocalPortForwarder(Poco::UInt16 localPort, Poco::UInt16 remotePort, const Poco::URI& remoteURI, WebSocketFactory::Ptr pWebSocketFactory):
	_localAddr("localhost"s, localPort),
	_remotePort(remotePort),
	_remoteURI(remoteURI),
	_localTimeout(0),
	_remoteTimeout(300, 0),
	_pWebSocketFactory(pWebSocketFactory),
	_serverSocket(_localAddr),
	_tcpServer(new LocalPortForwarderConnectionFactory(*this), _serverSocket),
	_pDispatcher(new SocketDispatcher),
	_logger(Poco::Logger::get("WebTunnel.LocalPortForwarder"s))
{
	_localAddr = _serverSocket.address();
	_tcpServer.start();
}


LocalPortForwarder::LocalPortForwarder(const Poco::Net::SocketAddress& localAddress, Poco::UInt16 remotePort, const Poco::URI& remoteURI, Poco::Net::TCPServerParams::Ptr pServerParams, WebSocketFactory::Ptr pWebSocketFactory):
	_localAddr(localAddress),
	_remotePort(remotePort),
	_remoteURI(remoteURI),
	_localTimeout(0),
	_remoteTimeout(300, 0),
	_pWebSocketFactory(pWebSocketFactory),
	_serverSocket(_localAddr),
	_tcpServer(new LocalPortForwarderConnectionFactory(*this), _serverSocket, pServerParams),
	_pDispatcher(new SocketDispatcher),
	_logger(Poco::Logger::get("WebTunnel.LocalPortForwarder"s))
{
	_localAddr = _serverSocket.address();
	_tcpServer.start();
}


LocalPortForwarder::~LocalPortForwarder()
{
	try
	{
		_tcpServer.stop();
		_pDispatcher->stop();
	}
	catch (...)
	{
		poco_unexpected();
	}
}


void LocalPortForwarder::setLocalTimeout(Poco::Timespan timeout)
{
	_localTimeout = timeout;
}


void LocalPortForwarder::setRemoteTimeout(Poco::Timespan timeout)
{
	_remoteTimeout = timeout;
}


void LocalPortForwarder::setCloseTimeout(Poco::Timespan timeout)
{
	_closeTimeout = timeout;
}


void LocalPortForwarder::forward(Poco::Net::StreamSocket& socket)
{
	if (_logger.debug())
	{
		_logger.debug("Local connection accepted, creating forwarding connection to %s, remote port %hu."s, _remoteURI.toString(), _remotePort);
	}
	try
	{
		std::string path(_remoteURI.getPathEtc());
		if (path.empty()) path = "/";
		Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, path, Poco::Net::HTTPRequest::HTTP_1_1);
		request.set(SEC_WEBSOCKET_PROTOCOL, WEBTUNNEL_PROTOCOL);
		request.set(X_WEBTUNNEL_REMOTEPORT, Poco::NumberFormatter::format(_remotePort));
		request.set(X_WEBTUNNEL_KEEPALIVE, Poco::NumberFormatter::format(_remoteTimeout.totalSeconds()));
		Poco::Net::HTTPResponse response;
		Poco::SharedPtr<Poco::Net::WebSocket> pWebSocket = _pWebSocketFactory->createWebSocket(_remoteURI, request, response);
		if (response.get(SEC_WEBSOCKET_PROTOCOL, ""s) != WEBTUNNEL_PROTOCOL)
		{
			_logger.error("The remote host does not support the WebTunnel protocol."s);
			pWebSocket->shutdown(Poco::Net::WebSocket::WS_PROTOCOL_ERROR);
			pWebSocket->shutdownSend();
			pWebSocket->setBlocking(false);
			if (pWebSocket->poll(_closeTimeout, Poco::Net::Socket::SELECT_READ | Poco::Net::Socket::SELECT_WRITE))
			{
				try
				{
					Poco::Buffer<char> buffer(0);
					int flags;
					int n = pWebSocket->receiveFrame(buffer, flags);
					if (n > 0 && (flags & Poco::Net::WebSocket::FRAME_OP_CLOSE) == 0)
					{
						_logger.warning("Unexpected data frame received after closing WebSocket connection."s);
					}
				}
				catch (Poco::Exception&)
				{
				}
			}
			pWebSocket->close();
			socket.close();
			return;
		}

		if (response.has(X_WEBTUNNEL_KEEPALIVE))
		{
			int keepAlive = Poco::NumberParser::parse(response.get(X_WEBTUNNEL_KEEPALIVE));
			_remoteTimeout.assign(keepAlive, 0);
			_logger.debug("Server has requested a keep-alive timeout (remoteTimeout) of %d seconds."s, keepAlive);
		}

		Poco::SharedPtr<ConnectionPair> pConnectionPair = new ConnectionPair(*pWebSocket, socket, _closeTimeout);

		socket.setNoDelay(true);
		socket.setBlocking(false);
		_pDispatcher->addSocket(socket, new StreamSocketToWebSocketForwarder(*this, _pDispatcher, pConnectionPair), 0, _localTimeout);

		pWebSocket->setNoDelay(true);
		pWebSocket->setBlocking(false);
		_pDispatcher->addSocket(*pWebSocket, new WebSocketToStreamSocketForwarder(*this, _pDispatcher, pConnectionPair), Poco::Net::PollSet::POLL_READ, _remoteTimeout);

		_pDispatcher->updateSocket(socket, Poco::Net::PollSet::POLL_READ);

		clientConnected(this, socket.peerAddress());
	}
	catch (Poco::Exception& exc)
	{
		_logger.error("Failed to open forwarding connection: %s"s, exc.displayText());
		socket.close();
	}
}


} } // namespace Poco::WebTunnel
