//
// SocketDispatcher.cpp
//
// Library: WebTunnel
// Package: WebTunnel
// Module:  SocketDispatcher
//
// Definition of the SocketDispatcher class.
//
// Copyright (c) 2013, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/WebTunnel/SocketDispatcher.h"
#include "Poco/Net/NetException.h"
#include "Poco/Event.h"
#include <numeric>


using namespace std::string_literals;


namespace Poco {
namespace WebTunnel {


class AddSocketNotification: public SocketDispatcher::TaskNotification
{
public:
	using Ptr = Poco::AutoPtr<AddSocketNotification>;

	AddSocketNotification(SocketDispatcher& dispatcher, const Poco::Net::StreamSocket& socket, const SocketDispatcher::SocketHandler::Ptr& pHandler, int mode, Poco::Timespan receiveTimeout, Poco::Timespan sendTimeout):
		TaskNotification(dispatcher),
		_socket(socket),
		_pHandler(pHandler),
		_mode(mode),
		_receiveTimeout(receiveTimeout),
		_sendTimeout(sendTimeout)
	{
	}

	void execute()
	{
		AutoSetEvent ase(_done);

		_dispatcher.addSocketImpl(_socket, _pHandler, _mode, _receiveTimeout, _sendTimeout);
	}

private:
	Poco::Net::StreamSocket _socket;
	SocketDispatcher::SocketHandler::Ptr _pHandler;
	int _mode;
	Poco::Timespan _receiveTimeout;
	Poco::Timespan _sendTimeout;
};


class UpdateSocketNotification: public SocketDispatcher::TaskNotification
{
public:
	using Ptr = Poco::AutoPtr<UpdateSocketNotification>;

	UpdateSocketNotification(SocketDispatcher& dispatcher, const Poco::Net::StreamSocket& socket, int mode, Poco::Timespan receiveTimeout, Poco::Timespan sendTimeout):
		TaskNotification(dispatcher),
		_socket(socket),
		_mode(mode),
		_receiveTimeout(receiveTimeout),
		_sendTimeout(sendTimeout)
	{
	}

	void execute()
	{
		AutoSetEvent ase(_done);

		_dispatcher.updateSocketImpl(_socket, _mode, _receiveTimeout, _sendTimeout);
	}

private:
	Poco::Net::StreamSocket _socket;
	int _mode;
	Poco::Timespan _receiveTimeout;
	Poco::Timespan _sendTimeout;
};


class RemoveSocketNotification: public SocketDispatcher::TaskNotification
{
public:
	using Ptr = Poco::AutoPtr<RemoveSocketNotification>;

	RemoveSocketNotification(SocketDispatcher& dispatcher, const Poco::Net::StreamSocket& socket):
		TaskNotification(dispatcher),
		_socket(socket)
	{
	}

	void execute()
	{
		AutoSetEvent ase(_done);

		_dispatcher.removeSocketImpl(_socket);
	}

private:
	Poco::Net::StreamSocket _socket;
};


class CloseSocketNotification: public SocketDispatcher::TaskNotification
{
public:
	using Ptr = Poco::AutoPtr<CloseSocketNotification>;

	CloseSocketNotification(SocketDispatcher& dispatcher, const Poco::Net::StreamSocket& socket):
		TaskNotification(dispatcher),
		_socket(socket)
	{
	}

	void execute()
	{
		AutoSetEvent ase(_done);

		_dispatcher.closeSocketImpl(_socket);
	}

private:
	Poco::Net::StreamSocket _socket;
};


class HasSocketNotification: public SocketDispatcher::TaskNotification
{
public:
	using Ptr = Poco::AutoPtr<HasSocketNotification>;

	HasSocketNotification(SocketDispatcher& dispatcher, const Poco::Net::StreamSocket& socket):
		TaskNotification(dispatcher),
		_socket(socket)
	{
	}

	void execute()
	{
		AutoSetEvent ase(_done);

		_result = _dispatcher.hasSocketImpl(_socket);
	}

	bool result() const
	{
		return _result;
	}

private:
	Poco::Net::StreamSocket _socket;
	bool _result = false;
};


class ResetNotification: public SocketDispatcher::TaskNotification
{
public:
	using Ptr = Poco::AutoPtr<ResetNotification>;

	ResetNotification(SocketDispatcher& dispatcher):
		TaskNotification(dispatcher)
	{
	}

	void execute()
	{
		AutoSetEvent ase(_done);

		_dispatcher.resetImpl();
	}
};


class SendBytesNotification: public SocketDispatcher::TaskNotification
{
public:
	using Ptr = Poco::AutoPtr<SendBytesNotification>;

	SendBytesNotification(SocketDispatcher& dispatcher, const Poco::Net::StreamSocket& socket, const void* pBuffer, std::size_t length, int options):
		TaskNotification(dispatcher),
		_socket(socket),
		_buffer(reinterpret_cast<const char*>(pBuffer), length),
		_options(options)
	{
	}

	void execute()
	{
		AutoSetEvent ase(_done);

		_dispatcher.sendBytesImpl(_socket, std::move(_buffer), _options, true);
	}

private:
	Poco::Net::StreamSocket _socket;
	Poco::Buffer<char> _buffer;
	int _options;
};


class ShutdownSendNotification: public SocketDispatcher::TaskNotification
{
public:
	using Ptr = Poco::AutoPtr<ShutdownSendNotification>;

	ShutdownSendNotification(SocketDispatcher& dispatcher, const Poco::Net::StreamSocket& socket):
		TaskNotification(dispatcher),
		_socket(socket)
	{
	}

	void execute()
	{
		AutoSetEvent ase(_done);

		_dispatcher.shutdownSendImpl(_socket);
	}

private:
	Poco::Net::StreamSocket _socket;
};


SocketDispatcher::SocketDispatcher(Poco::Timespan timeout):
	_timeout(timeout),
	_sendTimeout(30, 0),
	_stopped(false),
	_logger(Poco::Logger::get("WebTunnel.SocketDispatcher"s))
{
	_thread.start(*this);
}


SocketDispatcher::~SocketDispatcher()
{
	try
	{
		stop();
	}
	catch (...)
	{
		poco_unexpected();
	}
}


void SocketDispatcher::setSendTimeout(Poco::Timespan sendTimeout)
{
	_sendTimeout = sendTimeout;
}


void SocketDispatcher::stop()
{
	if (!stopped())
	{
		_stopped = true;
		_queue.wakeUpAll();
		_thread.join();
		_socketMap.clear();
		_pollSet.clear();
	}
}


void SocketDispatcher::reset()
{
	ResetNotification::Ptr pNf = new ResetNotification(*this);
	_queue.enqueueNotification(pNf);
	_pollSet.wakeUp();
	if (!inDispatcherThread())
	{
		pNf->wait();
	}
}


void SocketDispatcher::addSocket(const Poco::Net::StreamSocket& socket, SocketHandler::Ptr pHandler, int mode, Poco::Timespan receiveTimeout, Poco::Timespan sendTimeout)
{
	if (inDispatcherThread())
	{
		addSocketImpl(socket, pHandler, mode, receiveTimeout, sendTimeout);
	}
	else
	{
		AddSocketNotification::Ptr pNf = new AddSocketNotification(*this, socket, pHandler, mode, receiveTimeout, sendTimeout);
		_queue.enqueueNotification(pNf);
		_pollSet.wakeUp();
		pNf->wait();
	}
}


void SocketDispatcher::updateSocket(const Poco::Net::StreamSocket& socket, int mode, Poco::Timespan receiveTimeout, Poco::Timespan sendTimeout)
{
	if (inDispatcherThread())
	{
		updateSocketImpl(socket, mode, receiveTimeout, sendTimeout);
	}
	else
	{
		UpdateSocketNotification::Ptr pNf = new UpdateSocketNotification(*this, socket, mode, receiveTimeout, sendTimeout);
		_queue.enqueueNotification(pNf);
		_pollSet.wakeUp();
		pNf->wait();
	}
}


void SocketDispatcher::removeSocket(const Poco::Net::StreamSocket& socket)
{
	if (inDispatcherThread())
	{
		removeSocketImpl(socket);
	}
	else
	{
		RemoveSocketNotification::Ptr pNf = new RemoveSocketNotification(*this, socket);
		_queue.enqueueNotification(pNf);
		_pollSet.wakeUp();
		pNf->wait();
	}
}


void SocketDispatcher::closeSocket(Poco::Net::StreamSocket& socket)
{
	if (inDispatcherThread())
	{
		closeSocketImpl(socket);
	}
	else
	{
		CloseSocketNotification::Ptr pNf = new CloseSocketNotification(*this, socket);
		_queue.enqueueNotification(pNf);
		_pollSet.wakeUp();
		pNf->wait();
	}
}


bool SocketDispatcher::hasSocket(const Poco::Net::StreamSocket& socket)
{
	if (inDispatcherThread())
	{
		return hasSocketImpl(socket);
	}
	else
	{
		HasSocketNotification::Ptr pNf = new HasSocketNotification(*this, socket);
		_queue.enqueueNotification(pNf);
		_pollSet.wakeUp();
		pNf->wait();
		return pNf->result();
	}
}


void SocketDispatcher::sendBytes(Poco::Net::StreamSocket& socket, const void* buffer, std::size_t length, int options)
{
	if (inDispatcherThread())
	{
		sendBytesImpl(socket, Poco::Buffer<char>(reinterpret_cast<const char*>(buffer), length), options, false);
	}
	else
	{
		SendBytesNotification::Ptr pNf = new SendBytesNotification(*this, socket, buffer, length, options);
		_queue.enqueueNotification(pNf);
		_pollSet.wakeUp();
		pNf->wait();
	}
}


void SocketDispatcher::shutdownSend(Poco::Net::StreamSocket& socket)
{
	if (inDispatcherThread())
	{
		shutdownSendImpl(socket);
	}
	else
	{
		ShutdownSendNotification::Ptr pNf = new ShutdownSendNotification(*this, socket);
		_queue.enqueueNotification(pNf);
		_pollSet.wakeUp();
		pNf->wait();
	}
}


void SocketDispatcher::run()
{
	Poco::Timespan currentTimeout(_timeout);
	Poco::Timestamp lastSocketDump;
	while (!stopped())
	{
		try
		{
			bool dumpSockets = false;
			if (_logger.trace() && lastSocketDump.isElapsed(30*Poco::Timestamp::resolution()))
			{
				_logger.trace("Have %z sockets in dispatcher, %z in PollSet."s, _socketMap.size(), _pollSet.size());
				dumpSockets = true;
				lastSocketDump.update();
			}
			auto it = _socketMap.begin();
			while (it != _socketMap.end())
			{
				Poco::Net::Socket socket = it->first;
				SocketInfo::Ptr pSocketInfo = it->second;
				++it;
				if (dumpSockets)
				{
					_logger.trace("Socket %8?d -> %4d; %8Ld; %2z"s, socket.impl()->sockfd(), pSocketInfo->mode, pSocketInfo->receiveTimeout.totalMilliseconds(), pSocketInfo->pendingSends.size());
				}
				if (pSocketInfo->receiveTimeout != 0 && pSocketInfo->receiveTimeout < pSocketInfo->lastReceive.elapsed())
				{
					pSocketInfo->lastReceive.update();
					timeout(socket, pSocketInfo);
				}
				if (!pSocketInfo->removed && !pSocketInfo->pendingSends.empty() && pSocketInfo->sendTimeout < pSocketInfo->pendingSends[0].clock.elapsed())
				{
					_logger.debug("Socket %?d send timeout."s, socket.impl()->sockfd());
					pSocketInfo->pendingSends.clear();
					pSocketInfo->sslWriteWantRead = false;
					Poco::TimeoutException exc("Send timed out"s);
					exception(socket, pSocketInfo, &exc);
				}
				if (!pSocketInfo->removed)
				{
					int mode = pSocketInfo->mode;
					if ((mode & Poco::Net::PollSet::POLL_READ) != 0 && (pSocketInfo->pHandler->wantRead(*this) || pSocketInfo->sslWriteWantRead))
						mode |= Poco::Net::PollSet::POLL_READ;
					else
						mode &= ~Poco::Net::PollSet::POLL_READ;
					if ((!pSocketInfo->pendingSends.empty() && !pSocketInfo->sslWriteWantRead) || ((mode & Poco::Net::PollSet::POLL_WRITE) != 0 && pSocketInfo->pHandler->wantWrite(*this)))
						mode |= Poco::Net::PollSet::POLL_WRITE;
					else
						mode &= ~Poco::Net::PollSet::POLL_WRITE;
					_pollSet.update(socket, mode);
				}
			}

			Poco::Net::PollSet::SocketModeMap socketModeMap = _pollSet.poll(currentTimeout);
			if (!socketModeMap.empty())
			{
				if (_logger.trace()) _logger.trace("================"s);
				currentTimeout = _timeout;
				for (Poco::Net::PollSet::SocketModeMap::const_iterator it = socketModeMap.begin(); it != socketModeMap.end(); ++it)
				{
					Poco::Net::Socket socket = it->first;
					SocketMap::iterator its = _socketMap.find(socket);
					if (its != _socketMap.end())
					{
						SocketInfo::Ptr pSocketInfo = its->second;
						if ((it->second & Poco::Net::PollSet::POLL_ERROR) != 0)
						{
							if (_logger.trace()) _logger.trace("Socket %?d has exception."s, its->first.impl()->sockfd());
							exception(socket, pSocketInfo);
						}
						if (!pSocketInfo->removed && (it->second & Poco::Net::PollSet::POLL_READ) != 0)
						{
							if (_logger.trace()) _logger.trace("Socket %?d is readable."s, its->first.impl()->sockfd());
							its->second->lastReceive.update();
							readable(its->first, its->second);
						}
						if (!pSocketInfo->removed && (it->second & Poco::Net::PollSet::POLL_WRITE) != 0)
						{
							if (_logger.trace()) _logger.trace("Socket %?d is writable."s, its->first.impl()->sockfd());
							writable(its->first, its->second);
						}
					}
				}
			}
			else
			{
				if (currentTimeout.totalMicroseconds() < 4*_timeout.totalMicroseconds()) currentTimeout += _timeout.totalMicroseconds()/2;
			}

			Poco::Notification::Ptr pNf = _socketMap.empty() ? _queue.waitDequeueNotification(MAIN_QUEUE_TIMEOUT) : _queue.dequeueNotification();
			while (pNf)
			{
				TaskNotification::Ptr pTaskNf = pNf.cast<TaskNotification>();
				if (pTaskNf)
				{
					pTaskNf->execute();
				}
				pNf = _socketMap.empty() ? _queue.waitDequeueNotification(MAIN_QUEUE_TIMEOUT) : _queue.dequeueNotification();
			}
		}
		catch (Poco::Net::NetException& exc)
		{
			if (exc.code() == POCO_ENOTCONN)
			{
				_logger.debug("A socket is no longer connected."s);
			}
			else
			{
				_logger.error("Network exception in socket dispatcher: %s"s, exc.displayText());
			}
		}
		catch (Poco::Exception& exc)
		{
			_logger.error("Exception in socket dispatcher: %s"s, exc.displayText());
		}
	}
}


void SocketDispatcher::readable(const Poco::Net::Socket& socket, SocketDispatcher::SocketInfo::Ptr pInfo)
{
	try
	{
		Poco::Net::StreamSocket ss(socket);
		if (pInfo->sslWriteWantRead)
		{
			pInfo->sslWriteWantRead = false;
			writable(socket, pInfo);
			if (ss.available() == 0 || pInfo->sslWriteWantRead) return;
		}
		do
		{
			pInfo->pHandler->readable(*this, ss);
		}
		while (ss.good() && ss.available() > 0 && !ss.poll(0, Poco::Net::PollSet::POLL_READ));
		// Need to loop here as there could still be buffered data in an internal socket
		// buffer (especially with SecureStreamSocket) that would not be indicated by PollSet.
		// However, we don't want to be stuck handling just that one
		// socket if a peer drowns us in data.
	}
	catch (Poco::Exception& exc)
	{
		_logger.error("Error handling readable socket %?d: %s"s, socket.impl()->sockfd(), exc.displayText());
	}
}


void SocketDispatcher::writable(const Poco::Net::Socket& socket, SocketDispatcher::SocketInfo::Ptr pInfo)
{
	try
	{
		Poco::Net::StreamSocket ss(socket);
		if (pInfo->pendingSends.empty())
		{
			pInfo->pHandler->writable(*this, ss);
		}
		else
		{
			while (!pInfo->pendingSends.empty())
			{
				PendingSend& pending = *pInfo->pendingSends.begin();
				if (pending.options == PendingSend::OPT_SHUTDOWN)
				{
					_logger.debug("Shutting down socket %?d..."s, ss.impl()->sockfd());
					if (ss.shutdownSend() >= 0)
					{
						_logger.debug("Shut down socket %?d."s, ss.impl()->sockfd());
						if (pInfo->pendingSends.size() > 1)
						{
							_logger.debug("Discarding pending writes after shutdown."s);
						}
						pInfo->pendingSends.clear();
					}
					else break;
				}
				else
				{
					if (_logger.trace()) _logger.trace("Sending %z bytes to socket %?d."s, pending.buffer.size(), ss.impl()->sockfd());
					try
					{
						int sent = ss.sendBytes(pending.buffer.begin(), static_cast<int>(pending.buffer.size()), pending.options);
						if (sent > 0)
						{
							if (sent < pending.buffer.size())
							{
								if (_logger.trace()) _logger.trace("Short write (%d) on socket %?d."s, sent, ss.impl()->sockfd());
								std::memmove(pending.buffer.begin(), pending.buffer.begin() + sent, pending.buffer.size() - sent);
								pending.buffer.resize(pending.buffer.size() - sent);
								break;
							}
							else
							{
								pInfo->pendingSends.pop_front();
							}
						}
						else if (sent == ERR_SSL_WANT_READ)
						{
							if (_logger.trace()) _logger.trace("SSL write wants read (handshake) on socket %?d."s, ss.impl()->sockfd());
							pInfo->sslWriteWantRead = true;
							break;
						}
						else break;
					}
					catch (Poco::Exception& exc)
					{
						_logger.error("Error writing to socket %?d: %s"s, socket.impl()->sockfd(), exc.displayText());
						exception(socket, pInfo, &exc);
						break;
					}
				}
			}
		}
	}
	catch (Poco::Exception& exc)
	{
		_logger.error("Error handling writable socket %?d: %s"s, socket.impl()->sockfd(), exc.displayText());
	}
}


void SocketDispatcher::exception(const Poco::Net::Socket& socket, SocketDispatcher::SocketInfo::Ptr pInfo, const Poco::Exception* pException)
{
	try
	{
		Poco::Net::StreamSocket ss(socket);
		pInfo->pHandler->exception(*this, ss, pException);
	}
	catch (Poco::Exception& exc)
	{
		_logger.error("Error handling exceptioned socket %?d: %s"s, socket.impl()->sockfd(), exc.displayText());
	}
}


void SocketDispatcher::timeout(const Poco::Net::Socket& socket, SocketDispatcher::SocketInfo::Ptr pInfo)
{
	try
	{
		Poco::Net::StreamSocket ss(socket);
		pInfo->pHandler->timeout(*this, ss);
	}
	catch (Poco::Exception& exc)
	{
		_logger.log(exc);
	}
}


void SocketDispatcher::addSocketImpl(const Poco::Net::StreamSocket& socket, SocketHandler::Ptr pHandler, int mode, Poco::Timespan receiveTimeout, Poco::Timespan sendTimeout)
{
	if (_logger.trace()) _logger.trace("Adding socket %?d (%d)..."s, socket.impl()->sockfd(), mode);
	mode |= Poco::Net::PollSet::POLL_ERROR;
	if (sendTimeout == 0) sendTimeout = _sendTimeout;
	_socketMap[socket] = new SocketInfo(pHandler, mode, receiveTimeout, sendTimeout);
	_pollSet.add(socket, mode);
}


void SocketDispatcher::updateSocketImpl(const Poco::Net::StreamSocket& socket, int mode, Poco::Timespan receiveTimeout, Poco::Timespan sendTimeout)
{
	auto it = _socketMap.find(socket);
	if (it != _socketMap.end())
	{
		if (receiveTimeout != 0)
		{
			it->second->receiveTimeout = receiveTimeout;
			it->second->lastReceive.update();
		}
		if (sendTimeout != 0)
		{
			it->second->sendTimeout = sendTimeout;
		}
		mode |= Poco::Net::PollSet::POLL_ERROR;
		if (_logger.trace()) _logger.trace("Updating socket %?d (%d -> %d)..."s, socket.impl()->sockfd(), it->second->mode, mode);
		it->second->mode = mode;
		_pollSet.update(socket, mode);
	}
}


void SocketDispatcher::removeSocketImpl(const Poco::Net::StreamSocket& socket)
{
	auto it = _socketMap.find(socket);
	if (it != _socketMap.end())
	{
		if (_logger.trace()) _logger.trace("Removing socket %?d..."s, socket.impl()->sockfd());
		it->second->removed = true;
		_socketMap.erase(it);
		try
		{
			_pollSet.remove(socket);
		}
		catch (Poco::IOException&)
		{
		}
	}
}


void SocketDispatcher::closeSocketImpl(Poco::Net::StreamSocket& socket)
{
	if (_logger.trace()) _logger.trace("Closing socket %?d..."s, socket.impl()->sockfd());
	removeSocketImpl(socket);
	socket.close();
}


bool SocketDispatcher::hasSocketImpl(const Poco::Net::StreamSocket& socket) const
{
	return _socketMap.find(socket) != _socketMap.end();
}


void SocketDispatcher::resetImpl()
{
	_socketMap.clear();
	_pollSet.clear();
}


void SocketDispatcher::sendBytesImpl(Poco::Net::StreamSocket& socket, Poco::Buffer<char>&& buffer, int options, bool reportException)
{
	if (_logger.trace()) _logger.trace("Sending %z bytes on socket %?d."s, buffer.size(), socket.impl()->sockfd());
	auto it = _socketMap.find(socket);
	if (it != _socketMap.end())
	{
		if  (it->second->pendingSends.empty())
		{
			try
			{
				int sent = socket.sendBytes(buffer.begin(), static_cast<int>(buffer.size()), options);
				if (sent < 0)
				{
					it->second->pendingSends.emplace_back(std::move(buffer), options);
					if (sent == ERR_SSL_WANT_READ)
					{
						if (_logger.trace()) _logger.trace("SSL write wants read (handshake) on socket %?d."s, socket.impl()->sockfd());
						it->second->sslWriteWantRead = true;
					}
				}
				else if (sent < buffer.size())
				{
					if (_logger.trace()) _logger.trace("Short write (%d) on socket %?d."s, sent, socket.impl()->sockfd());
					it->second->pendingSends.emplace_back(buffer.begin() + sent, buffer.size() - sent, options);
				}
			}
			catch (Poco::Exception& exc)
			{
				_logger.error("Error writing to socket %?d: %s"s, socket.impl()->sockfd(), exc.displayText());
				if (reportException)
				{
					exception(socket, it->second, &exc);
				}
				else throw;
			}
		}
		else
		{
			it->second->pendingSends.emplace_back(std::move(buffer), options);
		}
	}
	else
	{
		_logger.error("sendBytes() called with unknown socket %?d."s, socket.impl()->sockfd());
	}
}


void SocketDispatcher::shutdownSendImpl(Poco::Net::StreamSocket& socket)
{
	_logger.debug("Shutting down socket %?d"s, socket.impl()->sockfd());
	auto it = _socketMap.find(socket);
	if (it != _socketMap.end())
	{
		if  (it->second->pendingSends.empty())
		{
			int rc = socket.shutdownSend();
			if (rc < 0)
			{
				// would block, try again later
				it->second->pendingSends.emplace_back(PendingSend::OPT_SHUTDOWN);
			}
		}
		else
		{
			it->second->pendingSends.emplace_back(PendingSend::OPT_SHUTDOWN);
		}
	}
}


std::size_t SocketDispatcher::countPendingSends(const Poco::Net::StreamSocket& socket) const
{
	auto it = _socketMap.find(socket);
	if (it != _socketMap.end())
	{
		return it->second->pendingSends.size();
	}
	else return 0;
}


std::size_t SocketDispatcher::countPendingBytesToSend(const Poco::Net::StreamSocket& socket) const
{
	auto it = _socketMap.find(socket);
	if (it != _socketMap.end())
	{
		return std::accumulate(
			it->second->pendingSends.begin(), it->second->pendingSends.end(), 0,
			[](std::size_t n, const PendingSend& p2)
			{
				return n + p2.buffer.size();
			}
		);
	}
	else return 0;
}


} } // namespace Poco::WebTunnel
