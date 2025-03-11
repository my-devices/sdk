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

	AddSocketNotification(SocketDispatcher& dispatcher, const Poco::Net::StreamSocket& socket, const SocketDispatcher::SocketHandler::Ptr& pHandler, int mode, Poco::Timespan timeout):
		TaskNotification(dispatcher),
		_socket(socket),
		_pHandler(pHandler),
		_mode(mode),
		_timeout(timeout)
	{
	}

	void execute()
	{
		AutoSetEvent ase(_done);

		_dispatcher.addSocketImpl(_socket, _pHandler, _mode, _timeout);
	}

private:
	Poco::Net::StreamSocket _socket;
	SocketDispatcher::SocketHandler::Ptr _pHandler;
	int _mode;
	Poco::Timespan _timeout;
};


class UpdateSocketNotification: public SocketDispatcher::TaskNotification
{
public:
	using Ptr = Poco::AutoPtr<UpdateSocketNotification>;

	UpdateSocketNotification(SocketDispatcher& dispatcher, const Poco::Net::StreamSocket& socket, int mode, Poco::Timespan timeout):
		TaskNotification(dispatcher),
		_socket(socket),
		_mode(mode),
		_timeout(timeout)
	{
	}

	void execute()
	{
		AutoSetEvent ase(_done);

		_dispatcher.updateSocketImpl(_socket, _mode, _timeout);
	}

private:
	Poco::Net::StreamSocket _socket;
	int _mode;
	Poco::Timespan _timeout;
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

		_dispatcher.sendBytesImpl(_socket, std::move(_buffer), _options);
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


void SocketDispatcher::addSocket(const Poco::Net::StreamSocket& socket, SocketHandler::Ptr pHandler, int mode, Poco::Timespan timeout)
{
	AddSocketNotification::Ptr pNf = new AddSocketNotification(*this, socket, pHandler, mode, timeout);
	_queue.enqueueNotification(pNf);
	_pollSet.wakeUp();
	if (!inDispatcherThread())
	{
		pNf->wait();
	}
}


void SocketDispatcher::updateSocket(const Poco::Net::StreamSocket& socket, int mode, Poco::Timespan timeout)
{
	if (inDispatcherThread())
	{
		updateSocketImpl(socket, mode, timeout);
	}
	else
	{
		UpdateSocketNotification::Ptr pNf = new UpdateSocketNotification(*this, socket, mode, timeout);
		_queue.enqueueNotification(pNf);
		_pollSet.wakeUp();
		pNf->wait();
	}
}


void SocketDispatcher::removeSocket(const Poco::Net::StreamSocket& socket)
{
	RemoveSocketNotification::Ptr pNf = new RemoveSocketNotification(*this, socket);
	_queue.enqueueNotification(pNf);
	_pollSet.wakeUp();
	if (!inDispatcherThread())
	{
		pNf->wait();
	}
}


void SocketDispatcher::closeSocket(const Poco::Net::StreamSocket& socket)
{
	CloseSocketNotification::Ptr pNf = new CloseSocketNotification(*this, socket);
	_queue.enqueueNotification(pNf);
	_pollSet.wakeUp();
	if (!inDispatcherThread())
	{
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
		sendBytesImpl(socket, Poco::Buffer<char>(reinterpret_cast<const char*>(buffer), length), options);
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
			for (SocketMap::iterator it = _socketMap.begin(); it != _socketMap.end(); ++it)
			{
				if (dumpSockets)
				{
					_logger.trace("Socket %8?d -> %4d; %8Ld; %2z"s, it->first.impl()->sockfd(), it->second->mode, it->second->timeout.totalMilliseconds(), it->second->pendingSends.size());
				}
				if (it->second->timeout != 0 && it->second->timeout < it->second->activity.elapsed())
				{
					it->second->activity.update();
					timeout(it->first, it->second);
				}
				int mode = it->second->mode;
				if ((mode & Poco::Net::PollSet::POLL_READ) != 0 && it->second->pHandler->wantRead(*this))
					mode |= Poco::Net::PollSet::POLL_READ;
				else
					mode &= ~Poco::Net::PollSet::POLL_READ;
				if (!it->second->pendingSends.empty() || ((mode & Poco::Net::PollSet::POLL_WRITE) != 0 && it->second->pHandler->wantWrite(*this)))
					mode |= Poco::Net::PollSet::POLL_WRITE;
				else
					mode &= ~Poco::Net::PollSet::POLL_WRITE;
				_pollSet.update(it->first, mode);
			}

			Poco::Net::PollSet::SocketModeMap socketModeMap = _pollSet.poll(currentTimeout);
			if (!socketModeMap.empty())
			{
				currentTimeout = _timeout;
				for (Poco::Net::PollSet::SocketModeMap::const_iterator it = socketModeMap.begin(); it != socketModeMap.end(); ++it)
				{
					SocketMap::iterator its = _socketMap.find(it->first);
					if (its != _socketMap.end())
					{
						its->second->activity.update();
						if (it->second & Poco::Net::PollSet::POLL_READ)
						{
							readable(its->first, its->second);
						}
						if ((it->second & Poco::Net::PollSet::POLL_WRITE))
						{
							writable(its->first, its->second);
						}
						if (it->second & Poco::Net::PollSet::POLL_ERROR)
						{
							exception(its->first, its->second);
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
		do
		{
			pInfo->pHandler->readable(*this, ss);
		}
		while (ss.available() > 0 && !ss.poll(0, Poco::Net::PollSet::POLL_READ));
		// Need to loop here as there could still be buffered data in an internal socket 
		// buffer (especially with SecureStreamSocket) that would not be indicated by PollSet.
		// However, we don't want to be stuck handling just that one
		// socket if a peer drowns us in data. 
	}
	catch (Poco::Exception& exc)
	{
		_logger.log(exc);
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
					int sent = ss.sendBytes(pending.buffer.begin(), static_cast<int>(pending.buffer.size()), pending.options);
					if (sent > 0)
					{
						if (sent < pending.buffer.size())
						{
							std::memmove(pending.buffer.begin(), pending.buffer.begin() + sent, pending.buffer.size() - sent);
							pending.buffer.resize(pending.buffer.size() - sent);
							break;
						}
						else
						{
							pInfo->pendingSends.pop_front();
						}
					}
					else break;
				}
			}
		}
	}
	catch (Poco::Exception& exc)
	{
		_logger.log(exc);
	}
}


void SocketDispatcher::exception(const Poco::Net::Socket& socket, SocketDispatcher::SocketInfo::Ptr pInfo)
{
	try
	{
		Poco::Net::StreamSocket ss(socket);
		pInfo->pHandler->exception(*this, ss);
	}
	catch (Poco::Exception& exc)
	{
		_logger.log(exc);
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


void SocketDispatcher::addSocketImpl(const Poco::Net::StreamSocket& socket, SocketHandler::Ptr pHandler, int mode, Poco::Timespan timeout)
{
	_logger.trace("Adding socket %?d (%d)..."s, socket.impl()->sockfd(), mode);
	mode |= Poco::Net::PollSet::POLL_ERROR;
	_socketMap[socket] = new SocketInfo(pHandler, mode, timeout);
	_pollSet.add(socket, mode);
}


void SocketDispatcher::updateSocketImpl(const Poco::Net::StreamSocket& socket, int mode, Poco::Timespan timeout)
{
	auto it = _socketMap.find(socket);
	if (it != _socketMap.end())
	{
		if (timeout != 0)
		{
			it->second->timeout = timeout;
			it->second->activity.update();
		}
		mode |= Poco::Net::PollSet::POLL_ERROR;
		_logger.trace("Updating socket %?d (%d -> %d)..."s, socket.impl()->sockfd(), it->second->mode, mode);
		it->second->mode = mode;
		_pollSet.update(socket, mode);
	}
}


void SocketDispatcher::removeSocketImpl(const Poco::Net::StreamSocket& socket)
{
	auto it = _socketMap.find(socket);
	if (it != _socketMap.end())
	{
		_logger.trace("Removing socket %?d..."s, socket.impl()->sockfd());
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
	_logger.trace("Closing socket %?d..."s, socket.impl()->sockfd());
	try
	{
		_pollSet.remove(socket);
		socket.close();
	}
	catch (Poco::IOException&)
	{
	}
	_socketMap.erase(socket);
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


void SocketDispatcher::sendBytesImpl(Poco::Net::StreamSocket& socket, Poco::Buffer<char>&& buffer, int options)
{
	auto it = _socketMap.find(socket);
	if (it != _socketMap.end())
	{
		if  (it->second->pendingSends.empty())
		{
			int sent = socket.sendBytes(buffer.begin(), static_cast<int>(buffer.size()), options);
			if (sent < 0)
			{
				it->second->pendingSends.emplace_back(std::move(buffer), options);
			}
			else if (sent < buffer.size())
			{
				it->second->pendingSends.emplace_back(buffer.begin() + sent, buffer.size() - sent, options);
			}
		}
		else
		{
			it->second->pendingSends.emplace_back(std::move(buffer), options);
		}
	}
	else
	{
		_logger.error("sendBytes() called with unknown socket."s);
	}
}


void SocketDispatcher::shutdownSendImpl(Poco::Net::StreamSocket& socket)
{
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
