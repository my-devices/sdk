//
// PollSet.cpp
//
// Library: Net
// Package: Sockets
// Module:  PollSet
//
// Copyright (c) 2016, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/Net/PollSet.h"
#include "Poco/Net/SocketImpl.h"
#include "Poco/Mutex.h"
#include <set>


#if defined(_WIN32) && _WIN32_WINNT >= 0x0600
#ifndef POCO_HAVE_FD_POLL
#define POCO_HAVE_FD_POLL 1
#endif
#elif defined(POCO_OS_FAMILY_BSD)
#ifndef POCO_HAVE_FD_POLL
#define POCO_HAVE_FD_POLL 1
#endif
#endif


#if defined(POCO_HAVE_FD_EPOLL)
#include <sys/epoll.h>
#include <sys/eventfd.h>
#elif defined(POCO_HAVE_FD_POLL)
#ifndef _WIN32
#include <poll.h>
#endif
#endif


namespace Poco {
namespace Net {


#if defined(POCO_HAVE_FD_EPOLL)


//
// Linux implementation using epoll
//
class PollSetImpl
{
public:
	PollSetImpl():
		_epollfd(-1),
		_eventfd(eventfd(0, 0)),
		_events(1024)
	{
		_epollfd = epoll_create(1);
		if (_epollfd < 0)
		{
			SocketImpl::error();
		}
		struct epoll_event ev;
		ev.events = EPOLLIN;
		ev.data.ptr = 0;
		if (epoll_ctl(_epollfd, EPOLL_CTL_ADD, _eventfd, &ev) < 0)
		{
			int err = SocketImpl::lastError();
			::close(_eventfd);
			::close(_epollfd);
			SocketImpl::error(err);
		}
	}

	~PollSetImpl()
	{
		if (_epollfd >= 0)
			::close(_epollfd);
		::close(_eventfd);
	}

	void add(const Socket& socket, int mode)
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		SocketImpl* sockImpl = socket.impl();
		poco_socket_t fd = sockImpl->sockfd();
		struct epoll_event ev;
		ev.events = 0;
		if (mode & PollSet::POLL_READ)
			ev.events |= EPOLLIN;
		if (mode & PollSet::POLL_WRITE)
			ev.events |= EPOLLOUT;
		if (mode & PollSet::POLL_ERROR)
			ev.events |= EPOLLERR;
		ev.data.ptr = socket.impl();
		int err = epoll_ctl(_epollfd, EPOLL_CTL_ADD, fd, &ev);

		if (err)
		{
			if (errno == EEXIST) update(socket, mode);
			else SocketImpl::error();
		}

		if (_socketMap.find(sockImpl) == _socketMap.end())
			_socketMap[sockImpl] = socket;
	}

	void remove(const Socket& socket)
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		poco_socket_t fd = socket.impl()->sockfd();
		struct epoll_event ev;
		ev.events = 0;
		ev.data.ptr = 0;
		int err = epoll_ctl(_epollfd, EPOLL_CTL_DEL, fd, &ev);
		if (err) SocketImpl::error();

		_socketMap.erase(socket.impl());
	}

	void update(const Socket& socket, int mode)
	{
		poco_socket_t fd = socket.impl()->sockfd();
		struct epoll_event ev;
		ev.events = 0;
		if (mode & PollSet::POLL_READ)
			ev.events |= EPOLLIN;
		if (mode & PollSet::POLL_WRITE)
			ev.events |= EPOLLOUT;
		if (mode & PollSet::POLL_ERROR)
			ev.events |= EPOLLERR;
		ev.data.ptr = socket.impl();
		int err = epoll_ctl(_epollfd, EPOLL_CTL_MOD, fd, &ev);
		if (err)
		{
			SocketImpl::error();
		}
	}

	bool has(const Socket& socket) const
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		SocketImpl* sockImpl = socket.impl();
		return sockImpl &&
			(_socketMap.find(sockImpl) != _socketMap.end());
	}

	bool empty() const
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		return _socketMap.empty();
	}

	std::size_t size() const
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		return _socketMap.size();
	}

	void clear()
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		::close(_epollfd);
		_socketMap.clear();
		_epollfd = epoll_create(1);
		if (_epollfd < 0)
		{
			SocketImpl::error();
		}
	}

	PollSet::SocketModeMap poll(const Poco::Timespan& timeout)
	{
		PollSet::SocketModeMap result;

		if (_socketMap.empty()) return result;

		Poco::Timespan remainingTime(timeout);
		int rc;
		do
		{
			Poco::Timestamp start;
			rc = epoll_wait(_epollfd, _events.data(), _events.size(), remainingTime.totalMilliseconds());
			if (rc < 0 && SocketImpl::lastError() == POCO_EINTR)
			{
				Poco::Timestamp end;
				Poco::Timespan waited = end - start;
				if (waited < remainingTime)
					remainingTime -= waited;
				else
					remainingTime = 0;
			}
		}
		while (rc < 0 && SocketImpl::lastError() == POCO_EINTR);
		if (rc < 0) SocketImpl::error();

		Poco::FastMutex::ScopedLock lock(_mutex);

		for (int i = 0; i < rc; i++)
		{
			if (_events[i].data.ptr == nullptr)
			{
				Poco::UInt64 d;
				read(_eventfd, &d, sizeof(d));
			}
			else
			{
				std::map<void*, Socket>::iterator it = _socketMap.find(_events[i].data.ptr);
				if (it != _socketMap.end())
				{
					if (_events[i].events & EPOLLIN)
						result[it->second] |= PollSet::POLL_READ;
					if (_events[i].events & EPOLLOUT)
						result[it->second] |= PollSet::POLL_WRITE;
					if (_events[i].events & EPOLLERR)
						result[it->second] |= PollSet::POLL_ERROR;
				}
			}
		}

		return result;
	}

	void wakeUp()
	{
		Poco::UInt64 d = 1;
		write(_eventfd, &d, sizeof(d));
	}

private:
	mutable Poco::FastMutex _mutex;
	int _epollfd;
	int _eventfd;
	std::map<void*, Socket> _socketMap;
	std::vector<struct epoll_event> _events;
};


#elif defined(POCO_HAVE_FD_POLL)


//
// BSD/Windows implementation using poll/WSAPoll
//
class PollSetImpl
{
public:
	PollSetImpl()
	{
	}

	void add(const Socket& socket, int mode)
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		poco_socket_t fd = socket.impl()->sockfd();
		_addMap[fd] = mode;
		_removeSet.erase(fd);
		_socketMap[fd] = socket;
	}

	void remove(const Socket& socket)
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		poco_socket_t fd = socket.impl()->sockfd();
		_removeSet.insert(fd);
		_addMap.erase(fd);
		_socketMap.erase(fd);
	}

	void update(const Socket& socket, int mode)
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		poco_socket_t fd = socket.impl()->sockfd();
		for (auto it = _pollfds.begin(); it != _pollfds.end(); ++it)
		{
			if (it->fd == fd)
			{
				it->events = 0;
				if (mode & PollSet::POLL_READ)
					it->events |= POLLIN;
				if (mode & PollSet::POLL_WRITE)
					it->events |= POLLOUT;
			}
		}
	}

	bool has(const Socket& socket) const
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		SocketImpl* sockImpl = socket.impl();
		return sockImpl && (_socketMap.find(sockImpl->sockfd()) != _socketMap.end());
	}

	bool empty() const
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		return _socketMap.empty();
	}

	std::size_t size() const
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		return _socketMap.size();
	}

	void clear()
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		_socketMap.clear();
		_addMap.clear();
		_removeSet.clear();
		_pollfds.clear();
	}

	PollSet::SocketModeMap poll(const Poco::Timespan& timeout)
	{
		PollSet::SocketModeMap result;
		{
			Poco::FastMutex::ScopedLock lock(_mutex);

			if (!_removeSet.empty())
			{
				for (auto it = _pollfds.begin(); it != _pollfds.end();)
				{
					if (_removeSet.find(it->fd) != _removeSet.end())
					{
						it = _pollfds.erase(it);
					}
					else ++it;
				}
				_removeSet.clear();
			}

			_pollfds.reserve(_pollfds.size() + _addMap.size());
			for (auto it = _addMap.begin(); it != _addMap.end(); ++it)
			{
				pollfd pfd;
				pfd.fd = it->first;
				pfd.events = 0;
				pfd.revents = 0;
				if (it->second & PollSet::POLL_READ)
					pfd.events |= POLLIN;
				if (it->second & PollSet::POLL_WRITE)
					pfd.events |= POLLOUT;

				_pollfds.push_back(pfd);
			}
			_addMap.clear();
		}

		if (_pollfds.empty()) return result;

		Poco::Timespan remainingTime(timeout);
		int rc;
		do
		{
			Poco::Timestamp start;
#ifdef _WIN32
			rc = WSAPoll(_pollfds.data(), static_cast<ULONG>(_pollfds.size()), static_cast<INT>(remainingTime.totalMilliseconds()));
#else
			rc = ::poll(_pollfds.data(), _pollfds.size(), remainingTime.totalMilliseconds());
#endif
			if (rc < 0 && SocketImpl::lastError() == POCO_EINTR)
			{
				Poco::Timestamp end;
				Poco::Timespan waited = end - start;
				if (waited < remainingTime)
					remainingTime -= waited;
				else
					remainingTime = 0;
			}
		}
		while (rc < 0 && SocketImpl::lastError() == POCO_EINTR);
		if (rc < 0) SocketImpl::error();

		{
			Poco::FastMutex::ScopedLock lock(_mutex);

			if (!_socketMap.empty())
			{
				for (auto it = _pollfds.begin(); it != _pollfds.end(); ++it)
				{
					std::map<poco_socket_t, Socket>::const_iterator its = _socketMap.find(it->fd);
					if (its != _socketMap.end())
					{
						if ((it->revents & POLLIN) && (it->events & POLLIN)) 
							result[its->second] |= PollSet::POLL_READ;
						if ((it->revents & POLLOUT) && (it->events & POLLOUT))
							result[its->second] |= PollSet::POLL_WRITE;
						if (it->revents & POLLERR)
							result[its->second] |= PollSet::POLL_ERROR;
						if ((it->revents & POLLHUP) && (it->events & POLLIN))
							result[its->second] |= PollSet::POLL_READ;
						if ((it->revents & POLLHUP) && (it->events & POLLOUT))
							result[its->second] |= PollSet::POLL_ERROR;
					}
					it->revents = 0;
				}
			}
		}

		return result;
	}

	void wakeUp()
	{
	}

private:
	mutable Poco::FastMutex _mutex;
	std::map<poco_socket_t, Socket> _socketMap;
	std::map<poco_socket_t, int> _addMap;
	std::set<poco_socket_t> _removeSet;
	std::vector<pollfd> _pollfds;
};


#else


//
// Fallback implementation using select()
//
class PollSetImpl
{
public:
	void add(const Socket& socket, int mode)
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		_map[socket] = mode;
	}

	void remove(const Socket& socket)
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		_map.erase(socket);
	}

	void update(const Socket& socket, int mode)
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		_map[socket] = mode;
	}

	bool has(const Socket& socket) const
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		return _map.find(socket) != _map.end();
	}

	bool empty() const
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		return _map.empty();
	}

	std::size_t size() const
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		return _map.size();
	}

	void clear()
	{
		Poco::FastMutex::ScopedLock lock(_mutex);

		_map.clear();
	}

	PollSet::SocketModeMap poll(const Poco::Timespan& timeout)
	{
		fd_set fdRead;
		fd_set fdWrite;
		fd_set fdExcept;
		int nfd = 0;

		FD_ZERO(&fdRead);
		FD_ZERO(&fdWrite);
		FD_ZERO(&fdExcept);

		{
			Poco::FastMutex::ScopedLock lock(_mutex);

			for (auto it = _map.begin(); it != _map.end(); ++it)
			{
				poco_socket_t fd = it->first.impl()->sockfd();
				if (fd != POCO_INVALID_SOCKET && it->second)
				{
					if (int(fd) > nfd) nfd = int(fd);

					if (it->second & PollSet::POLL_READ)
					{
						FD_SET(fd, &fdRead);
					}
					if (it->second & PollSet::POLL_WRITE)
					{
						FD_SET(fd, &fdWrite);
					}
					if (it->second & PollSet::POLL_ERROR)
					{
						FD_SET(fd, &fdExcept);
					}
				}
			}
		}

		PollSet::SocketModeMap result;
		if (nfd == 0) return result;

		Poco::Timespan remainingTime(timeout);
		int rc;
		do
		{
			struct timeval tv;
			tv.tv_sec  = (long) remainingTime.totalSeconds();
			tv.tv_usec = (long) remainingTime.useconds();
			Poco::Timestamp start;
			rc = ::select(nfd + 1, &fdRead, &fdWrite, &fdExcept, &tv);
			if (rc < 0 && SocketImpl::lastError() == POCO_EINTR)
			{
				Poco::Timestamp end;
				Poco::Timespan waited = end - start;
				if (waited < remainingTime)
					remainingTime -= waited;
				else
					remainingTime = 0;
			}
		}
		while (rc < 0 && SocketImpl::lastError() == POCO_EINTR);
		if (rc < 0) SocketImpl::error();

		{
			Poco::FastMutex::ScopedLock lock(_mutex);

			for (auto it = _map.begin(); it != _map.end(); ++it)
			{
				poco_socket_t fd = it->first.impl()->sockfd();
				if (fd != POCO_INVALID_SOCKET)
				{
					if (FD_ISSET(fd, &fdRead))
					{
						result[it->first] |= PollSet::POLL_READ;
					}
					if (FD_ISSET(fd, &fdWrite))
					{
						result[it->first] |= PollSet::POLL_WRITE;
					}
					if (FD_ISSET(fd, &fdExcept))
					{
						result[it->first] |= PollSet::POLL_ERROR;
					}
				}
			}
		}

		return result;
	}

	void wakeUp()
	{
	}

private:
	mutable Poco::FastMutex _mutex;
	PollSet::SocketModeMap  _map;
};


#endif


PollSet::PollSet():
	_pImpl(new PollSetImpl)
{
}


PollSet::~PollSet()
{
	delete _pImpl;
}


void PollSet::add(const Socket& socket, int mode)
{
	_pImpl->add(socket, mode);
}


void PollSet::remove(const Socket& socket)
{
	_pImpl->remove(socket);
}


void PollSet::update(const Socket& socket, int mode)
{
	_pImpl->update(socket, mode);
}


bool PollSet::has(const Socket& socket) const
{
	return _pImpl->has(socket);
}


bool PollSet::empty() const
{
	return _pImpl->empty();
}


std::size_t PollSet::size() const
{
	return _pImpl->size();
}


void PollSet::clear()
{
	_pImpl->clear();
}


PollSet::SocketModeMap PollSet::poll(const Poco::Timespan& timeout)
{
	return _pImpl->poll(timeout);
}


void PollSet::wakeUp()
{
	_pImpl->wakeUp();
}


} } // namespace Poco::Net
