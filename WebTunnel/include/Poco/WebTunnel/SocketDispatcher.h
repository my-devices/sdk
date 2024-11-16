//
// SocketDispatcher.h
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


#ifndef WebTunnel_SocketDispatcher_INCLUDED
#define WebTunnel_SocketDispatcher_INCLUDED


#include "Poco/WebTunnel/WebTunnel.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/Net/PollSet.h"
#include "Poco/NotificationQueue.h"
#include "Poco/Thread.h"
#include "Poco/Runnable.h"
#include "Poco/RefCountedObject.h"
#include "Poco/AutoPtr.h"
#include "Poco/SharedPtr.h"
#include "Poco/Clock.h"
#include "Poco/Logger.h"
#include <atomic>
#include <map>
#include <deque>


namespace Poco {
namespace WebTunnel {


class WebTunnel_API SocketDispatcher: public Poco::Runnable
	/// SocketDispatcher implements a multi-threaded variant of the
	/// Reactor pattern, optimized for forwarding data from one
	/// socket to another.
	///
	/// The SocketDispatcher runs a select() loop in a separate thread.
	/// As soon as a socket becomes readable, it will be put into a work
	/// queue. A number of worker threads dequeue work queue items and
	/// process the data received over the socket, using registered
	/// SocketHandler instances.
{
public:
	class SocketHandler: public Poco::RefCountedObject
	{
	public:
		using Ptr = Poco::AutoPtr<SocketHandler>;

		virtual void readable(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket) = 0;
		virtual void writable(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket) = 0;
		virtual void exception(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket) = 0;
		virtual void timeout(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket) = 0;
	};

	SocketDispatcher(int threadCount, Poco::Timespan timeout = Poco::Timespan(5000));
		/// Creates the SocketDispatcher, using the given number of worker threads.
		///
		/// The given timeout is used for the main select loop, as well as
		/// by workers to poll if more reads are possible, up to the given
		/// maximum number of reads per worker.

	~SocketDispatcher();
		/// Destroys the SocketDispatcher.

	void addSocket(const Poco::Net::StreamSocket& socket, SocketHandler::Ptr pHandler, int mode, Poco::Timespan timeout = 0);
		/// Adds a socket and its handler to the SocketDispatcher.

	void updateSocket(const Poco::Net::StreamSocket& socket, int mode, Poco::Timespan timeout = 0);
		/// Updates the socket's poll mode.

	void removeSocket(const Poco::Net::StreamSocket& socket);
		/// Removes a socket and its associated handler from the SocketDispatcher.

	void closeSocket(const Poco::Net::StreamSocket& socket);
		/// Closes and removes a socket and its associated handler from the SocketDispatcher.

	void stop();
		/// Stops the SocketDispatcher and removes all sockets.

	void reset();
		/// Removes all sockets but does not stop the SocketDispatcher.

	void sendBytes(Poco::Net::StreamSocket& socket, const void* buffer, std::size_t length, int options);
		/// Attempts to write the given buffer's contents to the socket.
		/// If the write fails due to EWOULDBLOCK, the contents of the buffer are
		/// stored and written the next time the socket becomes writable again.
		/// While at least one write is pending, that socket will not accept new data.
	
	bool hasPendingSends(const Poco::Net::StreamSocket& socket) const;
		/// Returns true if there are pending sends for the given socket.

	void shutdownSend(Poco::Net::StreamSocket& socket);
		/// Shuts down the sending direction of the socket, but only after
		/// all pending sends has been sent.

protected:
	struct PendingSend
	{
		enum
		{
			OPT_SHUTDOWN = 0x0FFFA01
		};

		PendingSend(Poco::Buffer<char>&& buf, int opt):
			buffer(std::move(buf)),
			options(opt)
		{
		}

		PendingSend(const char* buf, std::size_t len, int opt):
			buffer(buf, len),
			options(opt)
		{
		}

		explicit PendingSend(int opt):
			options(opt)
		{
		}

		Poco::Buffer<char> buffer{0};
		int options{0};
	};

	struct SocketInfo: public Poco::RefCountedObject
	{
		using Ptr = Poco::AutoPtr<SocketInfo>;

		SocketInfo(SocketHandler::Ptr pHnd, int m, Poco::Timespan tmo):
			pHandler(pHnd),
			mode(m),
			timeout(tmo)
		{
		}

		SocketHandler::Ptr pHandler;
		int mode;
		Poco::Timespan timeout;
		Poco::Clock activity;
		std::deque<PendingSend> pendingSends;
	};

	using SocketMap = std::map<Poco::Net::Socket, SocketInfo::Ptr>;

	enum
	{
		MAIN_QUEUE_TIMEOUT = 1000
	};

	void run();
	void readable(const Poco::Net::Socket& socket, SocketInfo::Ptr pInfo);
	void writable(const Poco::Net::Socket& socket, SocketInfo::Ptr pInfo);
	void exception(const Poco::Net::Socket& socket, SocketInfo::Ptr pInfo);
	void timeout(const Poco::Net::Socket& socket, SocketInfo::Ptr pInfo);
	void addSocketImpl(const Poco::Net::StreamSocket& socket, SocketHandler::Ptr pHandler, int mode, Poco::Timespan timeout);
	void updateSocketImpl(const Poco::Net::StreamSocket& socket, int mode, Poco::Timespan timeout);
	void removeSocketImpl(const Poco::Net::StreamSocket& socket);
	void closeSocketImpl(Poco::Net::StreamSocket& socket);
	void resetImpl();
	void sendBytesImpl(Poco::Net::StreamSocket& socket, Poco::Buffer<char>& buffer, int flags);
	void shutdownSendImpl(Poco::Net::StreamSocket& socket);
	bool stopped();
	bool inDispatcherThread() const;

private:
	Poco::Timespan _timeout;
	SocketMap _socketMap;
	Poco::Net::PollSet _pollSet;
	Poco::Thread _thread;
	Poco::NotificationQueue _queue;
	std::atomic<bool> _stopped;
	Poco::Logger& _logger;

	friend class ReadableNotification;
	friend class ExceptionNotification;
	friend class TimeoutNotification;
	friend class AddSocketNotification;
	friend class UpdateSocketNotification;
	friend class RemoveSocketNotification;
	friend class CloseSocketNotification;
	friend class ResetNotification;
	friend class SendBytesNotification;
	friend class ShutdownSendNotification;
};


//
// inlines
//
inline bool SocketDispatcher::stopped()
{
	return _stopped;
}


inline bool SocketDispatcher::inDispatcherThread() const
{
	return Poco::Thread::current() == &_thread;
}


} } // namespace Poco::WebTunnel


#endif // WebTunnel_SocketDispatcher_INCLUDED
