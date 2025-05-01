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


class AutoSetEvent
{
public:
	AutoSetEvent(Poco::Event& event):
		_event(event)
	{
	}

	~AutoSetEvent()
	{
		try
		{
			_event.set();
		}
		catch (...)
		{
			poco_unexpected();
		}
	}

private:
	Poco::Event& _event;
};


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

		virtual bool wantRead(SocketDispatcher& dispatcher) = 0;
		virtual bool wantWrite(SocketDispatcher& dispatcher) = 0;
		virtual void readable(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket) = 0;
		virtual void writable(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket) = 0;
		virtual void exception(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket, const Poco::Exception* pException = nullptr) = 0;
		virtual void timeout(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket) = 0;
	};

	explicit SocketDispatcher(Poco::Timespan dispatchTimeout = Poco::Timespan(5000));
		/// Creates the SocketDispatcher.
		///
		/// The given dispatchTimeout is used for the main select loop.

	~SocketDispatcher();
		/// Destroys the SocketDispatcher.

	void setSendTimeout(Poco::Timespan timeout);
		/// Sets the default send timeout. This must be set before
		/// the first socket is added and should not be changed
		/// afterwards as setting it is not thread safe.
		/// If not set, the default is 30 seconds.

	Poco::Timespan getSendTimeout() const;
		/// Returns the default send timeout.

	void addSocket(const Poco::Net::StreamSocket& socket, SocketHandler::Ptr pHandler, int mode, Poco::Timespan receiveTimeout = 0, Poco::Timespan sendTimeout = 0);
		/// Adds a socket and its handler to the SocketDispatcher.

	void updateSocket(const Poco::Net::StreamSocket& socket, int mode, Poco::Timespan receiveTimeout = 0, Poco::Timespan sendTimeout = 0);
		/// Updates the socket's poll mode.

	void removeSocket(const Poco::Net::StreamSocket& socket);
		/// Removes a socket and its associated handler from the SocketDispatcher.

	void closeSocket(Poco::Net::StreamSocket& socket);
		/// Closes and removes a socket and its associated handler from the SocketDispatcher.

	bool hasSocket(const Poco::Net::StreamSocket& socket);
		/// Returns true if the socket is active in the SocketDispatcher.

	void stop();
		/// Stops the SocketDispatcher and removes all sockets.

	void reset();
		/// Removes all sockets but does not stop the SocketDispatcher.

	void sendBytes(Poco::Net::StreamSocket& socket, const void* buffer, std::size_t length, int options);
		/// Attempts to write the given buffer's contents to the socket.
		/// If the write fails due to EWOULDBLOCK, the contents of the buffer are
		/// stored and written the next time the socket becomes writable again.
		/// While at least one write is pending, that socket will not accept new data.
	
	std::size_t countPendingSends(const Poco::Net::StreamSocket& socket) const;
		/// Returns the number of pending sends for the given socket.

	std::size_t countPendingBytesToSend(const Poco::Net::StreamSocket& socket) const;
		/// Returns the number of pending bytes to send for the given socket.

	void shutdownSend(Poco::Net::StreamSocket& socket);
		/// Shuts down the sending direction of the socket, but only after
		/// all pending sends has been sent.

	class WebTunnel_API TaskNotification: public Poco::Notification
	{
	public:
		using Ptr = Poco::AutoPtr<TaskNotification>;

		enum
		{
			TASK_WAIT_TIMEOUT = 30000
		};

		TaskNotification(SocketDispatcher& dispatcher):
			_dispatcher(dispatcher)
		{
		}

		~TaskNotification() = default;

		void wait()
		{
			_done.wait(TASK_WAIT_TIMEOUT);
		}

		virtual void execute() = 0;

	protected:
		SocketDispatcher& _dispatcher;
		Poco::Event _done;
	};

	template <class Fn>
	class FunctorTaskNotification: public TaskNotification
	{
	public:
		using Ptr = Poco::AutoPtr<FunctorTaskNotification>;
	
		FunctorTaskNotification(SocketDispatcher& dispatcher, Fn&& fn):
			TaskNotification(dispatcher),
			_fn(std::move(fn))
		{
		}

		void execute()
		{
			AutoSetEvent ase(_done);
	
			_fn(_dispatcher);
		}

	private:
		Fn _fn;
	};

	template <class Fn>
	void queueTask(Fn&& fn)
		/// Enqueues a task for execution in the dispatcher thread.
		/// The task is given as a lambda expression or functor.
	{
		typename FunctorTaskNotification<Fn>::Ptr pTask = new FunctorTaskNotification<Fn>(*this, std::move(fn));
		_queue.enqueueNotification(pTask);
		_pollSet.wakeUp();
		if (!inDispatcherThread())
		{
			pTask->wait();
		}
	}

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
		Poco::Clock clock;
	};

	struct SocketInfo: public Poco::RefCountedObject
	{
		using Ptr = Poco::AutoPtr<SocketInfo>;

		SocketInfo(SocketHandler::Ptr pHnd, int m, Poco::Timespan rtmo, Poco::Timespan stmo):
			pHandler(pHnd),
			mode(m),
			receiveTimeout(rtmo),
			sendTimeout(stmo)
		{
		}

		SocketHandler::Ptr pHandler;
		int mode;
		Poco::Timespan receiveTimeout;
		Poco::Timespan sendTimeout;
		Poco::Clock lastReceive;
		std::deque<PendingSend> pendingSends;
		bool sslWriteWantRead = false;
		bool removed = false;
	};

	using SocketMap = std::map<Poco::Net::Socket, SocketInfo::Ptr>;

	enum
	{
		MAIN_QUEUE_TIMEOUT = 1000
	};

	enum
	{
		ERR_SSL_WOULD_BLOCK = -1,
		ERR_SSL_WANT_READ  = -2,
		ERR_SSL_WANT_WRITE = -3
	};

	void run();
	void readable(const Poco::Net::Socket& socket, SocketInfo::Ptr pInfo);
	void writable(const Poco::Net::Socket& socket, SocketInfo::Ptr pInfo);
	void exception(const Poco::Net::Socket& socket, SocketInfo::Ptr pInfo, const Poco::Exception* pException = nullptr);
	void timeout(const Poco::Net::Socket& socket, SocketInfo::Ptr pInfo);
	void addSocketImpl(const Poco::Net::StreamSocket& socket, SocketHandler::Ptr pHandler, int mode, Poco::Timespan receiveTimeout, Poco::Timespan sendTimeout);
	void updateSocketImpl(const Poco::Net::StreamSocket& socket, int mode, Poco::Timespan receiveTimeout, Poco::Timespan sendTimeout);
	void removeSocketImpl(const Poco::Net::StreamSocket& socket);
	void closeSocketImpl(Poco::Net::StreamSocket& socket);
	bool hasSocketImpl(const Poco::Net::StreamSocket& socket) const;
	void resetImpl();
	void sendBytesImpl(Poco::Net::StreamSocket& socket, Poco::Buffer<char>&& buffer, int flags, bool reportException = false);
	void shutdownSendImpl(Poco::Net::StreamSocket& socket);
	bool stopped();
	bool inDispatcherThread() const;

private:
	Poco::Timespan _timeout;
	Poco::Timespan _sendTimeout;
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
	friend class HasSocketNotification;
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


inline Poco::Timespan SocketDispatcher::getSendTimeout() const
{
	return _sendTimeout;
}


} } // namespace Poco::WebTunnel


#endif // WebTunnel_SocketDispatcher_INCLUDED
