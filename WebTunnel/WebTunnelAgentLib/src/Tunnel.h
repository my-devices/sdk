//
// Tunnel.h
//
// Copyright (c) 2015-2023, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef Tunnel_INCLUDED
#define Tunnel_INCLUDED


#include "Poco/WebTunnel/SocketDispatcher.h"
#include "Poco/WebTunnel/RemotePortForwarder.h"
#include "Poco/Net/HTTPClientSession.h"
#include "Poco/Util/Timer.h"
#include "Poco/Util/AbstractConfiguration.h"
#include "Poco/URI.h"
#include "Poco/RefCountedObject.h"
#include "Poco/AutoPtr.h"
#include "Poco/SharedPtr.h"
#include "Poco/Process.h"
#include "Poco/Pipe.h"
#include "Poco/PipeStream.h"
#include "Poco/StreamCopier.h"
#include "Poco/Random.h"
#include "Poco/Mutex.h"
#include "Poco/Logger.h"


namespace WebTunnelAgentLib {


class Tunnel: public Poco::RefCountedObject
{
public:
	typedef Poco::AutoPtr<Tunnel> Ptr;

	enum Status
	{
		STATUS_DISCONNECTED = 0,
		STATUS_CONNECTED = 1,
		STATUS_ERROR = 2
	};

	enum
	{
		MIN_RETRY_DELAY = 1000,
		MAX_RETRY_DELAY = 30000
	};

	Tunnel(const std::string& deviceId, Poco::SharedPtr<Poco::Util::Timer> pTimer, Poco::SharedPtr<Poco::WebTunnel::SocketDispatcher> pDispatcher, Poco::AutoPtr<Poco::Util::AbstractConfiguration> pConfig, Poco::WebTunnel::SocketFactory::Ptr pSocketFactory);
		/// Creates the Tunnel, using the given deviceId, Timer, SocketDispatcher and configuration.

	~Tunnel();
		/// Destroys the Tunnel.

	void stop();
		/// Stops the Tunnel.

	const std::string& id() const;
		/// Returns the agent's device ID.

	Status status() const;
		/// Returns the agent status.

	std::string lastError() const;
		/// Returns the last error message for this tunnel.

protected:
	void connect();
	void disconnect();
	void onClose(const int& reason);
	void reconnectTask(Poco::Util::TimerTask&);
	void stopReconnectTask();
	void init();
	void addProperties(Poco::Net::HTTPRequest& request, const std::map<std::string, std::string>& props);
	void addPortProperty(Poco::Net::HTTPRequest& request, const std::string& proto, Poco::UInt16 port);
	void propertiesUpdateTask(Poco::Util::TimerTask&);
	void collectProperties(std::map<std::string, std::string>& props);
	void startPropertiesUpdateTask();
	void stopPropertiesUpdateTask();
	Poco::UInt16 loadPort(const std::string& proto) const;
	std::string formatPorts();
	std::string runCommand(const std::string& command);
	void statusChanged(Status status);
	void statusChanged(Status status, const std::string& error);
	void scheduleReconnect();
	void scheduleDisconnect();
	bool isStopping();
	static std::string quoteString(const std::string& str);

	static const std::string SEC_WEBSOCKET_PROTOCOL;
	static const std::string WEBTUNNEL_PROTOCOL;
	static const std::string WEBTUNNEL_AGENT;

private:
	std::string _id;
	Poco::AutoPtr<Poco::Util::AbstractConfiguration> _pConfig;
	Poco::WebTunnel::SocketFactory::Ptr _pSocketFactory;
	std::string _deviceName;
	Poco::Net::IPAddress _host;
	std::set<Poco::UInt16> _ports;
	Poco::URI _reflectorURI;
	Poco::URI _redirectURI;
	std::string _username;
	std::string _password;
	std::string _tenant;
	std::string _userAgent;
	std::string _httpPath;
	Poco::UInt16 _httpPort;
	bool _httpsRequired;
	Poco::UInt16 _sshPort;
	Poco::UInt16 _vncPort;
	Poco::UInt16 _rdpPort;
	Poco::UInt16 _appPort;
	bool _useProxy;
	std::string _proxyHost;
	Poco::UInt16 _proxyPort;
	std::string _proxyUsername;
	std::string _proxyPassword;
	Poco::Timespan _localTimeout;
	Poco::Timespan _connectTimeout;
	Poco::Timespan _remoteTimeout;
	Poco::Timespan _httpTimeout;
	Poco::Timespan _propertiesUpdateInterval;
	int _retryDelay;
	Poco::SharedPtr<Poco::Util::Timer> _pTimer;
	Poco::SharedPtr<Poco::WebTunnel::SocketDispatcher> _pDispatcher;
	Poco::SharedPtr<Poco::WebTunnel::RemotePortForwarder> _pForwarder;
	Poco::SharedPtr<Poco::Net::HTTPClientSession> _pHTTPClientSession;
	Poco::Util::TimerTask::Ptr _pReconnectTask;
	Poco::Util::TimerTask::Ptr _pPropertiesUpdateTask;
	Poco::Event _stopped;
	Poco::Random _random;
	Status _status;
	std::string _lastError;
	bool _stopping;
	mutable Poco::FastMutex _mutex;
	Poco::Logger& _logger;

	friend class ReconnectTask;
	friend class PropertiesUpdateTask;
};


//
// inlines
//


inline const std::string& Tunnel::id() const
{
	return _id;
}


} // namespace WebTunnelAgentLib


#endif // Tunnel_INCLUDED
