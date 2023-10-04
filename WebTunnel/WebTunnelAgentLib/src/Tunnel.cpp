//
// Tunnel.cpp
//
// Copyright (c) 2015-2023, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Tunnel.h"
#include "Poco/Util/TimerTaskAdapter.h"
#include "Poco/Net/HTTPSessionFactory.h"
#include "Poco/Net/HTTPSessionInstantiator.h"
#include "Poco/Net/HTTPBasicCredentials.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/NetException.h"
#include "Poco/Net/DNS.h"
#include "Poco/StringTokenizer.h"
#include "Poco/NumberParser.h"
#include "Poco/NumberFormatter.h"
#include "Poco/Environment.h"
#include "Poco/Delegate.h"
#include "Poco/Buffer.h"
#include "Poco/String.h"


using namespace std::string_literals;


namespace WebTunnelAgentLib {


const std::string Tunnel::SEC_WEBSOCKET_PROTOCOL("Sec-WebSocket-Protocol");
const std::string Tunnel::WEBTUNNEL_PROTOCOL("com.appinf.webtunnel.server/1.0");
const std::string Tunnel::WEBTUNNEL_AGENT("WebTunnelAgentLib/1.0.0");


class ReconnectTask: public Poco::Util::TimerTask
{
public:
	ReconnectTask(Tunnel::Ptr pWebTunnelAgent):
		_pWebTunnelAgent(pWebTunnelAgent)
	{
	}

	void run()
	{
		_pWebTunnelAgent->reconnectTask(*this);
	}

private:
	Tunnel::Ptr _pWebTunnelAgent;
};


class PropertiesUpdateTask: public Poco::Util::TimerTask
{
public:
	PropertiesUpdateTask(Tunnel::Ptr pWebTunnelAgent):
		_pWebTunnelAgent(pWebTunnelAgent)
	{
	}

	void run()
	{
		_pWebTunnelAgent->propertiesUpdateTask(*this);
	}

private:
	Tunnel::Ptr _pWebTunnelAgent;
};


Tunnel::Tunnel(const std::string& deviceId, Poco::SharedPtr<Poco::Util::Timer> pTimer, Poco::SharedPtr<Poco::WebTunnel::SocketDispatcher> pDispatcher, Poco::AutoPtr<Poco::Util::AbstractConfiguration> pConfig, Poco::WebTunnel::SocketFactory::Ptr pSocketFactory):
	_id(deviceId),
	_pConfig(pConfig),
	_pSocketFactory(pSocketFactory),
	_httpPort(0),
	_httpsRequired(false),
	_sshPort(0),
	_vncPort(0),
	_rdpPort(0),
	_useProxy(false),
	_proxyPort(0),
	_retryDelay(MIN_RETRY_DELAY),
	_pTimer(pTimer),
	_pDispatcher(pDispatcher),
	_status(STATUS_DISCONNECTED),
	_stopping(false),
	_logger(Poco::Logger::get("Tunnel"s))
{
	init();
}


Tunnel::~Tunnel()
{
	try
	{
		stop();
	}
	catch (Poco::Exception&)
	{
		poco_unexpected();
	}
}


void Tunnel::stop()
{
	bool stopping = false;
	{
		Poco::FastMutex::ScopedLock lock(_mutex);
		stopping = _stopping;
		_stopping = true;
	}
	if (!stopping)
	{
		_logger.debug("Stopping agent %s..."s, _id);
		_stopped.set();
		disconnect();
	}
}


void Tunnel::addProperties(Poco::Net::HTTPRequest& request, const std::map<std::string, std::string>& props)
{
	request.add("X-PTTH-Set-Property"s, Poco::format("device;targetHost=%s"s, _host.toString()));
	request.add("X-PTTH-Set-Property"s, Poco::format("device;targetPorts=%s"s, formatPorts()));
	if (!_httpPath.empty())
	{
		request.add("X-PTTH-Set-Property"s, Poco::format("device;httpPath=%s"s, quoteString(_httpPath)));
	}

	addPortProperty(request, "http"s, _httpPort);
	addPortProperty(request, "ssh"s, _sshPort);
	addPortProperty(request, "vnc"s, _vncPort);
	addPortProperty(request, "rdp"s, _rdpPort);
	addPortProperty(request, "app"s, _appPort);

	if (!_deviceName.empty())
	{
		request.add("X-PTTH-Set-Property"s, Poco::format("device;name=%s"s, quoteString(_deviceName)));
	}
	if (!_tenant.empty())
	{
		request.add("X-PTTH-Set-Property"s, Poco::format("device;tenant=%s"s, quoteString(_tenant)));
	}

	if (!props.empty())
	{
		for (std::map<std::string, std::string>::const_iterator it = props.begin(); it != props.end(); ++it)
		{
			request.add("X-PTTH-Set-Property"s, Poco::format("device;%s=%s"s, it->first, quoteString(it->second)));
		}
	}
	request.set("User-Agent"s, _userAgent);
}


void Tunnel::addPortProperty(Poco::Net::HTTPRequest& request, const std::string& proto, Poco::UInt16 port)
{
	if (port != 0)
	{
		request.add("X-PTTH-Set-Property"s, Poco::format("device;%sPort=%hu"s, proto, port));
	}
	else
	{
		request.add("X-PTTH-Set-Property"s, Poco::format("device;%sPort="s, proto));
	}
}


std::string Tunnel::formatPorts()
{
	std::string result;
	for (std::set<Poco::UInt16>::const_iterator it = _ports.begin(); it != _ports.end(); ++it)
	{
		if (!result.empty()) result += ", ";
		Poco::NumberFormatter::append(result, *it);
	}
	return result;
}


void Tunnel::startPropertiesUpdateTask()
{
	_logger.debug("Starting PropertiesUpdateTask..."s);
	_pPropertiesUpdateTask = new PropertiesUpdateTask(Ptr(this, true));
	_pTimer->scheduleAtFixedRate(_pPropertiesUpdateTask, _propertiesUpdateInterval.totalMilliseconds(), _propertiesUpdateInterval.totalMilliseconds());
}


void Tunnel::stopPropertiesUpdateTask()
{
	if (_pPropertiesUpdateTask)
	{
		_logger.debug("Stopping PropertiesUpdateTask..."s);
		_pPropertiesUpdateTask->cancel();
		_pPropertiesUpdateTask.reset();
	}
}


void Tunnel::stopReconnectTask()
{
	if (_pReconnectTask)
	{
		_logger.debug("Stopping ReconnectTask..."s);
		_pReconnectTask->cancel();
		_pReconnectTask.reset();
	}
}


void Tunnel::connect()
{
	Poco::URI reflectorURI;
	if (!_redirectURI.empty())
		reflectorURI = _redirectURI;
	else
		reflectorURI = _reflectorURI;

	_logger.information("Connecting device %s to %s..."s, _deviceName, reflectorURI.toString());

	_pHTTPClientSession = Poco::Net::HTTPSessionFactory::defaultFactory().createClientSession(reflectorURI);
	_pHTTPClientSession->setTimeout(_httpTimeout);
	if (_useProxy && !_proxyHost.empty())
	{
		_pHTTPClientSession->setProxy(_proxyHost, _proxyPort);
		if (!_proxyUsername.empty())
		{
			_pHTTPClientSession->setProxyCredentials(_proxyUsername, _proxyPassword);
		}
	}

	std::string path(reflectorURI.getPathEtc());
	if (path.empty()) path = "/";
	Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, path, Poco::Net::HTTPRequest::HTTP_1_1);
	request.set(SEC_WEBSOCKET_PROTOCOL, WEBTUNNEL_PROTOCOL);

	if (!_username.empty())
	{
		Poco::Net::HTTPBasicCredentials creds(_username, _password);
		creds.authenticate(request);
	}

	std::map<std::string, std::string> props;
	collectProperties(props);
	addProperties(request, props);
	request.set("User-Agent"s, _userAgent);

	Poco::Net::HTTPResponse response;
	bool reconnect = true;
	if (!_stopped.tryWait(1))
	{
		_logger.debug("Entering reconnect loop..."s);
		try
		{
			Poco::Net::DNS::reload();
			_logger.debug("Creating WebSocket..."s);
			Poco::SharedPtr<Poco::Net::WebSocket> pWebSocket = new Poco::Net::WebSocket(*_pHTTPClientSession, request, response);
			if (response.get(SEC_WEBSOCKET_PROTOCOL, ""s) == WEBTUNNEL_PROTOCOL)
			{
				_logger.debug("WebSocket established. Creating RemotePortForwarder..."s);
				pWebSocket->setNoDelay(true);
				_retryDelay = MIN_RETRY_DELAY;
				_pForwarder = new Poco::WebTunnel::RemotePortForwarder(*_pDispatcher, pWebSocket, _host, _ports, _remoteTimeout, _pSocketFactory);
				_pForwarder->setConnectTimeout(_connectTimeout);
				_pForwarder->setLocalTimeout(_localTimeout);
				_pForwarder->webSocketClosed += Poco::delegate(this, &Tunnel::onClose);
				_logger.information("WebTunnel connection established for device %s."s, _deviceName);

				if (!props.empty() && _propertiesUpdateInterval > 0)
				{
					startPropertiesUpdateTask();
				}
				statusChanged(STATUS_CONNECTED);

				return;
			}
			else
			{
				statusChanged(STATUS_ERROR, Poco::format("The host at %s does not support the WebTunnel protocol."s, reflectorURI.toString()));
				_logger.error(_lastError);

				pWebSocket->shutdown(Poco::Net::WebSocket::WS_PROTOCOL_ERROR);
				// receive final frame from peer; ignore if none is sent.
				if (pWebSocket->poll(Poco::Timespan(2, 0), Poco::Net::Socket::SELECT_READ))
				{
					Poco::Buffer<char> buffer(1024);
					int flags;
					try
					{
						pWebSocket->receiveFrame(buffer.begin(), static_cast<int>(buffer.size()), flags);
					}
					catch (Poco::Exception&)
					{
					}
				}
				pWebSocket->close();
				reconnect = false;
			}
		}
		catch (Poco::Net::WebSocketException& exc)
		{
			if (response.getStatus() == Poco::Net::HTTPResponse::HTTP_FOUND)
			{
				_redirectURI = Poco::URI(_reflectorURI, response.get("Location"s));
				_retryDelay = MIN_RETRY_DELAY;
				_logger.information("Redirected to %s."s, _redirectURI.toString());
			}
			else
			{
				std::string msg = response.get("X-PTTH-Error"s, exc.displayText());
				statusChanged(STATUS_ERROR, Poco::format("Cannot connect to reflector at %s: %s"s, reflectorURI.toString(), msg));
				_logger.error(_lastError);
				if (_retryDelay < MAX_RETRY_DELAY)
				{
					_retryDelay *= 2;
				}
				_redirectURI.clear();
			}
		}
		catch (Poco::Exception& exc)
		{
			statusChanged(STATUS_ERROR, Poco::format("Cannot connect device to reflector at %s: %s"s, reflectorURI.toString(), exc.displayText()));
			_logger.error("Cannot connect device %s to reflector at %s: %s"s, _deviceName, reflectorURI.toString(), exc.displayText());
			if (_retryDelay < MAX_RETRY_DELAY)
			{
				_retryDelay *= 2;
			}
			_redirectURI.clear();
			reconnect = true;
		}
		if (reconnect && !_stopped.tryWait(1))
		{
			scheduleReconnect();
		}
	}
}


void Tunnel::disconnect()
{
	stopReconnectTask();
	stopPropertiesUpdateTask();
	if (_pForwarder)
	{
		_logger.information("Disconnecting device %s from reflector server."s, _deviceName);

		_pForwarder->webSocketClosed -= Poco::delegate(this, &Tunnel::onClose);
		_pForwarder->stop();
		_pForwarder = 0;
	}
	if (_pHTTPClientSession)
	{
		try
		{
			_pHTTPClientSession->abort();
		}
		catch (Poco::Exception&)
		{
		}
	}
	statusChanged(STATUS_DISCONNECTED);
	_logger.debug("Disconnect complete."s);
}


void Tunnel::onClose(const int& reason)
{
	stopReconnectTask();
	stopPropertiesUpdateTask();

	std::string message;
	switch (reason)
	{
	case Poco::WebTunnel::RemotePortForwarder::RPF_CLOSE_GRACEFUL:
		message = "WebTunnel connection gracefully closed"s;
		break;
	case Poco::WebTunnel::RemotePortForwarder::RPF_CLOSE_UNEXPECTED:
		message = "WebTunnel connection unexpectedly closed"s;
		break;
	case Poco::WebTunnel::RemotePortForwarder::RPF_CLOSE_ERROR:
		message = "WebTunnel connection closed due to error"s;
		break;
	case Poco::WebTunnel::RemotePortForwarder::RPF_CLOSE_TIMEOUT:
		message = "WebTunnel connection closed due to timeout"s;
		break;
	}
	_logger.information("%s for device %s."s, message, _deviceName);

	statusChanged(STATUS_DISCONNECTED);
	scheduleReconnect();
}


void Tunnel::reconnectTask(Poco::Util::TimerTask&)
{
	try
	{
		if (!isStopping())
		{
			try
			{
				_logger.debug("Disconnecting for reconnect..."s);
				disconnect();
			}
			catch (Poco::Exception& exc)
			{
				_logger.warning("Exception during disconnect: %s"s, exc.displayText());
			}
			catch (std::exception& exc)
			{
				_logger.error("Exception during disconnect: "s + exc.what());
			}
			catch (...)
			{
				_logger.error("Unknown exception during disconnect."s);
			}
			connect();
		}
	}
	catch (Poco::Exception& exc)
	{
		_logger.fatal(exc.displayText());
		_retryDelay = MAX_RETRY_DELAY;
		scheduleReconnect();
	}
	catch (...)
	{
		_logger.fatal("Unknown exception during connect()"s);
	}
}


void Tunnel::scheduleReconnect()
{
	if (!_stopped.tryWait(1))
	{
		Poco::Clock::ClockDiff retryDelay(static_cast<Poco::Clock::ClockDiff>(_retryDelay)*1000);
		retryDelay += _random.next(250*_retryDelay);
		Poco::Clock nextClock;
		nextClock += retryDelay;
		_logger.information("Will reconnect in %.2f seconds."s, retryDelay/1000000.0);
		_pReconnectTask = new ReconnectTask(Ptr(this, true));
		_pTimer->schedule(_pReconnectTask, nextClock);
	}
}


void Tunnel::init()
{
	_deviceName = _pConfig->getString("webtunnel.deviceName"s, ""s);
	_reflectorURI = _pConfig->getString("webtunnel.reflectorURI"s);
	_username = _pConfig->getString("webtunnel.username"s, ""s);
	_password = _pConfig->getString("webtunnel.password"s, ""s);
	_tenant   = _pConfig->getString("webtunnel.tenant"s, ""s);
	std::string host = _pConfig->getString("webtunnel.host"s, "localhost"s);
	if (!Poco::Net::IPAddress::tryParse(host, _host))
	{
		_host = Poco::Net::DNS::resolveOne(host);
	}
	std::string ports = _pConfig->getString("webtunnel.ports"s, ""s);
	Poco::StringTokenizer tok(ports, ";,"s, Poco::StringTokenizer::TOK_TRIM | Poco::StringTokenizer::TOK_IGNORE_EMPTY);
	for (Poco::StringTokenizer::Iterator it = tok.begin(); it != tok.end(); ++it)
	{
		int port = Poco::NumberParser::parse(*it);
		if (port > 0 && port < 65536)
		{
			_ports.insert(static_cast<Poco::UInt16>(port));
		}
		else
		{
			_logger.warning("Ignoring out-of-range port number specified in configuration for device %s: %d"s, _deviceName, port);
		}
	}

	if (_ports.empty())
	{
		throw Poco::InvalidArgumentException("No ports to forward");
	}

	_localTimeout = Poco::Timespan(_pConfig->getInt("webtunnel.localTimeout"s, 7200), 0);
	_connectTimeout = Poco::Timespan(_pConfig->getInt("webtunnel.connectTimeout"s, 10), 0);
	_remoteTimeout = Poco::Timespan(_pConfig->getInt("webtunnel.remoteTimeout"s, 300), 0);
	_propertiesUpdateInterval = Poco::Timespan(_pConfig->getInt("webtunnel.propertiesUpdateInterval"s, 0), 0);
	_httpPath = _pConfig->getString("webtunnel.httpPath"s, ""s);
	_httpPort = loadPort("http"s);
	_sshPort = loadPort("ssh"s);
	_vncPort = loadPort("vnc"s);
	_rdpPort = loadPort("rdp"s);
	_appPort = loadPort("app"s);
	_userAgent = _pConfig->getString("webtunnel.userAgent"s, ""s);
	_httpTimeout = Poco::Timespan(_pConfig->getInt("http.timeout"s, 30), 0);
	_useProxy = _pConfig->getBool("http.proxy.enable"s, false);
	_proxyHost = _pConfig->getString("http.proxy.host"s, ""s);
	_proxyPort = static_cast<Poco::UInt16>(_pConfig->getInt("http.proxy.port"s, 80));
	_proxyUsername = _pConfig->getString("http.proxy.username"s, ""s);
	_proxyPassword = _pConfig->getString("http.proxy.password"s, ""s);

	if (_httpPort != 0 && _ports.find(_httpPort) == _ports.end())
	{
		_logger.warning("HTTP port (%hu) not in list of forwarded ports for device %s."s, _httpPort, _deviceName);
	}

	if (_userAgent.empty())
	{
		_userAgent = WEBTUNNEL_AGENT;
		_userAgent += " (";
		_userAgent += Poco::Environment::osName();
		_userAgent += "/";
		_userAgent += Poco::Environment::osVersion();
		_userAgent += "; ";
		_userAgent += Poco::Environment::osArchitecture();
		_userAgent += ") POCO/";
		_userAgent += Poco::format("%d.%d.%d"s,
			static_cast<int>(Poco::Environment::libraryVersion() >> 24),
			static_cast<int>((Poco::Environment::libraryVersion() >> 16) & 0xFF),
			static_cast<int>((Poco::Environment::libraryVersion() >> 8) & 0xFF));
	}

	_pTimer->schedule(new Poco::Util::TimerTaskAdapter<Tunnel>(*this, &Tunnel::reconnectTask), Poco::Clock());
}


Poco::UInt16 Tunnel::loadPort(const std::string& proto) const
{
	if (_pConfig->getBool(Poco::format("webtunnel.%sPort.enable"s, proto), true))
	{
		return static_cast<Poco::UInt16>(_pConfig->getUInt(Poco::format("webtunnel.%sPort"s, proto), 0));
	}
	else return 0;
}


void Tunnel::propertiesUpdateTask(Poco::Util::TimerTask&)
{
	_logger.debug("Updating device properties..."s);
	try
	{
		if (!isStopping())
		{
			std::map<std::string, std::string> props;
			collectProperties(props);
			_pForwarder->updateProperties(props);
		}
	}
	catch (Poco::Exception& exc)
	{
		_logger.error("Failed to update device properties: %s"s, exc.displayText());
	}
	_logger.debug("Done updating device properties."s);
}


void Tunnel::collectProperties(std::map<std::string, std::string>& props)
{
	std::vector<std::string> keys;
	_pConfig->keys("webtunnel.properties"s, keys);
	for (std::vector<std::string>::const_iterator it = keys.begin(); it != keys.end(); ++it)
	{
		std::string fullName("webtunnel.properties."s);
		fullName += *it;
		std::string value = _pConfig->getString(fullName);
		if (!value.empty() && value[0] == '`' && value[value.length() - 1] == '`')
		{
			std::string command(value, 1, value.length() - 2);
			try
			{
				_logger.debug("Running properties update command for property '%s': '%s'."s, *it, command);
				value = runCommand(command);
				props[*it] = value;
				_logger.debug("Property '%s' updated with value '%s'"s, *it, value);
			}
			catch (Poco::Exception& exc)
			{
				_logger.warning("Command for property '%s' failed: %s"s, *it, exc.displayText());
			}
		}
		else
		{
			props[*it] = value;
		}
	}
}


std::string Tunnel::runCommand(const std::string& command)
{
	std::string output;
#ifdef _WIN32
	std::string shell("cmd.exe");
	std::string shellArg("/C");
#else
	std::string shell("/bin/sh");
	std::string shellArg("-c");
#endif
	Poco::Pipe outPipe;
	Poco::Process::Args shellArgs;
	shellArgs.push_back(shellArg);
	shellArgs.push_back(command);
	Poco::ProcessHandle ph(Poco::Process::launch(shell, shellArgs, 0, &outPipe, &outPipe));
	Poco::PipeInputStream istr(outPipe);
	Poco::StreamCopier::copyToString(istr, output);
	ph.wait();
	Poco::trimInPlace(output);
	return output;
}


Tunnel::Status Tunnel::status() const
{
	Poco::FastMutex::ScopedLock lock(_mutex);

	return _status;
}


std::string Tunnel::lastError() const
{
	Poco::FastMutex::ScopedLock lock(_mutex);

	return _lastError;
}


void Tunnel::statusChanged(Status status)
{
	Poco::FastMutex::ScopedLock lock(_mutex);

	_status = status;
	_lastError.clear();
}


void Tunnel::statusChanged(Status status, const std::string& error)
{
	Poco::FastMutex::ScopedLock lock(_mutex);

	_status = status;
	_lastError = error;
}


std::string Tunnel::quoteString(const std::string& str)
{
	std::string quoted("\"");
	for (std::string::const_iterator it = str.begin(); it != str.end(); ++it)
	{
		if (*it < ' ')
		{
			quoted += ' ';
		}
		else
		{
			if (*it == '\"')
				quoted += '\\';
			quoted += *it;
		}
	}
	quoted += '"';
	return quoted;
}


bool Tunnel::isStopping()
{
	Poco::FastMutex::ScopedLock lock(_mutex);

	return _stopping;
}


} // namespace MyDevices::Gateway
