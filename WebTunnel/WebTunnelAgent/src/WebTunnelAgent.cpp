//
// WebTunnelAgent.cpp
//
// Copyright (c) 2013-2016, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/WebTunnel/RemotePortForwarder.h"
#include "Poco/Net/HTTPSessionFactory.h"
#include "Poco/Net/HTTPSessionInstantiator.h"
#include "Poco/Net/HTTPClientSession.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/HTTPBasicCredentials.h"
#include "Poco/Net/DNS.h"
#include "Poco/Net/NetException.h"
#if defined(WEBTUNNEL_ENABLE_TLS)
#include "Poco/Net/HTTPSSessionInstantiator.h"
#include "Poco/Net/SecureStreamSocket.h"
#include "Poco/Net/Context.h"
#include "Poco/Net/PrivateKeyPassphraseHandler.h"
#include "Poco/Net/AcceptCertificateHandler.h"
#include "Poco/Net/RejectCertificateHandler.h"
#include "Poco/Net/SSLManager.h"
#endif
#include "Poco/Util/ServerApplication.h"
#include "Poco/Util/Option.h"
#include "Poco/Util/OptionSet.h"
#include "Poco/Util/HelpFormatter.h"
#include "Poco/Util/IntValidator.h"
#include "Poco/Util/Timer.h"
#include "Poco/Util/TimerTaskAdapter.h"
#include "Poco/URI.h"
#include "Poco/NumberParser.h"
#include "Poco/NumberFormatter.h"
#include "Poco/StringTokenizer.h"
#include "Poco/SharedPtr.h"
#include "Poco/BasicEvent.h"
#include "Poco/Delegate.h"
#include "Poco/Buffer.h"
#include "Poco/Event.h"
#include "Poco/Environment.h"
#include "Poco/Clock.h"
#include "Poco/Random.h"
#include "Poco/Process.h"
#include "Poco/Pipe.h"
#include "Poco/PipeStream.h"
#include "Poco/String.h"
#include <iostream>


using Poco::Util::Option;
using Poco::Util::OptionSet;
using Poco::Util::OptionCallback;
using Poco::Util::HelpFormatter;


class SSLInitializer
{
public:
	SSLInitializer()
	{
#if defined(WEBTUNNEL_ENABLE_TLS)
		Poco::Net::initializeSSL();
#endif
	}

	~SSLInitializer()
	{
#if defined(WEBTUNNEL_ENABLE_TLS)
		Poco::Net::uninitializeSSL();
#endif
	}
};


#if defined(WEBTUNNEL_ENABLE_TLS)


class TLSSocketFactory: public Poco::WebTunnel::SocketFactory
{
public:
	TLSSocketFactory(Poco::UInt16 tlsPort, Poco::Net::Context::Ptr pContext):
		_tlsPort(tlsPort),
		_pContext(pContext)
	{
	}

	~TLSSocketFactory()
	{
	}

	Poco::Net::StreamSocket createSocket(const Poco::Net::SocketAddress& addr, Poco::Timespan timeout)
	{
		if (addr.port() == _tlsPort)
		{
			Poco::Net::SecureStreamSocket streamSocket(_pContext);
			streamSocket.connect(addr, timeout);
			streamSocket.setNoDelay(true);
			return streamSocket;
		}
		else
		{
			Poco::Net::StreamSocket streamSocket;
			streamSocket.connect(addr, timeout);
			streamSocket.setNoDelay(true);
			return streamSocket;
		}
	}

private:
	Poco::UInt16 _tlsPort;
	Poco::Net::Context::Ptr _pContext;
};


#endif // defined(WEBTUNNEL_ENABLE_TLS)


class WebTunnelAgent: public Poco::Util::ServerApplication
{
public:
	enum Status
	{
		STATUS_DISCONNECTED,
		STATUS_CONNECTED,
		STATUS_ERROR
	};

	enum
	{
		MIN_RETRY_DELAY = 1000,
		MAX_RETRY_DELAY = 30000
	};

	Poco::BasicEvent<const std::string> connected;
	Poco::BasicEvent<const std::string> disconnected;
	Poco::BasicEvent<const std::string> error;

	WebTunnelAgent():
		_helpRequested(false),
		_httpPort(0),
		_httpsRequired(false),
		_sshPort(0),
		_vncPort(0),
		_rdpPort(0),
		_useProxy(false),
		_proxyPort(0),
		_threads(8),
		_retryDelay(MIN_RETRY_DELAY),
		_status(STATUS_DISCONNECTED)
	{
		_random.seed();
	}

	~WebTunnelAgent()
	{
	}

protected:
	void initialize(Poco::Util::Application& self)
	{
		loadConfiguration(); // load default configuration files, if present
		Poco::Util::ServerApplication::initialize(self);
		Poco::Net::HTTPSessionInstantiator::registerInstantiator();
#if defined(WEBTUNNEL_ENABLE_TLS)
		Poco::Net::HTTPSSessionInstantiator::registerInstantiator();
#endif
		_pTimer = new Poco::Util::Timer;
	}

	void uninitialize()
	{
		Poco::Net::HTTPSessionInstantiator::unregisterInstantiator();
#if defined(WEBTUNNEL_ENABLE_TLS)
		Poco::Net::HTTPSSessionInstantiator::unregisterInstantiator();
#endif
		Poco::Util::ServerApplication::uninitialize();
	}

	void defineOptions(OptionSet& options)
	{
		Poco::Util::ServerApplication::defineOptions(options);

		options.addOption(
			Option("help", "h", "Display help information on command line arguments.")
				.required(false)
				.repeatable(false)
				.callback(OptionCallback<WebTunnelAgent>(this, &WebTunnelAgent::handleHelp)));

		options.addOption(
			Option("config-file", "c", "Load configuration data from a file.")
				.required(false)
				.repeatable(true)
				.argument("file")
				.callback(OptionCallback<WebTunnelAgent>(this, &WebTunnelAgent::handleConfig)));

		options.addOption(
			Option("define", "D", "Define or override a configuration property.")
				.required(false)
				.repeatable(true)
				.argument("name=value")
				.callback(OptionCallback<WebTunnelAgent>(this, &WebTunnelAgent::handleDefine)));
	}

	void handleHelp(const std::string& name, const std::string& value)
	{
		_helpRequested = true;
	}

	void handleConfig(const std::string& name, const std::string& value)
	{
		loadConfiguration(value);
	}

	void handleDefine(const std::string& name, const std::string& value)
	{
		defineProperty(value);
	}

	void displayHelp()
	{
		HelpFormatter helpFormatter(options());
		helpFormatter.setCommand(commandName());
		helpFormatter.setUsage("OPTIONS");
		helpFormatter.setHeader("\n"
			"macchina.io Remote Manager Agent.\n"
			"Copyright (c) 2013-2019 by Applied Informatics Software Engineering GmbH.\n"
			"All rights reserved.\n\n"
			"This application is used to forward local TCP ports to remote\n"
			"clients via the macchina.io Remote Manager.\n\n"
			"The following command-line options are supported:");
		helpFormatter.setFooter(
			"For more information, please visit the macchina.io "
			"website at <https://macchina.io>."
		);
		helpFormatter.setIndent(8);
		helpFormatter.format(std::cout);
	}

	void defineProperty(const std::string& def)
	{
		std::string name;
		std::string value;
		std::string::size_type pos = def.find('=');
		if (pos != std::string::npos)
		{
			name.assign(def, 0, pos);
			value.assign(def, pos + 1, def.length() - pos);
		}
		else name = def;
		config().setString(name, value);
	}

	void statusChanged(Status status, const std::string& msg = std::string())
	{
		if (status != _status)
		{
			_status = status;
			switch (_status)
			{
			case STATUS_DISCONNECTED:
				disconnected(msg);
				break;
			case STATUS_CONNECTED:
				connected(msg);
				break;
			case STATUS_ERROR:
				error(msg);
				break;
			}
		}
	}

	void addProperties(Poco::Net::HTTPRequest& request, const std::map<std::string, std::string>& props)
	{
		request.add("X-PTTH-Set-Property", Poco::format("device;targetHost=%s", _host.toString()));
		request.add("X-PTTH-Set-Property", Poco::format("device;targetPorts=%s", formatPorts()));
		if (!_httpPath.empty())
		{
			request.add("X-PTTH-Set-Property", Poco::format("device;httpPath=%s", quoteString(_httpPath)));
		}
		if (_httpPort != 0)
		{
			request.add("X-PTTH-Set-Property", Poco::format("device;httpPort=%hu", _httpPort));
		}
		if (_sshPort != 0)
		{
			request.add("X-PTTH-Set-Property", Poco::format("device;sshPort=%hu", _sshPort));
		}
		if (_vncPort != 0)
		{
			request.add("X-PTTH-Set-Property", Poco::format("device;vncPort=%hu", _vncPort));
		}
		if (_rdpPort != 0)
		{
			request.add("X-PTTH-Set-Property", Poco::format("device;rdpPort=%hu", _rdpPort));
		}
		if (!_deviceName.empty())
		{
			request.add("X-PTTH-Set-Property", Poco::format("device;name=%s", quoteString(_deviceName)));
		}
		if (!_deviceVersion.empty())
		{
			request.add("X-PTTH-Set-Property", Poco::format("device;version=%s", quoteString(_deviceVersion)));
		}

		if (!props.empty())
		{
			for (std::map<std::string, std::string>::const_iterator it = props.begin(); it != props.end(); ++it)
			{
				request.add("X-PTTH-Set-Property", Poco::format("device;%s=%s", it->first, quoteString(it->second)));
			}
		}
		request.set("User-Agent", _userAgent);
	}

	std::string formatPorts()
	{
		std::string result;
		for (std::set<Poco::UInt16>::const_iterator it = _ports.begin(); it != _ports.end(); ++it)
		{
			if (!result.empty()) result += ", ";
			Poco::NumberFormatter::append(result, *it);
		}
		return result;
	}

	void connect()
	{
		Poco::URI reflectorURI;
		if (!_redirectURI.empty())
			reflectorURI = _redirectURI;
		else
			reflectorURI = _reflectorURI;

		logger().information("Connecting to " + reflectorURI.toString() + "...");

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
		Poco::Net::HTTPResponse response;
		request.set(SEC_WEBSOCKET_PROTOCOL, WEBTUNNEL_PROTOCOL);

		std::map<std::string, std::string> props;
		collectProperties(props);
		addProperties(request, props);

		try
		{
			Poco::Net::DNS::reload();

			// Note: Obtain username/password as late as possible. Reason: The username
			// may contain ${system.nodeId} (Ethernet address), which may not be available
			// by the time we launch, as the network interface may not be up yet.
			std::string username = config().getString("webtunnel.username", "");
			std::string password = config().getString("webtunnel.password", "");
			if (!username.empty())
			{
				Poco::Net::HTTPBasicCredentials creds(username, password);
				creds.authenticate(request);
			}

			logger().debug("Creating WebSocket...");
			Poco::SharedPtr<Poco::Net::WebSocket> pWebSocket = new Poco::Net::WebSocket(*_pHTTPClientSession, request, response);
			if (response.get(SEC_WEBSOCKET_PROTOCOL, "") == WEBTUNNEL_PROTOCOL)
			{
				logger().debug("WebSocket established. Creating RemotePortForwarder...");
				pWebSocket->setNoDelay(true);
				_retryDelay = MIN_RETRY_DELAY;
				_pDispatcher = new Poco::WebTunnel::SocketDispatcher(_threads);
				_pForwarder = new Poco::WebTunnel::RemotePortForwarder(*_pDispatcher, pWebSocket, _host, _ports, _remoteTimeout, _pSocketFactory);
				_pForwarder->webSocketClosed += Poco::delegate(this, &WebTunnelAgent::onClose);
				_pForwarder->setConnectTimeout(_connectTimeout);
				_pForwarder->setLocalTimeout(_localTimeout);
				logger().information("WebTunnel connection established.");

				if (!props.empty() && _propertiesUpdateInterval > 0)
				{
					startPropertiesUpdateTask();
				}

				statusChanged(STATUS_CONNECTED);
				return;
			}
			else
			{
				std::string msg(Poco::format("The host at %s does not support the WebTunnel protocol.", reflectorURI.toString()));
				logger().error(msg);

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
				statusChanged(STATUS_ERROR, msg);
				_retryDelay = MAX_RETRY_DELAY;
			}
		}
		catch (Poco::Net::WebSocketException& exc)
		{
			if (response.getStatus() == Poco::Net::HTTPResponse::HTTP_FOUND)
			{
				_redirectURI = Poco::URI(_reflectorURI, response.get("Location"));
				_retryDelay = MIN_RETRY_DELAY;
				logger().information("Redirected to %s.", _redirectURI.toString());
			}
			else
			{
				std::string msg = response.get("X-PTTH-Error", exc.displayText());
				logger().error("Cannot connect to reflector at %s: %s", reflectorURI.toString(), msg);
				statusChanged(STATUS_ERROR, msg);
				if (_retryDelay < MAX_RETRY_DELAY)
				{
					_retryDelay *= 2;
				}
				_redirectURI.clear();
			}
		}
		catch (Poco::Exception& exc)
		{
			logger().error("Cannot connect to reflector at %s: %s", reflectorURI.toString(), exc.displayText());
			statusChanged(STATUS_ERROR, exc.displayText());
			if (_retryDelay < MAX_RETRY_DELAY)
			{
				_retryDelay *= 2;
			}
			_redirectURI.clear();
		}
		scheduleReconnect();
	}

	void disconnect()
	{
		stopPropertiesUpdateTask();
		if (_pForwarder)
		{
			logger().information("Disconnecting from reflector server");

			_pForwarder->webSocketClosed -= Poco::delegate(this, &WebTunnelAgent::onClose);
			_pForwarder->stop();
			_pDispatcher->reset();
			_pForwarder = 0;
			_pDispatcher = 0;
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
		logger().debug("Disconnected.");
	}

	void onClose(const int& reason)
	{
		stopPropertiesUpdateTask();

		std::string message;
		switch (reason)
		{
		case Poco::WebTunnel::RemotePortForwarder::RPF_CLOSE_GRACEFUL:
			message = "WebTunnel connection gracefully closed.";
			break;
		case Poco::WebTunnel::RemotePortForwarder::RPF_CLOSE_UNEXPECTED:
			message = "WebTunnel connection unexpectedly closed.";
			break;
		case Poco::WebTunnel::RemotePortForwarder::RPF_CLOSE_ERROR:
			message = "WebTunnel connection closed due to error.";
			break;
		case Poco::WebTunnel::RemotePortForwarder::RPF_CLOSE_TIMEOUT:
			message = "WebTunnel connection closed due to timeout.";
			break;
		}
		logger().information(message);

		statusChanged(STATUS_DISCONNECTED);
		scheduleReconnect();
	}

	void reconnectTask(Poco::Util::TimerTask&)
	{
		try
		{
			try
			{
				disconnect();
			}
			catch (Poco::Exception& exc)
			{
				logger().warning("Exception during disconnect: " + exc.displayText());
			}
			catch (std::exception& exc)
			{
				logger().error(std::string("Exception during disconnect: ") + exc.what());
			}
			catch (...)
			{
				logger().error("Unknown exception during disconnect.");
			}
			connect();
		}
		catch (Poco::Exception& exc)
		{
			logger().fatal(exc.displayText());
			_retryDelay = MAX_RETRY_DELAY;
			scheduleReconnect();
		}
		catch (...)
		{
			logger().fatal("Unknown exception during connect()");
		}
	}

	void disconnectTask(Poco::Util::TimerTask&)
	{
		try
		{
			disconnect();
		}
		catch (Poco::Exception& exc)
		{
			logger().warning("Exception during disconnect: " + exc.displayText());
		}
		_disconnected.set();
	}

	void scheduleReconnect()
	{
		if (!_stopped.tryWait(1))
		{
			Poco::Clock::ClockDiff retryDelay(static_cast<Poco::Clock::ClockDiff>(_retryDelay)*1000);
			retryDelay += _random.next(250*_retryDelay);
			Poco::Clock nextClock;
			nextClock += retryDelay;
			logger().information(Poco::format("Will reconnect in %.2f seconds.", retryDelay/1000000.0));
			_pTimer->schedule(new Poco::Util::TimerTaskAdapter<WebTunnelAgent>(*this, &WebTunnelAgent::reconnectTask), nextClock);
		}
	}

	void scheduleDisconnect()
	{
		_pTimer->schedule(new Poco::Util::TimerTaskAdapter<WebTunnelAgent>(*this, &WebTunnelAgent::disconnectTask), Poco::Clock());
	}

	void notifyConnected(const std::string&)
	{
		Poco::Process::Args args;
		args.push_back("connected");
		notify(args);
	}

	void notifyDisconnected(const std::string&)
	{
		Poco::Process::Args args;
		args.push_back("disconnected");
		notify(args);
	}

	void notifyError(const std::string& msg)
	{
		Poco::Process::Args args;
		args.push_back("error");
		args.push_back(msg);
		notify(args);
	}

	void notify(const Poco::Process::Args& args)
	{
		try
		{
			Poco::ProcessHandle ph = Poco::Process::launch(_notifyExec, args);
			ph.wait();
		}
		catch (Poco::Exception& exc)
		{
			logger().log(exc);
		}
	}

	static std::string quoteString(const std::string& str)
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

	void startPropertiesUpdateTask()
	{
		_pPropertiesUpdateTask = new Poco::Util::TimerTaskAdapter<WebTunnelAgent>(*this, &WebTunnelAgent::updateProperties);
		_pTimer->scheduleAtFixedRate(_pPropertiesUpdateTask, _propertiesUpdateInterval.totalMilliseconds(), _propertiesUpdateInterval.totalMilliseconds());
	}

	void stopPropertiesUpdateTask()
	{
		if (_pPropertiesUpdateTask)
		{
			_pPropertiesUpdateTask->cancel();
			_pPropertiesUpdateTask.reset();
		}
	}

	void updateProperties(Poco::Util::TimerTask&)
	{
		logger().debug("Updating device properties...");
		try
		{
			std::map<std::string, std::string> props;
			collectProperties(props);
			_pForwarder->updateProperties(props);
		}
		catch (Poco::Exception& exc)
		{
			logger().error("Failed to update device properties: %s", exc.displayText());
		}
	}

	void collectProperties(std::map<std::string, std::string>& props)
	{
		std::vector<std::string> keys;
		config().keys("webtunnel.properties", keys);
		for (std::vector<std::string>::const_iterator it = keys.begin(); it != keys.end(); ++it)
		{
			std::string fullName("webtunnel.properties.");
			fullName += *it;
			std::string value = config().getString(fullName);
			if (!value.empty() && value[0] == '`' && value[value.length() - 1] == '`')
			{
				std::string command(value, 1, value.length() - 2);
				try
				{
					value = runCommand(command);
					props[*it] = value;
				}
				catch (Poco::Exception& exc)
				{
					logger().warning("Command for property '%s' failed: %s", *it, exc.displayText());
				}
			}
			else
			{
				props[*it] = value;
			}
		}
	}

	std::string runCommand(const std::string& command)
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

#if defined(WEBTUNNEL_ENABLE_TLS)
	Poco::Net::Context::Ptr createContext(const std::string& prefix)
	{
		std::string cipherList = config().getString(prefix + ".ciphers", "HIGH:!DSS:!aNULL@STRENGTH");
		bool extendedVerification = config().getBool(prefix + ".extendedCertificateVerification", false);
		std::string caLocation = config().getString(prefix + ".caLocation", "");
		std::string privateKey = config().getString(prefix + ".privateKey", "");
		std::string certificate = config().getString(prefix + ".certificate", "");

#if defined(POCO_NETSSL_WIN)
		int options = Poco::Net::Context::OPT_DEFAULTS;
		if (!certificate.empty()) options |= Poco::Net::Context::OPT_LOAD_CERT_FROM_FILE;
		Poco::Net::Context::Ptr pContext = new Poco::Net::Context(Poco::Net::Context::TLSV1_CLIENT_USE, certificate, Poco::Net::Context::VERIFY_RELAXED, options);
#else
		Poco::Net::Context::Ptr pContext = new Poco::Net::Context(Poco::Net::Context::TLSV1_CLIENT_USE, privateKey, certificate, caLocation, Poco::Net::Context::VERIFY_RELAXED, 5, true, cipherList);
#endif // POCO_NETSSL_WIN
		pContext->enableExtendedCertificateVerification(extendedVerification);
		return pContext;
	}
#endif // WEBTUNNEL_ENABLE_TLS

	int main(const std::vector<std::string>& args)
	{
		if (_helpRequested)
		{
			displayHelp();
		}
		else
		{
			try
			{
				_deviceName = config().getString("webtunnel.deviceName", "");
				_deviceVersion = config().getString("webtunnel.deviceVersion", "");
				_reflectorURI = config().getString("webtunnel.reflectorURI");
				std::string host = config().getString("webtunnel.host", "localhost");
				if (!Poco::Net::IPAddress::tryParse(host, _host))
				{
					_host = Poco::Net::DNS::resolveOne(host);
				}
				std::string ports = config().getString("webtunnel.ports", "");
				Poco::StringTokenizer tok(ports, ";,", Poco::StringTokenizer::TOK_TRIM | Poco::StringTokenizer::TOK_IGNORE_EMPTY);
				for (Poco::StringTokenizer::Iterator it = tok.begin(); it != tok.end(); ++it)
				{
					int port = Poco::NumberParser::parse(*it);
					if (port > 0 && port < 65536)
					{
						_ports.insert(static_cast<Poco::UInt16>(port));
					}
					else
					{
						logger().error(Poco::format("Out-of-range port number specified in configuration: %d", port));
						return Poco::Util::Application::EXIT_CONFIG;
					}
				}

				if (_ports.empty())
				{
					logger().error("No ports to forward.");
					return Poco::Util::Application::EXIT_CONFIG;
				}

				_localTimeout = Poco::Timespan(config().getInt("webtunnel.localTimeout", 7200), 0);
				_connectTimeout = Poco::Timespan(config().getInt("webtunnel.connectTimeout", 10), 0);
				_remoteTimeout = Poco::Timespan(config().getInt("webtunnel.remoteTimeout", 300), 0);
				_threads = config().getInt("webtunnel.threads", 8);
				_httpPath = config().getString("webtunnel.httpPath", "");
				_httpPort = static_cast<Poco::UInt16>(config().getInt("webtunnel.httpPort", 0));
				_httpsRequired = config().getBool("webtunnel.httpsRequired", false);
				_sshPort = static_cast<Poco::UInt16>(config().getInt("webtunnel.sshPort", 0));
				_vncPort = static_cast<Poco::UInt16>(config().getInt("webtunnel.vncPort", 0));
				_rdpPort = static_cast<Poco::UInt16>(config().getInt("webtunnel.rdpPort", 0));
				_userAgent = config().getString("webtunnel.userAgent", "");
				_httpTimeout = Poco::Timespan(config().getInt("http.timeout", 30), 0);
				_propertiesUpdateInterval = Poco::Timespan(config().getInt("webtunnel.propertiesUpdateInterval", 0), 0);

				_useProxy = config().getBool("http.proxy.enable", false);
				_proxyHost = config().getString("http.proxy.host", "");
				_proxyPort = static_cast<Poco::UInt16>(config().getInt("http.proxy.port", 80));
				_proxyUsername = config().getString("http.proxy.username", "");
				_proxyPassword = config().getString("http.proxy.password", "");

				if (_httpPort != 0 && _ports.find(_httpPort) == _ports.end())
				{
					logger().warning(Poco::format("HTTP port (%hu) not in list of forwarded ports.", _httpPort));
				}
				if (_sshPort != 0 && _ports.find(_sshPort) == _ports.end())
				{
					logger().warning(Poco::format("SSH port (%hu) not in list of forwarded ports.", _sshPort));
				}
				if (_vncPort != 0 && _ports.find(_vncPort) == _ports.end())
				{
					logger().warning(Poco::format("VNC/RFB port (%hu) not in list of forwarded ports.", _vncPort));
				}
				if (_rdpPort != 0 && _ports.find(_rdpPort) == _ports.end())
				{
					logger().warning(Poco::format("RDP port (%hu) not in list of forwarded ports.", _rdpPort));
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
					_userAgent += Poco::format("%d.%d.%d",
						static_cast<int>(Poco::Environment::libraryVersion() >> 24),
						static_cast<int>((Poco::Environment::libraryVersion() >> 16) & 0xFF),
						static_cast<int>((Poco::Environment::libraryVersion() >> 8) & 0xFF));
				}

				_notifyExec = config().getString("webtunnel.status.notify", "");
				if (!_notifyExec.empty())
				{
					connected += Poco::delegate(this, &WebTunnelAgent::notifyConnected);
					disconnected += Poco::delegate(this, &WebTunnelAgent::notifyDisconnected);
					error += Poco::delegate(this, &WebTunnelAgent::notifyError);
				}

#if defined(WEBTUNNEL_ENABLE_TLS)
				Poco::Net::Context::Ptr pContext = createContext("tls");
				Poco::SharedPtr<Poco::Net::InvalidCertificateHandler> pCertificateHandler;
				bool acceptUnknownCert = config().getBool("tls.acceptUnknownCertificate", true);
				if (acceptUnknownCert)
					pCertificateHandler = new Poco::Net::AcceptCertificateHandler(false);
				else
					pCertificateHandler = new Poco::Net::RejectCertificateHandler(false);
				Poco::Net::SSLManager::instance().initializeClient(0, pCertificateHandler, pContext);

				if (_httpsRequired)
				{
					_pSocketFactory = new TLSSocketFactory(_httpPort, createContext("https"));
				}
#endif // WEBTUNNEL_ENABLE_TLS

				if (!_pSocketFactory)
				{
					_pSocketFactory = new Poco::WebTunnel::SocketFactory;
				}

				_pTimer->schedule(new Poco::Util::TimerTaskAdapter<WebTunnelAgent>(*this, &WebTunnelAgent::reconnectTask), Poco::Clock());

				waitForTerminationRequest();

				_stopped.set();
				scheduleDisconnect();
				_disconnected.wait();
				_pTimer->cancel(true);
			}
			catch (Poco::Exception& exc)
			{
				logger().log(exc);
				return Poco::Util::Application::EXIT_SOFTWARE;
			}
		}
		return Poco::Util::Application::EXIT_OK;
	}

	static const std::string SEC_WEBSOCKET_PROTOCOL;
	static const std::string WEBTUNNEL_PROTOCOL;
	static const std::string WEBTUNNEL_AGENT;

private:
	bool _helpRequested;
	std::string _deviceName;
	std::string _deviceVersion;
	Poco::Net::IPAddress _host;
	std::set<Poco::UInt16> _ports;
	Poco::URI _reflectorURI;
	Poco::URI _redirectURI;
	std::string _userAgent;
	std::string _httpPath;
	Poco::UInt16 _httpPort;
	bool _httpsRequired;
	Poco::UInt16 _sshPort;
	Poco::UInt16 _vncPort;
	Poco::UInt16 _rdpPort;
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
	std::string _notifyExec;
	int _threads;
	Poco::SharedPtr<Poco::WebTunnel::SocketDispatcher> _pDispatcher;
	Poco::SharedPtr<Poco::WebTunnel::RemotePortForwarder> _pForwarder;
	Poco::SharedPtr<Poco::Net::HTTPClientSession> _pHTTPClientSession;
	Poco::Event _stopped;
	Poco::Event _disconnected;
	int _retryDelay;
	Poco::SharedPtr<Poco::Util::Timer> _pTimer;
	Poco::Util::TimerTask::Ptr _pPropertiesUpdateTask;
	SSLInitializer _sslInitializer;
	Status _status;
	Poco::Random _random;
	Poco::WebTunnel::SocketFactory::Ptr _pSocketFactory;
};


const std::string WebTunnelAgent::SEC_WEBSOCKET_PROTOCOL("Sec-WebSocket-Protocol");
const std::string WebTunnelAgent::WEBTUNNEL_PROTOCOL("com.appinf.webtunnel.server/1.0");
const std::string WebTunnelAgent::WEBTUNNEL_AGENT("WebTunnelAgent/1.10.0");


POCO_SERVER_MAIN(WebTunnelAgent)
