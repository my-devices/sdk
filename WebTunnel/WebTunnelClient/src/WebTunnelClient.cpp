//
// WebTunnelClient.cpp
//
// Copyright (c) 2013-2021, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/WebTunnel/LocalPortForwarder.h"
#include "Poco/Net/HTTPClientSession.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPSessionFactory.h"
#include "Poco/Net/HTTPSessionInstantiator.h"
#if defined(WEBTUNNEL_ENABLE_TLS)
#include "Poco/Net/HTTPSSessionInstantiator.h"
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
#include "Poco/NumberParser.h"
#include "Poco/Process.h"
#include <iostream>
#if defined(POCO_OS_FAMILY_WINDOWS)
#include <windows.h>
#elif defined(POCO_OS_FAMILY_UNIX)
#include <termios.h>
#endif


using Poco::Util::Option;
using Poco::Util::OptionSet;
using Poco::Util::OptionCallback;
using Poco::Util::HelpFormatter;
using namespace std::string_literals;


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


class JWTWebSocketFactory: public Poco::WebTunnel::WebSocketFactory
{
public:
	JWTWebSocketFactory(const std::string& jwt, Poco::Timespan timeout = Poco::Timespan(30, 0)):
		_jwt(jwt),
		_timeout(timeout)
	{
	}

	Poco::Net::WebSocket* createWebSocket(const Poco::URI& uri, Poco::Net::HTTPRequest& request, Poco::Net::HTTPResponse& response)
	{
		Poco::SharedPtr<Poco::Net::HTTPClientSession> pSession = Poco::Net::HTTPSessionFactory::defaultFactory().createClientSession(uri);
		pSession->setTimeout(_timeout);
		if (!_jwt.empty())
		{
			request.set(Poco::Net::HTTPRequest::AUTHORIZATION, Poco::format("bearer %s", _jwt));
		}
		return new Poco::Net::WebSocket(*pSession, request, response);
	}

private:
	std::string _jwt;
	Poco::Timespan _timeout;
};


class WebTunnelClient: public Poco::Util::ServerApplication
{
public:
	WebTunnelClient():
		_helpRequested(false),
		_localPort(0),
		_remotePort(0),
		_bindAddress("localhost"s)
	{
	}

	~WebTunnelClient()
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
			Option("help"s, "h"s, "Display help information on command line arguments."s)
				.required(false)
				.repeatable(false)
				.callback(OptionCallback<WebTunnelClient>(this, &WebTunnelClient::handleHelp)));

		options.addOption(
			Option("config-file"s, "c"s, "Load configuration data from a file."s)
				.required(false)
				.repeatable(true)
				.argument("file"s)
				.callback(OptionCallback<WebTunnelClient>(this, &WebTunnelClient::handleConfig)));

		options.addOption(
			Option("local-port"s, "L"s, "Specify local port number (required)."s)
				.required(false)
				.repeatable(false)
				.argument("port"s)
				.validator(new Poco::Util::IntValidator(1, 65535))
				.callback(OptionCallback<WebTunnelClient>(this, &WebTunnelClient::handleLocalPort)));

		options.addOption(
			Option("remote-port"s, "R"s, "Specify remote port number (required)."s)
				.required(false)
				.repeatable(false)
				.argument("port"s)
				.validator(new Poco::Util::IntValidator(1, 65535))
				.callback(OptionCallback<WebTunnelClient>(this, &WebTunnelClient::handleRemotePort)));

		options.addOption(
			Option("bind-address"s, "b"s, "Specify local address to bind server socket to (defaults to \"localhost\")."s)
				.required(false)
				.repeatable(false)
				.argument("address"s)
				.callback(OptionCallback<WebTunnelClient>(this, &WebTunnelClient::handleBindAddress)));

		options.addOption(
			Option("username"s, "u"s, "Specify username for Remote Manager server."s)
				.required(false)
				.repeatable(false)
				.argument("username")
				.callback(OptionCallback<WebTunnelClient>(this, &WebTunnelClient::handleUsername)));

		options.addOption(
			Option("password"s, "p"s, "Specify password for Remote Manager server."s)
				.required(false)
				.repeatable(false)
				.argument("password")
				.callback(OptionCallback<WebTunnelClient>(this, &WebTunnelClient::handlePassword)));

		options.addOption(
			Option("token"s, "t"s, "Specify token (JWT) for authenticating against Remote Manager server."s)
				.required(false)
				.repeatable(false)
				.argument("token"s)
				.callback(OptionCallback<WebTunnelClient>(this, &WebTunnelClient::handleToken)));

		options.addOption(
			Option("command"s, "C"s, "Specify a command to run (instead of waiting)."s)
				.required(false)
				.repeatable(false)
				.argument("command"s)
				.callback(OptionCallback<WebTunnelClient>(this, &WebTunnelClient::handleCommand)));

		options.addOption(
			Option("define"s, "D"s, "Define or override a configuration property."s)
				.required(false)
				.repeatable(true)
				.argument("name=value"s)
				.callback(OptionCallback<WebTunnelClient>(this, &WebTunnelClient::handleDefine)));
	}

	void handleHelp(const std::string& name, const std::string& value)
	{
		_helpRequested = true;
	}

	void handleConfig(const std::string& name, const std::string& value)
	{
		loadConfiguration(value);
	}

	void handleLocalPort(const std::string& name, const std::string& value)
	{
		_localPort = static_cast<Poco::UInt16>(Poco::NumberParser::parseUnsigned(value));
	}

	void handleRemotePort(const std::string& name, const std::string& value)
	{
		_remotePort = static_cast<Poco::UInt16>(Poco::NumberParser::parseUnsigned(value));
	}

	void handleBindAddress(const std::string& name, const std::string& value)
	{
		_bindAddress = value;
	}

	void handleUsername(const std::string& name, const std::string& value)
	{
		_username = value;
	}

	void handlePassword(const std::string& name, const std::string& value)
	{
		_password = value;
	}

	void handleToken(const std::string& name, const std::string& value)
	{
		_token = value;
	}

	void handleCommand(const std::string& name, const std::string& value)
	{
		_command = value;
	}

	void handleDefine(const std::string& name, const std::string& value)
	{
		defineProperty(value);
	}

	void displayHelp()
	{
		HelpFormatter helpFormatter(options());
		helpFormatter.setCommand(commandName());
		helpFormatter.setUsage("OPTIONS <Remote-URI>"s);
		helpFormatter.setHeader("\n"
			"macchina.io Remote Manager Client.\n"
			"Copyright (c) 2013-2021 by Applied Informatics Software Engineering GmbH.\n"
			"All rights reserved.\n\n"
			"This application is used to forward a remote TCP port to the local\n"
			"host via the macchina.io Remote Manager server.\n\n"
			"<Remote-URI> specifies the URI of the remote device via the\n"
			"Remote Manager server, e.g.:\n"
#if defined(WEBTUNNEL_ENABLE_TLS)
			"https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net"
#else
			"http://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net"
#endif
			"\n\n"
			"The following command-line options are supported:"s
		);
		helpFormatter.setFooter(
			"For more information, please visit the macchina.io "
			"website at <https://macchina.io>."s
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

	void promptLogin()
	{
		if (_username.empty())
		{
			std::cout << "Remote Manager Username: " << std::flush;
			std::getline(std::cin, _username);
		}
		if (_password.empty())
		{
			std::cout << "Remote Manager Password: " << std::flush;
			echo(false);
			std::getline(std::cin, _password);
			echo(true);
			std::cout << std::endl;
		}
	}

	void echo(bool status)
	{
#if defined(POCO_OS_FAMILY_WINDOWS)
		HANDLE stdIn = GetStdHandle(STD_INPUT_HANDLE);
		DWORD mode;
		GetConsoleMode(stdIn, &mode);
		mode = status ? mode | ENABLE_ECHO_INPUT : mode & ~ENABLE_ECHO_INPUT;
		SetConsoleMode(stdIn, mode);
#elif defined(POCO_OS_FAMILY_UNIX)
		struct termios tio;
		tcgetattr(0, &tio);
		tio.c_lflag = status ? tio.c_lflag | ECHO : tio.c_lflag & ~(ECHO);
		tcsetattr(0, TCSANOW, &tio);
#endif
	}

	int main(const std::vector<std::string>& args)
	{
		int rc = Poco::Util::Application::EXIT_OK;

		if (_helpRequested || args.empty())
		{
			displayHelp();
		}
		else
		{
			Poco::Timespan connectTimeout = Poco::Timespan(config().getInt("webtunnel.connectTimeout"s, 30), 0);
			Poco::Timespan remoteTimeout = Poco::Timespan(config().getInt("webtunnel.remoteTimeout"s, 300), 0);
			Poco::Timespan localTimeout = Poco::Timespan(config().getInt("webtunnel.localTimeout"s, 7200), 0);

#if defined(WEBTUNNEL_ENABLE_TLS)
			bool acceptUnknownCert = config().getBool("tls.acceptUnknownCertificate"s, true);
			std::string cipherList = config().getString("tls.ciphers"s, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"s);
			bool extendedVerification = config().getBool("tls.extendedCertificateVerification"s, false);
			std::string caLocation = config().getString("tls.caLocation"s, ""s);

			Poco::SharedPtr<Poco::Net::InvalidCertificateHandler> pCertificateHandler;
			if (acceptUnknownCert)
				pCertificateHandler = new Poco::Net::AcceptCertificateHandler(false);
			else
				pCertificateHandler = new Poco::Net::RejectCertificateHandler(false);

#if defined(POCO_NETSSL_WIN)
			Poco::Net::Context::Ptr pContext = new Poco::Net::Context(Poco::Net::Context::TLSV1_CLIENT_USE, ""s, Poco::Net::Context::VERIFY_RELAXED);
#else
			Poco::Net::Context::Ptr pContext = new Poco::Net::Context(Poco::Net::Context::TLSV1_CLIENT_USE, ""s, ""s, caLocation, Poco::Net::Context::VERIFY_RELAXED, 5, true, cipherList);
#endif
			pContext->enableExtendedCertificateVerification(extendedVerification);
			Poco::Net::SSLManager::instance().initializeClient(0, pCertificateHandler, pContext);
#endif

			if (config().getBool("http.proxy.enable"s, false))
			{
				logger().information("Proxy enable"s);
				Poco::Net::HTTPClientSession::ProxyConfig proxyConfig;
				proxyConfig.host = config().getString("http.proxy.host"s, ""s);
				proxyConfig.port = static_cast<Poco::UInt16>(config().getInt("http.proxy.port"s, 80));
				proxyConfig.username = config().getString("http.proxy.username"s, ""s);
				proxyConfig.password = config().getString("http.proxy.password"s, ""s);
				Poco::Net::HTTPClientSession::setGlobalProxyConfig(proxyConfig);
			}

			if (_token.empty())
			{
				promptLogin();
			}

			Poco::URI uri(args[0]);
			Poco::WebTunnel::WebSocketFactory::Ptr pWSF;
			if (!_token.empty())
			{
				pWSF = new JWTWebSocketFactory(_token, connectTimeout);
			}
			else
			{
				pWSF = new Poco::WebTunnel::DefaultWebSocketFactory(_username, _password, connectTimeout);
			}
			Poco::Net::SocketAddress localAddr(_bindAddress, _localPort);
			Poco::WebTunnel::LocalPortForwarder forwarder(localAddr, _remotePort, uri, 0, pWSF);
			forwarder.setRemoteTimeout(remoteTimeout);
			forwarder.setLocalTimeout(localTimeout);

			if (_command.empty())
			{
				waitForTerminationRequest();
			}
			else
			{
				Poco::Process::Args commandArgs(args.begin() + 1, args.end());
				Poco::ProcessHandle ph = Poco::Process::launch(_command, commandArgs);
				rc = ph.wait();
			}
		}
		return rc;
	}

private:
	bool _helpRequested;
	Poco::UInt16 _localPort;
	Poco::UInt16 _remotePort;
	std::string _bindAddress;
	std::string _username;
	std::string _password;
	std::string _token;
	std::string _command;
	SSLInitializer _sslInitializer;
};


POCO_SERVER_MAIN(WebTunnelClient)
