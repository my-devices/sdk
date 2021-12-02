//
// WebTunnelSFTP.cpp
//
// Copyright (c) 2014-2021, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/WebTunnel/LocalPortForwarder.h"
#include "Poco/Net/HTTPClientSession.h"
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
#include "Poco/Util/Application.h"
#include "Poco/Util/Option.h"
#include "Poco/Util/OptionSet.h"
#include "Poco/Util/HelpFormatter.h"
#include "Poco/Util/IntValidator.h"
#include "Poco/NumberParser.h"
#include "Poco/NumberFormatter.h"
#include "Poco/Process.h"
#include "Poco/Environment.h"
#include "Poco/Format.h"
#include "Poco/String.h"
#include "Poco/Path.h"
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


class WebTunnelSFTP: public Poco::Util::Application
{
public:
	WebTunnelSFTP():
		_helpRequested(false),
		_localPort(0),
		_remotePort(22)
	{
#if defined(POCO_OS_FAMILY_WINDOWS)
		_sftpClient = findExecutable("sftp.exe"s);
#else
		_sftpClient = "sftp";
#endif
	}

	~WebTunnelSFTP()
	{
	}

protected:
	void initialize(Poco::Util::Application& self)
	{
		loadConfiguration(); // load default configuration files, if present
		Poco::Util::Application::initialize(self);
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
		Poco::Util::Application::uninitialize();
	}

	void defineOptions(OptionSet& options)
	{
		Poco::Util::Application::defineOptions(options);

		options.addOption(
			Option("help"s, "h"s, "Display help information on command line arguments."s)
				.required(false)
				.repeatable(false)
				.callback(OptionCallback<WebTunnelSFTP>(this, &WebTunnelSFTP::handleHelp)));

		options.addOption(
			Option("config-file"s, "c"s, "Load configuration data from a file."s)
				.required(false)
				.repeatable(true)
				.argument("file"s)
				.callback(OptionCallback<WebTunnelSFTP>(this, &WebTunnelSFTP::handleConfig)));

		options.addOption(
			Option("sftp-client", "C"s, "Specify the name of the SFTP client executable (default: sftp)."s)
				.required(false)
				.repeatable(false)
				.argument("program"s)
				.callback(OptionCallback<WebTunnelSFTP>(this, &WebTunnelSFTP::handleClient)));

		options.addOption(
			Option("local-port"s, "L"s, "Specify local port number (default: ephemeral)."s)
				.required(false)
				.repeatable(false)
				.argument("port"s)
				.validator(new Poco::Util::IntValidator(1, 65535))
				.callback(OptionCallback<WebTunnelSFTP>(this, &WebTunnelSFTP::handleLocalPort)));

		options.addOption(
			Option("remote-port"s, "R"s, "Specify remote port number (default: SSH/22)."s)
				.required(false)
				.repeatable(false)
				.argument("port"s)
				.validator(new Poco::Util::IntValidator(1, 65535))
				.callback(OptionCallback<WebTunnelSFTP>(this, &WebTunnelSFTP::handleRemotePort)));

		options.addOption(
			Option("username"s, "u"s, "Specify username for macchina.io REMOTE server."s)
				.required(false)
				.repeatable(false)
				.argument("username"s)
				.callback(OptionCallback<WebTunnelSFTP>(this, &WebTunnelSFTP::handleUsername)));

		options.addOption(
			Option("password"s, "p"s, "Specify password for macchina.io REMOTE server."s)
				.required(false)
				.repeatable(false)
				.argument("password"s)
				.callback(OptionCallback<WebTunnelSFTP>(this, &WebTunnelSFTP::handlePassword)));

		options.addOption(
			Option("login-name"s, "l"s, "Specify remote (SSH) login name."s)
				.required(false)
				.repeatable(false)
				.argument("username"s)
				.callback(OptionCallback<WebTunnelSFTP>(this, &WebTunnelSFTP::handleLogin)));

		options.addOption(
			Option("define"s, "D"s, "Define or override a configuration property."s)
				.required(false)
				.repeatable(true)
				.argument("name=value"s)
				.callback(OptionCallback<WebTunnelSFTP>(this, &WebTunnelSFTP::handleDefine)));
	}

	void handleHelp(const std::string& name, const std::string& value)
	{
		_helpRequested = true;
	}

	void handleConfig(const std::string& name, const std::string& value)
	{
		loadConfiguration(value);
	}

	void handleClient(const std::string& name, const std::string& value)
	{
		_sftpClient = value;
	}

	void handleLocalPort(const std::string& name, const std::string& value)
	{
		_localPort = static_cast<Poco::UInt16>(Poco::NumberParser::parseUnsigned(value));
	}

	void handleRemotePort(const std::string& name, const std::string& value)
	{
		_remotePort = static_cast<Poco::UInt16>(Poco::NumberParser::parseUnsigned(value));
	}

	void handleUsername(const std::string& name, const std::string& value)
	{
		_username = value;
	}

	void handlePassword(const std::string& name, const std::string& value)
	{
		_password = value;
	}

	void handleLogin(const std::string& name, const std::string& value)
	{
		_login = value;
	}

	void handleDefine(const std::string& name, const std::string& value)
	{
		defineProperty(value);
	}

	void displayHelp()
	{
		HelpFormatter helpFormatter(options());
		helpFormatter.setCommand(commandName());
		helpFormatter.setUsage("OPTIONS <Remote-URI> [-- SFTP-OPTIONS]"s);
		helpFormatter.setHeader("\n"
			"macchina.io REMOTE SFTP Client.\n"
			"Copyright (c) 2021 by Applied Informatics Software Engineering GmbH.\n"
			"All rights reserved.\n\n"
			"This application is used to launch a SFTP (Secure/SSH File Transfer Protocol)\n"
			"connection to a remote host via the macchina.io REMOTE server.\n\n"
			"<Remote-URI> specifies the URI of the remote device via the\n"
			"macchina.io REMOTE server, e.g.:\n"
#if defined(WEBTUNNEL_ENABLE_TLS)
			"https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net"
#else
			"http://8ba57423-ec1a-4f31-992f-a66c240cbfa0.my-devices.net"
#endif
			"\n\n"
			"The following command-line options are supported:"s
		);
		helpFormatter.setFooter(
			"For more information, please visit the macchina.io REMOTE "
			"website at <https://macchina.io/remote>."s
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
			std::cout << "macchina.io REMOTE Username: " << std::flush;
			std::getline(std::cin, _username);
		}
		if (_password.empty())
		{
			std::cout << "macchina.io REMOTE Password: " << std::flush;
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

	std::string findExecutable(const std::string& name)
	{
		std::string pathList = Poco::Environment::get("PATH"s);
		Poco::Path p;
		if (Poco::Path::find(pathList, name, p))
			return p.toString();
		else
			return std::string();
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
				Poco::Net::HTTPClientSession::ProxyConfig proxyConfig;
				proxyConfig.host = config().getString("http.proxy.host"s, ""s);
				proxyConfig.port = static_cast<Poco::UInt16>(config().getInt("http.proxy.port"s, 80));
				proxyConfig.username = config().getString("http.proxy.username"s, ""s);
				proxyConfig.password = config().getString("http.proxy.password"s, ""s);
				Poco::Net::HTTPClientSession::setGlobalProxyConfig(proxyConfig);
			}

			_sftpClient = config().getString("sftp.executable", _sftpClient);
			if (_sftpClient.empty())
			{
				logger().error("No SFTP client program available. Please configure the SFTP client program using the sftp.executable configuration property or sftp-client option."s);
				return Poco::Util::Application::EXIT_CONFIG;
			}

			promptLogin();

			std::string remoteURI = args[0];
			if (remoteURI.compare(0, 8, "https://") != 0 && remoteURI.compare(0, 7, "http://") != 0)
			{
				if (remoteURI.compare(0, 7, "sftp://") == 0)
				{
					remoteURI.erase(0, 7);
				}
				std::string protocol;
#if defined(WEBTUNNEL_ENABLE_TLS)
				protocol = "https";
#else
				protocol = "http";
#endif
				protocol = config().getString("webtunnel.protocol"s, protocol);
				protocol += "://";
				remoteURI.insert(0, protocol);
			}
			Poco::URI uri(remoteURI);
			Poco::WebTunnel::LocalPortForwarder forwarder(_localPort, _remotePort, uri, new Poco::WebTunnel::DefaultWebSocketFactory(_username, _password, connectTimeout));
			forwarder.setRemoteTimeout(remoteTimeout);
			forwarder.setLocalTimeout(localTimeout);

			if (_login.empty())
			{
				_login = uri.getUserInfo();
			}

			Poco::UInt16 localPort = forwarder.localPort();

			std::string sftpURI = "sftp://";
			if (!_login.empty())
			{
				sftpURI += _login;
				sftpURI += "@";
			}

			sftpURI += Poco::format("localhost:%hu"s, localPort);

			Poco::Process::Args sftpArgs;
			std::vector<std::string>::const_iterator itArgs = ++args.begin();
			sftpArgs.insert(sftpArgs.end(), itArgs, args.end());
			sftpArgs.push_back(sftpURI);

			logger().debug("Launching SFTP client: %s"s, _sftpClient);
			Poco::ProcessHandle ph = Poco::Process::launch(_sftpClient, sftpArgs);
			rc = ph.wait();
			logger().debug("SFTP client terminated with exit code %d"s, rc);
		}
		return rc;
	}

private:
	bool _helpRequested;
	Poco::UInt16 _localPort;
	Poco::UInt16 _remotePort;
	std::string _username;
	std::string _password;
	std::string _login;
	std::string _sftpClient;
	SSLInitializer _sslInitializer;
};


POCO_APP_MAIN(WebTunnelSFTP)
