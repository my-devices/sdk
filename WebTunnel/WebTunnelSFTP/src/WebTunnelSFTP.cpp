//
// WebTunnelSFTP.cpp
//
// Copyright (c) 2014-2025, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/WebTunnel/LocalPortForwarder.h"
#include "Poco/WebTunnel/Version.h"
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
#include "Poco/File.h"
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
	WebTunnelSFTP()
	{
#if defined(POCO_OS_FAMILY_WINDOWS)
		_sftpClient = findExecutable("sftp.exe"s);
#else
		_sftpClient = "sftp";
#endif
	}

	~WebTunnelSFTP() = default;

protected:
	void initialize(Poco::Util::Application& self)
	{
		if (!loadUserConfiguration("remote-sftp"s) && !loadUserConfiguration("remote-client"s))
		{
			loadConfiguration(); // load default configuration files, if present
		}
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

	bool loadUserConfiguration(const std::string& baseName)
	{
		Poco::Path p(Poco::Path::home());
		p.setFileName(Poco::format(".%s.properties"s, baseName));
		Poco::File f(p.toString());
		if (f.exists())
		{
			loadConfiguration(f.path());
			return true;
		}
		else return false;
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
			Option("version"s, "v"s, "Display version information and exit."s)
				.required(false)
				.repeatable(false)
				.callback(OptionCallback<WebTunnelSFTP>(this, &WebTunnelSFTP::handleVersion)));

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
			Option("proxy"s, "P"s, "Specify a HTTP proxy server to connect through, e.g. \"http://proxy.nowhere.com:8080\"."s)
				.required(false)
				.repeatable(false)
				.argument("url"s)
				.callback(OptionCallback<WebTunnelSFTP>(this, &WebTunnelSFTP::handleProxy)));

		options.addOption(
			Option("login-name"s, "l"s, "Specify remote (SSH) login name."s)
				.required(false)
				.repeatable(false)
				.argument("username"s)
				.callback(OptionCallback<WebTunnelSFTP>(this, &WebTunnelSFTP::handleLogin)));

		options.addOption(
			Option("identity-file"s, "i"s, "Specify SSH identity file. This is passed on to the SFTP client (-i)."s)
				.required(false)
				.repeatable(false)
				.argument("path"s)
				.callback(OptionCallback<WebTunnelSFTP>(this, &WebTunnelSFTP::handleIdentity)));

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

	void handleVersion(const std::string& name, const std::string& value)
	{
		_versionRequested = true;
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

	void handleProxy(const std::string& name, const std::string& value)
	{
		config().setBool("http.proxy.enable"s, true);
		config().setString("http.proxy.url"s, value);
		config().setString("http.proxy.host"s, ""s);
	}

	void handleLogin(const std::string& name, const std::string& value)
	{
		_login = value;
	}

	void handleIdentity(const std::string& name, const std::string& value)
	{
		_identity = value;
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
			"Copyright (c) 2021-2025 by Applied Informatics Software Engineering GmbH.\n"
			"All rights reserved.\n\n"
			"This application is used to launch a SFTP (Secure/SSH File Transfer Protocol)\n"
			"connection to a remote host via the macchina.io REMOTE server.\n\n"
			"<Remote-URI> specifies the URI of the remote device via the\n"
			"macchina.io REMOTE server, e.g.:\n"
#if defined(WEBTUNNEL_ENABLE_TLS)
			"https://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io"
#else
			"http://8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io"
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
		if (_versionRequested)
		{
			std::cout << Poco::WebTunnel::formatVersion(WEBTUNNEL_VERSION) << std::endl;
		}
		else if (_helpRequested || args.empty())
		{
			displayHelp();
		}
		else
		{
			Poco::Timespan connectTimeout = Poco::Timespan(config().getInt("webtunnel.connectTimeout"s, 30), 0);
			Poco::Timespan remoteTimeout = Poco::Timespan(config().getInt("webtunnel.remoteTimeout"s, 300), 0);
			Poco::Timespan localTimeout = Poco::Timespan(config().getInt("webtunnel.localTimeout"s, 7200), 0);

			if (_username.empty())
			{
				_username = config().getString("remote.username"s, ""s);
			}
			if (_password.empty())
			{
				_password = config().getString("remote.password"s, ""s);
			}

#if defined(WEBTUNNEL_ENABLE_TLS)
			bool acceptUnknownCert = config().getBool("tls.acceptUnknownCertificate"s, true);
			std::string cipherList = config().getString("tls.ciphers"s, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"s);
			bool extendedVerification = config().getBool("tls.extendedCertificateVerification"s, false);
			std::string caLocation = config().getString("tls.caLocation"s, ""s);
			std::string tlsMinVersion = config().getString("tls.minVersion", ""s);

			Poco::Net::Context::VerificationMode vMode = Poco::Net::Context::VERIFY_RELAXED;
			std::string vModeStr = config().getString("tls.verification", ""s);
			if (vModeStr == "none")
				vMode = Poco::Net::Context::VERIFY_NONE;
			else if (vModeStr == "relaxed")
				vMode = Poco::Net::Context::VERIFY_RELAXED;
			else if (vModeStr == "strict")
				vMode = Poco::Net::Context::VERIFY_STRICT;
			else if (vModeStr != "")
				throw Poco::InvalidArgumentException("tls.verification", vModeStr);

			Poco::Net::Context::Protocols minProto = Poco::Net::Context::PROTO_TLSV1_2;
			if (tlsMinVersion == "tlsv1" || tlsMinVersion == "tlsv1_0")
				minProto = Poco::Net::Context::PROTO_TLSV1;
			else if (tlsMinVersion == "tlsv1_1")
				minProto = Poco::Net::Context::PROTO_TLSV1_1;
			else if (tlsMinVersion == "tlsv1_2")
				minProto = Poco::Net::Context::PROTO_TLSV1_2;
			else if (tlsMinVersion == "tlsv1_3")
				minProto = Poco::Net::Context::PROTO_TLSV1_3;
			else if (tlsMinVersion != "")
				throw Poco::InvalidArgumentException("tls.minVersion", tlsMinVersion);

			Poco::SharedPtr<Poco::Net::InvalidCertificateHandler> pCertificateHandler;
			if (acceptUnknownCert)
				pCertificateHandler = new Poco::Net::AcceptCertificateHandler(false);
			else
				pCertificateHandler = new Poco::Net::RejectCertificateHandler(false);

#if defined(POCO_NETSSL_WIN)
			Poco::Net::Context::Ptr pContext = new Poco::Net::Context(Poco::Net::Context::TLS_CLIENT_USE, ""s, vMode);
#else
			Poco::Net::Context::Ptr pContext = new Poco::Net::Context(Poco::Net::Context::TLS_CLIENT_USE, ""s, ""s, caLocation, vMode, 5, true, cipherList);
#endif
			pContext->requireMinimumProtocol(minProto);
			pContext->enableExtendedCertificateVerification(extendedVerification);
			Poco::Net::SSLManager::instance().initializeClient(0, pCertificateHandler, pContext);
#endif

			if (config().getBool("http.proxy.enable"s, false))
			{
				Poco::Net::HTTPClientSession::ProxyConfig proxyConfig;
				proxyConfig.host = config().getString("http.proxy.host"s, ""s);
				proxyConfig.port = config().getUInt16("http.proxy.port"s, 80);
				std::string proxyURL = config().getString("http.proxy.url"s, ""s);
				if (!proxyURL.empty() && proxyConfig.host.empty())
				{
					Poco::URI proxyURI(proxyURL);
					if (proxyURI.getScheme() != "http")
					{
						logger().warning("Proxy URL specified, but scheme is not \"http\"."s);
					}
					proxyConfig.host = proxyURI.getHost();
					proxyConfig.port = proxyURI.getPort();
				}
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
			if (!_identity.empty())
			{
				sftpArgs.push_back("-i");
				sftpArgs.push_back(_identity);
			}
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
	bool _helpRequested = false;
	bool _versionRequested = false;
	Poco::UInt16 _localPort = 0;
	Poco::UInt16 _remotePort = 22;
	std::string _username = Poco::Environment::get("REMOTE_USERNAME"s, ""s);
	std::string _password = Poco::Environment::get("REMOTE_PASSWORD"s, ""s);
	std::string _login;
	std::string _identity;
	std::string _sftpClient;
	SSLInitializer _sslInitializer;
};


POCO_APP_MAIN(WebTunnelSFTP)
