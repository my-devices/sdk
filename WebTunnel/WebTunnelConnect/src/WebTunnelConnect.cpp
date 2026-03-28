//
// WebTunnelConnect.cpp
//
// Copyright (c) 2026, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/WebTunnel/SocketDispatcher.h"
#include "Poco/WebTunnel/Version.h"
#include "Poco/Net/HTTPClientSession.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/HTTPSessionFactory.h"
#include "Poco/Net/HTTPSessionInstantiator.h"
#include "Poco/Net/HTTPBasicCredentials.h"
#include "Poco/Net/OAuth20Credentials.h"
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
#include "Poco/StreamCopier.h"
#include "Poco/Environment.h"
#include "Poco/Path.h"
#include "Poco/File.h"
#include "Poco/Format.h"
#include <iostream>
#include <atomic>
#if defined(POCO_OS_FAMILY_WINDOWS)
#include <windows.h>
#elif defined(POCO_OS_FAMILY_UNIX)
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#endif


using Poco::Util::Option;
using Poco::Util::OptionSet;
using Poco::Util::OptionCallback;
using Poco::Util::HelpFormatter;
using Poco::WebTunnel::SocketDispatcher;
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


class StdIO
{
public:
	static int read(char* buffer, std::size_t bufferSize);
	static int write(const char* buffer, std::size_t length);

private:
#if defined(POCO_OS_FAMILY_WINDOWS)
	static HANDLE _in;
	static HANDLE _out;
#endif
};


#if defined(POCO_OS_FAMILY_WINDOWS)
HANDLE StdIO::_in = ::GetStdHandle(STD_INPUT_HANDLE);
HANDLE StdIO::_out = ::GetStdHandle(STD_OUTPUT_HANDLE);
#endif


int StdIO::read(char* buffer, std::size_t bufferSize)
{
#if defined(POCO_OS_FAMILY_WINDOWS)
	DWORD n;
	BOOL ok = ::ReadFile(_in, buffer, static_cast<DWORD>(bufferSize), &n, nullptr);
	return ok ? static_cast<int>(n) : -1;
#else
	return ::read(0, buffer, static_cast<int>(bufferSize));
#endif
}


int StdIO::write(const char* buffer, std::size_t length)
{
#if defined(POCO_OS_FAMILY_WINDOWS)
	BOOL ok = ::WriteFile(_out, buffer, static_cast<DWORD>(length), nullptr, nullptr);
	return ok ? static_cast<int>(length) : -1;
#else
	return ::write(1, buffer, static_cast<int>(length));
#endif
}


class ProxyHandler: public SocketDispatcher::SocketHandler
{
public:
	ProxyHandler()
	{
	}

	bool wantRead(SocketDispatcher& dispatcher)
	{
		return true;
	}

	bool wantWrite(SocketDispatcher& dispatcher)
	{
		return false;
	}

	void readable(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
	{
		try
		{
			int n = socket.receiveBytes(_buffer.begin(), static_cast<int>(_buffer.size()));
			if (n > 0)
			{
				StdIO::write(_buffer.begin(), n);
			}
			else
			{
				_peerClosed = true;
				if (n < 0)
				{
					_logger.error("Error reading from peer."s);
				}
			}
		}
		catch (Poco::Exception& exc)
		{
			_logger.error("Error reading from peer: %s"s, exc.displayText());
		}
	}

	void writable(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
	{
	}

	void exception(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket, const Poco::Exception* pException)
	{
		if (pException)
		{
			_logger.error("Socket error: %s"s, pException->displayText());
			_peerClosed = true;
		}
	}

	void timeout(SocketDispatcher& dispatcher, Poco::Net::StreamSocket& socket)
	{
	}

	bool peerClosed() const
	{
		return _peerClosed.load();
	}

private:
	Poco::Logger& _logger = Poco::Logger::get("ProxyHandler"s);
	Poco::Buffer<char> _buffer{8192};
	std::atomic<bool> _peerClosed{false};
};


class WebTunnelConnect: public Poco::Util::Application
{
public:
	WebTunnelConnect() = default;

	~WebTunnelConnect() = default;

protected:
	void initialize(Poco::Util::Application& self)
	{
		if (!loadUserConfiguration("remote-proxy"s))
		{
			loadConfiguration(); // load default configuration files, if present
		}
		loadUserConfiguration("remote-credentials"s);
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
				.callback(OptionCallback<WebTunnelConnect>(this, &WebTunnelConnect::handleHelp)));

		options.addOption(
			Option("version"s, "v"s, "Display version information and exit."s)
				.required(false)
				.repeatable(false)
				.callback(OptionCallback<WebTunnelConnect>(this, &WebTunnelConnect::handleVersion)));

		options.addOption(
			Option("config-file"s, "c"s, "Load configuration data from a file."s)
				.required(false)
				.repeatable(true)
				.argument("file"s)
				.callback(OptionCallback<WebTunnelConnect>(this, &WebTunnelConnect::handleConfig)));

		options.addOption(
			Option("username"s, "u"s, "Specify username for macchina.io REMOTE server."s)
				.required(false)
				.repeatable(false)
				.argument("username")
				.callback(OptionCallback<WebTunnelConnect>(this, &WebTunnelConnect::handleUsername)));

		options.addOption(
			Option("password"s, "p"s, "Specify password for macchina.io REMOTE server."s)
				.required(false)
				.repeatable(false)
				.argument("password")
				.callback(OptionCallback<WebTunnelConnect>(this, &WebTunnelConnect::handlePassword)));

		options.addOption(
			Option("token"s, "t"s, "Specify token (JWT) for authenticating against macchina.io REMOTE server."s)
				.required(false)
				.repeatable(false)
				.argument("token"s)
				.callback(OptionCallback<WebTunnelConnect>(this, &WebTunnelConnect::handleToken)));

		options.addOption(
			Option("reflector-uri"s, "R"s, "Specify macchina.io REMOTE reflector server URL."s)
				.required(false)
				.repeatable(false)
				.argument("url"s)
				.callback(OptionCallback<WebTunnelConnect>(this, &WebTunnelConnect::handleReflectorURI)));

		options.addOption(
			Option("proxy"s, "P"s, "Specify a HTTP proxy server to connect through, e.g. \"http://proxy.nowhere.com:8080\"."s)
				.required(false)
				.repeatable(false)
				.argument("url"s)
				.callback(OptionCallback<WebTunnelConnect>(this, &WebTunnelConnect::handleProxy)));

		options.addOption(
			Option("define"s, "D"s, "Define or override a configuration property."s)
				.required(false)
				.repeatable(true)
				.argument("name=value"s)
				.callback(OptionCallback<WebTunnelConnect>(this, &WebTunnelConnect::handleDefine)));
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

	void handleToken(const std::string& name, const std::string& value)
	{
		_token = value;
	}

	void handleReflectorURI(const std::string& name, const std::string& value)
	{
		_reflectorURI = Poco::URI(value);
	}

	void handleProxy(const std::string& name, const std::string& value)
	{
		config().setBool("http.proxy.enable"s, true);
		config().setString("http.proxy.url"s, value);
		config().setString("http.proxy.host"s, ""s);
	}

	void handleDefine(const std::string& name, const std::string& value)
	{
		defineProperty(value);
	}

	void displayHelp()
	{
		HelpFormatter helpFormatter(options());
		helpFormatter.setCommand(commandName());
		helpFormatter.setUsage("OPTIONS <Target>:<Port>"s);
		helpFormatter.setHeader("\n"
			"macchina.io REMOTE Connect.\n"
			"Copyright (c) 2026 by Applied Informatics Software Engineering GmbH.\n"
			"All rights reserved.\n\n"
			"This application is used to create a tunnel to a remote device "
			"via the macchina.io REMOTE server "
			"for use with OpenSSH ProxyCommand or similar tools.\n"
			"It can also be used like netcat (nc) with a remote device.\n\n"
			"<Target> and <Port> specify the host name of the remote device and "
			"port number to connect to via the macchina.io REMOTE server, e.g.:\n"
			"8ba57423-ec1a-4f31-992f-a66c240cbfa0.remote.macchina.io:22"
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

	void pumpTunnel(Poco::Net::StreamSocket socket)
	{
		Poco::AutoPtr<ProxyHandler> pProxyHandler = Poco::makeAuto<ProxyHandler>();
		SocketDispatcher dispatcher;
		dispatcher.addSocket(socket, pProxyHandler, Poco::Net::PollSet::POLL_READ);

		Poco::Buffer<char> buffer(8192);
		int n = StdIO::read(buffer.begin(), buffer.size());
		while (n > 0 && !pProxyHandler->peerClosed())
		{
			dispatcher.sendBytes(socket, buffer.begin(), n, 0);
			n = StdIO::read(buffer.begin(), buffer.size());
		}
		dispatcher.shutdownSend(socket);
		logger().debug("End of input, waiting for peer to close connection."s);
		while (!pProxyHandler->peerClosed())
		{
			Poco::Thread::sleep(100);
		}
	}

	int runTunnel(const std::string& target)
	{
		logger().debug("Connecting to %s through %s..."s, target, _reflectorURI.toString());
		Poco::SharedPtr<Poco::Net::HTTPClientSession> pSession = Poco::Net::HTTPSessionFactory::defaultFactory().createClientSession(_reflectorURI);
		pSession->setKeepAlive(true);
		pSession->setTimeout(_connectTimeout);
		Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_CONNECT, target, Poco::Net::HTTPRequest::HTTP_1_1);
		if (!_token.empty())
		{
			Poco::Net::OAuth20Credentials creds(_token);
			creds.proxyAuthenticate(request);
		}
		else
		{
			Poco::Net::HTTPBasicCredentials creds(_username, _password);
			creds.proxyAuthenticate(request);
		}
		request.setKeepAlive(true);
		request.setHost(target);
		std::ostream& requestStream = pSession->sendRequest(request);
		Poco::Net::HTTPResponse response;
		std::istream& responseStream = pSession->receiveResponse(response);
		if (response.getStatus() == Poco::Net::HTTPResponse::HTTP_OK)
		{
			logger().debug("Tunnel established."s);
			Poco::Net::StreamSocket socket = pSession->detachSocket();
			pumpTunnel(socket);
			return Poco::Util::Application::EXIT_OK;
		}
		else
		{
			logger().error("Failed to establish tunnel: %s (%d)"s, response.getReason(), static_cast<int>(response.getStatus()));
			Poco::StreamCopier::copyStream(responseStream, std::cerr);
			return Poco::Util::Application::EXIT_UNAVAILABLE;
		}
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
			_connectTimeout = Poco::Timespan(config().getInt("remote.connectTimeout"s, 30), 0);

			if (_username.empty())
			{
				_username = config().getString("remote.username"s, ""s);
			}
			if (_password.empty())
			{
				_password = config().getString("remote.password"s, ""s);
			}
			if (_token.empty())
			{
				_token = config().getString("remote.token"s, ""s);
			}
			if (_reflectorURI.empty() && config().has("remote.reflectorURI"s))
			{
				_reflectorURI = config().getString("remote.reflectorURI"s);
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

			if (_token.empty() && _username.empty())
			{
				rc = Poco::Util::Application::EXIT_CONFIG;
			}
			else
			{
				const std::string target = args[0];
				try
				{
					Poco::Net::SocketAddress targetAddr(target);
				}
				catch (Poco::Exception&)
				{
					std::cerr << "Invalid target name specified. The host name is malformed or the port number is missing." << std::endl;
					rc = Poco::Util::Application::EXIT_USAGE;
				}

				if (rc == Poco::Util::Application::EXIT_OK && _reflectorURI.empty())
				{
					std::string::size_type pos1 = target.find('.');
					if (pos1 != std::string::npos)
					{
						std::string::size_type pos2 = target.rfind(':');
						if (pos2 == std::string::npos) pos2 = target.size();
						const std::string reflectorName(target, pos1 + 1, pos2 - pos1);
						_reflectorURI = "https://"s + reflectorName;
					}
					else
					{
						std::cerr << "Invalid target name specified." << std::endl;
						rc = Poco::Util::Application::EXIT_USAGE;
					}
				}
				if (rc == Poco::Util::Application::EXIT_OK)
				{
					rc = runTunnel(target);
				}
			}
		}
		return rc;
	}

private:
	bool _helpRequested = false;
	bool _versionRequested = false;
	Poco::URI _reflectorURI;
	Poco::UInt16 _remotePort = 0;
	std::string _username = Poco::Environment::get("REMOTE_USERNAME"s, ""s);
	std::string _password = Poco::Environment::get("REMOTE_PASSWORD"s, ""s);
	std::string _token = Poco::Environment::get("REMOTE_TOKEN"s, ""s);
	Poco::Timespan _connectTimeout;
	SSLInitializer _sslInitializer;
};


POCO_APP_MAIN(WebTunnelConnect)
