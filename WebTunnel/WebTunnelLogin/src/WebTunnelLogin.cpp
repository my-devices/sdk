//
// WebTunnelLogin.cpp
//
// Copyright (c) 2026, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/WebTunnel/Version.h"
#include "Poco/Net/HTTPClientSession.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/HTMLForm.h"
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
#include "Poco/Dynamic/Var.h"
#include "Poco/NumberParser.h"
#include "Poco/StreamCopier.h"
#include "Poco/DateTime.h"
#include "Poco/DateTimeFormatter.h"
#include "Poco/Path.h"
#include "Poco/File.h"
#include "Poco/FileStream.h"
#include "Poco/Format.h"
#include <iostream>
#if defined(POCO_OS_FAMILY_WINDOWS)
#include <windows.h>
#elif defined(POCO_OS_FAMILY_UNIX)
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
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


class WebTunnelLogin: public Poco::Util::Application
{
public:
	WebTunnelLogin() = default;

	~WebTunnelLogin() = default;

protected:
	void initialize(Poco::Util::Application& self)
	{
		if (!loadUserConfiguration("remote-login"s))
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
				.callback(OptionCallback<WebTunnelLogin>(this, &WebTunnelLogin::handleHelp)));

		options.addOption(
			Option("version"s, "v"s, "Display version information and exit."s)
				.required(false)
				.repeatable(false)
				.callback(OptionCallback<WebTunnelLogin>(this, &WebTunnelLogin::handleVersion)));

		options.addOption(
			Option("config-file"s, "c"s, "Load configuration data from a file."s)
				.required(false)
				.repeatable(true)
				.argument("file"s)
				.callback(OptionCallback<WebTunnelLogin>(this, &WebTunnelLogin::handleConfig)));

		options.addOption(
			Option("username"s, "u"s, "Specify username for macchina.io REMOTE server."s)
				.required(false)
				.repeatable(false)
				.argument("username")
				.callback(OptionCallback<WebTunnelLogin>(this, &WebTunnelLogin::handleUsername)));

		options.addOption(
			Option("password"s, "p"s, "Specify password for macchina.io REMOTE server."s)
				.required(false)
				.repeatable(false)
				.argument("password")
				.callback(OptionCallback<WebTunnelLogin>(this, &WebTunnelLogin::handlePassword)));

		options.addOption(
			Option("reflector-uri"s, "R"s, "Specify macchina.io REMOTE reflector server URL."s)
				.required(false)
				.repeatable(false)
				.argument("url"s)
				.callback(OptionCallback<WebTunnelLogin>(this, &WebTunnelLogin::handleReflectorURI)));

		options.addOption(
			Option("proxy"s, "P"s, "Specify a HTTP proxy server to connect through, e.g. \"http://proxy.nowhere.com:8080\"."s)
				.required(false)
				.repeatable(false)
				.argument("url"s)
				.callback(OptionCallback<WebTunnelLogin>(this, &WebTunnelLogin::handleProxy)));

		options.addOption(
			Option("define"s, "D"s, "Define or override a configuration property."s)
				.required(false)
				.repeatable(true)
				.argument("name=value"s)
				.callback(OptionCallback<WebTunnelLogin>(this, &WebTunnelLogin::handleDefine)));

		options.addOption(
			Option("status"s, "s"s, "Check existing login status."s)
				.required(false)
				.repeatable(false)
				.callback(OptionCallback<WebTunnelLogin>(this, &WebTunnelLogin::handleStatus)));

		options.addOption(
			Option("clear"s, "C"s, "Clear login token."s)
				.required(false)
				.repeatable(false)
				.callback(OptionCallback<WebTunnelLogin>(this, &WebTunnelLogin::handleClear)));
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

	void handleUsername(const std::string& name, const std::string& value)
	{
		_username = value;
	}

	void handlePassword(const std::string& name, const std::string& value)
	{
		_password = value;
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

	void handleStatus(const std::string& name, const std::string& value)
	{
		_statusRequested = true;
	}

	void handleClear(const std::string& name, const std::string& value)
	{
		_clearRequested = true;
	}

	void displayHelp()
	{
		HelpFormatter helpFormatter(options());
		helpFormatter.setCommand(commandName());
		helpFormatter.setUsage("OPTIONS"s);
		helpFormatter.setHeader("\n"
			"macchina.io REMOTE Login.\n"
			"Copyright (c) 2026 by Applied Informatics Software Engineering GmbH.\n"
			"All rights reserved.\n\n"
			"This application is used to obtain an authentication token from "
			"the macchina.io REMOTE server. This token is stored locally and "
			"can then be used by the other macchina.io REMOTE client programs "
			"like remote-client, remote-ssh or remote-connect."s
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

	void displayStatus()
	{
		loadUserConfiguration("remote-credentials"s);
		std::string token = config().getString("remote.token"s, ""s);
		Poco::Int64 expires = config().getInt64("remote.tokenExpires"s, 0);
		if (!token.empty() && expires != 0)
		{
			Poco::Timestamp now;
			Poco::Timestamp expiresTS = Poco::Timestamp::fromEpochTime(expires);
			if (expiresTS > now)
			{
				Poco::Int64 seconds = (expiresTS - now)/Poco::Timestamp::resolution();
				std::cout << "Token is valid, expires " << Poco::DateTimeFormatter::format(expiresTS, Poco::DateTimeFormat::SORTABLE_FORMAT) << " (in " << seconds << " seconds)." << std::endl;
			}
			else
			{
				std::cout << "Token has expired." << std::endl;
			}
		}
		else
		{
			std::cout << "No valid login." << std::endl;
		}
	}

	void clearLogin()
	{
		Poco::Path p(Poco::Path::home());
		p.setFileName(".remote-credentials.properties"s);
		Poco::File f(p.toString());
		if (f.exists())
		{
			f.remove();
		}
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

	void promptTOTP()
	{
		std::cout << "One-Time Password: " << std::flush;
		echo(false);
		std::getline(std::cin, _totp);
		echo(true);
		std::cout << std::endl;
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

	enum LoginStatus
	{
		LOGIN_OK,
		LOGIN_TOTP,
		LOGIN_FAILED
	};

	struct TokenResult
	{
		LoginStatus status;
		std::string token;
		Poco::Int64 expires;
	};

	TokenResult requestToken()
	{
		TokenResult result;
		Poco::SharedPtr<Poco::Net::HTTPClientSession> pSession = Poco::Net::HTTPSessionFactory::defaultFactory().createClientSession(_reflectorURI);
		pSession->setTimeout(_connectTimeout);

		Poco::Net::HTMLForm params;
		params.set("username"s, _username);
		params.set("password"s, _password);
		params.set("application"s, _application);
		if (!_totp.empty())
		{
			params.set("totp"s, _totp);
		}
		Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, "/my-devices/api/token", Poco::Net::HTTPRequest::HTTP_1_1);
		params.prepareSubmit(request);
		params.write(pSession->sendRequest(request));
		Poco::Net::HTTPResponse response;
		std::istream& responseStream = pSession->receiveResponse(response);
		if (response.getStatus() == Poco::Net::HTTPResponse::HTTP_OK)
		{
			std::string json;
			Poco::StreamCopier::copyToString(responseStream, json);
			Poco::Dynamic::Var tokenHolder = Poco::Dynamic::Var::parse(json);
			result.status = LOGIN_OK;
			result.token = tokenHolder["token"].toString();
			result.expires = tokenHolder["expires"].convert<Poco::Int64>();
		}
		else if (response.getStatus() == Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED)
		{
			if (response.get("X-Authenticate"s, ""s) == "TOTP"s)
			{
				result.status = LOGIN_TOTP;
			}
			else
			{
				result.status = LOGIN_FAILED;
			}
		}
		else
		{
			result.status = LOGIN_FAILED;
		}
		return result;
	}

	void saveToken(const std::string& token, Poco::Int64 expires)
	{
		Poco::Path p(Poco::Path::home());
		p.setFileName(".remote-credentials.properties"s);
		Poco::FileOutputStream file(p.toString());
		Poco::DateTime now;
		Poco::Timestamp expireTS = Poco::Timestamp::fromEpochTime(expires);
		file
			<< "# Token obtained " << Poco::DateTimeFormatter::format(now, Poco::DateTimeFormat::SORTABLE_FORMAT) << " from " << _reflectorURI.toString() << "\n"
			<< "remote.token = " << token << "\n"
			<< "# Token expires " << Poco::DateTimeFormatter::format(expireTS, Poco::DateTimeFormat::SORTABLE_FORMAT) << "\n"
			<< "remote.tokenExpires = " << expires << "\n";
		file.close();
#if defined(POCO_OS_FAMILY_UNIX)
		::chmod(p.toString().c_str(), S_IRUSR | S_IWUSR);
#endif
	}

	int main(const std::vector<std::string>& args)
	{
		int rc = Poco::Util::Application::EXIT_OK;

		if (_versionRequested)
		{
			std::cout << Poco::WebTunnel::formatVersion(WEBTUNNEL_VERSION) << std::endl;
		}
		else if (_statusRequested)
		{
			displayStatus();
		}
		else if (_clearRequested)
		{
			clearLogin();
		}
		else if (_helpRequested)
		{
			displayHelp();
		}
		else
		{
			_connectTimeout = Poco::Timespan(config().getInt("remote.connectTimeout"s, 30), 0);

			if (_reflectorURI.empty() && config().has("remote.reflectorURI"s))
			{
				_reflectorURI = config().getString("remote.reflectorURI"s);
			}

			_application = config().getString("remote.jwt.application"s, "WebTunnelLogin"s);

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

			promptLogin();
			auto result = requestToken();
			if (result.status == LOGIN_TOTP)
			{
				promptTOTP();
				result = requestToken();
			}
			if (result.status == LOGIN_OK)
			{
				Poco::Timestamp expireTS = Poco::Timestamp::fromEpochTime(result.expires);
				std::cout << "Login successful, token valid until " << Poco::DateTimeFormatter::format(expireTS, Poco::DateTimeFormat::SORTABLE_FORMAT) << "." << std::endl;
				saveToken(result.token, result.expires);
			}
			else
			{
				std::cerr << "Login failed." << std::endl;
			}
		}
		return rc;
	}

private:
	bool _helpRequested = false;
	bool _versionRequested = false;
	bool _statusRequested = false;
	bool _clearRequested = false;
	Poco::URI _reflectorURI = Poco::URI("https://remote.macchina.io"s);
	std::string _username;
	std::string _password;
	std::string _application;
	std::string _totp;
	Poco::Timespan _connectTimeout;
	SSLInitializer _sslInitializer;
};


POCO_APP_MAIN(WebTunnelLogin)
