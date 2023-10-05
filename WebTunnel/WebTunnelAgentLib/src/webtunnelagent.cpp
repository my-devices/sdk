//
// webtunnelagent.cpp
//
// Copyright (c) 2023, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "webtunnelagent.h"
#include "Tunnel.h"
#include "Poco/Util/PropertyFileConfiguration.h"
#if defined(WEBTUNNEL_ENABLE_TLS)
#include "Poco/Net/HTTPSSessionInstantiator.h"
#include "Poco/Net/Context.h"
#include "Poco/Net/PrivateKeyPassphraseHandler.h"
#include "Poco/Net/AcceptCertificateHandler.h"
#include "Poco/Net/RejectCertificateHandler.h"
#include "Poco/Net/SSLManager.h"
#include "Poco/Net/SecureStreamSocket.h"
#endif
#include "Poco/WebTunnel/SocketDispatcher.h"
#include "Poco/MemoryStream.h"
#include "Poco/NumberFormatter.h"


using namespace std::string_literals;


namespace
{
	int connectTimeout = 30;
	int remoteTimeout = 900;
	int localTimeout = 7200;
	Poco::SharedPtr<Poco::Util::Timer> pTimer;
	static thread_local std::string lastError;

	struct Holder
	{
		enum 
		{
			SIGNATURE = 0x41474E54
		};

		Holder(std::unique_ptr<WebTunnelAgentLib::Tunnel>&& pTunnel):
			pTunnel(std::move(pTunnel))
		{
		}

		Poco::UInt32 signature = SIGNATURE;
		std::unique_ptr<WebTunnelAgentLib::Tunnel> pTunnel;
	};

	const std::string DEFAULT_CONFIG = R"PROPS(
webtunnel.domain = 00000000-0000-0000-0000-000000000000
webtunnel.deviceId = 00000000-0000-0000-0000-000000000000
webtunnel.host = 127.0.0.1
webtunnel.ports = 0
webtunnel.httpPort = 0
webtunnel.https.enable = false
# webtunnel.sshPort = 22
# webtunnel.vncPort = 5900
# webtunnel.rdpPort = 3389
# webtunnel.appPort = 1234
webtunnel.reflectorURI = https://remote.macchina.io
webtunnel.username = ${webtunnel.deviceId}@${webtunnel.domain}
webtunnel.password =
webtunnel.connectTimeout = 10
webtunnel.localTimeout = 7200
webtunnel.remoteTimeout = 900
webtunnel.threads = 4
http.timeout = 30
tls.acceptUnknownCertificate = false
tls.ciphers = HIGH:!DSS:!aNULL@STRENGTH
tls.verification = relaxed
tls.minVersion = tlsv1_2
tls.extendedCertificateVerification = true
tls.caLocation =
webtunnel.https.ciphers = HIGH:!DSS:!aNULL@STRENGTH
webtunnel.https.verification = none
webtunnel.https.minVersion = tlsv1
webtunnel.https.extendedCertificateVerification = false
webtunnel.https.caLocation =
logging.loggers.root.level = error
logging.loggers.root.channel = console
logging.channels.console.class = ColorConsoleChannel
logging.channels.console.pattern = %Y-%m-%d %H:%M:%S.%i [%p] %s<%I>: %t	
	)PROPS";


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


	Poco::Net::Context::Ptr createContext(Poco::Util::AbstractConfiguration::Ptr pConfig, const std::string& prefix)
	{
		std::string cipherList = pConfig->getString(prefix + ".ciphers", "HIGH:!DSS:!aNULL@STRENGTH"s);
		bool extendedVerification = pConfig->getBool(prefix + ".extendedCertificateVerification", false);
		std::string caLocation = pConfig->getString(prefix + ".caLocation", ""s);
		std::string privateKey = pConfig->getString(prefix + ".privateKey", ""s);
		std::string certificate = pConfig->getString(prefix + ".certificate", ""s);
		std::string tlsMinVersion = pConfig->getString(prefix + ".minVersion", ""s);

		Poco::Net::Context::VerificationMode vMode = Poco::Net::Context::VERIFY_RELAXED;
		std::string vModeStr = pConfig->getString(prefix + ".verification", ""s);
		if (vModeStr == "none")
			vMode = Poco::Net::Context::VERIFY_NONE;
		else if (vModeStr == "relaxed")
			vMode = Poco::Net::Context::VERIFY_RELAXED;
		else if (vModeStr == "strict")
			vMode = Poco::Net::Context::VERIFY_STRICT;
		else if (vModeStr != "")
			throw Poco::InvalidArgumentException(prefix + ".verification", vModeStr);

		Poco::Net::Context::Protocols minProto = Poco::Net::Context::PROTO_TLSV1_2;
		if (tlsMinVersion == "tlsv1" or tlsMinVersion == "tlsv1_0")
			minProto = Poco::Net::Context::PROTO_TLSV1;
		else if (tlsMinVersion == "tlsv1_1")
			minProto = Poco::Net::Context::PROTO_TLSV1_1;
		else if (tlsMinVersion == "tlsv1_2")
			minProto = Poco::Net::Context::PROTO_TLSV1_2;
		else if (tlsMinVersion == "tlsv1_3")
			minProto = Poco::Net::Context::PROTO_TLSV1_3;
		else if (tlsMinVersion != "")
			throw Poco::InvalidArgumentException(prefix + ".minVersion", tlsMinVersion);

#if defined(POCO_NETSSL_WIN)
		int options = Poco::Net::Context::OPT_DEFAULTS;
		if (!certificate.empty()) options |= Poco::Net::Context::OPT_LOAD_CERT_FROM_FILE;
		Poco::Net::Context::Ptr pContext = new Poco::Net::Context(Poco::Net::Context::TLS_CLIENT_USE, certificate, vMode, options);
#else
		Poco::Net::Context::Ptr pContext = new Poco::Net::Context(Poco::Net::Context::TLS_CLIENT_USE, privateKey, certificate, caLocation, vMode, 5, true, cipherList);
#endif // POCO_NETSSL_WIN

		pContext->requireMinimumProtocol(minProto);
		pContext->enableExtendedCertificateVerification(extendedVerification);
		return pContext;
	}


#endif // defined(WEBTUNNEL_ENABLE_TLS)


	int error(const std::string& error)
	{
		lastError = error;
		return webtunnel_agent_result_error;
	}

	int error(const Poco::Exception& exc)
	{
		return error(exc.displayText());
	}

	int success()
	{
		lastError.clear();
		return webtunnel_agent_result_ok;
	}


} // namespace


int WebTunnelAgent_API webtunnel_agent_init(void)
{
	try
	{
		Poco::Net::initializeNetwork();

#if defined(WEBTUNNEL_ENABLE_TLS)
		Poco::Net::initializeSSL();
		Poco::Net::HTTPSSessionInstantiator::registerInstantiator();
#endif

		pTimer = new Poco::Util::Timer;

		return success();
	}
	catch (Poco::Exception& exc)
	{
		return error(exc);
	}
}


void WebTunnelAgent_API webtunnel_agent_cleanup(void)
{
	try
	{
		pTimer.reset();

#if defined(WEBTUNNEL_ENABLE_TLS)
		Poco::Net::HTTPSSessionInstantiator::unregisterInstantiator();
		Poco::Net::uninitializeSSL();
#endif

		Poco::Net::uninitializeNetwork();
	}
	catch (...)
	{
	}
}


int WebTunnelAgent_API webtunnel_agent_configure_tls(bool accept_unknown_cert, bool extended_verification, const char* ciphers, const char* ca_location, int minimum_protocol)
{
#if defined(WEBTUNNEL_ENABLE_TLS)
	try
	{
		std::string cipherList;
		if (ciphers) 
			cipherList = ciphers;
		else
			cipherList = "HIGH:!DSS:!aNULL@STRENGTH";
		std::string caLocation;
		if (ca_location) caLocation = caLocation;
			
		Poco::SharedPtr<Poco::Net::InvalidCertificateHandler> pCertificateHandler;
		if (accept_unknown_cert)
			pCertificateHandler = new Poco::Net::AcceptCertificateHandler(false);
		else
			pCertificateHandler = new Poco::Net::RejectCertificateHandler(false);

#if defined(POCO_NETSSL_WIN)
		Poco::Net::Context::Ptr pContext = new Poco::Net::Context(Poco::Net::Context::TLS_CLIENT_USE, ""s, Poco::Net::Context::VERIFY_RELAXED);
#else
		Poco::Net::Context::Ptr pContext = new Poco::Net::Context(Poco::Net::Context::TLS_CLIENT_USE, ""s, ""s, caLocation, Poco::Net::Context::VERIFY_RELAXED, 5, true, cipherList);
#endif	

		switch (minimum_protocol)
		{
		case webtunnel_agent_tls_1_0:
			pContext->requireMinimumProtocol(Poco::Net::Context::PROTO_TLSV1);
			break;
		case webtunnel_agent_tls_1_1:
			pContext->requireMinimumProtocol(Poco::Net::Context::PROTO_TLSV1_1);
			break;
		case webtunnel_agent_tls_1_2:
			pContext->requireMinimumProtocol(Poco::Net::Context::PROTO_TLSV1_2);
			break;
		case webtunnel_agent_tls_1_3:
			pContext->requireMinimumProtocol(Poco::Net::Context::PROTO_TLSV1_3);
			break;
		}

		pContext->enableExtendedCertificateVerification(extended_verification);
		Poco::Net::SSLManager::instance().initializeClient(nullptr, pCertificateHandler, pContext);

		return success();
	}
	catch (Poco::Exception& exc)
	{
		return error(exc);
	}
#else
	return webtunnel_agent_not_supported;
#endif
}


int WebTunnelAgent_API webtunnel_agent_configure_proxy(bool enable_proxy, const char* proxy_host, unsigned short proxy_port, const char* proxy_username, const char* proxy_password)
{
	try
	{
		Poco::Net::HTTPClientSession::ProxyConfig proxyConfig;
		if (enable_proxy)
		{
			if (!proxy_host) return webtunnel_agent_result_error;
			proxyConfig.host = proxy_host;
			proxyConfig.port = proxy_port;
			if (proxy_username) proxyConfig.username = proxy_username;
			if (proxy_password) proxyConfig.password = proxy_password;
		}
		Poco::Net::HTTPClientSession::setGlobalProxyConfig(proxyConfig);
		return success();
	}
	catch (Poco::Exception& exc)
	{
		return error(exc);
	}
}


int WebTunnelAgent_API webtunnel_agent_configure_timeouts(int connect_timeout, int remote_timeout, int local_timeout)
{
	if (connect_timeout >= 0 && remote_timeout >= 0 && local_timeout >= 0)
	{
		connectTimeout = connect_timeout;
		remoteTimeout  = remote_timeout;
		localTimeout   = local_timeout;
		return success();
	}
	else return error("bad parameters"s);
}


webtunnel_agent WebTunnelAgent_API webtunnel_agent_create(const char* reflector_uri, const char* target_host, const char* device_id, const char* device_password, const char* domain_id, const char* tenant_id, const webtunnel_agent_port_spec* ports, unsigned ports_len, const char* custom_config_path)
{
	try
	{	
		Poco::Util::PropertyFileConfiguration::Ptr pConfig;
		if (custom_config_path)
		{
			pConfig = new Poco::Util::PropertyFileConfiguration(std::string(custom_config_path));
		}
		else
		{
			Poco::MemoryInputStream istr(DEFAULT_CONFIG.data(), DEFAULT_CONFIG.size());
			pConfig = new Poco::Util::PropertyFileConfiguration(istr);
		}

		std::string deviceId;
		if (reflector_uri)
		{
			pConfig->setString("webtunnel.reflectorURI"s, reflector_uri);
		}
		if (target_host)
		{
			pConfig->setString("webtunnel.host"s, target_host);
		}
		if (device_id)
		{
			deviceId = device_id;
			pConfig->setString("webtunnel.deviceId"s, deviceId);
		}
		if (device_password)
		{
			pConfig->setString("webtunnel.password"s, device_password);
		}
		if (domain_id)
		{
			pConfig->setString("webtunnel.domain"s, domain_id);
		}
		if (tenant_id)
		{
			pConfig->setString("webtunnel.tenant"s, tenant_id);
		}
		pConfig->setInt("webtunnel.connectTimeout"s, connectTimeout);
		pConfig->setInt("webtunnel.localTimeout"s, localTimeout);
		pConfig->setInt("webtunnel.remoteTimeout"s, remoteTimeout);

		std::string portsList;
		if (ports && ports_len > 0)
		{
			for (unsigned i = 0; i < ports_len; i++)
			{
				if (!portsList.empty()) portsList += ',';
				portsList += Poco::NumberFormatter::format(static_cast<unsigned>(ports[i].port));
				switch (ports[i].type)
				{
				case webtunnel_port_http:
					pConfig->setUInt16("webtunnel.httpPort"s, ports[i].port);
					pConfig->setBool("webtunnel.https.enable"s, false);
					break;
				case webtunnel_port_https:
					pConfig->setUInt16("webtunnel.httpPort"s, ports[i].port);
					pConfig->setBool("webtunnel.https.enable"s, true);
					break;
				case webtunnel_port_ssh:
					pConfig->setUInt16("webtunnel.sshPort"s, ports[i].port);
					break;
				case webtunnel_port_vnc:
					pConfig->setUInt16("webtunnel.vncPort"s, ports[i].port);
					break;
				case webtunnel_port_rdp:
					pConfig->setUInt16("webtunnel.rdpPort"s, ports[i].port);
					break;
				case webtunnel_port_app:
					pConfig->setUInt16("webtunnel.appPort"s, ports[i].port);
					break;
				case webtunnel_port_other:
				default:
					break;
				}
			}
			pConfig->setString("webtunnel.ports"s, portsList);
		}

		Poco::SharedPtr<Poco::WebTunnel::SocketDispatcher> pDispatcher = new Poco::WebTunnel::SocketDispatcher(pConfig->getInt("webtunnel.threads"s, 4));
		Poco::WebTunnel::SocketFactory::Ptr pSocketFactory;
#if defined(WEBTUNNEL_ENABLE_TLS)
		if (pConfig->getBool("webtunnel.https.enable"s, false))
		{
			pSocketFactory = new TLSSocketFactory(pConfig->getUInt16("webtunnel.httpPort"s), createContext(pConfig, "webtunnel.https"s));
		}
#endif // WEBTUNNEL_ENABLE_TLS
		if (!pSocketFactory)
		{
			pSocketFactory = new Poco::WebTunnel::SocketFactory;
		}

		auto pTunnel = std::make_unique<WebTunnelAgentLib::Tunnel>(deviceId, pTimer, pDispatcher, pConfig, pSocketFactory);
		(void) success();
		return new Holder(std::move(pTunnel));
	}
	catch (Poco::Exception& exc)
	{
		(void) error(exc);
		return NULL;
	}
}


int WebTunnelAgent_API webtunnel_agent_get_status(webtunnel_agent wt)
{
	Holder* pHolder = reinterpret_cast<Holder*>(wt);
	if (pHolder && pHolder->signature == Holder::SIGNATURE)
	{
		return pHolder->pTunnel->status();
	}
	else
	{
		return webtunnel_agent_status_unknown;
	}
}


void WebTunnelAgent_API webtunnel_agent_destroy(webtunnel_agent wt)
{
	Holder* pHolder = reinterpret_cast<Holder*>(wt);
	if (pHolder && pHolder->signature == Holder::SIGNATURE)
	{
		try
		{
			pHolder->signature = 0xDEADBEEF;
			pHolder->pTunnel->stop();
			delete pHolder;
		}
		catch (...)
		{
		}
	}
}


const char WebTunnelAgent_API* webtunnel_agent_get_last_error_text(webtunnel_agent wt)
{
	Holder* pHolder = reinterpret_cast<Holder*>(wt);
	if (pHolder && pHolder->signature == Holder::SIGNATURE)
	{
		lastError = pHolder->pTunnel->lastError();
		return lastError.c_str();
	}
	else if (!lastError.empty())
	{
		return lastError.c_str();
	}
	else return NULL;
}
