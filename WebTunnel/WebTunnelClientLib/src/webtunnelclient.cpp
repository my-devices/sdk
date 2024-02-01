//
// webtunnelclient.cpp
//
// Copyright (c) 2020-2024, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "webtunnelclient.h"
#include "Poco/WebTunnel/LocalPortForwarder.h"
#include "Poco/Net/HTTPSessionFactory.h"
#include "Poco/Net/HTTPSessionInstantiator.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPClientSession.h"
#if defined(WEBTUNNEL_ENABLE_TLS)
#include "Poco/Net/HTTPSSessionInstantiator.h"
#include "Poco/Net/Context.h"
#include "Poco/Net/PrivateKeyPassphraseHandler.h"
#include "Poco/Net/AcceptCertificateHandler.h"
#include "Poco/Net/RejectCertificateHandler.h"
#include "Poco/Net/SSLManager.h"
#endif


using namespace std::string_literals;


namespace
{
	Poco::Timespan connectTimeout{30, 0};
	Poco::Timespan remoteTimeout{900, 0};
	Poco::Timespan localTimeout{0};
	static thread_local std::string lastError;

	struct Holder
	{
		enum 
		{
			SIGNATURE = 0x4D414343
		};

		Holder(std::unique_ptr<Poco::WebTunnel::LocalPortForwarder>&& pLPF):
			pLocalPortForwarder(std::move(pLPF))
		{
		}

		Poco::UInt32 signature = SIGNATURE;
		std::unique_ptr<Poco::WebTunnel::LocalPortForwarder> pLocalPortForwarder;
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
				request.set(Poco::Net::HTTPRequest::AUTHORIZATION, Poco::format("bearer %s"s, _jwt));
			}
			return new Poco::Net::WebSocket(*pSession, request, response);
		}

	private:
		std::string _jwt;
		Poco::Timespan _timeout;
	};

	int error(const std::string& error)
	{
		lastError = error;
		return webtunnel_client_result_error;
	}

	int error(const Poco::Exception& exc)
	{
		return error(exc.displayText());
	}

	int success()
	{
		lastError.clear();
		return webtunnel_client_result_ok;
	}
}


int WebTunnelClient_API webtunnel_client_init(void)
{
	try
	{
		Poco::Net::initializeNetwork();

#if defined(WEBTUNNEL_ENABLE_TLS)
		Poco::Net::initializeSSL();
		Poco::Net::HTTPSSessionInstantiator::registerInstantiator();
#endif

		return success();
	}
	catch (Poco::Exception& exc)
	{
		return error(exc);
	}
}


void WebTunnelClient_API webtunnel_client_cleanup(void)
{
	try
	{
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


int WebTunnelClient_API webtunnel_client_configure_tls(bool accept_unknown_cert, bool extended_verification, const char* ciphers, const char* ca_location, int minimum_protocol)
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
		case webtunnel_client_tls_1_0:
			pContext->requireMinimumProtocol(Poco::Net::Context::PROTO_TLSV1);
			break;
		case webtunnel_client_tls_1_1:
			pContext->requireMinimumProtocol(Poco::Net::Context::PROTO_TLSV1_1);
			break;
		case webtunnel_client_tls_1_2:
			pContext->requireMinimumProtocol(Poco::Net::Context::PROTO_TLSV1_2);
			break;
		case webtunnel_client_tls_1_3:
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
	return webtunnel_client_not_supported;
#endif
}


int WebTunnelClient_API webtunnel_client_configure_proxy(bool enable_proxy, const char* proxy_host, unsigned short proxy_port, const char* proxy_username, const char* proxy_password)
{
	try
	{
		Poco::Net::HTTPClientSession::ProxyConfig proxyConfig;
		if (enable_proxy)
		{
			if (!proxy_host) return webtunnel_client_result_error;
			proxyConfig.host = proxy_host;
			proxyConfig.port = proxy_port;
			if (proxy_username) proxyConfig.username = proxy_username;
			if (proxy_password) proxyConfig.password = proxy_password;
		}
		Poco::Net::HTTPClientSession::setGlobalProxyConfig(proxyConfig);
		Poco::Net::HTTPSessionFactory::defaultFactory().setProxy(proxyConfig.host, proxyConfig.port);
		Poco::Net::HTTPSessionFactory::defaultFactory().setProxyCredentials(proxyConfig.username, proxyConfig.password);
		return success();
	}
	catch (Poco::Exception& exc)
	{
		return error(exc);
	}
}


int WebTunnelClient_API webtunnel_client_configure_timeouts(int connect_timeout, int remote_timeout, int local_timeout)
{
	if (connect_timeout >= 0 && remote_timeout >= 0 && local_timeout >= 0)
	{
		connectTimeout = Poco::Timespan(connect_timeout, 0);
		remoteTimeout  = Poco::Timespan(remote_timeout, 0);
		localTimeout   = Poco::Timespan(local_timeout, 0);
		return success();
	}
	else return error("bad parameters"s);
}


webtunnel_client WebTunnelClient_API webtunnel_client_create(const char* local_addr, unsigned short local_port, unsigned short remote_port, const char* remote_uri, const char* username, const char* password)
{
	try
	{
		Poco::URI uri;
		if (remote_uri)
			uri = std::string(remote_uri);
		else
			return NULL;
		std::string user;
		if (username)
			user = username;
		std::string pass;
		if (password)
			pass = password;
		Poco::Net::SocketAddress localAddr(!local_addr ? std::string("127.0.0.1") : std::string(local_addr), local_port);
		std::unique_ptr<Poco::WebTunnel::LocalPortForwarder> pLPF(new Poco::WebTunnel::LocalPortForwarder(localAddr, remote_port, uri, nullptr, new Poco::WebTunnel::DefaultWebSocketFactory(user, pass, connectTimeout)));
		if (remoteTimeout > 0)
			pLPF->setRemoteTimeout(remoteTimeout);
		if (localTimeout > 0)
			pLPF->setLocalTimeout(localTimeout);

		(void) success();
		return new Holder(std::move(pLPF));
	}
	catch (Poco::Exception& exc)
	{
		(void) error(exc);
		return NULL;
	}
}


webtunnel_client WebTunnelClient_API webtunnel_client_create_jwt(const char* local_addr, unsigned short local_port, unsigned short remote_port, const char* remote_uri, const char* jwt)
{
	try
	{
		Poco::URI uri;
		if (remote_uri)
			uri = std::string(remote_uri);
		else
			return NULL;
		std::string token;
		if (jwt)
			token = jwt;
		Poco::Net::SocketAddress localAddr(!local_addr ? std::string("127.0.0.1") : std::string(local_addr), local_port);
		std::unique_ptr<Poco::WebTunnel::LocalPortForwarder> pLPF(new Poco::WebTunnel::LocalPortForwarder(localAddr, remote_port, uri, nullptr, new JWTWebSocketFactory(token, connectTimeout)));
		if (remoteTimeout > 0)
			pLPF->setRemoteTimeout(remoteTimeout);
		if (localTimeout > 0)
			pLPF->setLocalTimeout(localTimeout);

		(void) success();
		return new Holder(std::move(pLPF));
	}
	catch (Poco::Exception& exc)
	{
		error(exc);
		return NULL;
	}
}


void WebTunnelClient_API webtunnel_client_destroy(webtunnel_client wt)
{
	Holder* pHolder = reinterpret_cast<Holder*>(wt);
	if (pHolder && pHolder->signature == Holder::SIGNATURE)
	{
		try
		{
			pHolder->signature = 0xDEADBEEF;
			delete pHolder;
		}
		catch (...)
		{
		}
	}
}


unsigned short WebTunnelClient_API webtunnel_client_get_local_port(webtunnel_client wt)
{
	Holder* pHolder = reinterpret_cast<Holder*>(wt);
	if (pHolder && pHolder->signature == Holder::SIGNATURE)
	{
		return pHolder->pLocalPortForwarder->localPort();
	}
	return 0;
}


const char WebTunnelClient_API* webtunnel_client_get_last_error_text(void)
{
	if (!lastError.empty())
		return lastError.c_str();
	else
		return NULL;
}
