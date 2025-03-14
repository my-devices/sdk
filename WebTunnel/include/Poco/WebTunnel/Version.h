//
// Version.h
//
// Library: WebTunnel
// Package: WebTunnel
// Module:  Version
//
// Version information for macchina.io REMOTE SDK and clients.
//
// Copyright (c) 2025, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef WebTunnel_Version_INCLUDED
#define WebTunnel_Version_INCLUDED


#include "Poco/Format.h"
#include <string>


//
// Version Information
//
// Following Semantic Versioning 2.0
// (https://semver.org/spec/v2.0.0.html)
//
// Version format is 0xAABBCCDD, where
//    - AA is the major version number,
//    - BB is the minor version number,
//    - CC is the patch	version number, and
//    - DD is the pre-release designation/number.
//      The pre-release designation hex digits have a special meaning:
//      00: final/stable releases
//      Dx: development releases
//      Ax: alpha releases
//      Bx: beta releases
//
#define WEBTUNNEL_VERSION 0x02020000U


namespace Poco {
namespace WebTunnel {


inline std::string formatVersion(Poco::UInt32 version)
{
	using namespace std::string_literals;

	return Poco::format("%u.%u.%u"s,
		static_cast<unsigned>(version >> 24),
		static_cast<unsigned>((version >> 16) & 0xFF),
		static_cast<unsigned>((version >> 8) & 0xFF));
}


} } // namespace Poco::WebTunnel


#endif // WebTunnel_Version_INCLUDED
