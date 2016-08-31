//
// OAuth10CredentialsTest.h
//
// $Id: //poco/1.7/Net/testsuite/src/OAuth10CredentialsTest.h#1 $
//
// Definition of the OAuth10CredentialsTest class.
//
// Copyright (c) 2014, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef OAuth10CredentialsTest_INCLUDED
#define OAuth10CredentialsTest_INCLUDED


#include "Poco/Net/Net.h"
#include "CppUnit/TestCase.h"


class OAuth10CredentialsTest: public CppUnit::TestCase
{
public:
	OAuth10CredentialsTest(const std::string& name);
	~OAuth10CredentialsTest();

	void testCallback();
	void testParams();
	void testRealm();
	void testPlaintext();
	void testVerify();
	void testVerifyPlaintext();

	void setUp();
	void tearDown();

	static CppUnit::Test* suite();

private:
};


#endif // OAuth10CredentialsTest_INCLUDED
