//
// DynamicTestSuite.h
//
// $Id: //poco/1.7/Foundation/testsuite/src/DynamicTestSuite.h#1 $
//
// Definition of the DynamicTestSuite class.
//
// Copyright (c) 2004-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef DynamicTestSuite_INCLUDED
#define DynamicTestSuite_INCLUDED


#include "CppUnit/TestSuite.h"


class DynamicTestSuite
{
public:
	static CppUnit::Test* suite();
};


#endif // DynamicTestSuite_INCLUDED
