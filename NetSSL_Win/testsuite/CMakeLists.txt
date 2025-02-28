# Sources
file(GLOB SRCS_G "src/*.cpp")
POCO_SOURCES_AUTO(TEST_SRCS ${SRCS_G})

# Headers
file(GLOB_RECURSE HDRS_G "src/*.h")
POCO_HEADERS_AUTO(TEST_SRCS ${HDRS_G})

POCO_SOURCES_AUTO_PLAT(TEST_SRCS OFF
	src/WinDriver.cpp
)

POCO_SOURCES_AUTO_PLAT(TEST_SRCS WINCE
	src/WinCEDriver.cpp
)

add_executable(NetSSLWin-testrunner ${TEST_SRCS})
add_test(
	NAME NetSSLWin
	WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
	COMMAND NetSSLWin-testrunner -ignore ${CMAKE_SOURCE_DIR}/cppignore.lnx -all
)
set_tests_properties(NetSSLWin PROPERTIES ENVIRONMENT POCO_BASE=${CMAKE_SOURCE_DIR})
target_link_libraries(NetSSLWin-testrunner PUBLIC Poco::NetSSLWin Poco::Util Poco::XML CppUnit)

# The test is run in the build directory. So the test data is copied there too
add_custom_command(
	TARGET NetSSLWin-testrunner POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/any.pfx ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/TestSuite.xml ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/NetSSLWin-testrunner.xml
)
