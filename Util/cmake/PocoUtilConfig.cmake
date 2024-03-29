include(CMakeFindDependencyMacro)
find_dependency(PocoFoundation)
if (ENABLE_XML)
  find_dependency(PocoXML)
endif()
if (ENABLE_JSON)
  find_dependency(PocoJSON)
endif()
include("${CMAKE_CURRENT_LIST_DIR}/PocoUtilTargets.cmake")
