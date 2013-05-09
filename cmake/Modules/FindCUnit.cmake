
if (NOT CUnit_INCLUDE_DIR)
	find_path(CUnit_INCLUDE_DIR CUnit/Basic.h)
endif (NOT CUnit_INCLUDE_DIR)

if (NOT CUnit_LIBRARY)
  find_library(CUnit_LIBRARY NAMES cunit)
endif (NOT CUnit_LIBRARY)

if(CUnit_INCLUDE_DIR AND CUnit_LIBRARY)
  set(CUnit_FOUND TRUE)
endif(CUnit_INCLUDE_DIR AND CUnit_LIBRARY)

if(CUnit_FOUND)
  if(NOT CUnit_FIND_QUIETLY)
	message(STATUS "Found CUnit: ${CUnit_LIBRARY}")
  endif(NOT CUnit_FIND_QUIETLY)
else(CUnit_FOUND)
  if(CUnit_FIND_REQUIRED)
	  message(FATAL_ERROR "Could not find the CUnit library.")
  endif(CUnit_FIND_REQUIRED)
endif(CUnit_FOUND)
