# -*- cmake -*-
if (NOT BerkeleyDB_INCLUDE_DIR)
  find_path(BerkeleyDB_INCLUDE_DIR
    NAMES
      db.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
  )
endif (NOT BerkeleyDB_INCLUDE_DIR)

if (NOT BerkeleyDB_LIBRARY)
  find_library(BerkeleyDB_LIBRARY
    NAMES
      db
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )
endif (NOT BerkeleyDB_LIBRARY)

if(BerkeleyDB_INCLUDE_DIR AND BerkeleyDB_LIBRARY)
  set(BerkeleyDB_FOUND TRUE)
  if(NOT BerkeleyDB_FIND_QUIETLY)
	message(STATUS "Found Berkeley DB: ${BerkeleyDB_LIBRARY}")
  endif(NOT BerkeleyDB_FIND_QUIETLY)
endif(BerkeleyDB_INCLUDE_DIR AND BerkeleyDB_LIBRARY)

if (NOT BerkeleyDB_FOUND AND KyotoCabinet_FIND_REQUIRED)
  message(FATAL_ERROR "Could not find Berkeley DB")
endif (NOT BerkeleyDB_FOUND AND KyotoCabinet_FIND_REQUIRED)
