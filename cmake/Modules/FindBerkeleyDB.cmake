# -*- cmake -*-

set(DB_FIND_QUIETLY ON)
set(DB_FIND_REQUIRED ON)

if (NOT DB_INCLUDE_DIR)
  find_path(DB_INCLUDE_DIR
    NAMES
      db.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
  )
endif (NOT DB_INCLUDE_DIR)

if (NOT DB_LIBRARY)
  find_library(DB_LIBRARY
    NAMES
      db
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )
endif (NOT DB_LIBRARY)

if (NOT DB_LIBRARY)
  message(FATAL_ERROR "Could not find Berkeley DB")
endif (NOT DB_LIBRARY)
