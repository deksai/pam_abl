# -*- cmake -*-

include(LibFindMacros)
libfind_pkg_check_modules(BerkeleyDB db)

if (NOT DB_INCLUDE_DIR)
  find_path(BerkeleyDB_INCLUDE_DIR
    NAMES
      db.h
    PATHS
        ${BerkeleyDB_PKGCONF_INCLUDE_DIRS}
  )
endif ()

if (NOT DB_LIBRARY)
  find_library(BerkeleyDB_LIBRARY
    NAMES
      db
    PATHS
        ${BerkeleyDB_PKGCONF_LIBRARY_DIRS}
  )
endif ()

set(BerkeleyDB_PROCESS_INCLUDES BerkeleyDB_INCLUDE_DIR)
set(BerkeleyDB_PROCESS_LIBS BerkeleyDB_LIBRARY)
libfind_process(BerkeleyDB)

