# -*- cmake -*-

include(LibFindMacros)
libfind_pkg_check_modules(KyotoCabinet kyotocabinet)

if (NOT KyotoCabinet_INCLUDE_DIR)
  find_path(KyotoCabinet_INCLUDE_DIR
    NAMES
      kcdb.h
    PATHS
      ${KyotoCabinet_PKGCONF_INCLUDE_DIRS}
  )
endif (NOT KyotoCabinet_INCLUDE_DIR)

if (NOT KyotoCabinet_LIBRARY)
  find_library(KyotoCabinet_LIBRARY
    NAMES
      kyotocabinet
    PATHS
      ${KyotoCabinet_PKGCONF_LIBRARY_DIRS}
  )
endif (NOT KyotoCabinet_LIBRARY)
set(KyotoCabinet_PROCESS_INCLUDES KyotoCabinet_INCLUDE_DIR)
set(KyotoCabinet_PROCESS_LIBS KyotoCabinet_LIBRARY)
libfind_process(KyotoCabinet)

