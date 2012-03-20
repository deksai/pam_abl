# - Try to find PAM
# Once done this will define
#
#  PAM_FOUND - system has PAM
#  PAM_INCLUDE_DIRS - the PAM include directory
#  PAM_LIBRARIES - Link these to use PAM
#  PAM_DEFINITIONS - Compiler switches required for using PAM
#
#  Copyright (c) 2008 Andreas Schneider <mail@cynapses.org>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (PAM_LIBRARIES AND PAM_INCLUDE_DIRS)
  # in cache already
  set(PAM_FOUND TRUE)
else (PAM_LIBRARIES AND PAM_INCLUDE_DIRS)
  find_path(PAM_INCLUDE_DIR
    NAMES
      security/pam_modules.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
  )

  find_library(PAM_LIBRARY
    NAMES
      pam
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )
  find_library(PAM_MISC_LIBRARY
    NAMES
      pam_misc
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )
  find_library(PAMC_LIBRARY
    NAMES
      pamc
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

  if (PAM_LIBRARY)
    set(PAM_FOUND TRUE)
  endif (PAM_LIBRARY)
  if (PAM_MISC_LIBRARY)
    set(PAM_MISC_FOUND TRUE)
  endif (PAM_MISC_LIBRARY)
  if (PAMC_LIBRARY)
    set(PAMC_FOUND TRUE)
  endif (PAMC_LIBRARY)

  set(PAM_INCLUDE_DIRS
    ${PAM_INCLUDE_DIR}
  )

  if (PAM_FOUND)
    set(PAM_LIBRARIES
      ${PAM_LIBRARIES}
      ${PAM_LIBRARY}
    )
  endif (PAM_FOUND)
  if (PAM_MISC_FOUND)
    set(PAM_LIBRARIES
      ${PAM_LIBRARIES}
      ${PAM_MISC_LIBRARY}
    )
  endif (PAM_MISC_FOUND)
  if (PAMC_FOUND)
    set(PAM_LIBRARIES
      ${PAM_LIBRARIES}
      ${PAMC_LIBRARY}
    )
  endif (PAMC_FOUND)

  if (PAM_INCLUDE_DIRS AND PAM_LIBRARIES)
     set(PAM_FOUND TRUE)
  endif (PAM_INCLUDE_DIRS AND PAM_LIBRARIES)

  if (PAM_FOUND)
    if (NOT PAM_FIND_QUIETLY)
      message(STATUS "Found PAM: ${PAM_LIBRARIES}")
    endif (NOT PAM_FIND_QUIETLY)
  else (PAM_FOUND)
    if (PAM_FIND_REQUIRED)
      message(FATAL_ERROR "Could not find PAM")
    endif (PAM_FIND_REQUIRED)
  endif (PAM_FOUND)

  # show the PAM_INCLUDE_DIRS and PAM_LIBRARIES variables only in the advanced view
  mark_as_advanced(PAM_INCLUDE_DIRS PAM_LIBRARIES)

endif (PAM_LIBRARIES AND PAM_INCLUDE_DIRS)

