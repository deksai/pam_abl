cmake_minimum_required (VERSION 2.6)
project(pam_abl)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "pam_abl")
SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README")
SET(CPACK_PACKAGE_VERSION_MAJOR "0")
SET(CPACK_PACKAGE_VERSION_MINOR "9")
SET(CPACK_PACKAGE_VERSION_PATCH "0")
SET(CPACK_GENERATOR "TGZ")
set(CPACK_SOURCE_GENERATOR TGZ)
set(CPACK_SOURCE_IGNORE_FILES
    "htdocs/"
    "\\\\.git/"
)

INCLUDE(CPack)


find_package(BerkeleyDB)
find_package(KyotoCabinet)
find_package(Pam REQUIRED)

set(PAM_ABL_COMMON_SRC
	config.c
	log.c
	pam_abl.c
	rule.c
	typefun.c
)


set(PAM_ABL_TOOLS_SRC
	tools.c
)

set(PAM_ABL_LIB_SRC
	pam_functions.c
)

set(ABL_BDB_LIB_SRC
	bdb.c
)

set(ABL_KCDB_LIB_SRC
	kc.c
)

set(PAM_ABL_TEST_SRC
	test_abl.c
	test.c
	test_db.c
	test_rule.c
	test_types.c
	test_config.c
	test_pam_functions.c
	pam_functions.c
)

# Building without Berkeley Db or Kyoto Cabinet
# If you want to build a version with one of the supported db's disabled
# you can use one of the following commandline arguments when calling cmake
# -DUSE_BDB=FALSE
# -DUSE_KC=FALSE
option (USE_BDB "Create a loadable module that uses Berkeley Db" ON)
option (USE_KC "Create a loadable module that uses Kyoto Cabinet" ON)
if(NOT USE_BDB AND NOT USE_KC)
    message(FATAL_ERROR "No database selected.  At least one of either Berkeley Db or Kyoto Cabinet must be enabled")
endif(NOT USE_BDB AND NOT USE_KC)

if(USE_BDB)
	find_package(BerkeleyDB)
endif(USE_BDB)

if(USE_KC)
	find_package(KyotoCabinet)
endif(USE_KC)

# Building without the tests
# If you don't want to build the test executable you can add the following argument
# -DBUILD_TESTS=FALSE
option (BUILD_TESTS "Create the test executable" ON)
if(BUILD_TESTS)
	find_package(CUnit)
endif(BUILD_TESTS)

find_package(Pam REQUIRED)

#we at least need BerkeleyDB or KyotoCabinet
if(NOT BerkeleyDB_FOUND AND NOT KyotoCabinet_FOUND)
	message(FATAL_ERROR "Unable to find a version of Berkeley DB or Kyoto Cabinet")
endif(NOT BerkeleyDB_FOUND AND NOT KyotoCabinet_FOUND)

#Building pam_abl using a different version of Berkeley db.
#If you have only one version of Berkeley db installed, it should normally work without any changes.
#If you have multiple versions installed, you can specify the version to use by providing the params
#on the commandline when calling cmake:
# -DBerkeleyDB_LIBRARY=<db version, "db-4.7">
# -DBerkeleyDB_INCLUDE_DIR=<db include dir>
# -DBerkeleyDB_LINK_DIR=<db link dir>
#
#for example: cmake -DBerkeleyDB_INCLUDE_DIR=/db-5.3.15/include/ -DBerkeleyDB_LINK_DIR=/db-5.3.15/lib/ -DBerkeleyDB_LIBRARY=db-5.3
#or it can be as easy as: cmake -DBerkeleyDB_LIBRARY=db-4.7 ../
if(DEFINED BerkeleyDB_LINK_DIR)
	link_directories(${BerkeleyDB_LINK_DIR})
endif(DEFINED BerkeleyDB_LINK_DIR)

#Building pam_abl using a different version of Kyoto Cabinet.
#If you have only one version of Kyoto Cabinet installed, it should normally work without any changes.
#If you have multiple versions installed, you can specify the version to use by providing the params
#on the commandline when calling cmake:
# -DKyotoCabinet_LIBRARY=<db version, "kyotocabinet">
# -DKyotoCabinet_INCLUDE_DIR=<include dir>
# -DKyotoCabinet_LINK_DIR=<db link dir>
if(DEFINED KyotoCabinet_LINK_DIR)
	link_directories(${KyotoCabinet_LINK_DIR})
endif(DEFINED KyotoCabinet_LINK_DIR)

#if you want a debug build, please add "-DCMAKE_BUILD_TYPE=Debug" as param to the cmake call
if( NOT CMAKE_BUILD_TYPE)
	set( CMAKE_BUILD_TYPE Release)
endif( NOT CMAKE_BUILD_TYPE)

include_directories(${PAM_INCLUDE_DIRS})
add_definitions(-W -Wall -Wshadow -Winit-self -Wredundant-decls -Wcast-align -Wfloat-equal -Winline -Wunreachable-code -Wmissing-declarations -Wswitch-enum -Wswitch-default -Wformat -Wmain -Wextra -Wunused -Wmissing-noreturn)
set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_EXE_LINKER_FLAGS "-rdynamic")

if(BerkeleyDB_FOUND)
	add_definitions(-DBDB_PRESENT)
	include_directories(${BerkeleyDB_INCLUDE_DIR})
	add_library(pam_abl_bdb SHARED ${PAM_ABL_COMMON_SRC} ${ABL_BDB_LIB_SRC})
	target_link_libraries(pam_abl_bdb ${BerkeleyDB_LIBRARY} ${PAM_LIBRARY})
	INSTALL(TARGETS pam_abl_bdb DESTINATION lib/security)
endif(BerkeleyDB_FOUND)

if(KyotoCabinet_FOUND)
	add_definitions(-DKC_PRESENT)
	include_directories(${KyotoCabinet_INCLUDE_DIR})
	add_library(pam_abl_kc SHARED ${PAM_ABL_COMMON_SRC} ${ABL_KCDB_LIB_SRC})
	target_link_libraries(pam_abl_kc ${KyotoCabinet_LIBRARY} ${PAM_LIBRARY})
	INSTALL(TARGETS pam_abl_kc DESTINATION lib/security)
endif(KyotoCabinet_FOUND)

add_executable(pam_abl_bin ${PAM_ABL_COMMON_SRC} ${PAM_ABL_TOOLS_SRC})
set_target_properties(pam_abl_bin PROPERTIES OUTPUT_NAME pam_abl)
set_target_properties(pam_abl_bin PROPERTIES COMPILE_DEFINITIONS "TOOLS")
target_link_libraries(pam_abl_bin ${CMAKE_DL_LIBS})

if(CUnit_FOUND)
	include_directories(${CUnit_INCLUDE_DIR})
	add_executable(pam_abl_test ${PAM_ABL_COMMON_SRC} ${PAM_ABL_TEST_SRC})
	set_target_properties(pam_abl_test PROPERTIES COMPILE_DEFINITIONS "TEST")
	target_link_libraries(pam_abl_test ${CMAKE_DL_LIBS} ${CUnit_LIBRARY} ${PAM_LIBRARY})
endif(CUnit_FOUND)

add_library(pam_abl_lib SHARED ${PAM_ABL_COMMON_SRC} ${PAM_ABL_LIB_SRC})
set_target_properties(pam_abl_lib PROPERTIES OUTPUT_NAME pam_abl)
target_link_libraries(pam_abl_lib ${CMAKE_DL_LIBS} ${PAM_LIBRARY})

INSTALL(TARGETS pam_abl_bin
	RUNTIME DESTINATION bin
)
INSTALL(TARGETS pam_abl_lib DESTINATION lib/security)
