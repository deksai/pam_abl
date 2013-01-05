cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

project(pam_abl)
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
    #test_db.c
    test_rule.c
    test_types.c
)

find_package(BerkeleyDB)
find_package(Pam REQUIRED)

#Building pam_abl using a different version of Berkeley db.
#If you have only one version of Berkeley db installed, it should normally work without any changes.
#If you have multiple versions installed, you can specify the version to use by providing the params
#on the commandline when calling cmake:
# -DDB_LIBRARY=<db version, "db-4.7">
# -DDB_INCLUDE_DIR=<db include dir>
# -DDB_LINK_DIR=<db link dir>
#
#for example: cmake -DDB_INCLUDE_DIR=/db-5.3.15/include/ -DDB_LINK_DIR=/db-5.3.15/lib/ -DDB_LIBRARY=db-5.3
#or it can be as easy as: cmake -DDB_LIBRARY=db-4.7 ../
if (DEFINED DB_LINK_DIR)
	link_directories(${DB_LINK_DIR})
endif(DEFINED DB_LINK_DIR)

#if you want a debug build, please add "-DCMAKE_BUILD_TYPE=Debug" as param to the cmake call
if( NOT CMAKE_BUILD_TYPE)
	set( CMAKE_BUILD_TYPE Release)
endif( NOT CMAKE_BUILD_TYPE)

include_directories(${DB_INCLUDE_DIR} ${PAM_INCLUDE_DIRS})
add_definitions(-W -Wall -Wshadow -Winit-self -Wredundant-decls -Wcast-align -Wfloat-equal -Winline -Wunreachable-code -Wmissing-declarations -Wswitch-enum -Wswitch-default -Wformat -Wmain -Wextra -Wunused -Wmissing-noreturn)
set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_EXE_LINKER_FLAGS "-rdynamic")

add_executable(pam_abl_bin ${PAM_ABL_COMMON_SRC} ${PAM_ABL_TOOLS_SRC})
set_target_properties(pam_abl_bin PROPERTIES OUTPUT_NAME pam_abl)
set_target_properties(pam_abl_bin PROPERTIES COMPILE_DEFINITIONS "TOOLS")
target_link_libraries(pam_abl_bin ${DB_LIBRARY} dl)

add_executable(pam_abl_test ${PAM_ABL_COMMON_SRC} ${PAM_ABL_TEST_SRC})
set_target_properties(pam_abl_test PROPERTIES COMPILE_DEFINITIONS "TEST")
target_link_libraries(pam_abl_test ${DB_LIBRARY} dl )

add_library(pam_abl_bdb SHARED ${ABL_BDB_LIB_SRC})
target_link_libraries(pam_abl_bdb ${DB_LIBRARY} ${PAM_LIBRARY})

add_library(pam_abl_kc SHARED ${ABL_KCDB_LIB_SRC})
target_link_libraries(pam_abl_kc -lkyotocabinet -lz -lstdc++ -lrt -lpthread -lm -lc ${PAM_LIBRARY})

add_library(pam_abl_lib SHARED ${PAM_ABL_COMMON_SRC} ${PAM_ABL_LIB_SRC})
set_target_properties(pam_abl_lib PROPERTIES OUTPUT_NAME pam_abl)
target_link_libraries(pam_abl_lib ${DB_LIBRARY} ${PAM_LIBRARY})

INSTALL(TARGETS pam_abl_bin
	RUNTIME DESTINATION bin
)
INSTALL(TARGETS pam_abl_lib DESTINATION lib/security)
INSTALL(TARGETS pam_abl_bdb DESTINATION lib/security)
