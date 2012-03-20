cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

project(pam-able)
set(PAM_ABLE_COMMON_SRC
	config.c
	dbfun.c
	log.c
	pam_able.c
	rule.c
	typefun.c
)


set(PAM_ABLE_TOOLS_SRC
	tools.c
)

set(PAM_ABLE_LIB_SRC
	pam_functions.c
)

set(PAM_ABLE_TEST_SRC
	test_able.c
	test.c
	test_db.c
	test_rule.c
	test_types.c
)

find_package(BerkeleyDB REQUIRED)
find_package(Pam REQUIRED)

if( NOT CMAKE_BUILD_TYPE)
	set( CMAKE_BUILD_TYPE Release)
endif( NOT CMAKE_BUILD_TYPE)

include_directories(${DB_INCLUDE_DIR} ${PAM_INCLUDE_DIRS})
add_definitions(-W -Wall -Wshadow -Winit-self -Wredundant-decls -Wcast-align -Wfloat-equal -Winline -Wunreachable-code -Wmissing-declarations -Wswitch-enum -Wswitch-default -Wmain -Wextra)
set(CMAKE_SHARED_LIBRARY_PREFIX "")

add_executable(pam-able_bin ${PAM_ABLE_COMMON_SRC} ${PAM_ABLE_TOOLS_SRC})
set_target_properties(pam-able_bin PROPERTIES OUTPUT_NAME pam-able)
set_target_properties(pam-able_bin PROPERTIES COMPILE_DEFINITIONS "TOOLS")
target_link_libraries(pam-able_bin ${DB_LIBRARY} )

add_executable(pam-able_test ${PAM_ABLE_COMMON_SRC} ${PAM_ABLE_TEST_SRC})
set_target_properties(pam-able_test PROPERTIES COMPILE_DEFINITIONS "TEST")
target_link_libraries(pam-able_test ${DB_LIBRARY} )

add_library(pam-able_lib SHARED ${PAM_ABLE_COMMON_SRC} ${PAM_ABLE_LIB_SRC}) 
set_target_properties(pam-able_lib PROPERTIES OUTPUT_NAME pam-able)
target_link_libraries(pam-able_lib ${DB_LIBRARY} ${PAM_LIBRARY})

INSTALL(TARGETS pam-able_bin
	RUNTIME DESTINATION bin
)
INSTALL(TARGETS pam-able_lib DESTINATION lib/security)
