/*
 *   pam_abl - a PAM module and program for automatic blacklisting of hosts and users
 *
 *   Copyright (C) 2005-2012
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "pam_abl.h"
#include "log.h"
#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#define TEST_DIR "/tmp/pam-abl_test-dir"

static const char *exePath = NULL;
static const char *dbModule = NULL;

static void emptyConfig() {
    if (args)
        config_free();
    config_create();
    args->db_module = dbModule;
}

static int setupTestEnvironment(abl_db **_abldb) {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);
    char *userClearBuffer = malloc(100);
    memset(userClearBuffer, 0, 100);
    char *hostClearBuffer = malloc(100);
    memset(hostClearBuffer, 0, 100);
    char *userBlockedBuffer = malloc(100);
    memset(userBlockedBuffer, 0, 100);
    char *hostBlockedBuffer = malloc(100);
    memset(hostBlockedBuffer, 0, 100);
    //config_create();
    args->db_home = TEST_DIR;
    //args->db_module = db_module;

    void *dblib = NULL;
    abl_db_open_ptr db_open = NULL;

    dblib = dlopen(args->db_module, RTLD_LAZY);
    if (!dblib) {
        CU_FAIL("Failed to load the database module.");
        return 1;
    }
    dlerror();
    db_open = dlsym(dblib, "abl_db_open");
    if (!db_open) {
        CU_FAIL("Could not load the \"abl_db_open\" function.");
        return 1;
    }
    *_abldb = db_open(args->db_home);
    abl_db *abldb = *_abldb;
    if (!abldb) {
        CU_FAIL("Could not open the database.");
        return 1;
    }

    int i = 0;
    for (; i < 20; ++i) {
        AuthState *userClearState = NULL;
        AuthState *userBlockedState = NULL;
        if (createEmptyState(CLEAR, &userClearState) || createEmptyState(BLOCKED, &userBlockedState)) {
            CU_FAIL("Could not create an empty state.");
            return 1;
        }
        AuthState *hostClearState = NULL;
        AuthState *hostBlockedState = NULL;
        if (createEmptyState(CLEAR, &hostClearState) || createEmptyState(BLOCKED, &hostBlockedState)) {
            CU_FAIL("Could not create an empty state.");
            return 1;
        }
        snprintf(userClearBuffer, 100, "cu_%d", i);
        snprintf(hostClearBuffer, 100, "ch_%d", i);
        snprintf(userBlockedBuffer, 100, "bu_%d", i);
        snprintf(hostBlockedBuffer, 100, "bh_%d", i);
        time_t tm = time(NULL);
        int x = 50;
        for (; x >= 0; --x) {
            time_t logTime = tm - x*10;
            CU_ASSERT_FALSE(addAttempt(userClearState, USER_BLOCKED, logTime, "host", "Service", 0, 0));
            CU_ASSERT_FALSE(addAttempt(userBlockedState, USER_BLOCKED, logTime, "host", "Service", 0, 0));
            CU_ASSERT_FALSE(addAttempt(hostClearState, USER_BLOCKED, logTime, "user", "Service", 0, 0));
            CU_ASSERT_FALSE(addAttempt(hostBlockedState, USER_BLOCKED, logTime, "user", "Service", 0, 0));
        }
        CU_ASSERT_FALSE(abldb->put(abldb, userClearBuffer, userClearState, USER));
        CU_ASSERT_FALSE(abldb->put(abldb, userBlockedBuffer, userBlockedState, USER));
        CU_ASSERT_FALSE(abldb->put(abldb, hostClearBuffer, hostClearState, HOST));
        CU_ASSERT_FALSE(abldb->put(abldb, hostBlockedBuffer, hostBlockedState, HOST));
        destroyAuthState(userClearState);
        destroyAuthState(userBlockedState);
        destroyAuthState(hostClearState);
        destroyAuthState(hostBlockedState);
    }
    free(userClearBuffer);
    free(hostClearBuffer);
    free(userBlockedBuffer);
    free(hostBlockedBuffer);
    return 0;
}

static void checkAttemptWithSubject(abl_db *abldb, const char *user, const char *userRule, BlockState newUserState,
                         const char *host, const char *hostRule, BlockState newHostState,
                         const char *service, BlockState expectedBlockState, BlockReason bReason, ModuleAction subjects) {
    args->host_rule = hostRule;
    args->user_rule = userRule;

    abl_info info;
    memset(&info, 0, sizeof(abl_info));
    info.user = (char*)user;
    info.host = (char*)host;
    info.service = (char*)service;
    BlockState newState = check_attempt(abldb, &info, subjects);
    CU_ASSERT_EQUAL(newState, expectedBlockState);
    CU_ASSERT_EQUAL(info.blockReason, bReason);
    AuthState *userState = NULL;
    int err = abldb->start_transaction(abldb);
    if (err) {
        CU_FAIL("starting transaction failed");
        return;
    }
    CU_ASSERT_FALSE(abldb->get(abldb, user, &userState, USER));
    if (userState) {
        BlockState retrievedState = getState(userState);
        CU_ASSERT_EQUAL(retrievedState, newUserState);
        destroyAuthState(userState);
    } else {
        CU_FAIL("Unable to retrieve the subject from the database.");
    }

    AuthState *hostState = NULL;
    CU_ASSERT_FALSE(abldb->get(abldb, host, &hostState, HOST));
    if (hostState) {
        BlockState retrievedState = getState(hostState);
        CU_ASSERT_EQUAL(retrievedState, newHostState);
        destroyAuthState(hostState);
    } else {
        CU_FAIL("Unable to retrieve the host from the database.");
    }
    abldb->abort_transaction(abldb);
}

static void checkAttempt(abl_db *abldb, const char *user, const char *userRule, BlockState newUserState,
                         const char *host, const char *hostRule, BlockState newHostState,
                         const char *service, BlockState expectedBlockState, BlockReason bReason) {
    checkAttemptWithSubject(abldb, user, userRule, newUserState, host, hostRule, newHostState, service,
                            expectedBlockState, bReason, ACTION_CHECK_HOST | ACTION_CHECK_USER);
}

static void testCheckAttempt() {
    removeDir(TEST_DIR);

    abl_db *abldb = NULL;
    if (setupTestEnvironment(&abldb) || !abldb) {
        CU_FAIL("Could not create our test environment.");
        return;
    }

    //we have 20 user/hosts with a CLEAR/BLOCKED state, all with 50 attempts
    const char *clearRule = "*:30/10s";
    const char *blockRule = "*:1/1h";
    const char *service = "Service";

    //user clear, host clear, no blocking
    checkAttempt(abldb, "cu_0", clearRule, CLEAR, "ch_0", clearRule, CLEAR, service, CLEAR, AUTH_FAILED);
    //user clear, host clear, user blocked
    checkAttempt(abldb, "cu_1", blockRule, BLOCKED, "ch_1", clearRule, CLEAR, service, BLOCKED, USER_BLOCKED);
    //user clear, host clear, host blocked
    checkAttempt(abldb, "cu_2", clearRule, CLEAR, "ch_2", blockRule, BLOCKED, service, BLOCKED, HOST_BLOCKED);
    //user clear, host clear, both blocked
    checkAttempt(abldb, "cu_3", blockRule, BLOCKED, "ch_3", blockRule, BLOCKED, service, BLOCKED, BOTH_BLOCKED);

    //user blocked, host clear, no blocking
    checkAttempt(abldb, "bu_4", clearRule, CLEAR, "ch_4", clearRule, CLEAR, service, CLEAR, AUTH_FAILED);
    //user blocked, host clear, user blocked
    checkAttempt(abldb, "bu_5", blockRule, BLOCKED, "ch_5", clearRule, CLEAR, service, BLOCKED, USER_BLOCKED);
    //user blocked, host clear, host blocked
    checkAttempt(abldb, "bu_6", clearRule, CLEAR, "ch_6", blockRule, BLOCKED, service, BLOCKED, HOST_BLOCKED);
    //user blocked, host clear, both blocked
    checkAttempt(abldb, "bu_7", blockRule, BLOCKED, "ch_7", blockRule, BLOCKED, service, BLOCKED, BOTH_BLOCKED);

    //user clear, host blocked, no blocking
    checkAttempt(abldb, "cu_8", clearRule, CLEAR, "bh_8", clearRule, CLEAR, service, CLEAR, AUTH_FAILED);
    //user clear, host blocked, user blocked
    checkAttempt(abldb, "cu_9", blockRule, BLOCKED, "bh_9", clearRule, CLEAR, service, BLOCKED, USER_BLOCKED);
    //user clear, host blocked, host blocked
    checkAttempt(abldb, "cu_10", clearRule, CLEAR, "bh_10", blockRule, BLOCKED, service, BLOCKED, HOST_BLOCKED);
    //user clear, host blocked, both blocked
    checkAttempt(abldb, "cu_11", blockRule, BLOCKED, "bh_11", blockRule, BLOCKED, service, BLOCKED, BOTH_BLOCKED);

    //user blocked, host blocked, no blocking
    checkAttempt(abldb, "bu_12", clearRule, CLEAR, "bh_12", clearRule, CLEAR, service, CLEAR, AUTH_FAILED);
    //user blocked, host blocked, user blocked
    checkAttempt(abldb, "bu_13", blockRule, BLOCKED, "bh_13", clearRule, CLEAR, service, BLOCKED, USER_BLOCKED);
    //user blocked, host blocked, host blocked
    checkAttempt(abldb, "bu_14", clearRule, CLEAR, "bh_14", blockRule, BLOCKED, service, BLOCKED, HOST_BLOCKED);
    //user blocked, host blocked, both blocked
    checkAttempt(abldb, "bu_15", blockRule, BLOCKED, "bh_15", blockRule, BLOCKED, service, BLOCKED, BOTH_BLOCKED);

    abldb->close(abldb);
    removeDir(TEST_DIR);
}

static void testCheckAttemptOnlyHost() {
    removeDir(TEST_DIR);

    abl_db *abldb = NULL;
    if (setupTestEnvironment(&abldb) || !abldb) {
        CU_FAIL("Could not create our test environment.");
        return;
    }

    //we have 20 user/hosts with a CLEAR/BLOCKED state, all with 50 attempts
    const char *clearRule = "*:30/10s";
    const char *blockRule = "*:1/1h";
    const char *service = "Service";
    ModuleAction subject = ACTION_CHECK_HOST;

    //user clear, host clear, no blocking
    checkAttemptWithSubject(abldb, "cu_0", clearRule, CLEAR, "ch_0", clearRule, CLEAR, service, CLEAR, AUTH_FAILED, subject);
    //user clear, host clear, no blocking
    checkAttemptWithSubject(abldb, "cu_1", blockRule, CLEAR, "ch_1", clearRule, CLEAR, service, CLEAR, AUTH_FAILED, subject);
    //user clear, host clear, host blocked
    checkAttemptWithSubject(abldb, "cu_2", clearRule, CLEAR, "ch_2", blockRule, BLOCKED, service, BLOCKED, HOST_BLOCKED, subject);
    //user clear, host clear, host blocked
    checkAttemptWithSubject(abldb, "cu_3", blockRule, CLEAR, "ch_3", blockRule, BLOCKED, service, BLOCKED, HOST_BLOCKED, subject);

    //user blocked, host clear, no blocking
    checkAttemptWithSubject(abldb, "bu_4", clearRule, BLOCKED, "ch_4", clearRule, CLEAR, service, CLEAR, AUTH_FAILED, subject);
    //user blocked, host clear, no blocking
    checkAttemptWithSubject(abldb, "bu_5", blockRule, BLOCKED, "ch_5", clearRule, CLEAR, service, CLEAR, AUTH_FAILED, subject);
    //user blocked, host clear, host blocked
    checkAttemptWithSubject(abldb, "bu_6", clearRule, BLOCKED, "ch_6", blockRule, BLOCKED, service, BLOCKED, HOST_BLOCKED, subject);
    //user blocked, host clear, host blocked
    checkAttemptWithSubject(abldb, "bu_7", blockRule, BLOCKED, "ch_7", blockRule, BLOCKED, service, BLOCKED, HOST_BLOCKED, subject);

    //user clear, host blocked, no blocking
    checkAttemptWithSubject(abldb, "cu_8", clearRule, CLEAR, "bh_8", clearRule, CLEAR, service, CLEAR, AUTH_FAILED, subject);
    //user clear, host blocked, no blocking
    checkAttemptWithSubject(abldb, "cu_9", blockRule, CLEAR, "bh_9", clearRule, CLEAR, service, CLEAR, AUTH_FAILED, subject);
    //user clear, host blocked, host blocked
    checkAttemptWithSubject(abldb, "cu_10", clearRule, CLEAR, "bh_10", blockRule, BLOCKED, service, BLOCKED, HOST_BLOCKED, subject);
    //user clear, host blocked, host blocked
    checkAttemptWithSubject(abldb, "cu_11", blockRule, CLEAR, "bh_11", blockRule, BLOCKED, service, BLOCKED, HOST_BLOCKED, subject);

    //user blocked, host blocked, no blocking
    checkAttemptWithSubject(abldb, "bu_12", clearRule, BLOCKED, "bh_12", clearRule, CLEAR, service, CLEAR, AUTH_FAILED, subject);
    //user blocked, host blocked, no blocking
    checkAttemptWithSubject(abldb, "bu_13", blockRule, BLOCKED, "bh_13", clearRule, CLEAR, service, CLEAR, AUTH_FAILED, subject);
    //user blocked, host blocked, host blocked
    checkAttemptWithSubject(abldb, "bu_14", clearRule, BLOCKED, "bh_14", blockRule, BLOCKED, service, BLOCKED, HOST_BLOCKED, subject);
    //user blocked, host blocked, host blocked
    checkAttemptWithSubject(abldb, "bu_15", blockRule, BLOCKED, "bh_15", blockRule, BLOCKED, service, BLOCKED, HOST_BLOCKED, subject);

    abldb->close(abldb);
    removeDir(TEST_DIR);
}

static void testCheckAttemptOnlyUser() {
    removeDir(TEST_DIR);

    abl_db *abldb = NULL;
    if (setupTestEnvironment(&abldb) || !abldb) {
        CU_FAIL("Could not create our test environment.");
        return;
    }

    //we have 20 user/hosts with a CLEAR/BLOCKED state, all with 50 attempts
    const char *clearRule = "*:30/10s";
    const char *blockRule = "*:1/1h";
    const char *service = "Service";
    ModuleAction subject = ACTION_CHECK_USER;

    //user clear, host clear, no blocking
    checkAttemptWithSubject(abldb, "cu_0", clearRule, CLEAR, "ch_0", clearRule, CLEAR, service, CLEAR, AUTH_FAILED, subject);
    //user clear, host clear, user blocked
    checkAttemptWithSubject(abldb, "cu_1", blockRule, BLOCKED, "ch_1", clearRule, CLEAR, service, BLOCKED, USER_BLOCKED, subject);
    //user clear, host clear, no blocking
    checkAttemptWithSubject(abldb, "cu_2", clearRule, CLEAR, "ch_2", blockRule, CLEAR, service, CLEAR, AUTH_FAILED, subject);
    //user clear, host clear, user blocked
    checkAttemptWithSubject(abldb, "cu_3", blockRule, BLOCKED, "ch_3", blockRule, CLEAR, service, BLOCKED, USER_BLOCKED, subject);

    //user blocked, host clear, no blocking
    checkAttemptWithSubject(abldb, "bu_4", clearRule, CLEAR, "ch_4", clearRule, CLEAR, service, CLEAR, AUTH_FAILED, subject);
    //user blocked, host clear, user blocked
    checkAttemptWithSubject(abldb, "bu_5", blockRule, BLOCKED, "ch_5", clearRule, CLEAR, service, BLOCKED, USER_BLOCKED, subject);
    //user blocked, host clear, no blocking
    checkAttemptWithSubject(abldb, "bu_6", clearRule, CLEAR, "ch_6", blockRule, CLEAR, service, CLEAR, AUTH_FAILED, subject);
    //user blocked, host clear, user blocked
    checkAttemptWithSubject(abldb, "bu_7", blockRule, BLOCKED, "ch_7", blockRule, CLEAR, service, BLOCKED, USER_BLOCKED, subject);

    //user clear, host blocked, no blocking
    checkAttemptWithSubject(abldb, "cu_8", clearRule, CLEAR, "bh_8", clearRule, BLOCKED, service, CLEAR, AUTH_FAILED, subject);
    //user clear, host blocked, user blocked
    checkAttemptWithSubject(abldb, "cu_9", blockRule, BLOCKED, "bh_9", clearRule, BLOCKED, service, BLOCKED, USER_BLOCKED, subject);
    //user clear, host blocked, no blocking
    checkAttemptWithSubject(abldb, "cu_10", clearRule, CLEAR, "bh_10", blockRule, BLOCKED, service, CLEAR, AUTH_FAILED, subject);
    //user clear, host blocked, user blocked
    checkAttemptWithSubject(abldb, "cu_11", blockRule, BLOCKED, "bh_11", blockRule, BLOCKED, service, BLOCKED, USER_BLOCKED, subject);

    //user blocked, host blocked, no blocking
    checkAttemptWithSubject(abldb, "bu_12", clearRule, CLEAR, "bh_12", clearRule, BLOCKED, service, CLEAR, AUTH_FAILED, subject);
    //user blocked, host blocked, user blocked
    checkAttemptWithSubject(abldb, "bu_13", blockRule, BLOCKED, "bh_13", clearRule, BLOCKED, service, BLOCKED, USER_BLOCKED, subject);
    //user blocked, host blocked, no blocking
    checkAttemptWithSubject(abldb, "bu_14", clearRule, CLEAR, "bh_14", blockRule, BLOCKED, service, CLEAR, AUTH_FAILED, subject);
    //user blocked, host blocked, user blocked
    checkAttemptWithSubject(abldb, "bu_15", blockRule, BLOCKED, "bh_15", blockRule, BLOCKED, service, BLOCKED, USER_BLOCKED, subject);

    abldb->close(abldb);
    removeDir(TEST_DIR);
}

static void testRecordAttemptWithAction(ModuleAction subject) {
    removeDir(TEST_DIR);
    char userBuffer[100];
    char hostBuffer[100];
    char serviceBuffer[100];
    time_t currentTime = time(NULL);

    //let's clean the config
    emptyConfig();
    //make sure we don't purge
    args->host_purge = 60*60*24; //1 day
    args->user_purge = 60*60*24; //1 day
    //make sure we're not blocked
    args->user_rule = "*:1000/1h";
    args->host_rule = "*:1000/1h";

    abl_info info;
    memset(&info, 0, sizeof(abl_info));
    info.blockReason = USER_BLOCKED;
    info.user = &userBuffer[0];
    info.host = &hostBuffer[0];
    info.service = &serviceBuffer[0];

    abl_db *abldb = NULL;
    if (setupTestEnvironment(&abldb) || !abldb) {
        CU_FAIL("Could not create our test environment.");
        return;
    }

    int x = 0;
    int y = 0;
    for (x = 0; x < 5; ++x) {
        for (y = 0; y < 10; ++y) {
            snprintf(&userBuffer[0], 100, "user_%d", y);
            snprintf(&hostBuffer[0], 100, "host_%d", y);
            snprintf(&serviceBuffer[0], 100, "service_%d", y);
            CU_ASSERT_FALSE(record_attempt(abldb, &info, subject));
        }
    }

    int err = abldb->start_transaction(abldb);
    if (err) {
        CU_FAIL("Starting transaction failed.");
        return;
    }

    for (y = 0; y < 10; ++y) {
        snprintf(&userBuffer[0], 100, "user_%d", y);
        snprintf(&hostBuffer[0], 100, "host_%d", y);
        snprintf(&serviceBuffer[0], 100, "service_%d", y);
        AuthState *userState = NULL;
        AuthState *hostState = NULL;
        CU_ASSERT_FALSE(abldb->get(abldb, &userBuffer[0], &userState, USER));
        CU_ASSERT_FALSE(abldb->get(abldb, &hostBuffer[0], &hostState, HOST));
        if (subject & ACTION_LOG_USER) {
            if (userState) {
                CU_ASSERT_EQUAL(getState(userState), CLEAR);
                if (getNofAttempts(userState) != 5) {
                    CU_FAIL("We expected to find five attempts.");
                } else {
                    AuthAttempt attempt;
                    while (nextAttempt(userState, &attempt) == 0) {
                        CU_ASSERT_STRING_EQUAL(&hostBuffer[0], attempt.m_userOrHost);
                        CU_ASSERT_STRING_EQUAL(&serviceBuffer[0], attempt.m_service);
                        CU_ASSERT_FALSE(attempt.m_time < currentTime);
                        CU_ASSERT_EQUAL(attempt.m_reason, USER_BLOCKED);
                    }
                }
            } else {
                CU_FAIL("Could not retrieve the user state.");
            }
        } else {
            CU_ASSERT_PTR_NULL(userState);
        }
        if (subject & ACTION_LOG_HOST) {
            if (hostState) {
                if (getNofAttempts(hostState) != 5) {
                    CU_FAIL("We expected to find five attempts.");
                } else {
                    AuthAttempt attempt;
                    while (nextAttempt(hostState, &attempt) == 0) {
                        CU_ASSERT_STRING_EQUAL(&userBuffer[0], attempt.m_userOrHost);
                        CU_ASSERT_STRING_EQUAL(&serviceBuffer[0], attempt.m_service);
                        CU_ASSERT_FALSE(attempt.m_time < currentTime);
                        CU_ASSERT_EQUAL(attempt.m_reason, USER_BLOCKED);
                    }
                }
            } else {
                CU_FAIL("Could not retrieve the host state.");
            }
        } else {
            CU_ASSERT_PTR_NULL(hostState);
        }
        if (userState)
            destroyAuthState(userState);
        if (hostState)
            destroyAuthState(hostState);
    }

    abldb->commit_transaction(abldb);

    abldb->close(abldb);
    removeDir(TEST_DIR);
    emptyConfig();
}

static void testRecordAttempt() {
    testRecordAttemptWithAction(ACTION_LOG_USER | ACTION_LOG_HOST);
}

static void testRecordAttemptOnlyHost() {
    testRecordAttemptWithAction(ACTION_LOG_HOST);
}

static void testRecordAttemptOnlyUser() {
    testRecordAttemptWithAction(ACTION_LOG_USER);
}

static void testRecordAttemptWithActionUpdatedStateBlocked(ModuleAction subject) {
    removeDir(TEST_DIR);
    char userBuffer[100];
    char hostBuffer[100];
    char serviceBuffer[100];

    //let's clean the config
    emptyConfig();
    //make sure we don't purge
    args->host_purge = 60*60*24; //1 day
    args->user_purge = 60*60*24; //1 day
    //make sure we can get blocked
    args->user_rule = "*:3/1d";
    args->host_rule = "*:5/1d";

    abl_info info;
    memset(&info, 0, sizeof(abl_info));
    info.blockReason = AUTH_FAILED;
    info.user = &userBuffer[0];
    info.host = &hostBuffer[0];
    info.service = &serviceBuffer[0];

    abl_db *abldb = NULL;
    if (setupTestEnvironment(&abldb) || !abldb) {
        CU_FAIL("Could not create our test environment.");
        return;
    }

    int x = 1;
    int y = 1;
    for (x = 1; x < 10; ++x) {
        for (y = 1; y < 10; ++y) {
            snprintf(&userBuffer[0], 100, "user_%d", y);
            snprintf(&hostBuffer[0], 100, "host_%d", y);
            snprintf(&serviceBuffer[0], 100, "service_%d", y);
            CU_ASSERT_FALSE(record_attempt(abldb, &info, subject));

            //now check the state
            AuthState *userState = NULL;
            AuthState *hostState = NULL;
            int err = abldb->start_transaction(abldb);
            if (err) {
                CU_FAIL("Starting transaction failed.");
                return;
            }
            CU_ASSERT_FALSE(abldb->get(abldb, &userBuffer[0], &userState, USER));
            CU_ASSERT_FALSE(abldb->get(abldb, &hostBuffer[0], &hostState, HOST));
            if (subject & ACTION_LOG_USER) {
                if (userState) {
                    //at the third attempt, the state will change
                    BlockState expected = (x >= 3 ? BLOCKED : CLEAR);
                    if (getState(userState) != expected) {
                        x++;
                        --x;
                    }
                    CU_ASSERT(getState(userState) == expected);
                    destroyAuthState(userState);
                } else {
                    CU_FAIL("Unable to retreive the user state.");
                }
            } else {
                CU_ASSERT_PTR_NULL(userState);
            }
            if (subject & ACTION_LOG_HOST) {
                if (hostState) {
                    CU_ASSERT(getState(hostState) == (x >= 5 ? BLOCKED : CLEAR));
                    destroyAuthState(hostState);
                } else {
                    CU_FAIL("Unable to retreive the host state.");
                }
            } else {
                CU_ASSERT_PTR_NULL(hostState);
            }
            abldb->commit_transaction(abldb);
        }
    }

    abldb->close(abldb);
    removeDir(TEST_DIR);
    emptyConfig();
}

static void testRecordAttemptWithActionUpdatedStateClear(ModuleAction subject) {
    removeDir(TEST_DIR);
    char *user = "user";
    char *host = "host";
    char *service = "service";

    //let's clean the config
    emptyConfig();
    //make sure we don't purge
    args->host_purge = 60*60*24; //1 day
    args->user_purge = 60*60*24; //1 day
    //make sure we can get blocked
    args->user_rule = "*:3/1h";
    args->host_rule = "*:5/1h";

    abl_info info;
    memset(&info, 0, sizeof(abl_info));
    info.blockReason = AUTH_FAILED;
    info.user = user;
    info.host = host;
    info.service = service;

    abl_db *abldb = NULL;
    if (setupTestEnvironment(&abldb) || !abldb) {
        CU_FAIL("Could not create our test environment.");
        return;
    }

    AuthState *userState = NULL;
    AuthState *hostState = NULL;
    CU_ASSERT_FALSE(createEmptyState(BLOCKED, &userState));
    CU_ASSERT_FALSE(createEmptyState(BLOCKED, &hostState));

    time_t now = time(NULL);
    int x = 0;
    for (x = 0; x < 10; ++x) {
        //add some failed attempts in the past, evaluating the rule now should result in a CLEAR
        CU_ASSERT_FALSE(addAttempt(userState, AUTH_FAILED, now - (2*3600), user, service, 0, 0));
        CU_ASSERT_FALSE(addAttempt(userState, AUTH_FAILED, now - (2*3600), user, service, 0, 0));
    }
    //save the states
    CU_ASSERT_FALSE(abldb->start_transaction(abldb));
    CU_ASSERT_FALSE(abldb->put(abldb, user, userState, USER));
    CU_ASSERT_FALSE(abldb->put(abldb, host, hostState, HOST));
    CU_ASSERT_FALSE(abldb->commit_transaction(abldb));

    destroyAuthState(userState);
    destroyAuthState(hostState);
    userState = NULL;
    hostState = NULL;

    //now do a record_attempt
    CU_ASSERT_FALSE(record_attempt(abldb, &info, subject));

    //now check the state
    CU_ASSERT_FALSE(abldb->start_transaction(abldb));
    CU_ASSERT_FALSE(abldb->get(abldb, user, &userState, USER));
    CU_ASSERT_FALSE(abldb->get(abldb, host, &hostState, HOST));
    if (userState) {
        BlockState expected = (subject & ACTION_LOG_USER ? CLEAR : BLOCKED);
        CU_ASSERT_EQUAL(getState(userState),expected);
    } else {
        CU_FAIL("Unable to get the saved user.");
    }
    if (hostState) {
        BlockState expected = (subject & ACTION_LOG_HOST ? CLEAR : BLOCKED);
        CU_ASSERT_EQUAL(getState(hostState),expected);
    } else {
        CU_FAIL("Unable to get the saved host.");
    }
    destroyAuthState(userState);
    destroyAuthState(hostState);

    abldb->commit_transaction(abldb);

    abldb->close(abldb);
    removeDir(TEST_DIR);
    emptyConfig();
}

static void testRecordAttemptUpdatedState() {
    testRecordAttemptWithActionUpdatedStateBlocked(ACTION_LOG_USER | ACTION_LOG_HOST);
    testRecordAttemptWithActionUpdatedStateBlocked(ACTION_LOG_USER);
    testRecordAttemptWithActionUpdatedStateBlocked(ACTION_LOG_HOST);

    testRecordAttemptWithActionUpdatedStateClear(ACTION_LOG_USER | ACTION_LOG_HOST);
    testRecordAttemptWithActionUpdatedStateClear(ACTION_LOG_USER);
    testRecordAttemptWithActionUpdatedStateClear(ACTION_LOG_HOST);
}

static void testRecordAttemptWhitelistHost() {
    removeDir(TEST_DIR);
    char userBuffer[100];
    char serviceBuffer[100];
    char hostBuffer[100];

    //config_create();
    args->host_purge = 60*60*24; //1 day
    args->user_purge = 60*60*24; //1 day
    args->host_whitelist = "1.1.1.1;2.2.2.2/32;127.0.0.1";
    args->user_whitelist = "blaat1;username;blaat3";

    abl_info info;

    abl_db *abldb = NULL;
    if (setupTestEnvironment(&abldb) || !abldb) {
        CU_FAIL("Could not create our test environment.");
        return;
    }

    int x = 0;
    int y = 0;
    for (x = 0; x < 5; ++x) {
        for (y = 0; y < 10; ++y) {
            memset(&info, 0, sizeof(abl_info));
            info.blockReason = USER_BLOCKED;
            info.user = &userBuffer[0];
            info.service = &serviceBuffer[0];

            //
            // Add some host checking attempts
            //
            snprintf(&userBuffer[0], 100, "user_%d", y);
            snprintf(&serviceBuffer[0], 100, "service_%d", y);
            info.host = "127.0.0.1";
            CU_ASSERT_FALSE(record_attempt(abldb, &info, ACTION_LOG_HOST | ACTION_LOG_USER));

            snprintf(&userBuffer[0], 100, "user__%d", y);
            snprintf(&serviceBuffer[0], 100, "service__%d", y);
            info.host = "";
            CU_ASSERT_FALSE(record_attempt(abldb, &info, ACTION_LOG_HOST | ACTION_LOG_USER));

            //
            // Add some user checking attempts
            //
            info.host = &hostBuffer[0];
            snprintf(&hostBuffer[0], 100, "host_%d", y);
            snprintf(&serviceBuffer[0], 100, "service_%d", y);

            info.user = "username";
            CU_ASSERT_FALSE(record_attempt(abldb, &info, ACTION_LOG_HOST | ACTION_LOG_USER));

            info.user = "";
            CU_ASSERT_FALSE(record_attempt(abldb, &info, ACTION_LOG_HOST | ACTION_LOG_USER));
        }
    }

    int err = abldb->start_transaction(abldb);
    if (err) {
        log_error("starting transaction to %s.", __func__);
        return;
    }

    for (y = 0; y < 10; ++y) {
        snprintf(&userBuffer[0], 100, "user_%d", y);
        snprintf(&serviceBuffer[0], 100, "service_%d", y);
        AuthState *userState = NULL;
        CU_ASSERT_FALSE(abldb->get(abldb, &userBuffer[0], &userState, USER));
        if (userState) {
            CU_ASSERT_EQUAL(getNofAttempts(userState), 5);
            destroyAuthState(userState);
        } else {
            CU_FAIL("Could not retrieve the user state.");
        }
    }

    AuthState *hostState = NULL;
    CU_ASSERT_FALSE(abldb->get(abldb, "127.0.0.1", &hostState, HOST));
    CU_ASSERT_PTR_NULL(hostState);

    hostState = NULL;
    CU_ASSERT_FALSE(abldb->get(abldb, "", &hostState, HOST));
    CU_ASSERT_PTR_NULL(hostState);


    AuthState *userState = NULL;
    CU_ASSERT_FALSE(abldb->get(abldb, "", &userState, USER));
    CU_ASSERT_PTR_NULL(userState);

    userState = NULL;
    CU_ASSERT_FALSE(abldb->get(abldb, "username", &userState, USER));
    CU_ASSERT_PTR_NULL(userState);

    abldb->commit_transaction(abldb);
    abldb->close(abldb);
    removeDir(TEST_DIR);
}

static void testRecordAttemptPurge() {
    removeDir(TEST_DIR);

    //config_create();
    args->host_purge = 25;
    args->user_purge = 15;

    abl_info info;
    memset(&info, 0, sizeof(abl_info));
    info.blockReason = USER_BLOCKED;
    info.user = "cu_0";
    info.host = "ch_0";
    info.service = "Cool_Service";

    abl_db *abldb = NULL;
    if (setupTestEnvironment(&abldb) || !abldb) {
        CU_FAIL("Could not create our test environment.");
        return;
    }

    CU_ASSERT_FALSE(record_attempt(abldb, &info, ACTION_LOG_HOST | ACTION_LOG_USER));

    //we know in the db every 10 seconds an attempt was made, lets's see if it is purged enough
    //time_t logTime = tm - x*10;
    int err = abldb->start_transaction(abldb);
    if (err) {
        log_error("starting transaction to %s.", __func__);
        return;
    }
    AuthState *userState = NULL;
    AuthState *hostState = NULL;
    CU_ASSERT_FALSE(abldb->get(abldb, info.user, &userState, USER));
    CU_ASSERT_FALSE(abldb->get(abldb, info.host, &hostState, HOST));
    if (userState && hostState) {
        //for the user we purged every attempt older then 15 seconds, so we expect to see: now, now - 10 and our just logged time
        CU_ASSERT_EQUAL(getNofAttempts(userState), 3);
        CU_ASSERT_EQUAL(getNofAttempts(hostState), 4);
    }
    CU_ASSERT_FALSE(abldb->commit_transaction(abldb));
    abldb->close(abldb);
    if (userState)
        destroyAuthState(userState);
    if (hostState)
        destroyAuthState(hostState);
}

static u_int32_t getIp(int x, int y, int z, int j) {
    u_int32_t ip = x;
    ip = (ip << 8) + y;
    ip = (ip << 8) + z;
    ip = (ip << 8) + j;
    return ip;
}

static int validIpComponents[]   = {  0,  1,   2, 100,  253,   254,  255 };
static int invalidIpComponents[] = { -2, -1, 256, 257, 1024, 01245,  5000};

static void testParseIpValid() {
    char buffer[100];
    int bufSize = sizeof(validIpComponents)/sizeof(int);
    int x = 0;
    for (; x < bufSize; ++x) {
        int y = 0;
        for (; y < bufSize; ++y) {
            int z = 0;
            for (; z < bufSize; ++z) {
                int j = 0;
                for (; j < bufSize; ++j) {
                    snprintf(&buffer[0], 100, "%d.%d.%d.%d", validIpComponents[x], validIpComponents[y], validIpComponents[z], validIpComponents[j]);
                    u_int32_t expectedIp = getIp(validIpComponents[x], validIpComponents[y], validIpComponents[z], validIpComponents[j]);
                    size_t strLen = strlen(&buffer[0]);
                    //let's try to mess things up by not letting the string end with \0
                    //but instead add an extra '0', if the parsing does not use the length given
                    //it will probably parse the extra 0
                    buffer[strLen] = '0';
                    buffer[strLen+1] = '\0';
                    int netmask = 0;
                    u_int32_t parsedIp;
                    buffer[strLen] = '\0';
                    if (parseIP(&buffer[0], strLen, &netmask, &parsedIp) != 0) {
                        CU_FAIL("IP parsing failed.");
                    } else {
                        CU_ASSERT_FALSE(parsedIp != expectedIp || netmask != -1);
                    }
                }
            }
        }
    }
}

static char *invalidIps[] = {
    "....",
    "blaat",
    "0t.0.0.0",
    "",
    "1.1.11",
    "1.1..1"
};

static void testParseIpInvalid() {
    char buffer[100];
    int bufSize = sizeof(validIpComponents)/sizeof(int);
    int netmask = 0;
    u_int32_t parsedIp;
    int x = 0;
    for (; x < bufSize; ++x) {
        int y = 0;
        for (; y < bufSize; ++y) {
            int z = 0;
            for (; z < bufSize; ++z) {
                int j = 0;
                for (; j < bufSize; ++j) {
                    snprintf(&buffer[0], 100, "%d.%d.%d.%d", invalidIpComponents[x], validIpComponents[y], validIpComponents[z], validIpComponents[j]);
                    size_t strLen = strlen(&buffer[0]);
                    CU_ASSERT_NOT_EQUAL(parseIP(&buffer[0], strLen, &netmask, &parsedIp), 0);

                    snprintf(&buffer[0], 100, "%d.%d.%d.%d", validIpComponents[x], invalidIpComponents[y], validIpComponents[z], validIpComponents[j]);
                    strLen = strlen(&buffer[0]);
                    CU_ASSERT_NOT_EQUAL(parseIP(&buffer[0], strLen, &netmask, &parsedIp), 0);

                    snprintf(&buffer[0], 100, "%d.%d.%d.%d", validIpComponents[x], validIpComponents[y], invalidIpComponents[z], validIpComponents[j]);
                    strLen = strlen(&buffer[0]);
                    CU_ASSERT_NOT_EQUAL(parseIP(&buffer[0], strLen, &netmask, &parsedIp), 0);

                    snprintf(&buffer[0], 100, "%d.%d.%d.%d", validIpComponents[x], validIpComponents[y], validIpComponents[z], invalidIpComponents[j]);
                    strLen = strlen(&buffer[0]);
                    CU_ASSERT_NOT_EQUAL(parseIP(&buffer[0], strLen, &netmask, &parsedIp), 0);
                }
            }
        }
    }

    x=0;
    for (; x< (int)(sizeof(invalidIps)/sizeof(char*)); ++x) {
        CU_ASSERT_NOT_EQUAL(parseIP(invalidIps[x], strlen(invalidIps[x]), &netmask, &parsedIp), 0);
    }
}

static void testParseIpValidWithNetmask() {
    char buffer[100];
    int x = 0;
    int netmask = 0;
    u_int32_t parsedIp;
    for (; x <= 32; ++x) {
        snprintf(&buffer[0], 100, "1.1.1.1/%d", x);
        size_t strLen = strlen(&buffer[0]);
        buffer[strLen] = '0';
        buffer[strLen+1] = '\0';
        if (parseIP(&buffer[0], strLen, &netmask, &parsedIp) != 0) {
            CU_FAIL("IP parsing failed.");
        } else if (netmask != x) {
            CU_FAIL("IP parsing failed, an invalid netmwask was returned.");
        }
    }
}

static char *invalidIpsWithNetmask[] = {
    "1.1.1.1/33",
    "1.1.1.1/-1",
    "1.1.1.1:2",
    "1.1.1.1-5",
    "1.1.1.1.1",
    "1.1.1.1/1000",
    "1.1.1.1/000000033",
    "1.1.1/2",
    "1.1.1.1/pol",
    "1.1.1.1/",
};


static void testParseIpInvalidWithNetmask() {
    int netmask = 0;
    u_int32_t parsedIp;
    int x=0;
    for (; x< (int)(sizeof(invalidIpsWithNetmask)/sizeof(char*)); ++x) {
        CU_ASSERT_NOT_EQUAL(parseIP(invalidIpsWithNetmask[x], strlen(invalidIpsWithNetmask[x]), &netmask, &parsedIp), 0);
    }
}

static void testInSameSubnet() {
    u_int32_t ip = getIp(192,168,1,1);
    int x = 0;
    for (; x < 256; ++x) {
        u_int32_t host = getIp(192,168,1,x);
        CU_ASSERT_NOT_EQUAL(inSameSubnet(host, ip, 24), 0);
        if (x != 192) {
            host = getIp(x,168,1,1);
            CU_ASSERT_FALSE(inSameSubnet(host, ip, 24));
        }
        if (x != 168) {
            host = getIp(192,x,1,1);
            CU_ASSERT_FALSE(inSameSubnet(host, ip, 24));
        }
        if (x != 1) {
            host = getIp(192,168,x,1);
            CU_ASSERT_FALSE(inSameSubnet(host, ip, 24));
        }
    }

    ip = getIp(128,128,128,128);
    for (x=0; x < 256; ++x) {
        u_int32_t host = getIp(128,128,128,x);
        if (x == 128) {
            CU_ASSERT_NOT_EQUAL(inSameSubnet(host, ip, 32), 0);
        } else {
            CU_ASSERT_FALSE(inSameSubnet(host, ip, 32));
        }
    }

    CU_ASSERT_NOT_EQUAL(inSameSubnet(getIp(1,1,1,1), ip, 0), 0);
    CU_ASSERT_NOT_EQUAL(inSameSubnet(getIp(255,255,255,255), ip, 0), 0);
}

static char *whiteListed[] = {
    "10.10.10.10",
    "10.10.10.0",
    "10.10.10.255",
    "1.1.1.1",
    "2.2.2.2",
    "blaat",
    "192.168.1.1",
    "192.168.1.0",
    "192.168.1.255"
};

static char *notWhiteListed[] = {
    "10.10.09.255",
    "10.10.11.0",
    "1.1.1.0",
    "1.1.1.2",
    "2.2.2.1",
    "2.2.2.3",
    "lorem",
    "192.168.0.255",
    "192.168.2.0",
};

static void testWhitelistMatch() {
    const char *hostWhitelist = "10.10.10.10/24;1.1.1.1;2.2.2.2/32;blaat;192.168.1.1/24";
    int x=0;
    for (; x< (int)(sizeof(whiteListed)/sizeof(char*)); ++x) {
        CU_ASSERT_NOT_EQUAL(whitelistMatch(whiteListed[x], hostWhitelist, 1), 0);
    }

    for (x=0; x< (int)(sizeof(notWhiteListed)/sizeof(char*)); ++x) {
        CU_ASSERT_EQUAL(whitelistMatch(notWhiteListed[x], hostWhitelist, 1), 0);
    }
}

static void testSubstitute(const char *str, const char *user, const char *host, const char *service, const char *result) {
    abl_info info;
    info.user = (char*)user;
    info.host = (char*)host;
    info.service = (char*)service;

    int resultSize = prepare_string(str, &info, NULL);
    if (resultSize != (int)(strlen(result)+1)) {
        CU_FAIL("Substitute length was incorrect.");
        return;
    }
    char *res = malloc(resultSize * sizeof(char));
    int i = 0;
    for (; i < resultSize; ++i)
        res[i] = 'a';
    resultSize = prepare_string(str, &info, res);
    if (resultSize != (int)(strlen(result)+1)) {
        CU_FAIL("Actual substitute length was incorrect.");
    } else {
        CU_ASSERT_STRING_EQUAL(res, result);
    }
    free(res);
}

static void testSubstituteNormal() {
    testSubstitute("command %u", "user", "host", "service", "command user");
    testSubstitute("command %h", "user", "host", "service", "command host");
    testSubstitute("command %s", "user", "host", "service", "command service");
    testSubstitute("command %u %h %s", "user", "host", "service", "command user host service");
    testSubstitute("command %u%h%s", "user", "host", "service", "command userhostservice");
    testSubstitute("command %u %h %u %s %h %s", "user", "host", "service", "command user host user service host service");
}

static void testNoSubstitute() {
    testSubstitute("command ", "user", "host", "service", "command ");
    testSubstitute("", "user", "host", "service", "");
    testSubstitute("", "user", "host", "service", "");
    testSubstitute("", "", "", "", "");
}

static void testEmptySubstitute() {
    testSubstitute("command %u %h %s", "", "host", "service", "command  host service");
    testSubstitute("command %u %h %s", "user", "", "service", "command user  service");
    testSubstitute("command %u %h %s", "user", "host", "", "command user host ");
    testSubstitute("command %u %h %s", "", "", "", "command   ");
}

static void testSubstituteWithPercent() {
    testSubstitute("%%command %%%u %%%h %%%s %%", "user", "host", "service", "%command %user %host %service %");
    testSubstitute("%%command %%%u %%%h %%%s %%", "%user%", "%host%", "%service%", "%command %%user% %%host% %%service% %");
}

static int ablTestInit() {
    emptyConfig();
    return 0;
}

static int ablTestCleanup() {
    config_free();
    dbModule = NULL;
    return 0;
}

void addAblTests(const char *module) {
    if (!module || !*module) {
        printf("Failed to add the Abl tests (no database module).\n");
        return;
    }
    dbModule = module;
    CU_pSuite pSuite = NULL;
    pSuite = CU_add_suite("Abl tests", ablTestInit, ablTestCleanup);
    if (NULL == pSuite)
        return;
    CU_add_test(pSuite, "testCheckAttempt", testCheckAttempt);
    CU_add_test(pSuite, "testCheckAttemptOnlyHost", testCheckAttemptOnlyHost);
    CU_add_test(pSuite, "testCheckAttemptOnlyUser", testCheckAttemptOnlyUser);
    CU_add_test(pSuite, "testRecordAttempt", testRecordAttempt);
    CU_add_test(pSuite, "testRecordAttemptOnlyHost", testRecordAttemptOnlyHost);
    CU_add_test(pSuite, "testRecordAttemptOnlyUser", testRecordAttemptOnlyUser);
    CU_add_test(pSuite, "testRecordAttemptUpdatedState", testRecordAttemptUpdatedState);
    CU_add_test(pSuite, "testRecordAttemptWhitelistHost", testRecordAttemptWhitelistHost);
    CU_add_test(pSuite, "testRecordAttemptPurge", testRecordAttemptPurge);
    CU_add_test(pSuite, "testParseIpValid", testParseIpValid);
    CU_add_test(pSuite, "testParseIpInvalid", testParseIpInvalid);
    CU_add_test(pSuite, "testParseIpValidWithNetmask", testParseIpValidWithNetmask);
    CU_add_test(pSuite, "testParseIpInvalidWithNetmask", testParseIpInvalidWithNetmask);
    CU_add_test(pSuite, "testInSameSubnet", testInSameSubnet);
    CU_add_test(pSuite, "testWhitelistMatch", testWhitelistMatch);
    CU_add_test(pSuite, "testSubstituteNormal", testSubstituteNormal);
    CU_add_test(pSuite, "testNoSubstitute", testNoSubstitute);
    CU_add_test(pSuite, "testEmptySubstitute", testEmptySubstitute);
    CU_add_test(pSuite, "testSubstituteWithPercent", testSubstituteWithPercent);
}

static void testCommand(const char *cmd, int exitCode) {
    char** cmdArr = malloc(4*sizeof(char*));
    char buff[10];
    snprintf(buff, 10, "%d", exitCode);
    cmdArr[0] = (char*)cmd;
    cmdArr[1] = "-e";
    cmdArr[2] = &buff[0];
    cmdArr[3] = NULL;
    int result = ablExec(&cmdArr[0]);
    CU_ASSERT_EQUAL(result, exitCode);
    free(cmdArr);
}

static void testNormalCommand() {
    int i = 0;
    for (; i < 10; ++i ) {
        testCommand(exePath, i);
    }
}

static void testNonExistingCommand() {
    testCommand("command_that_doenst_exist", 255);
}

static void testInvalidInputCommand() {
    testCommand(0, -1);
    testCommand("", -1);
}

void addExternalCommandTests(const char *cmd) {
    exePath = cmd;
    CU_pSuite pSuite = NULL;
    pSuite = CU_add_suite("External command tests", NULL, NULL);
    if (NULL == pSuite)
        return;
    CU_add_test(pSuite, "testNormalCommand", testNormalCommand);
    CU_add_test(pSuite, "testNonExistingCommand", testNonExistingCommand);
    CU_add_test(pSuite, "testInvalidInputCommand", testInvalidInputCommand);
}

static const char **s_expected_arg = NULL;
static int s_execFun_called = 0;
static int s_execFun_exitCode = 0;

static int execFun(char *const arg[]) {
    s_execFun_called = 1;
    int i = 0;
    while (s_expected_arg[i]) {
        if (arg[i]) {
            if (strcmp(s_expected_arg[i], arg[i]) != 0) {
                CU_FAIL("execFun: argument mismatch.");
                return s_execFun_exitCode;
            }
        } else {
            CU_FAIL("execFun: missing argument.");
            return s_execFun_exitCode;
        }
        ++i;
    }
    CU_ASSERT_EQUAL(arg[i], NULL);
    return s_execFun_exitCode;
}

//int _runCommand(const char *origCommand, const abl_info *info, log_context *logContext, int (execFun)(char *const arg[]))
static void testRunCommandHelper(const char *origCommand, int isOk, const abl_info *info, const char *arg1, const char *arg2, const char *arg3, const char *arg4) {
    const char *expected[5];
    expected[0] = arg1;
    expected[1] = arg2;
    expected[2] = arg3;
    expected[3] = arg4;
    expected[4] = NULL;
    s_expected_arg = (const char **)(&expected[0]);
    int i = 0;
    for (i = 0; i < 2; ++i) {
        s_execFun_called = 0;
        s_execFun_exitCode = i;
        int returnCode = _runCommand(origCommand, info, execFun);
        CU_ASSERT_EQUAL(s_execFun_called, isOk);
        CU_ASSERT_EQUAL(returnCode, s_execFun_exitCode);
    }
}

static void commandTest() {
    abl_info info;
    info.host = "127.0.0.1";
    info.user = "mooh";
    info.service = "sharing";
    testRunCommandHelper("[command]", 1, &info, "command", NULL, NULL, NULL);
    testRunCommandHelper("[command %u]", 1, &info, "command mooh", NULL, NULL, NULL);
    testRunCommandHelper("[command | > %u %h %s]", 1, &info, "command | > mooh 127.0.0.1 sharing", NULL, NULL, NULL);
    testRunCommandHelper("[command] [arg1] [%u] [%h]", 1, &info, "command", "arg1", "mooh", "127.0.0.1");
    info.user = "[lol]";
    testRunCommandHelper("[command %u] [%u]", 1, &info, "command [lol]", "[lol]", NULL, NULL);
}

void addRunCommandTests() {
    CU_pSuite pSuite = NULL;
    pSuite = CU_add_suite("Run command tests", NULL, NULL);
    if (NULL == pSuite)
        return;
    CU_add_test(pSuite, "commandTest", commandTest);
}
