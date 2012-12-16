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

#include "test.h"
#include "pam_abl.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define TEST_DIR "/tmp/pam-abl_test-dir"

static void testPamAblDbEnv() {
    //first start off wit a non existing dir, we expect it to fail
    abl_args args;
    memset(&args, 0, sizeof(abl_args));
    args.db_home = "/tmp/blaat/non-existing";
    args.host_db = "/tmpt/blaat/non-existing/hosts.db";
    args.user_db = "/tmpt/blaat/non-existing/users.db";

    printf("   This message should be followed by 2 errors (No such file or directory ...).\n");
    PamAblDbEnv *dummy = openPamAblDbEnvironment(&args, NULL);
    if (dummy) {
        printf("   The db could be opened on a non existing environment.\n");
    }

    //next start it using an existing dir, it should succeed
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);
    args.db_home = TEST_DIR;
    args.host_db = TEST_DIR"/hosts.db";
    args.user_db = TEST_DIR"/users.db";
    dummy = openPamAblDbEnvironment(&args, NULL);
    if (dummy) {
        destroyPamAblDbEnvironment(dummy);
    } else {
        printf("   The db could be opened on a non existing environment.\n");
    }
    removeDir(TEST_DIR);
}

static int setupTestEnvironment(PamAblDbEnv **dbEnv) {
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
    abl_args args;
    memset(&args, 0, sizeof(abl_args));
    args.db_home = TEST_DIR;
    args.host_db = TEST_DIR"/hosts.db";
    args.user_db = TEST_DIR"/users.db";
    *dbEnv = openPamAblDbEnvironment(&args, NULL);
    if (!*dbEnv) {
        printf("   The db environment could not be opened.\n");
        return 1;
    }

    int i = 0;
    for (; i < 20; ++i) {
        AuthState *userClearState = NULL;
        AuthState *userBlockedState = NULL;
        if (createEmptyState(CLEAR, &userClearState) || createEmptyState(BLOCKED, &userBlockedState)) {
            printf("   Could not create an empty state.\n");
            return 1;
        }
        AuthState *hostClearState = NULL;
        AuthState *hostBlockedState = NULL;
        if (createEmptyState(CLEAR, &hostClearState) || createEmptyState(BLOCKED, &hostBlockedState)) {
            printf("   Could not create an empty state.\n");
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
            if (addAttempt(userClearState, USER_BLOCKED, logTime, "host", "Service", 0, 0))
                printf("   Could not add an attempt for user %s.\n", userClearBuffer);
            if (addAttempt(userBlockedState, USER_BLOCKED, logTime, "host", "Service", 0, 0))
                printf("   Could not add an attempt for user %s.\n", userBlockedBuffer);
            if (addAttempt(hostClearState, USER_BLOCKED, logTime, "user", "Service", 0, 0))
                printf("   Could not add an attempt for host %s.\n", hostClearBuffer);
            if (addAttempt(hostBlockedState, USER_BLOCKED, logTime, "user", "Service", 0, 0))
                printf("   Could not add an attempt for host %s.\n", hostBlockedBuffer);
        }
        if (saveInfo((*dbEnv)->m_userDb, userClearBuffer, userClearState))
            printf("   Could not save state for user %s.\n", userClearBuffer);
        if (saveInfo((*dbEnv)->m_userDb, userBlockedBuffer, userBlockedState))
            printf("   Could not save state for user %s.\n", userBlockedBuffer);
        if (saveInfo((*dbEnv)->m_hostDb, hostClearBuffer, hostClearState))
            printf("   Could not save state for host %s.\n", hostClearBuffer);
        if (saveInfo((*dbEnv)->m_hostDb, hostBlockedBuffer, hostBlockedState))
            printf("   Could not save state for host %s.\n", hostBlockedBuffer);
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

static void checkAttempt(const char *user, const char *userRule, BlockState newUserState,
                         const char *host, const char *hostRule, BlockState newHostState,
                         const char *service, BlockState expectedBlockState, BlockReason bReason, const PamAblDbEnv *dbEnv) {
    abl_args args;
    memset(&args, 0, sizeof(abl_args));
    args.host_rule = hostRule;
    args.user_rule = userRule;

    abl_info info;
    memset(&info, 0, sizeof(abl_info));
    info.user = user;
    info.host = host;
    info.service = service;
    BlockState newState = check_attempt(dbEnv, &args, &info, NULL);
    if (newState != expectedBlockState) {
        printf("   Expected attempt to have as result %d, yet %d was returned.\n", (int)expectedBlockState, (int)newState);
    }
    if (info.blockReason != bReason) {
        printf("   Expected the reason to be %d, yet %d was returned.\n", (int)bReason, (int)info.blockReason);
    }
    startTransaction(dbEnv->m_environment);
    AuthState *userState = NULL;
    if (getUserOrHostInfo(dbEnv->m_userDb, user, &userState))
        printf("   Could not retrieve the current state of the user.\n");
    if (userState) {
        BlockState retrievedState = getState(userState);
        if (retrievedState != newUserState)
            printf("   Expected attempt to have as user blockstate %d, yet %d was returned.\n", (int)newUserState, (int)retrievedState);
        destroyAuthState(userState);
    } else {
        printf("   Does the host not exist in the db?.\n");
    }

    AuthState *hostState = NULL;
    if (getUserOrHostInfo(dbEnv->m_hostDb, host, &hostState))
        printf("   Could not retrieve the current state of the host.\n");
    if (hostState) {
        BlockState retrievedState = getState(hostState);
        if (retrievedState != newHostState)
            printf("   Expected attempt to have as host blockstate %d, yet %d was returned.\n", (int)newHostState, (int)retrievedState);
        destroyAuthState(hostState);
    } else {
        printf("   Does the host not exist in the db?.\n");
    }
    abortTransaction(dbEnv->m_environment);
}

static void testCheckAttempt() {
    removeDir(TEST_DIR);

    PamAblDbEnv *dbEnv = NULL;
    if (setupTestEnvironment(&dbEnv) || !dbEnv) {
        printf("   Could not create our test environment.\n");
        return;
    }

    //we have 20 user/hosts with a CLEAR/BLOCKED state, all with 50 attempts
    const char *clearRule = "*:30/10s";
    const char *blockRule = "*:1/1h";
    const char *service = "Service";

    //user clear, host clear, no blocking
    checkAttempt("cu_0", clearRule, CLEAR, "ch_0", clearRule, CLEAR, service, CLEAR, AUTH_FAILED, dbEnv);
    //user clear, host clear, user blocked
    checkAttempt("cu_1", blockRule, BLOCKED, "ch_1", clearRule, CLEAR, service, BLOCKED, USER_BLOCKED, dbEnv);
    //user clear, host clear, host blocked
    checkAttempt("cu_2", clearRule, CLEAR, "ch_2", blockRule, BLOCKED, service, BLOCKED, HOST_BLOCKED, dbEnv);
    //user clear, host clear, both blocked
    checkAttempt("cu_3", blockRule, BLOCKED, "ch_3", blockRule, BLOCKED, service, BLOCKED, BOTH_BLOCKED, dbEnv);

    //user blocked, host clear, no blocking
    checkAttempt("bu_4", clearRule, CLEAR, "ch_4", clearRule, CLEAR, service, CLEAR, AUTH_FAILED, dbEnv);
    //user blocked, host clear, user blocked
    checkAttempt("bu_5", blockRule, BLOCKED, "ch_5", clearRule, CLEAR, service, BLOCKED, USER_BLOCKED, dbEnv);
    //user blocked, host clear, host blocked
    checkAttempt("bu_6", clearRule, CLEAR, "ch_6", blockRule, BLOCKED, service, BLOCKED, HOST_BLOCKED, dbEnv);
    //user blocked, host clear, both blocked
    checkAttempt("bu_7", blockRule, BLOCKED, "ch_7", blockRule, BLOCKED, service, BLOCKED, BOTH_BLOCKED, dbEnv);

    //user clear, host blocked, no blocking
    checkAttempt("cu_8", clearRule, CLEAR, "bh_8", clearRule, CLEAR, service, CLEAR, AUTH_FAILED, dbEnv);
    //user clear, host blocked, user blocked
    checkAttempt("cu_9", blockRule, BLOCKED, "bh_9", clearRule, CLEAR, service, BLOCKED, USER_BLOCKED, dbEnv);
    //user clear, host blocked, host blocked
    checkAttempt("cu_10", clearRule, CLEAR, "bh_10", blockRule, BLOCKED, service, BLOCKED, HOST_BLOCKED, dbEnv);
    //user clear, host blocked, both blocked
    checkAttempt("cu_11", blockRule, BLOCKED, "bh_11", blockRule, BLOCKED, service, BLOCKED, BOTH_BLOCKED, dbEnv);

    //user blocked, host blocked, no blocking
    checkAttempt("bu_12", clearRule, CLEAR, "bh_12", clearRule, CLEAR, service, CLEAR, AUTH_FAILED, dbEnv);
    //user blocked, host blocked, user blocked
    checkAttempt("bu_13", blockRule, BLOCKED, "bh_13", clearRule, CLEAR, service, BLOCKED, USER_BLOCKED, dbEnv);
    //user blocked, host blocked, host blocked
    checkAttempt("bu_14", clearRule, CLEAR, "bh_14", blockRule, BLOCKED, service, BLOCKED, HOST_BLOCKED, dbEnv);
    //user blocked, host blocked, both blocked
    checkAttempt("bu_15", blockRule, BLOCKED, "bh_15", blockRule, BLOCKED, service, BLOCKED, BOTH_BLOCKED, dbEnv);

    destroyPamAblDbEnvironment(dbEnv);
    removeDir(TEST_DIR);
}

static void testRecordAttempt() {
    removeDir(TEST_DIR);
    char userBuffer[100];
    char hostBuffer[100];
    char serviceBuffer[100];
    time_t currentTime = time(NULL);

    abl_args args;
    memset(&args, 0, sizeof(abl_args));
    args.host_purge = 60*60*24; //1 day
    args.user_purge = 60*60*24; //1 day

    abl_info info;
    memset(&info, 0, sizeof(abl_info));
    info.blockReason = USER_BLOCKED;
    info.user = &userBuffer[0];
    info.host = &hostBuffer[0];
    info.service = &serviceBuffer[0];

    PamAblDbEnv *dbEnv = NULL;
    if (setupTestEnvironment(&dbEnv) || !dbEnv) {
        printf("   Could not create our test environment.\n");
        return;
    }

    int x = 0;
    int y = 0;
    for (x = 0; x < 5; ++x) {
        for (y = 0; y < 10; ++y) {
            snprintf(&userBuffer[0], 100, "user_%d", y);
            snprintf(&hostBuffer[0], 100, "host_%d", y);
            snprintf(&serviceBuffer[0], 100, "service_%d", y);
            if (record_attempt(dbEnv, &args, &info, NULL))
                printf("   Could not add an attempt.\n");
        }
    }

    startTransaction(dbEnv->m_environment);
    for (y = 0; y < 10; ++y) {
        snprintf(&userBuffer[0], 100, "user_%d", y);
        snprintf(&hostBuffer[0], 100, "host_%d", y);
        snprintf(&serviceBuffer[0], 100, "service_%d", y);
        AuthState *userState = NULL;
        AuthState *hostState = NULL;
        if (getUserOrHostInfo(dbEnv->m_userDb, &userBuffer[0], &userState))
            printf("   Could not retrieve info for user %s.\n", &userBuffer[0]);
        if (getUserOrHostInfo(dbEnv->m_hostDb, &hostBuffer[0], &hostState))
            printf("   Could not retrieve info for host %s.\n", &hostBuffer[0]);
        if (userState && hostState) {
            if (getNofAttempts(userState) != 5 || getNofAttempts(hostState) != 5) {
                printf("   We expected to find five attempts.\n");
            } else {
                AuthAttempt attempt;
                while (nextAttempt(userState, &attempt) == 0) {
                    if (strcmp(&hostBuffer[0], attempt.m_userOrHost) != 0)
                        printf("   Expected host %s, but recieved %s.\n", &hostBuffer[0], attempt.m_userOrHost);
                    if (strcmp(&serviceBuffer[0], attempt.m_service) != 0)
                        printf("   Expected service %s, but recieved %s.\n", &serviceBuffer[0], attempt.m_service);
                    if (attempt.m_time < currentTime)
                        printf("   The attempt took place in the past.\n");
                }

                while (nextAttempt(hostState, &attempt) == 0) {
                    if (strcmp(&userBuffer[0], attempt.m_userOrHost) != 0)
                        printf("   Expected user %s, but recieved %s.\n", &userBuffer[0], attempt.m_userOrHost);
                    if (strcmp(&serviceBuffer[0], attempt.m_service) != 0)
                        printf("   Expected service %s, but recieved %s.\n", &serviceBuffer[0], attempt.m_service);
                    if (attempt.m_time < currentTime)
                        printf("   The attempt took place in the past.\n");
                    if (attempt.m_reason != USER_BLOCKED)
                        printf("   Exptected the reason to be %d, yet %d was returned.\n", (int)USER_BLOCKED, (int)attempt.m_reason);
                }
            }
        } else {
            if (!userState)
                printf("   Could not retrieve the user state.\n");
            if (!hostState)
                printf("   Could not retrieve the host state.\n");
        }
        if (userState)
            destroyAuthState(userState);
        if (hostState)
            destroyAuthState(hostState);
    }
    commitTransaction(dbEnv->m_environment);

    destroyPamAblDbEnvironment(dbEnv);
    removeDir(TEST_DIR);
}

static void testRecordAttemptWhitelistHost() {
    removeDir(TEST_DIR);
    char userBuffer[100];
    char serviceBuffer[100];
    char hostBuffer[100];

    abl_args args;
    memset(&args, 0, sizeof(abl_args));
    args.host_purge = 60*60*24; //1 day
    args.user_purge = 60*60*24; //1 day
    args.host_whitelist = "1.1.1.1;2.2.2.2/32;127.0.0.1";
    args.user_whitelist = "blaat1;username;blaat3";

    abl_info info;
    PamAblDbEnv *dbEnv = NULL;
    if (setupTestEnvironment(&dbEnv) || !dbEnv) {
        printf("   Could not create our test environment.\n");
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
            if (record_attempt(dbEnv, &args, &info, NULL))
                printf("   Could not add an attempt.\n");

            snprintf(&userBuffer[0], 100, "user__%d", y);
            snprintf(&serviceBuffer[0], 100, "service__%d", y);
            info.host = "";
            if (record_attempt(dbEnv, &args, &info, NULL))
                printf("   Could not add an attempt.\n");

            //
            // Add some user checking attempts
            //
            info.host = &hostBuffer[0];
            snprintf(&hostBuffer[0], 100, "host_%d", y);
            snprintf(&serviceBuffer[0], 100, "service_%d", y);

            info.user = "username";
            if (record_attempt(dbEnv, &args, &info, NULL))
                printf("   Could not add an attempt.\n");

            info.user = "";
            if (record_attempt(dbEnv, &args, &info, NULL))
                printf("   Could not add an attempt.\n");
        }
    }

    startTransaction(dbEnv->m_environment);
    for (y = 0; y < 10; ++y) {
        snprintf(&userBuffer[0], 100, "user_%d", y);
        snprintf(&serviceBuffer[0], 100, "service_%d", y);
        AuthState *userState = NULL;
        if (getUserOrHostInfo(dbEnv->m_userDb, &userBuffer[0], &userState))
            printf("   Could not retrieve info for user %s.\n", &userBuffer[0]);
        if (userState) {
            if (getNofAttempts(userState) != 5) {
                printf("   We expected to find five attempts %d.\n", (int)(getNofAttempts(userState)));
            }
            destroyAuthState(userState);
        } else {
            printf("   Could not retrieve the user state.\n");
        }
    }

    AuthState *hostState = NULL;
    if (getUserOrHostInfo(dbEnv->m_hostDb, "127.0.0.1", &hostState))
        printf("   Could not retrieve info for host 127.0.0.1.\n");
    if (hostState)
        printf("   We expected an empty state for host 127.0.0.1\n");

    hostState = NULL;
    if (getUserOrHostInfo(dbEnv->m_hostDb, "", &hostState))
        printf("   Could not retrieve info for the empty host.\n");
    if (hostState)
        printf("   We expected an empty state for the empty host\n");


    AuthState *userState = NULL;
    if (getUserOrHostInfo(dbEnv->m_userDb, "", &userState))
        printf("   Could not retrieve info for the empty user.\n");
    if (userState)
        printf("   We expected an empty state for the empty user\n");

    userState = NULL;
    if (getUserOrHostInfo(dbEnv->m_userDb, "username", &userState))
        printf("   Could not retrieve info for the empty user.\n");
    if (userState)
        printf("   We expected an empty state for the empty user\n");

    commitTransaction(dbEnv->m_environment);
    destroyPamAblDbEnvironment(dbEnv);
    removeDir(TEST_DIR);
}

static void testRecordAttemptPurge() {
    removeDir(TEST_DIR);

    abl_args args;
    memset(&args, 0, sizeof(abl_args));
    args.host_purge = 25;
    args.user_purge = 15;

    abl_info info;
    memset(&info, 0, sizeof(abl_info));
    info.blockReason = USER_BLOCKED;
    info.user = "cu_0";
    info.host = "ch_0";
    info.service = "Cool_Service";

    PamAblDbEnv *dbEnv = NULL;
    if (setupTestEnvironment(&dbEnv) || !dbEnv) {
        printf("   Could not create our test environment.\n");
        return;
    }

    if (record_attempt(dbEnv, &args, &info, NULL))
        printf("   Could not add an attempt.\n");

    //we know in the db every 10 seconds an attempt was made, lets's see if it is purged enough
    //time_t logTime = tm - x*10;
    startTransaction(dbEnv->m_environment);
    AuthState *userState = NULL;
    AuthState *hostState = NULL;
    if (getUserOrHostInfo(dbEnv->m_userDb, info.user, &userState))
        printf("   Could not retrieve info for user %s.\n", info.user);
    if (getUserOrHostInfo(dbEnv->m_hostDb, info.host, &hostState))
        printf("   Could not retrieve info for host %s.\n", info.host);
    if (userState && hostState) {
        //for the user we purged every attempt older then 15 seconds, so we expect to see: now, now - 10 and our just logged time
        if (getNofAttempts(userState) != 3) {
            printf("   The current user state holds %d entries.\n", getNofAttempts(userState));
        }
        if (getNofAttempts(hostState) != 4) {
            printf("   The current host state holds %d entries.\n", getNofAttempts(hostState));
        }
    }
    commitTransaction(dbEnv->m_environment);
    destroyPamAblDbEnvironment(dbEnv);
    if (userState)
        destroyAuthState(userState);
    if (hostState)
        destroyAuthState(hostState);
}

static void testOpenOnlyHostDb() {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);
    abl_args args;
    memset(&args, 0, sizeof(abl_args));
    args.db_home = TEST_DIR;
    args.host_db = TEST_DIR"/hosts.db";
    args.user_db = NULL;
    PamAblDbEnv *dbEnv = openPamAblDbEnvironment(&args, NULL);
    if (!dbEnv) {
        printf("   The db environment could not be opened.\n");
        return;
    }
    if (!dbEnv->m_environment)
        printf("   The db environment was not filled in.\n");
    if (dbEnv->m_userDb)
        printf("   The user db was filled in.\n");
    if (!dbEnv->m_hostDb)
        printf("   The host db was not filled in.\n");
    destroyPamAblDbEnvironment(dbEnv);
    removeDir(TEST_DIR);
}

static void testOpenOnlyUserDb() {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);
    abl_args args;
    memset(&args, 0, sizeof(abl_args));
    args.db_home = TEST_DIR;
    args.host_db = NULL;
    args.user_db = TEST_DIR"/users.db";
    PamAblDbEnv *dbEnv = openPamAblDbEnvironment(&args, NULL);
    if (!dbEnv) {
        printf("   The db environment could not be opened.\n");
        return;
    }
    if (!dbEnv->m_environment)
        printf("   The db environment was not filled in.\n");
    if (!dbEnv->m_userDb)
        printf("   The user db was not filled in.\n");
    if (dbEnv->m_hostDb)
        printf("   The host db was filled in.\n");
    destroyPamAblDbEnvironment(dbEnv);
    removeDir(TEST_DIR);
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
                        printf("   IP parsing failed for %s.\n", &buffer[0]);
                    } else {
                        if (parsedIp != expectedIp || netmask != -1)
                            printf("   IP parsing failed for %s, result was not as expected\n", &buffer[0]);
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
                    if (parseIP(&buffer[0], strLen, &netmask, &parsedIp) == 0)
                        printf("   IP parsing succeeded for %s.\n", &buffer[0]);

                    snprintf(&buffer[0], 100, "%d.%d.%d.%d", validIpComponents[x], invalidIpComponents[y], validIpComponents[z], validIpComponents[j]);
                    strLen = strlen(&buffer[0]);
                    if (parseIP(&buffer[0], strLen, &netmask, &parsedIp) == 0)
                        printf("   IP parsing succeeded for %s.\n", &buffer[0]);

                    snprintf(&buffer[0], 100, "%d.%d.%d.%d", validIpComponents[x], validIpComponents[y], invalidIpComponents[z], validIpComponents[j]);
                    strLen = strlen(&buffer[0]);
                    if (parseIP(&buffer[0], strLen, &netmask, &parsedIp) == 0)
                        printf("   IP parsing succeeded for %s.\n", &buffer[0]);

                    snprintf(&buffer[0], 100, "%d.%d.%d.%d", validIpComponents[x], validIpComponents[y], validIpComponents[z], invalidIpComponents[j]);
                    strLen = strlen(&buffer[0]);
                    if (parseIP(&buffer[0], strLen, &netmask, &parsedIp) == 0)
                        printf("   IP parsing succeeded for %s.\n", &buffer[0]);
                }
            }
        }
    }

    x=0;
    for (; x< (int)(sizeof(invalidIps)/sizeof(char*)); ++x) {
        if (parseIP(invalidIps[x], strlen(invalidIps[x]), &netmask, &parsedIp) == 0)
            printf("   IP parsing succeeded for %s.\n", invalidIps[x]);
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
        if (parseIP(&buffer[0], strLen, &netmask, &parsedIp) != 0)
            printf("   IP parsing failed for %s.\n", invalidIps[x]);
       else if (netmask != x) {
            printf("   IP parsing failed for %s: Invalid netmwask returned.\n", invalidIps[x]);
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
        if (parseIP(invalidIpsWithNetmask[x], strlen(invalidIpsWithNetmask[x]), &netmask, &parsedIp) == 0)
            printf("   IP parsing succeeded for %s.\n", invalidIpsWithNetmask[x]);
    }
}

static void testInSameSubnet() {
    u_int32_t ip = getIp(192,168,1,1);
    int x = 0;
    for (; x < 256; ++x) {
        u_int32_t host = getIp(192,168,1,x);
        if (inSameSubnet(host, ip, 24) == 0) {
            printf("   testInSameSubnet failed.\n");
        }
        if (x != 192) {
            host = getIp(x,168,1,1);
            if (inSameSubnet(host, ip, 24)) {
                printf("   testInSameSubnet failed.\n");
            }
        }
        if (x != 168) {
            host = getIp(192,x,1,1);
            if (inSameSubnet(host, ip, 24)) {
                printf("   testInSameSubnet failed.\n");
            }
        }
        if (x != 1) {
            host = getIp(192,168,x,1);
            if (inSameSubnet(host, ip, 24)) {
                printf("   testInSameSubnet failed.\n");
            }
        }
    }

    ip = getIp(128,128,128,128);
    for (x=0; x < 256; ++x) {
        u_int32_t host = getIp(128,128,128,x);
        if (x == 128) {
            if (inSameSubnet(host, ip, 32) == 0)
                printf("   testInSameSubnet failed.\n");
        } else {
            if (inSameSubnet(host, ip, 32))
                printf("   testInSameSubnet failed.\n");
        }
    }

    if (inSameSubnet(getIp(1,1,1,1), ip, 0) == 0)
        printf("   the 0 subnet should contain all ip's.\n");

    if (inSameSubnet(getIp(255,255,255,255), ip, 0) == 0)
        printf("   the 0 subnet should contain all ip's.\n");
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
        if (whitelistMatch(whiteListed[x], hostWhitelist, 1) == 0) {
            printf("   %s was not whitelisted\n", whiteListed[x]);
        }
    }

    for (x=0; x< (int)(sizeof(notWhiteListed)/sizeof(char*)); ++x) {
        if (whitelistMatch(notWhiteListed[x], hostWhitelist, 1) != 0) {
            printf("   %s was whitelisted\n", notWhiteListed[x]);
        }
    }
}

static void testSubstitute(const char *str, const char *user, const char *host, const char *service, const char *result) {
    abl_info info;
    info.user = user;
    info.host = host;
    info.service = service;

    int resultSize = prepare_string(str, &info, NULL);
    if (resultSize != (int)(strlen(result)+1)) {
        printf("   substitute length was incorrect for \"%s\"\n", str);
        return;
    }
    char *res = malloc(resultSize * sizeof(char));
    int i = 0;
    for (; i < resultSize; ++i)
        res[i] = 'a';
    resultSize = prepare_string(str, &info, res);
    if (resultSize != (int)(strlen(result)+1)) {
        printf("   actual substitute length was incorrect for \"%s\"\n", str);
    } else {
        if (strcmp(res, result) != 0)
            printf("   substitute was incorrect \"%s\" != \"%s\"\n", res, str);
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

void testAbl() {
    printf("Abl test start.\n");
    printf(" Starting testPamAblDbEnv.\n");
    testPamAblDbEnv();
    printf(" Starting testCheckAttempt.\n");
    testCheckAttempt();
    printf(" Starting testRecordAttempt.\n");
    testRecordAttempt();
    printf(" Starting testRecordAttemptWhitelistHost.\n");
    testRecordAttemptWhitelistHost();
    printf(" Starting testRecordAttemptPurge.\n");
    testRecordAttemptPurge();
    printf(" Starting testOpenOnlyHostDb.\n");
    testOpenOnlyHostDb();
    printf(" Starting testOpenOnlyUserDb.\n");
    testOpenOnlyUserDb();
    printf(" Starting testParseIpValid.\n");
    testParseIpValid();
    printf(" Starting testParseIpInvalid.\n");
    testParseIpInvalid();
    printf(" Starting testParseIpValidWithNetmask.\n");
    testParseIpValidWithNetmask();
    printf(" Starting testParseIpInvalidWithNetmask.\n");
    testParseIpInvalidWithNetmask();
    printf(" Starting testInSameSubnet.\n");
    testInSameSubnet();
    printf(" Starting testWhitelistMatch.\n");
    testWhitelistMatch();
    printf(" Starting testSubstituteNormal.\n");
    testSubstituteNormal();
    printf(" Starting testNoSubstitute.\n");
    testNoSubstitute();
    printf(" Starting testEmptySubstitute.\n");
    testEmptySubstitute();
    printf(" Starting testSubstituteWithPercent.\n");
    testSubstituteWithPercent();
    printf("Abl test end.\n");
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
    if (result != exitCode) {
        printf("   ablExec exit code: \"%d\" != \"%d\"\n", result, exitCode);
    }
}

void testExternalCommand(const char *cmd) {
    printf("testExternalCommand start.\n");
    printf(" Basic exitcode tests.\n");
    int i = 0;
    for (; i < 10; ++i ) {
        testCommand(cmd, i);
    }
    printf(" Non existing command test.\n");
    testCommand("command_that_doenst_exist", 255);
    printf(" Invalid input test.\n");
    testCommand(0, -1);
    testCommand("", -1);
    printf("testExternalCommand end.\n");
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
                printf("   execFun: argument mismatch \"%s\" != \"%s\"\n", arg[i], s_expected_arg[i]);
                return s_execFun_exitCode;
            }
        } else {
            printf("   execFun: missing argument \"%s\"\n", s_expected_arg[i]);
            return s_execFun_exitCode;
        }
        ++i;
    }
    if (arg[i] != NULL) {
        printf("   we got more parameters than expected: \"%s\"", arg[i]);
    }
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
        int returnCode = _runCommand(origCommand, info, NULL, execFun);
        if (s_execFun_called != isOk) {
            if (isOk)
                printf("   Expected the command \"%s\" to be called.", arg1);
            else
                printf("   Did not expect the command \"%s\" to be called.", arg1);
        }
        if (returnCode != s_execFun_exitCode) {
            printf("   Expected exit code \"%d\" instead of \"%d\".", s_execFun_exitCode, returnCode);
        }
    }
}


void testRunCommand() {
    printf("testRunCommand start.\n");
    abl_info info;
    info.host = "127.0.0.1";
    info.user = "mooh";
    info.service = "sharing";
    printf(" basic command test.\n");
    testRunCommandHelper("[command]", 1, &info, "command", NULL, NULL, NULL);
    printf(" command with substitution test.\n");
    testRunCommandHelper("[command %u]", 1, &info, "command mooh", NULL, NULL, NULL);
    printf(" command with some shell code test.\n");
    testRunCommandHelper("[command | > %u %h %s]", 1, &info, "command | > mooh 127.0.0.1 sharing", NULL, NULL, NULL);

    testRunCommandHelper("[command] [arg1] [%u] [%h]", 1, &info, "command", "arg1", "mooh", "127.0.0.1");

    info.user = "[lol]";
    testRunCommandHelper("[command %u] [%u]", 1, &info, "command [lol]", "[lol]", NULL, NULL);
    printf("testRunCommand end.\n");
}
