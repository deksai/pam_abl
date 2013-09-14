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

#include "pam_functions.h"
#include "pam_abl.h"
#include "log.h"
#include "test.h"

#include <stdio.h>
#include <string.h>

static const char *dbModule = NULL;

static void emptyConfig() {
    if (args)
        config_free();
    config_create();
    args->db_module = dbModule;
}

/*
 * \param iterations, how many times should we repeat the authenticate/log loop
 * \param auths, how many authentications should we do in each loop
 * \param authErrorCount, after how many attempts should we see a PAM_AUTH_ERR
 */
static void authHelperOldImpl(int iterations, int auths, int authErrorCount) {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);
    char userBuffer[100];
    char hostBuffer[100];
    char serviceBuffer[100];
    int i = 0;
    int a = 0;
    int count = 0;
    int pamResult = 0;
    abl_context context;

    const char *user = "username";
    const char *host = "10.10.10.10";
    const char *service = "service";

    for (i = 0; i < iterations; ++i) {
        memset(&context, 0, sizeof(abl_context));
        sprintf(userBuffer, "%s", user);
        sprintf(hostBuffer, "%s", host);
        sprintf(serviceBuffer, "%s", service);
        for (a = 0; a < auths; ++a) {
            pamResult = pam_inner_authenticate(&context, &userBuffer[0], &hostBuffer[0], &serviceBuffer[0], ACTION_NONE);
            CU_ASSERT_EQUAL(pamResult, count < authErrorCount ? PAM_SUCCESS : PAM_AUTH_ERR);
            ++count;
        }
        CU_ASSERT_PTR_NOT_NULL(context.attemptInfo);
        //override the user,host,service with a unique name before adding it to the list
        //normally context.attemptInfo  should contain a COPY of the old values
        sprintf(userBuffer, "%s%d", user, iterations);
        sprintf(hostBuffer, "%s%d", host, iterations);
        sprintf(serviceBuffer, "%s%d", service, iterations);
        setup_and_log_attempt(context.attemptInfo);
        destroyAblInfo(context.attemptInfo);
        context.attemptInfo = NULL;
    }

    //check the db
    abl_db *abldb = setup_db();
    CU_ASSERT_PTR_NOT_NULL(abldb);
    if (abldb) {
        int err = abldb->start_transaction(abldb);
        CU_ASSERT_EQUAL(err, 0);
        if (!err) {
            AuthState *objectState = NULL;
            err = abldb->get(abldb, user, &objectState, USER);
            CU_ASSERT_EQUAL(err, 0);
            CU_ASSERT_PTR_NOT_NULL(objectState);
            if (!err && objectState) {
                CU_ASSERT_EQUAL((int)getNofAttempts(objectState), iterations*auths);
                destroyAuthState(objectState);
            }
            err = abldb->get(abldb, host, &objectState, HOST);
            CU_ASSERT_EQUAL(err, 0);
            CU_ASSERT_PTR_NOT_NULL(objectState);
            if (!err && objectState) {
                CU_ASSERT_EQUAL((int)getNofAttempts(objectState), iterations*auths);
                destroyAuthState(objectState);
            }
            abldb->commit_transaction(abldb);
        }
        abldb->close(abldb);
    }
    removeDir(TEST_DIR);
}

//test the 'old' flow (where no action is specified and we use the cleanup function)
static void oldImplTestUserBlocked() {
    //let's clean the config
    emptyConfig();
    //make sure we don't purge
    args->host_purge = 60*60*24; //1 day
    args->user_purge = 60*60*24; //1 day
    args->db_module = dbModule;
    args->db_home = TEST_DIR;
    args->user_rule = "*:10/1h";
    args->host_rule = "*:1000/1h";

    authHelperOldImpl(15, 1, 10);
    authHelperOldImpl(10, 2, 10);
    authHelperOldImpl(10, 3, 10);
}

static void oldImplTestHostBlocked() {
    //let's clean the config
    emptyConfig();
    //make sure we don't purge
    args->host_purge = 60*60*24; //1 day
    args->user_purge = 60*60*24; //1 day
    args->db_module = dbModule;
    args->db_home = TEST_DIR;
    args->user_rule = "*:1000/1h";
    args->host_rule = "*:10/1h";

    authHelperOldImpl(15, 1, 10);
    authHelperOldImpl(10, 2, 10);
    authHelperOldImpl(10, 3, 10);
}

static void oldImplTestBothBlocked() {
    //let's clean the config
    emptyConfig();
    //make sure we don't purge
    args->host_purge = 60*60*24; //1 day
    args->user_purge = 60*60*24; //1 day
    args->db_module = dbModule;
    args->db_home = TEST_DIR;
    args->user_rule = "*:10/1h";
    args->host_rule = "*:10/1h";

    authHelperOldImpl(15, 1, 10);
    authHelperOldImpl(10, 2, 10);
    authHelperOldImpl(10, 3, 10);
}

/*
 * \param iterations, How many times should we repeat the check/log loop
 * \param auths, how many check should we do before calling the log function
 * \param authErrorCount, after how many attempts should we see a PAM_AUTH_ERR
 */
static void authHelperNewImpl(int iterations, int auths, int authErrorCount, ModuleAction checkAction, ModuleAction logAction) {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);
    int i = 0;
    int a = 0;
    int count = 0;
    int pamResult = 0;

    char *user = "username";
    char *host = "10.10.10.10";
    char *service = "service";

    for (i = 0; i < iterations; ++i) {
        for (a = 0; a < auths; ++a) {
            pamResult = pam_inner_authenticate(NULL, user, host, service, checkAction);
            int expected = count < authErrorCount ? PAM_SUCCESS : PAM_AUTH_ERR;
            if (pamResult != expected) {
                int x = 0;
                ++x;
                x++;
            }
            CU_ASSERT_EQUAL(pamResult, expected);
        }
        pamResult = pam_inner_authenticate(NULL, user, host, service, logAction);
        ++count;
        //logging an authentication should always result in PAM_SUCCESS
        CU_ASSERT_EQUAL(pamResult, PAM_SUCCESS);
    }
    //check the db
    abl_db *abldb = setup_db();
    CU_ASSERT_PTR_NOT_NULL(abldb);
    if (abldb) {
        int err = abldb->start_transaction(abldb);
        CU_ASSERT_EQUAL(err, 0);
        if (!err) {
            AuthState *objectState = NULL;
            err = abldb->get(abldb, user, &objectState, USER);
            CU_ASSERT_EQUAL(err, 0);
            if (logAction & ACTION_LOG_USER) {
                CU_ASSERT_PTR_NOT_NULL(objectState);
                if (!err && objectState) {
                    CU_ASSERT_EQUAL((int)getNofAttempts(objectState), iterations);
                    destroyAuthState(objectState);
                }
            } else {
                CU_ASSERT_PTR_NULL(objectState);
            }
            err = abldb->get(abldb, host, &objectState, HOST);
            CU_ASSERT_EQUAL(err, 0);
            if (logAction & ACTION_LOG_HOST) {
                CU_ASSERT_PTR_NOT_NULL(objectState);
                if (!err && objectState) {
                    CU_ASSERT_EQUAL((int)getNofAttempts(objectState), iterations);
                    destroyAuthState(objectState);
                }
            } else {
                CU_ASSERT_PTR_NULL(objectState);
            }
            abldb->commit_transaction(abldb);
        }
        abldb->close(abldb);
    }
    removeDir(TEST_DIR);
}

static ModuleAction checkActions[]   = { ACTION_CHECK_USER, ACTION_CHECK_HOST, ACTION_CHECK_USER | ACTION_CHECK_HOST };
static ModuleAction logActions[]   = { ACTION_LOG_USER, ACTION_LOG_HOST, ACTION_LOG_USER | ACTION_LOG_HOST };
static char* blockStrings[] = { "*:10/1h", "*:15/1h", "*:20/1h" };
static int blockCounts[]    = {        10,        15,        20 };

//test the 'new' flow (where we specify an action and no context is needed)
static void newImplTestAllCombinations() {
    int checkSize = sizeof(checkActions)/sizeof(ModuleAction);
    int logSize = sizeof(logActions)/sizeof(ModuleAction);
    int blockStringsSize = sizeof(blockStrings)/sizeof(char*);
    //let's clean the config
    emptyConfig();
    //make sure we don't purge
    args->host_purge = 60*60*24; //1 day
    args->user_purge = 60*60*24; //1 day
    args->db_module = dbModule;
    args->db_home = TEST_DIR;
    args->user_rule = "*:10/1h";
    args->host_rule = "*:1000/1h";

    int checkActionIndex = 0;
    int logActionIndex = 0;
    int blockIndexUser = 0;
    int blockIndexHost = 0;

    for (checkActionIndex = 0; checkActionIndex < checkSize; ++checkActionIndex) {
        ModuleAction checkAction = checkActions[checkActionIndex];
        for (logActionIndex = 0; logActionIndex < logSize; ++logActionIndex) {
            ModuleAction logAction = logActions[logActionIndex];
            for (blockIndexUser = 0; blockIndexUser < blockStringsSize; ++blockIndexUser) {
                args->user_rule = blockStrings[blockIndexUser];
                for (blockIndexHost = 0; blockIndexHost < blockStringsSize; ++blockIndexHost) {
                    args->host_rule = blockStrings[blockIndexHost];
                    int blockedAfter = 1000;
                    if (logAction & ACTION_LOG_USER && checkAction & ACTION_CHECK_USER && blockedAfter > blockCounts[blockIndexUser])
                        blockedAfter = blockCounts[blockIndexUser];
                    if (logAction & ACTION_LOG_HOST && checkAction & ACTION_CHECK_HOST && blockedAfter > blockCounts[blockIndexHost])
                        blockedAfter = blockCounts[blockIndexHost];

                    authHelperNewImpl(30, 1, blockedAfter, checkAction, logAction);
                    authHelperNewImpl(30, 2, blockedAfter, checkAction, logAction);
                    authHelperNewImpl(30, 5, blockedAfter, checkAction, logAction);
                }
            }
        }
    }
}

void addPamFunctionsTests(const char *module) {
    if (!module || !*module) {
        printf("Failed to add the Pam Functions test (no database module).\n");
        return;
    }
    dbModule = module;

    CU_pSuite pSuite = NULL;
    pSuite = CU_add_suite("Pam functions tests", NULL, NULL);
    if (NULL == pSuite)
        return;
    CU_add_test(pSuite, "oldImplTestUserBlocked", oldImplTestUserBlocked);
    CU_add_test(pSuite, "oldImplTestHostBlocked", oldImplTestHostBlocked);
    CU_add_test(pSuite, "oldImplTestBothBlocked", oldImplTestBothBlocked);
    CU_add_test(pSuite, "newImplTestAllCombinations", newImplTestAllCombinations);
}
