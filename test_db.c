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

#include "test.h"
#include "dbfun.h"

#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

static const char *bdbFile = "./pam_abl_bdb.so";
static const char *kcFile = "./pam_abl_kc.so";
static abl_db_open_ptr openFunc = NULL;


static abl_db_open_ptr load_db(const char *db_module) {
    void *dblib = NULL;
    abl_db_open_ptr db_open = NULL;

    dblib = dlopen(db_module, RTLD_LAZY|RTLD_GLOBAL);
    if (!dblib) {
        printf("   Failed to open db module \"%s\": %s\n", db_module, dlerror());
        return db_open;
    }
    dlerror();
    db_open = dlsym(dblib, "abl_db_open");
    if  (!db_open) {
        printf("   Unable to get the abl_db_open symbol");
    }
    return db_open;
}

/*
 * Test if we can open and close a db
 * It also test if all the required functions are defined
 * \return 0 if the test succeeded, 1 if not
 */
static void testOpenClose() {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);

    abl_db *db = openFunc(TEST_DIR);
    if (!db) {
        CU_FAIL("Unable to open the db environment.");
        return;
    }
    CU_ASSERT_PTR_NOT_NULL(db->put);
    CU_ASSERT_PTR_NOT_NULL(db->del);
    CU_ASSERT_PTR_NOT_NULL(db->get);
    CU_ASSERT_PTR_NOT_NULL(db->c_open);
    CU_ASSERT_PTR_NOT_NULL(db->c_close);
    CU_ASSERT_PTR_NOT_NULL(db->c_get);
    CU_ASSERT_PTR_NOT_NULL(db->start_transaction);
    CU_ASSERT_PTR_NOT_NULL(db->commit_transaction);
    CU_ASSERT_PTR_NOT_NULL(db->abort_transaction);
    if (!db->close) {
        CU_FAIL("close function is not defined.");
    } else {
        db->close(db);
    }
    removeDir(TEST_DIR);
}

static void testWriteReadOneTransactionWithObjectType(abl_db *db, ablObjectType type) {
    const char *key = "mykey";
    AuthState *result = NULL;
    CU_ASSERT_FALSE(db->get(db, key, &result, type));
    CU_ASSERT_PTR_NULL(result);
    if (createEmptyState(CLEAR, &result)) {
        CU_FAIL("Creating an empty State failed.");
    } else {
        CU_ASSERT_FALSE(db->put(db, key, result, type));

        AuthState *result2 = NULL;
        CU_ASSERT_FALSE(db->get(db, key, &result2, type));

        if (result && result2) {
            if (result->m_usedSize != result2->m_usedSize) {
                CU_FAIL("The size of the saved state and the retrieved state is not the same.");
            } else {
                CU_ASSERT_FALSE(memcmp(result->m_data, result2->m_data, result->m_usedSize));
            }
        }
        if (result)
            destroyAuthState(result);
        if (result2)
            destroyAuthState(result2);
    }
}

static void testWriteReadOneTransaction() {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);

    abl_db *db = openFunc(TEST_DIR);
    if (!db) {
        CU_FAIL("Unable to open the db environment.");
        return;
    }

    if (db->start_transaction(db)) {
        //starting transaction failed
        CU_FAIL("Unable to open a transaction.");
    } else {
        testWriteReadOneTransactionWithObjectType(db, HOST);
        testWriteReadOneTransactionWithObjectType(db, USER);
        CU_ASSERT_FALSE(db->commit_transaction(db));
    }
    db->close(db);
    removeDir(TEST_DIR);
}

static void testWriteReadDifferentTransactionsWithObjectType(abl_db *db, ablObjectType type) {
    if (db->start_transaction(db)) {
        //starting transaction failed
        CU_FAIL("Unable to open a transaction");
    } else {
        const char *key = "valueKey";
        AuthState *result = NULL;
        if (createEmptyState(CLEAR, &result)) {
            CU_FAIL("Creating an empty State failed.");
        } else {
            CU_ASSERT_FALSE(addAttempt(result, USER_BLOCKED, 2, "User1", "Service1", 0, 0));
            CU_ASSERT_FALSE(db->put(db, key, result, type));
            CU_ASSERT_FALSE(db->commit_transaction(db));
            CU_ASSERT_FALSE(db->start_transaction(db));
            AuthState *result2 = NULL;
            CU_ASSERT_FALSE(db->get(db, key, &result2, type));

            if (result && result2) {
                if (result->m_usedSize != result2->m_usedSize) {
                    CU_FAIL("The size of the saved state and the retrieved state is not the same.");
                } else {
                    CU_ASSERT_FALSE(memcmp(result->m_data, result2->m_data, result->m_usedSize));
                }
            }
            if (result)
                destroyAuthState(result);
            if (result2)
                destroyAuthState(result2);
        }
        CU_ASSERT_FALSE(db->commit_transaction(db));
    }
}

static void testWriteReadDifferentTransactions() {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);

    abl_db *db = openFunc(TEST_DIR);
    if (!db) {
        CU_FAIL("Unable to open the db environment.");
        return;
    }
    testWriteReadDifferentTransactionsWithObjectType(db, USER);
    testWriteReadDifferentTransactionsWithObjectType(db, HOST);

    db->close(db);
    removeDir(TEST_DIR);
}

static void testCreateRetrieveUpdateWithObjectType(abl_db *db, ablObjectType type) {
    const char *key = "valueKey";
    AuthState *result = NULL;
    if (db->start_transaction(db)) {
        CU_FAIL("The get transaction could not be opened.");
        return;
    }
    if (createEmptyState(CLEAR, &result)) {
        CU_FAIL("Creating an empty State failed.");
    } else {
        CU_ASSERT_FALSE(addAttempt(result, USER_BLOCKED, 2, "User1", "Service1", 0, 0));
        CU_ASSERT_FALSE(db->put(db, key, result, type));
        CU_ASSERT_FALSE(db->commit_transaction(db));
        CU_ASSERT_FALSE(db->start_transaction(db));
        AuthState *result2 = NULL;
        CU_ASSERT_FALSE(db->get(db, key, &result2, type));

        if (result && result2) {
            if (result->m_usedSize != result2->m_usedSize) {
                CU_FAIL("The size of the saved state and the retrieved state is not the same.");
            } else {
                if (memcmp(result->m_data, result2->m_data, result->m_usedSize)) {
                    CU_FAIL("The saved and retrieved values are not the same.");
                } else {
                    CU_ASSERT_FALSE(addAttempt(result2, USER_BLOCKED, 50, "User2", "Service2", 0, 0));
                    CU_ASSERT_FALSE(db->put(db, key, result2, type));
                    AuthState *result3 = NULL;
                    CU_ASSERT_FALSE(db->get(db, key, &result3, type));
                    if (result3) {
                        CU_ASSERT_EQUAL(getNofAttempts(result3), 2);
                        CU_ASSERT_EQUAL(result2->m_usedSize, result3->m_usedSize);
                        CU_ASSERT_FALSE(memcmp(result2->m_data, result3->m_data, result2->m_usedSize));
                        destroyAuthState(result3);
                    }
                }
            }
        }
        if (result)
            destroyAuthState(result);
        if (result2)
            destroyAuthState(result2);
    }
    CU_ASSERT_FALSE(db->commit_transaction(db));
}

static void testCreateRetrieveUpdate() {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);

    abl_db *db = openFunc(TEST_DIR);
    if (!db) {
        CU_FAIL("Unable to open the db environment.");
        return;
    }
    testCreateRetrieveUpdateWithObjectType(db, USER);
    testCreateRetrieveUpdateWithObjectType(db, HOST);

    db->close(db);
    removeDir(TEST_DIR);
}

static void testCreateRetrieveDeleteWithObjectType(abl_db *db, ablObjectType type) {
    if (db->start_transaction(db)) {
        CU_FAIL("Could not start a transaction.");
    } else {
        const char *key = "valueKey";
        AuthState *result = NULL;
        if (createEmptyState(CLEAR, &result)) {
            CU_FAIL("Creating an empty State failed.");
        } else {
            CU_ASSERT_FALSE(addAttempt(result, USER_BLOCKED, 2, "User1", "Service1", 0, 0));
            CU_ASSERT_FALSE(db->put(db, key, result, type));
            AuthState *result2 = NULL;
            CU_ASSERT_FALSE(db->get(db, key, &result2, type));
            CU_ASSERT_PTR_NOT_NULL(result2);
            CU_ASSERT_FALSE(db->commit_transaction(db));
            CU_ASSERT_FALSE(db->start_transaction(db));
            CU_ASSERT_FALSE(db->del(db, key, type));
            AuthState *result3 = NULL;
            CU_ASSERT_FALSE(db->get(db, key, &result3, type));
            CU_ASSERT_PTR_NULL(result3);
            if (result)
                destroyAuthState(result);
            if (result2)
                destroyAuthState(result2);
            if (result3)
                destroyAuthState(result3);
        }
        CU_ASSERT_FALSE(db->commit_transaction(db));
    }
}

static void testCreateRetrieveDelete() {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);

    abl_db *db = openFunc(TEST_DIR);
    if (!db) {
        CU_FAIL("Unable to open the db environment.");
        return;
    }
    testCreateRetrieveDeleteWithObjectType(db, USER);
    testCreateRetrieveDeleteWithObjectType(db, HOST);

    db->close(db);
    removeDir(TEST_DIR);
}

static void testUserIsNotHost() {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);

    abl_db *db = openFunc(TEST_DIR);
    if (!db) {
        CU_FAIL("Unable to open the db environment");
        return;
    }
    const char *key = "valueKey";
    AuthState *result = NULL;
    if (db->start_transaction(db)) {
        CU_FAIL("The get transaction could not be opened.");
        return;
    }
    if (createEmptyState(CLEAR, &result)) {
        CU_FAIL("Creating an empty State failed.");
    } else {
        CU_ASSERT_FALSE(addAttempt(result, USER_BLOCKED, 2, "User1", "Service1", 0, 0));
        CU_ASSERT_FALSE(db->put(db, key, result, USER));
        AuthState *result2 = NULL;
        CU_ASSERT_FALSE(db->get(db, key, &result2, USER));

        AuthState *result3 = NULL;
        CU_ASSERT_FALSE(db->get(db, key, &result3, HOST));
        CU_ASSERT_PTR_NULL(result3);

        if (result)
            destroyAuthState(result);
        if (result2)
            destroyAuthState(result2);
    }
    CU_ASSERT_FALSE(db->commit_transaction(db));

    db->close(db);
    removeDir(TEST_DIR);
}

static void testInvalidDbHome() {
    const char *dbhome = "/tmp/nonexisting/dbhome";
    abl_db *db = openFunc(dbhome);
    CU_ASSERT_FALSE(db);
}

static void testConcurrency() {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);
    int pCount = 10;
    int updateCount = 50;
    int i = 0;
    int x = 0;
    const char *key = "SecretKey";
    pid_t* pID = malloc(sizeof(pid_t)*pCount);
    for (i = 0; i < pCount; ++i) {
        pID[i]= fork();
        if (pID[i] == 0) {
            //child
            abl_db *dbFuncs = openFunc(TEST_DIR);
            if (!dbFuncs) {
                printf("   Unable to open the db environment\n");
                exit(0);
            }
            for (x = 0; x < updateCount; ++x) {
                if (dbFuncs->start_transaction(dbFuncs)) {
                    printf("   The get transaction could not be opened.\n");
                    exit(0);
                }

                AuthState *result = NULL;
                if (dbFuncs->get(dbFuncs, key, &result, USER))
                    printf("   Could not get the saved key.\n");

                if (!result) {
                    if (createEmptyState(CLEAR, &result)) {
                        printf("   Creating an empty State failed.\n");
                    }
                }
                if (result) {
                    if (addAttempt(result, USER_BLOCKED, 2, "User1", "Service1", 0, 0))
                        printf("   Could not add an attempt.\n");

                    if (dbFuncs->put(dbFuncs, key, result, USER))
                        printf("   Could not save the empty state.\n");
                    destroyAuthState(result);
                } else {
                    printf("   something went wrong.\n");
                }

                //to really test the concurrency, sleep while holding the lock
                int msSleep = (rand() % 30) + 10;
                usleep(msSleep * 1000);
                if (dbFuncs->commit_transaction(dbFuncs)) {
                    printf("   Transaction could not be committed.\n");
                    exit(0);
                }
            }
            dbFuncs->close(dbFuncs);
            exit(0);
        } else if (pID[i] < 0) {
            //failed to fork
        }
    }
    for (i = 0; i < pCount; ++i) {
        int status;
        waitpid(pID[i], &status, 0);
    }
    //all childs exited, let's look at the result
    abl_db *dbFuncs = openFunc(TEST_DIR);
    if (!dbFuncs) {
        CU_FAIL("Unable to open the db environment.");
        return;
    }
    CU_ASSERT_FALSE(dbFuncs->start_transaction(dbFuncs));
    AuthState *result = NULL;
    CU_ASSERT_FALSE(dbFuncs->get(dbFuncs, key, &result, USER));
    if (result) {
        //let's see if all our children could update it
        unsigned int nofAttempts = getNofAttempts(result);
        unsigned int expected = (unsigned int)(updateCount*pCount);
        CU_ASSERT_EQUAL(nofAttempts, expected);
        destroyAuthState(result);
    } else {
        CU_FAIL("Unable to retreive the saved data.");
    }
    CU_ASSERT_FALSE(dbFuncs->commit_transaction(dbFuncs));
    dbFuncs->close(dbFuncs);
    free(pID);
    removeDir(TEST_DIR);
}

static void addDbTests(CU_pSuite pSuite) {
    CU_add_test(pSuite, "testOpenClose", testOpenClose);
    CU_add_test(pSuite, "testWriteReadOneTransaction", testWriteReadOneTransaction);
    CU_add_test(pSuite, "testWriteReadDifferentTransactions", testWriteReadDifferentTransactions);
    CU_add_test(pSuite, "testCreateRetrieveUpdate", testCreateRetrieveUpdate);
    CU_add_test(pSuite, "testCreateRetrieveDelete", testCreateRetrieveDelete);
    CU_add_test(pSuite, "testUserIsNotHost", testUserIsNotHost);
    CU_add_test(pSuite, "testInvalidDbHome", testInvalidDbHome);
    CU_add_test(pSuite, "testConcurrency", testConcurrency);
}

#ifdef BDB_PRESENT
static int bdbSuiteInit() {
    struct stat bdbSts;
    if (stat(bdbFile, &bdbSts) == 0) {
        openFunc = load_db(bdbFile);
        //if we are unable to load the open function, just skip the rest of the tests
        if (!openFunc)
           return 1;
    } else {
        return 1;
    }
    return 0;
}

static int bdbSuiteCleanup() {
    openFunc = NULL;
    return 0;
}

static void addBdbTests() {
    CU_pSuite pSuite = NULL;
    pSuite = CU_add_suite("Berkeley DB test suite", bdbSuiteInit, bdbSuiteCleanup);
    if (NULL == pSuite)
        return;
    addDbTests(pSuite);
}
#endif

#ifdef KC_PRESENT
static int kcSuiteInit() {
    struct stat bdbSts;
    if (stat(kcFile, &bdbSts) == 0) {
        openFunc = load_db(kcFile);
        //if we are unable to load the open function, just skip the rest of the tests
        if (!openFunc)
           return 1;
    } else {
        return 1;
    }
    return 0;
}

static int kcSuiteCleanup() {
    openFunc = NULL;
    return 0;
}

static void addKcTests() {
    CU_pSuite pSuite = NULL;
    pSuite = CU_add_suite("Kyoto Cabinet test suite", kcSuiteInit, kcSuiteCleanup);
    if (NULL == pSuite)
        return;
    addDbTests(pSuite);
}
#endif

void addDatabaseTests() {
#ifdef BDB_PRESENT
    struct stat bdbSts;
    if (stat(bdbFile, &bdbSts) == 0) {
        addBdbTests();
    } else {
        printf ("Could not find the pam-abl bdb module: %s\n", bdbFile);
    }
#endif
#ifdef KC_PRESENT
    struct stat kcSts;
    if (stat(kcFile, &kcSts) == 0) {
        addKcTests();
    } else {
        printf ("Could not find the pam-abl kc module: %s\n", kcFile);
    }
#endif
}
