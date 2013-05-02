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

#define TEST_DIR "/tmp/pam-abl_dbtest-dir"

typedef enum {
    DB_BDB,
    DB_KC,
} DbType;

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
static int testOpenClose(abl_db_open_ptr openFunc) {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);
    int retValue = 0;

    abl_db *db = openFunc(TEST_DIR);
    if (!db) {
        printf("   Unable to open the db environment\n");
        return 1;
    }
    if (!db->put) {
        printf("   put function is not defined.\n");
        retValue = 1;
    }
    if (!db->del) {
        printf("   del function is not defined.\n");
        retValue = 1;
    }
    if (!db->get) {
        printf("   get function is not defined.\n");
        retValue = 1;
    }
    if (!db->c_open) {
        printf("   c_open function is not defined.\n");
        retValue = 1;
    }
    if (!db->c_close) {
        printf("   c_close function is not defined.\n");
        retValue = 1;
    }
    if (!db->c_get) {
        printf("   c_get function is not defined.\n");
        retValue = 1;
    }
    if (!db->start_transaction) {
        printf("   start_transaction function is not defined.\n");
        retValue = 1;
    }
    if (!db->commit_transaction) {
        printf("    commit_transaction function is not defined.\n");
        retValue = 1;
    }
    if (!db->abort_transaction) {
        printf("   abort_transaction function is not defined.\n");
        retValue = 1;
    }
    if (!db->close) {
        printf("   close function is not defined.\n");
        retValue = 1;
    } else {
        db->close(db);
    }

    removeDir(TEST_DIR);
    return retValue;
}

static void testWriteReadOneTransactionWithObjectType(abl_db *db, ablObjectType type) {
    const char *key = "mykey";
    AuthState *result = NULL;
    if (db->get(db, key, &result, type))
        printf("   Could not get a non existing key.\n");
    if (result)
        printf("   We expected that the key would not be found.\n");
    if (createEmptyState(CLEAR, &result)) {
        printf("   Creating an empty State failed.\n");
    } else {
        if (db->put(db, key, result, type))
            printf("   Could not save the empty state.\n");

        AuthState *result2 = NULL;
        if (db->get(db, key, &result2, type))
            printf("   Could not get the saved key.\n");

        if (result && result2) {
            if (result->m_usedSize != result2->m_usedSize) {
                printf("   The size of the saved state and the retrieved state is not the same.\n");
            } else {
                if (memcmp(result->m_data, result2->m_data, result->m_usedSize))
                    printf("   The saved and retrieved values are not the same.\n");
            }
        }
        if (result)
            destroyAuthState(result);
        if (result2)
            destroyAuthState(result2);
    }
}

static void testWriteReadOneTransaction(abl_db_open_ptr openFunc) {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);

    abl_db *db = openFunc(TEST_DIR);
    if (!db) {
        printf("   Unable to open the db environment\n");
        return;
    }

    if (db->start_transaction(db)) {
        //starting transaction failed
        printf("   Unable to open a transaction\n");
    } else {
        testWriteReadOneTransactionWithObjectType(db, HOST);
        testWriteReadOneTransactionWithObjectType(db, USER);
        if (db->commit_transaction(db))
            printf("   Transaction could not be committed.\n");
    }
    db->close(db);
    removeDir(TEST_DIR);
}

static void testWriteReadDifferentTransactionsWithObjectType(abl_db *db, ablObjectType type) {
    if (db->start_transaction(db)) {
        //starting transaction failed
        printf("   Unable to open a transaction\n");
    } else {
        const char *key = "valueKey";
        AuthState *result = NULL;
        if (createEmptyState(CLEAR, &result)) {
            printf("   Creating an empty State failed.\n");
        } else {
            if (addAttempt(result, USER_BLOCKED, 2, "User1", "Service1", 0, 0))
                printf("   Could not add an attempt.\n");
            if (db->put(db, key, result, type))
                printf("   Could not save the empty state.\n");
            if (db->commit_transaction(db))
                printf("   Transaction of get could not be ended.\n");
            if (db->start_transaction(db))
                printf("   The get transaction could not be opened.\n");
            AuthState *result2 = NULL;
            if (db->get(db, key, &result2, type))
                printf("   Could not get the saved key.\n");

            if (result && result2) {
                if (result->m_usedSize != result2->m_usedSize) {
                    printf("   The size of the saved state and the retrieved state is not the same.\n");
                } else {
                    if (memcmp(result->m_data, result2->m_data, result->m_usedSize))
                        printf("   The saved and retrieved values are not the same.\n");
                }
            }
            if (result)
                destroyAuthState(result);
            if (result2)
                destroyAuthState(result2);
        }
        if (db->commit_transaction(db)) {
            printf("   Transaction could not be committed.\n");
        }
    }
}

static void testWriteReadDifferentTransactions(abl_db_open_ptr openFunc) {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);

    abl_db *db = openFunc(TEST_DIR);
    if (!db) {
        printf("   Unable to open the db environment\n");
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
        printf("   The get transaction could not be opened.\n");
        return;
    }
    if (createEmptyState(CLEAR, &result)) {
        printf("   Creating an empty State failed.\n");
    } else {
        if (addAttempt(result, USER_BLOCKED, 2, "User1", "Service1", 0, 0))
            printf("   Could not add an attempt.\n");
        if (db->put(db, key, result, type))
            printf("   Could not save the empty state.\n");
        if (db->commit_transaction(db))
            printf("   Transaction of get could not be ended.\n");
        if (db->start_transaction(db))
            printf("   The get transaction could not be opened.\n");
        AuthState *result2 = NULL;
        if (db->get(db, key, &result2, type))
            printf("   Could not get the saved key.\n");

        if (result && result2) {
            if (result->m_usedSize != result2->m_usedSize) {
                printf("   The size of the saved state and the retrieved state is not the same.\n");
            } else {
                if (memcmp(result->m_data, result2->m_data, result->m_usedSize)) {
                    printf("   The saved and retrieved values are not the same.\n");
                } else {
                    if (addAttempt(result2, USER_BLOCKED, 50, "User2", "Service2", 0, 0))
                        printf("   Could not add a second attempt.");
                    if (db->put(db, key, result2, type))
                        printf("   Could not save the empty state.\n");
                    AuthState *result3 = NULL;
                    if (db->get(db, key, &result3, type))
                        printf("   Could not get the updated value.\n");
                    if (result3) {
                        if (getNofAttempts(result3) != 2
                            || result2->m_usedSize != result3->m_usedSize
                            || memcmp(result2->m_data, result3->m_data, result2->m_usedSize))
                            printf("   Did not retrieve the updated value.\n");
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
    if (db->commit_transaction(db)) {
        printf("   Transaction could not be committed.\n");
    }
}

static void testCreateRetrieveUpdate(abl_db_open_ptr openFunc) {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);

    abl_db *db = openFunc(TEST_DIR);
    if (!db) {
        printf("   Unable to open the db environment\n");
        return;
    }
    testCreateRetrieveUpdateWithObjectType(db, USER);
    testCreateRetrieveUpdateWithObjectType(db, HOST);

    db->close(db);
    removeDir(TEST_DIR);
}

static void testCreateRetrieveDeleteWithObjectType(abl_db *db, ablObjectType type) {
    if (db->start_transaction(db)) {
        printf("   Could not start a transaction.");
    } else {
        const char *key = "valueKey";
        AuthState *result = NULL;
        if (createEmptyState(CLEAR, &result)) {
            printf("   Creating an empty State failed.\n");
        } else {
            if (addAttempt(result, USER_BLOCKED, 2, "User1", "Service1", 0, 0))
                printf("   Could not add an attempt.\n");
            if (db->put(db, key, result, type))
                printf("   Could not save the empty state.\n");
            AuthState *result2 = NULL;
            if (db->get(db, key, &result2, type))
                printf("   Could not get the saved key.\n");
            if (!result2)
                printf("   The saved value could not be retrieved.\n");
            if (db->commit_transaction(db))
                printf("   Transaction of get could not be ended.\n");
            if (db->start_transaction(db))
                printf("   The get transaction could not be opened.\n");
            if (db->del(db, key, type))
                printf("   The saved information could not be removed\n");
            AuthState *result3 = NULL;
            if (db->get(db, key, &result3, type))
                printf("   An error occured while retrieving an unexisting record.\n");
            if (result3)
                printf("   The removed information still exists.\n");
            if (result)
                destroyAuthState(result);
            if (result2)
                destroyAuthState(result2);
            if (result3)
                destroyAuthState(result3);
        }
        if (db->commit_transaction(db)) {
            printf("   Transaction could not be committed.\n");
        }
    }
}

static void testCreateRetrieveDelete(abl_db_open_ptr openFunc) {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);

    abl_db *db = openFunc(TEST_DIR);
    if (!db) {
        printf("   Unable to open the db environment\n");
        return;
    }
    testCreateRetrieveDeleteWithObjectType(db, USER);
    testCreateRetrieveDeleteWithObjectType(db, HOST);

    db->close(db);
    removeDir(TEST_DIR);
}

static void testUserIsNotHost(abl_db_open_ptr openFunc) {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);

    abl_db *db = openFunc(TEST_DIR);
    if (!db) {
        printf("   Unable to open the db environment\n");
        return;
    }
    const char *key = "valueKey";
    AuthState *result = NULL;
    if (db->start_transaction(db)) {
        printf("   The get transaction could not be opened.\n");
        return;
    }
    if (createEmptyState(CLEAR, &result)) {
        printf("   Creating an empty State failed.\n");
    } else {
        if (addAttempt(result, USER_BLOCKED, 2, "User1", "Service1", 0, 0))
            printf("   Could not add an attempt.\n");
        if (db->put(db, key, result, USER))
            printf("   Could not save the empty state.\n");
        AuthState *result2 = NULL;
        if (db->get(db, key, &result2, USER))
            printf("   Could not get the saved key.\n");

        AuthState *result3 = NULL;
        if (db->get(db, key, &result3, HOST))
            printf("   Could not get the saved key.\n");
        if (result3)
            printf("   Could get a USER by retrieving a HOST.\n");

        if (result)
            destroyAuthState(result);
        if (result2)
            destroyAuthState(result2);
    }
    if (db->commit_transaction(db)) {
        printf("   Transaction could not be committed.\n");
    }

    db->close(db);
    removeDir(TEST_DIR);
}

static void testInvalidDbHome(abl_db_open_ptr openFunc) {
    const char *dbhome = "/tmp/nonexisting/dbhome";
    abl_db *db = openFunc(dbhome);
    if (db) {
        printf("   Could open the db using a non existing directory.\n");
    }
}

static void testConcurrency(abl_db_open_ptr openFunc, DbType dbType) {
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
        printf("   Unable to open the db environment\n");
        return;
    }
    if (dbFuncs->start_transaction(dbFuncs)) {
        printf("   The get transaction could not be opened.\n");
    }
    AuthState *result = NULL;
    if (dbFuncs->get(dbFuncs, key, &result, USER))
        printf("   Could not get the saved key.\n");
    if (result) {
        //let's see if all our children could update it
        unsigned int nofAttempts = getNofAttempts(result);
        unsigned int expected = (unsigned int)(updateCount*pCount);
        if (nofAttempts != expected) {
            printf("   Not all updates made it in the db. %u != %u\n", nofAttempts, expected);
        }
        destroyAuthState(result);
    } else {
        printf("   Unable to retreive the saved data.\n");
    }
    if (dbFuncs->commit_transaction(dbFuncs)) {
        printf("   The transaction could not be closed.\n");
    }
    dbFuncs->close(dbFuncs);
    free(pID);
    removeDir(TEST_DIR);
}

static void runTestsWithDb(const char *db, const char *dbName, DbType dbType) {
    printf(" Db test start with %s.\n", dbName);
    abl_db_open_ptr openFunc = load_db(db);
    //if we are unable to load the open function, just skip the rest of the tests
    if (!openFunc)
       return;
    printf("  Starting testOpenClose.\n");
    //abort the test as soon as we notice the open/close test failes
    if (testOpenClose(openFunc)) {
        printf("  Aborting db test with %s.\n", dbName);
        return;
    }
    printf("  Starting testWriteReadOneTransaction.\n");
    testWriteReadOneTransaction(openFunc);
    printf("  Starting testWriteReadDifferentTransactions.\n");
    testWriteReadDifferentTransactions(openFunc);
    printf("  Starting testCreateRetrieveUpdate.\n");
    testCreateRetrieveUpdate(openFunc);
    printf("  Starting testCreateRetrieveDelete.\n");
    testCreateRetrieveDelete(openFunc);
    printf("  Starting testUserIsNotHost.\n");
    testUserIsNotHost(openFunc);
    printf("  Starting testInvalidDbHome.\n");
    testInvalidDbHome(openFunc);
    printf("  Starting testConcurrency.\n");
    testConcurrency(openFunc, dbType);
    printf(" Db test end.\n");
}

void runDatabaseTests() {
    printf("Starting db tests\n");
#ifdef BDB_PRESENT
    const char *bdbFile = "./pam_abl_bdb.so";
    struct stat bdbSts;
    if (stat(bdbFile, &bdbSts) == 0) {
        runTestsWithDb(bdbFile, "Berkeley db", DB_BDB);
    } else {
        printf ("Could not find the pam-abl bdb module: %s\n", bdbFile);
    }
#endif
#ifdef KC_PRESENT
    const char *kcFile = "./pam_abl_kc.so";
    struct stat kcSts;
    if (stat(kcFile, &kcSts) == 0) {
        runTestsWithDb(kcFile, "Kyoto Cabinet", DB_KC);
    } else {
        printf ("Could not find the pam-abl kc module: %s\n", kcFile);
    }
#endif
    printf("db tests end\n");
}
