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

#include <string.h>

#define TEST_DIR "/tmp/pam-abl_dbtest-dir"

static DbEnvironment *openTestEnvironment() {
    DbEnvironment *environment = NULL;
    if (createEnvironment(NULL, TEST_DIR, &environment)) {
        printf("   Could not create the test environment.\n");
        return NULL;
    }
    if (!environment) {
        printf("   Environment creation succeeded, yet no valid pointer.\n");
        return NULL;
    }
    return environment;
}

static Database *openTestDb(DbEnvironment *environment) {
    Database *db = NULL;
    if (openDatabase(environment, "test.db", "test", &db)) {
        printf("   Could not open our test database.\n");
        return NULL;
    }
    if (!db) {
        printf("   Database creation succeeded, yet no valid pointer.\n");
        return NULL;
    }
    return db;
}

static void testOpenClose() {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);

    DbEnvironment *environment = openTestEnvironment();
    if (!environment)
        return;

    Database *db = openTestDb(environment);
    if (db)
        closeDatabase(db);
    destroyEnvironment(environment);
    removeDir(TEST_DIR);
}

static void testWriteReadOneTransaction() {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);

    DbEnvironment *environment = openTestEnvironment();
    if (!environment)
        return;

    Database *db = openTestDb(environment);
    if (db) {
        if (startTransaction(environment)) {
            printf("   Could not start a transaction.");
        } else {
            const char *key = "mykey";
            AuthState *result = NULL;
            if (getUserOrHostInfo(db, key, &result))
                printf("   Could not get a non existing key.\n");
            if (result)
                printf("   We expected that the key would not be found.\n");
            if (createEmptyState(CLEAR, &result)) {
                printf("   Creating an empty State failed.\n");
            } else {
                if (saveInfo(db, key, result))
                    printf("   Could not save the empty state.\n");

                AuthState *result2 = NULL;
                if (getUserOrHostInfo(db, key, &result2))
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
            if (commitTransaction(environment)) {
                printf("   Transaction could not be committed\n.");
            }
        }
        closeDatabase(db);
    }
    destroyEnvironment(environment);
    removeDir(TEST_DIR);
}

static void testWriteReadDifferentTransactions() {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);

    DbEnvironment *environment = openTestEnvironment();
    if (!environment)
        return;

    Database *db = openTestDb(environment);
    if (db) {
        if (startTransaction(environment)) {
            printf("   Could not start a transaction.");
        } else {
            const char *key = "valueKey";
            AuthState *result = NULL;
            if (createEmptyState(CLEAR, &result)) {
                printf("   Creating an empty State failed.\n");
            } else {
                if (addAttempt(result, USER_BLOCKED, 2, "User1", "Service1", 0, 0))
                    printf("   Could not add an attempt.\n");
                if (saveInfo(db, key, result))
                    printf("   Could not save the empty state.\n");
                if (commitTransaction(environment))
                    printf("   Transaction of get could not be ended.\n");
                if (startTransaction(environment))
                    printf("   The get transaction could not be opened.\n");
                AuthState *result2 = NULL;
                if (getUserOrHostInfo(db, key, &result2))
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
            if (commitTransaction(environment)) {
                printf("   Transaction could not be committed\n.");
            }
        }
        closeDatabase(db);
    }
    destroyEnvironment(environment);
    removeDir(TEST_DIR);
}

static void testCreateRetrieveUpdate() {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);

    DbEnvironment *environment = openTestEnvironment();
    if (!environment)
        return;

    Database *db = openTestDb(environment);
    if (db) {
        if (startTransaction(environment)) {
            printf("   Could not start a transaction.");
        } else {
            const char *key = "valueKey";
            AuthState *result = NULL;
            if (createEmptyState(CLEAR, &result)) {
                printf("   Creating an empty State failed.\n");
            } else {
                if (addAttempt(result, USER_BLOCKED, 2, "User1", "Service1", 0, 0))
                    printf("   Could not add an attempt.\n");
                if (saveInfo(db, key, result))
                    printf("   Could not save the empty state.\n");
                if (commitTransaction(environment))
                    printf("   Transaction of get could not be ended.\n");
                if (startTransaction(environment))
                    printf("   The get transaction could not be opened.\n");
                AuthState *result2 = NULL;
                if (getUserOrHostInfo(db, key, &result2))
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
                            if (saveInfo(db, key, result2))
                                printf("   Could not save the empty state.\n");
                            AuthState *result3 = NULL;
                            if (getUserOrHostInfo(db, key, &result3))
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
            if (commitTransaction(environment)) {
                printf("   Transaction could not be committed\n.");
            }
        }
        closeDatabase(db);
    }
    destroyEnvironment(environment);
    removeDir(TEST_DIR);
}

static void testCreateRetrieveDelete() {
    removeDir(TEST_DIR);
    makeDir(TEST_DIR);

    DbEnvironment *environment = openTestEnvironment();
    if (!environment)
        return;

    Database *db = openTestDb(environment);
    if (db) {
        if (startTransaction(environment)) {
            printf("   Could not start a transaction.");
        } else {
            const char *key = "valueKey";
            AuthState *result = NULL;
            if (createEmptyState(CLEAR, &result)) {
                printf("   Creating an empty State failed.\n");
            } else {
                if (addAttempt(result, USER_BLOCKED, 2, "User1", "Service1", 0, 0))
                    printf("   Could not add an attempt.\n");
                if (saveInfo(db, key, result))
                    printf("   Could not save the empty state.\n");
                AuthState *result2 = NULL;
                if (getUserOrHostInfo(db, key, &result2))
                    printf("   Could not get the saved key.\n");
                if (!result2)
                    printf("   The saved value could not be retrieved\n.");
                if (commitTransaction(environment))
                    printf("   Transaction of get could not be ended.\n");
                if (startTransaction(environment))
                    printf("   The get transaction could not be opened.\n");
                if (removeInfo(db, key))
                    printf("   The saved information could not be removed\n");
                AuthState *result3 = NULL;
                if (getUserOrHostInfo(db, key, &result3))
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
            if (commitTransaction(environment)) {
                printf("   Transaction could not be committed\n.");
            }
        }
        closeDatabase(db);
    }
    destroyEnvironment(environment);
    removeDir(TEST_DIR);
}

void runDatabaseTests() {
    printf("Db test start.\n");
    printf(" Starting testOpenClose.\n");
    testOpenClose();
    printf(" Starting testWriteReadOneTransaction.\n");
    testWriteReadOneTransaction();
    printf(" Starting testWriteReadDifferentTransactions.\n");
    testWriteReadDifferentTransactions();
    printf(" Starting testCreateRetrieveUpdate.\n");
    testCreateRetrieveUpdate();
    printf(" Starting testCreateRetrieveDelete.\n");
    testCreateRetrieveDelete();
    printf("Db test end.\n");
}
