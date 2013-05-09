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

#include "typefun.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static char *writeHeader(char *bufferPtr, int state, unsigned int count) {
    *((int*)bufferPtr) = state;
    bufferPtr += sizeof(int);
    *((unsigned int*)bufferPtr) = count;
    bufferPtr += sizeof(unsigned int);
    return bufferPtr;
}

//writes an attempt to the given buffer and returns a pointer right after the written data
static void *writeAttempt(void *data, time_t pTime, BlockReason reason, const char *user, const char *service) {
    char *bufferPtr = data;
    *((time_t*)bufferPtr) = pTime;
    bufferPtr += sizeof(time_t);

    *((int*)bufferPtr) = reason;
    bufferPtr += sizeof(int);

    strcpy(bufferPtr, user);
    bufferPtr += strlen(user) + 1;

    strcpy(bufferPtr, service);
    bufferPtr += strlen(service) + 1;

    return bufferPtr;
}

static void compareAttempt(AuthState *state, time_t pTime, BlockReason reason, const char *user, const char *service, int isLastAttempt) {
    AuthAttempt attempt;
    memset(&attempt, 0, sizeof(AuthState));
    if (nextAttempt(state, &attempt)) {
        CU_FAIL("Could not retrieve the next attempt.");
        return;
    }

    CU_ASSERT_EQUAL(attempt.m_time, pTime);
    CU_ASSERT_EQUAL(attempt.m_reason, reason);
    CU_ASSERT_STRING_EQUAL(attempt.m_service, service);
    CU_ASSERT_STRING_EQUAL(attempt.m_userOrHost, user);

    if (isLastAttempt) {
        memset(&attempt, 0, sizeof(AuthState));
        CU_ASSERT(nextAttempt(state, &attempt));
    }
}

static void testMultipleAttempts() {
    //I think it will be big enough for our small test
    char buffer[1024];
    char userBuffer[100];
    char serviceBuffer[100];
    char *bufferPtr = &buffer[0];

    bufferPtr = writeHeader(bufferPtr, CLEAR, 10);

    int counter = 0;
    for (; counter < 10; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);
        bufferPtr = writeAttempt(bufferPtr, counter, AUTH_FAILED, &userBuffer[0], &serviceBuffer[0]);
    }
    AuthState *result;
    if (createAuthState(&buffer[0], (size_t)(bufferPtr - &buffer[0]), &result)) {
        CU_FAIL("Could not create AuthState from buffer.");
        return;
    }

    if (!result) {
        CU_FAIL("AutState was not filled in.");
        return;
    }

    //write over the buffer, make sure that AuthState does not read our old buffer
    memset(&buffer[0], 3, sizeof(buffer));

    CU_ASSERT_EQUAL(getState(result), CLEAR);
    CU_ASSERT_EQUAL(getNofAttempts(result), 10);

    for (counter = 0; counter < 10; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);
        compareAttempt(result, counter, AUTH_FAILED, &userBuffer[0], &serviceBuffer[0], counter == 9 ? 1 : 0);
    }

    destroyAuthState(result);
}

static void testMultipleAttemptsLastIncomplete() {
    //I think it will be big enough for our small test
    char buffer[1024];
    char userBuffer[100];
    char serviceBuffer[100];
    char *bufferPtr = &buffer[0];

    bufferPtr = writeHeader(bufferPtr, CLEAR, 5);

    int counter = 0;
    for (; counter < 5; ++counter) {
        sprintf(&userBuffer[0], "User2_%d", counter);
        sprintf(&serviceBuffer[0], "Service2_%d", counter);
        bufferPtr = writeAttempt(bufferPtr, counter, AUTH_FAILED, &userBuffer[0], &serviceBuffer[0]);
    }
    AuthState *result;
    if (createAuthState(&buffer[0], ((size_t)(bufferPtr - &buffer[0])) - 2, &result)) {
        CU_FAIL("Could not create AuthState from buffer.");
        return;
    }

    if (!result) {
        CU_FAIL("AutState was not filled in.");
        return;
    }

    //write over the buffer, make sure that AuthState does not read our old buffer
    memset(&buffer[0], 3, sizeof(buffer));

    CU_ASSERT_EQUAL(getState(result), CLEAR);
    CU_ASSERT_EQUAL(getNofAttempts(result), 5);

    for (counter = 0; counter < 4; ++counter) {
        sprintf(&userBuffer[0], "User2_%d", counter);
        sprintf(&serviceBuffer[0], "Service2_%d", counter);
        compareAttempt(result, counter, AUTH_FAILED, &userBuffer[0], &serviceBuffer[0], 0);
    }

    AuthAttempt attempt;
    memset(&attempt, 0, sizeof(AuthState));
    CU_ASSERT(nextAttempt(result, &attempt));
    destroyAuthState(result);
}

static void testCorrectOneAttempt() {
    char buffer[100];
    const char *user = "MyUser";
    const char *service = "MyService";
    char *bufferPtr = &buffer[0];

    bufferPtr = writeHeader(bufferPtr, BLOCKED, 1);
    bufferPtr = writeAttempt(bufferPtr, 11, USER_BLOCKED, user, service);

    AuthState *result;
    if (createAuthState(&buffer[0], (size_t)(bufferPtr - &buffer[0]), &result)) {
        CU_FAIL("Could not create AuthState from buffer.");
        return;
    }

    if (!result) {
        CU_FAIL("AutState was not filled in.");
        return;
    }

    //write over the buffer, make sure that AuthState does not read our old buffer
    memset(&buffer[0], 3, sizeof(buffer));

    CU_ASSERT_EQUAL(getState(result), BLOCKED);

    compareAttempt(result, 11, USER_BLOCKED, user, service, 1);

    destroyAuthState(result);
}

static void testEmptyService() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        CU_FAIL("Could not create an empty state.");
        return;
    }
    int i;
    for (i = 0; i < 10; ++i) {
        //addAttempt(AuthState *state, BlockReason reason, time_t pTime, const char *userOrHost, const char *service)
        CU_ASSERT_FALSE(addAttempt(state, HOST_BLOCKED, i, "", "", 0, 0));
    }
    firstAttempt(state);
    AuthAttempt attempt;
    i = 0;
    while (nextAttempt(state, &attempt) == 0) {
        CU_ASSERT_FALSE(*attempt.m_service);
        CU_ASSERT_FALSE(*attempt.m_userOrHost);
        CU_ASSERT_EQUAL(attempt.m_time, i);
        ++i;
    }
    CU_ASSERT_EQUAL(i, 10);
    destroyAuthState(state);
}

static void testEmptyAttempts() {
    char buffer[100];
    writeHeader(&buffer[0], CLEAR, 0);
    AuthState *result;
    if (createAuthState(&buffer[0], sizeof(int)+sizeof(unsigned int), &result)) {
        CU_FAIL("Could not create AuthState from buffer.");
        return;
    }

    AuthAttempt attempt;
    CU_ASSERT(nextAttempt(result, &attempt));
    destroyAuthState(result);
}

static void testCreateEmptyAttempt() {
    char buffer[100];
    writeHeader(&buffer[0], CLEAR, 0);
    AuthState *result;
    if (createAuthState(&buffer[0], sizeof(int)+sizeof(unsigned int), &result)) {
        CU_FAIL("Could not create AuthState from buffer.");
        return;
    }

    AuthState *empty = NULL;
    if (createEmptyState(CLEAR, &empty)) {
        CU_FAIL("Could not create empty AuthState.");
        return;
    }

    if (!empty) {
        CU_FAIL("Creation succeeded, yet no valid pointer.");
        return;
    }

    if (result->m_usedSize != empty->m_usedSize) {
        CU_FAIL("The size of the empty State does not match.");
        return;
    }

    CU_ASSERT_FALSE(memcmp(result->m_data, empty->m_data, empty->m_usedSize));
    destroyAuthState(result);
    destroyAuthState(empty);
}

static void testAddAttempt() {
    char buffer[1024];
    char userBuffer[100];
    char serviceBuffer[100];
    char *bufferPtr = &buffer[0];

    bufferPtr = writeHeader(bufferPtr, CLEAR, 10);

    char tmp[100];
    writeHeader(&tmp[0], CLEAR, 0);
    AuthState *result;
    if (createAuthState(&tmp[0], sizeof(int)+sizeof(unsigned int), &result)) {
        CU_FAIL("Could not create AuthState from buffer.");
        return;
    }

    int counter = 0;
    for (; counter < 10; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);
        bufferPtr = writeAttempt(bufferPtr, counter, AUTH_FAILED, &userBuffer[0], &serviceBuffer[0]);

        if (addAttempt(result, AUTH_FAILED, counter, &userBuffer[0], &serviceBuffer[0], 0, 0)) {
            CU_FAIL("Could not add an attempt.");
            return;
        }
    }

    if (result->m_usedSize != (size_t)(bufferPtr - &buffer[0])) {
        CU_FAIL("The buffer sizes do not match.");
        return;
    } else {
        if (memcmp(&buffer[0], result->m_data, result->m_usedSize)) {
            CU_FAIL("The buffers are not equal.");
            return;
        }
    }
    destroyAuthState(result);
}

static void testInvalidSize() {
    char buffer[100];
    const char *user = "MyUser";
    const char *service = "MyService";
    char *bufferPtr = &buffer[0];

    bufferPtr = writeHeader(bufferPtr, BLOCKED, 1);
    bufferPtr = writeAttempt(bufferPtr, 11, USER_BLOCKED, user, service);

    //we know that the buffer is filled with 33 bytes, let's tell that it's smaller
    size_t reportSize = 32;
    for (;reportSize >= sizeof(int)+sizeof(unsigned int); --reportSize) {
        AuthState *result;
        //this should still succeed
        if (createAuthState(&buffer[0], reportSize, &result)) {
            CU_FAIL("Could not create AuthState from buffer.");
            continue;
        }

        AuthAttempt attempt;
        memset(&attempt, 0, sizeof(AuthState));
        CU_ASSERT(nextAttempt(result, &attempt));
        destroyAuthState(result);
    }

    AuthState *temp = NULL;
    //if we give it a real small size, we expect it to fail while creating the AuthState
    for (reportSize = 0; reportSize < sizeof(unsigned int)+sizeof(int); ++reportSize) {
        CU_ASSERT(createAuthState(&buffer[0], reportSize, &temp));
    }
}

static void testPurgeNothingRemoved() {
    char buffer[1024];
    char userBuffer[100];
    char serviceBuffer[100];
    char *bufferPtr = &buffer[0];

    bufferPtr = writeHeader(bufferPtr, CLEAR, 10);

    int counter = 0;
    for (; counter < 10; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);
        bufferPtr = writeAttempt(bufferPtr, counter+10, AUTH_FAILED, &userBuffer[0], &serviceBuffer[0]);
    }
    AuthState *result;
    if (createAuthState(&buffer[0], (size_t)(bufferPtr - &buffer[0]), &result)) {
        CU_FAIL("Could not create AuthState from buffer.");
    }

    if (!result) {
        CU_FAIL("AutState was not filled in.");
        return;
    }

    //write over the buffer, make sure that AuthState does not read our old buffer
    memset(&buffer[0], 3, sizeof(buffer));

    //let's purge the damn thing, nothing should have been deleted
    purgeAuthState(result, 5);

    CU_ASSERT_EQUAL(getState(result), CLEAR);
    CU_ASSERT_EQUAL(getNofAttempts(result), 10);

    for (counter = 0; counter < 10; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);
        compareAttempt(result, counter+10, AUTH_FAILED, &userBuffer[0], &serviceBuffer[0], counter == 9 ? 1 : 0);
    }
    destroyAuthState(result);
}

static void testPurgeSomeRemoved() {
    char buffer[1024];
    char userBuffer[100];
    char serviceBuffer[100];
    char *bufferPtr = &buffer[0];

    bufferPtr = writeHeader(bufferPtr, CLEAR, 10);

    int counter = 0;
    for (; counter < 10; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);
        bufferPtr = writeAttempt(bufferPtr, counter, AUTH_FAILED, &userBuffer[0], &serviceBuffer[0]);
    }
    AuthState *result;
    if (createAuthState(&buffer[0], (size_t)(bufferPtr - &buffer[0]), &result)) {
        CU_FAIL("Could not create AuthState from buffer.");
        return;
    }

    if (!result) {
        CU_FAIL("AutState was not filled in.");
        return;
    }

    //write over the buffer, make sure that AuthState does not read our old buffer
    memset(&buffer[0], 3, sizeof(buffer));

    //let's purge the damn thing, some of them should be deleted
    purgeAuthState(result, 5);

    CU_ASSERT_EQUAL(getState(result), CLEAR);
    CU_ASSERT_EQUAL(getNofAttempts(result), 5);

    for (counter = 5; counter < 10; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);
        compareAttempt(result, counter, AUTH_FAILED, &userBuffer[0], &serviceBuffer[0], counter == 9 ? 1 : 0);
    }
    destroyAuthState(result);
}

static void testPurgeAllButOneRemoved() {
    char buffer[1024];
    char userBuffer[100];
    char serviceBuffer[100];
    char *bufferPtr = &buffer[0];

    bufferPtr = writeHeader(bufferPtr, CLEAR, 10);

    int counter = 0;
    for (; counter < 10; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);
        bufferPtr = writeAttempt(bufferPtr, counter, AUTH_FAILED, &userBuffer[0], &serviceBuffer[0]);
    }
    AuthState *result;
    if (createAuthState(&buffer[0], (size_t)(bufferPtr - &buffer[0]), &result)) {
        CU_FAIL("Could not create AuthState from buffer.");
        return;
    }

    if (!result) {
        CU_FAIL("AutState was not filled in.");
        return;
    }

    //write over the buffer, make sure that AuthState does not read our old buffer
    memset(&buffer[0], 3, sizeof(buffer));

    //let's purge the damn thing, all but one should be removed
    purgeAuthState(result, 9);

    CU_ASSERT_EQUAL(getState(result), CLEAR);
    CU_ASSERT_EQUAL(getNofAttempts(result), 1);

    // is the 9-th attempt still here?
    sprintf(&userBuffer[0], "User_%d", 9);
    sprintf(&serviceBuffer[0], "Service_%d", 9);
    compareAttempt(result, 9, AUTH_FAILED, &userBuffer[0], &serviceBuffer[0], 1);
    destroyAuthState(result);
}

static void testPurgeEmptyAttemptList() {
    char buffer[100];
    writeHeader(&buffer[0], CLEAR, 0);
    AuthState *result;
    if (createAuthState(&buffer[0], sizeof(int)+sizeof(unsigned int), &result)) {
        CU_FAIL("Could not create AuthState from buffer.");
        return;
    }

    //purging will not do anything normally, because there is nothing to remove
    purgeAuthState(result, 9);

    CU_ASSERT_EQUAL(getState(result), CLEAR);
    CU_ASSERT_EQUAL(getNofAttempts(result), 0);

    AuthAttempt attempt;
    CU_ASSERT(nextAttempt(result, &attempt));
    destroyAuthState(result);
}

static void testPurgeAllRemoved() {
    char buffer[1024];
    char userBuffer[100];
    char serviceBuffer[100];
    char *bufferPtr = &buffer[0];

    bufferPtr = writeHeader(bufferPtr, CLEAR, 10);

    int counter = 0;
    for (; counter < 10; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);
        bufferPtr = writeAttempt(bufferPtr, counter, AUTH_FAILED, &userBuffer[0], &serviceBuffer[0]);
    }
    AuthState *result;
    if (createAuthState(&buffer[0], (size_t)(bufferPtr - &buffer[0]), &result)) {
        CU_FAIL("Could not create AuthState from buffer.");
        return;
    }

    if (!result) {
        CU_FAIL("AutState was not filled in.");
        return;
    }

    //write over the buffer, make sure that AuthState does not read our old buffer
    memset(&buffer[0], 3, sizeof(buffer));

    //let's purge the damn thing, all should be removed
    purgeAuthState(result, 1000);

    CU_ASSERT_EQUAL(getState(result), CLEAR);
    CU_ASSERT_EQUAL(getNofAttempts(result), 0);

    AuthAttempt attempt;
    CU_ASSERT(nextAttempt(result, &attempt));

    destroyAuthState(result);
}

static void testPurgePerformance(int maxCount) {
    char *buffer = malloc(((maxCount / 1000)+1) * 50000); //for 1000 entries we will probably need something of a 35k, make it 50 to be sure
    char userBuffer[100];
    char serviceBuffer[100];
    char *bufferPtr = buffer;
    printf("Type performance test with %d attempts:\n", maxCount);
    bufferPtr = writeHeader(bufferPtr, CLEAR, maxCount);

    clock_t begin = clock();
    int counter = 0;
    for (; counter < maxCount; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);
        bufferPtr = writeAttempt(bufferPtr, counter, AUTH_FAILED, &userBuffer[0], &serviceBuffer[0]);
    }
    AuthState *result;
    printf("   - %d bytes.\n", (int)(bufferPtr - buffer));
    if (createAuthState(buffer, (size_t)(bufferPtr - buffer), &result)) {
        printf("   Could not create AuthState from buffer.\n");
        return;
    }

    if (!result) {
        printf("   AutState was not filled in.\n");
        return;
    }
    clock_t end = clock();
    double elapsed = (double)(end - begin) / CLOCKS_PER_SEC;
    printf("   - creating took us %f seconds.\n", elapsed);

    begin = clock();
    purgeAuthState(result, maxCount + 1000);
    end = clock();
    elapsed = (double)(end - begin) / CLOCKS_PER_SEC;
    printf("   - iterating took us %f seconds.\n", elapsed);

    destroyAuthState(result);
    free(buffer);
}

static void testAddAttemptLimitReached() {
    char userBuffer[100];
    char serviceBuffer[100];

    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        CU_FAIL("Could not create an empty AuthState.");
        return;
    }

    int counter = 1;
    unsigned int expected = 0;
    for (; counter <= 100; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);

        if (addAttempt(state, AUTH_FAILED, counter, &userBuffer[0], &serviceBuffer[0], 5, 10)) {
            CU_FAIL("Could not add an attempt.");
            return;
        }
        ++expected;
        if (expected == 11)
            expected = 5;
        unsigned int nof = getNofAttempts(state);
        if (nof != expected) {
            CU_FAIL("The count is wrong.");
        } else {
            firstAttempt(state);
            int start = counter - expected + 1;
            AuthAttempt attempt;
            while (nextAttempt(state, &attempt) == 0) {
                sprintf(&userBuffer[0], "User_%d", start);
                CU_ASSERT_STRING_EQUAL(attempt.m_userOrHost, &userBuffer[0]);
                ++start;
            }
            CU_ASSERT_EQUAL(start, counter+1);
        }
    }
    destroyAuthState(state);
}

static void testAddAttemptLowerLimitZero() {
    char userBuffer[100];
    char serviceBuffer[100];

    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        CU_FAIL("Could not create an empty AuthState.");
        return;
    }

    int counter = 1;
    unsigned int expected = 0;
    for (; counter <= 100; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);

        if (addAttempt(state, AUTH_FAILED, counter, &userBuffer[0], &serviceBuffer[0], 0, 10)) {
            CU_FAIL("Could not add an attempt.");
            return;
        }
        ++expected;
        if (expected == 11)
            expected = 1;
        unsigned int nof = getNofAttempts(state);
        if (nof != expected) {
            CU_FAIL("The count is wrong.\n");
        } else {
            firstAttempt(state);
            int start = counter - expected + 1;
            AuthAttempt attempt;
            while (nextAttempt(state, &attempt) == 0) {
                sprintf(&userBuffer[0], "User_%d", start);
                if (strcmp(attempt.m_userOrHost, &userBuffer[0]) != 0) {
                    CU_FAIL("Receiven an unexpected username.");
                    break;
                }
                ++start;
            }
            CU_ASSERT_EQUAL(start, counter+1);
        }
    }
    destroyAuthState(state);
}

static void testAddAttemptLimitsTheSame() {
    char userBuffer[100];
    char serviceBuffer[100];

    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        CU_FAIL("Could not create an empty AuthState.");
        return;
    }

    int counter = 1;
    for (; counter <= 100; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);

        if (addAttempt(state, AUTH_FAILED, counter, &userBuffer[0], &serviceBuffer[0], 10, 10)) {
            CU_FAIL("Could not add an attempt.");
            return;
        }

        unsigned int nof = getNofAttempts(state);
        if (counter <= 10) {
            CU_ASSERT_EQUAL((int)nof, counter);
        } else {
            if (nof != 10) {
                CU_FAIL("The count is wrong, expected 10.");
            } else {
                firstAttempt(state);
                int start = counter - 10 + 1;
                AuthAttempt attempt;
                while (nextAttempt(state, &attempt) == 0) {
                    sprintf(&userBuffer[0], "User_%d", start);
                    if (strcmp(attempt.m_userOrHost, &userBuffer[0]) != 0) {
                        CU_FAIL("Received un unexpected username.");
                        break;
                    }
                    ++start;
                }
                CU_ASSERT_EQUAL(start, counter+1);
            }
        }
    }
    destroyAuthState(state);
}


void addTypeTests() {
    CU_pSuite pSuite = NULL;
    pSuite = CU_add_suite("TypeTests", NULL, NULL);
    if (NULL == pSuite)
        return;
    CU_add_test(pSuite, "testCorrectOneAttempt", testCorrectOneAttempt);
    CU_add_test(pSuite, "testEmptyAttempts", testEmptyAttempts);
    CU_add_test(pSuite, "testCreateEmptyAttempt", testCreateEmptyAttempt);
    CU_add_test(pSuite, "testInvalidSize", testInvalidSize);
    CU_add_test(pSuite, "testMultipleAttempts", testMultipleAttempts);
    CU_add_test(pSuite, "testMultipleAttemptsLastIncomplete", testMultipleAttemptsLastIncomplete);
    CU_add_test(pSuite, "testAddAttempt", testAddAttempt);
    CU_add_test(pSuite, "testAddAttemptLimitReached", testAddAttemptLimitReached);
    CU_add_test(pSuite, "testAddAttemptLowerLimitZero", testAddAttemptLowerLimitZero);
    CU_add_test(pSuite, "testAddAttemptLimitsTheSame", testAddAttemptLimitsTheSame);
    CU_add_test(pSuite, "testEmptyService", testEmptyService);
    CU_add_test(pSuite, "testPurgeNothingRemoved", testPurgeNothingRemoved);
    CU_add_test(pSuite, "testPurgeSomeRemoved", testPurgeSomeRemoved);
    CU_add_test(pSuite, "testPurgeAllButOneRemoved", testPurgeAllButOneRemoved);
    CU_add_test(pSuite, "testPurgeEmptyAttemptList", testPurgeEmptyAttemptList);
    CU_add_test(pSuite, "testPurgeAllRemoved", testPurgeAllRemoved);
}

void runPerformanceTest() {
    testPurgePerformance(1000);
    testPurgePerformance(100000);
}
