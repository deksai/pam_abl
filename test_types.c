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
        printf("   Could not retrieve the next attempt.\n");
        return;
    }

    if (attempt.m_time != pTime) {
        printf("   Attempt time was incorrect.\n");
    }

    if (attempt.m_reason != reason) {
        printf("   Block reason was incorrect.\n");
    }

    if (strcmp(attempt.m_service, service) != 0) {
        printf("   Service was incorrect.\n");
    }

    if (strcmp(attempt.m_userOrHost, user) != 0) {
        printf("   User was incorrect.\n");
    }

    if (isLastAttempt) {
        memset(&attempt, 0, sizeof(AuthState));
        if (!nextAttempt(state, &attempt)) {
            printf("   We could read another Attempt.\n");
        }
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
        printf("   Could not create AuthState from buffer.\n");
        return;
    }

    if (!result) {
        printf("   AutState was not filled in.\n");
        return;
    }

    //write over the buffer, make sure that AuthState does not read our old buffer
    memset(&buffer[0], 3, sizeof(buffer));

    if (getState(result) != CLEAR) {
        printf("   State was incorrect.\n");
    }

    if (getNofAttempts(result) != 10) {
        printf("   Number of attempts was incorrect.\n");
    }

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
        printf("   Could not create AuthState from buffer.\n");
        return;
    }

    if (!result) {
        printf("   AutState was not filled in.\n");
        return;
    }

    //write over the buffer, make sure that AuthState does not read our old buffer
    memset(&buffer[0], 3, sizeof(buffer));

    if (getState(result) != CLEAR) {
        printf("   State was incorrect.\n");
    }
    if (getNofAttempts(result) != 5) {
        printf("   Number of attempts was incorrect.\n");
    }

    for (counter = 0; counter < 4; ++counter) {
        sprintf(&userBuffer[0], "User2_%d", counter);
        sprintf(&serviceBuffer[0], "Service2_%d", counter);
        compareAttempt(result, counter, AUTH_FAILED, &userBuffer[0], &serviceBuffer[0], 0);
    }

    AuthAttempt attempt;
    memset(&attempt, 0, sizeof(AuthState));
    if (!nextAttempt(result, &attempt)) {
        printf("   The first attempt could be retrieved.\n");
    }
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
        printf("   Could not create AuthState from buffer.\n");
        return;
    }

    if (!result) {
        printf("   AutState was not filled in.\n");
        return;
    }

    //write over the buffer, make sure that AuthState does not read our old buffer
    memset(&buffer[0], 3, sizeof(buffer));

    if (getState(result) != BLOCKED) {
        printf("   State was incorrect.\n");
    }

    compareAttempt(result, 11, USER_BLOCKED, user, service, 1);

    destroyAuthState(result);
}

static void testEmptyService() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        printf("   Could not create an empty state.\n");
        return;
    }
    int i;
    for (i = 0; i < 10; ++i) {
        //addAttempt(AuthState *state, BlockReason reason, time_t pTime, const char *userOrHost, const char *service)
        if (addAttempt(state, HOST_BLOCKED, i, "", "", 0, 0)) {
            printf("   Could not add an attempt.\n");
        }
    }
    firstAttempt(state);
    AuthAttempt attempt;
    i = 0;
    while (nextAttempt(state, &attempt) == 0) {
        if (*attempt.m_service)
            printf("   We added an empty service, yet a real service is returned.\n");
        if (*attempt.m_userOrHost)
            printf("   We added an empty data field, yet a real service is returned.\n");
        if (attempt.m_time != i)
            printf("   Time was not matched.\n");
        ++i;
    }
    if (i != 10)
        printf("   We added 10 attempts, yet %d were returned.\n", i);
    destroyAuthState(state);
}

static void testEmptyAttempts() {
    char buffer[100];
    writeHeader(&buffer[0], CLEAR, 0);
    AuthState *result;
    if (createAuthState(&buffer[0], sizeof(int)+sizeof(unsigned int), &result)) {
        printf("   Could not create AuthState from buffer.\n");
        return;
    }

    AuthAttempt attempt;
    if (!nextAttempt(result, &attempt)) {
        printf("   The first attempt could be retrieved.\n");
    }
    destroyAuthState(result);
}

static void testCreateEmptyAttempt() {
    char buffer[100];
    writeHeader(&buffer[0], CLEAR, 0);
    AuthState *result;
    if (createAuthState(&buffer[0], sizeof(int)+sizeof(unsigned int), &result)) {
        printf("   Could not create AuthState from buffer.\n");
        return;
    }

    AuthState *empty = NULL;
    if (createEmptyState(CLEAR, &empty)) {
        printf("   Could not create empty AuthState.\n");
        return;
    }

    if (!empty) {
        printf("   Creation succeeded, yet no valid pointer.\n");
        return;
    }

    if (result->m_usedSize != empty->m_usedSize) {
        printf("   The size of the empty State does not match.");
        return;
    }

    if (memcmp(result->m_data, empty->m_data, empty->m_usedSize)) {
        printf("   The data does not match.\n");
    }
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
        printf("   Could not create AuthState from buffer.\n");
        return;
    }

    int counter = 0;
    for (; counter < 10; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);
        bufferPtr = writeAttempt(bufferPtr, counter, AUTH_FAILED, &userBuffer[0], &serviceBuffer[0]);

        if (addAttempt(result, AUTH_FAILED, counter, &userBuffer[0], &serviceBuffer[0], 0, 0)) {
            printf("   Could not add an attempt.\n");
            return;
        }
    }

    if (result->m_usedSize != (size_t)(bufferPtr - &buffer[0])) {
        printf("   The buffer sizes do not match.\n");
        return;
    } else {
        if (memcmp(&buffer[0], result->m_data, result->m_usedSize)) {
            printf("   The buffers are not equal.\n");
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
            printf("   Could not create AuthState from buffer.\n");
            continue;
        }

        AuthAttempt attempt;
        memset(&attempt, 0, sizeof(AuthState));
        if (!nextAttempt(result, &attempt)) {
            printf("   The first attempt could be retrieved while giving size %d.\n", (int)reportSize);
        }
        destroyAuthState(result);
    }

    AuthState *temp = NULL;
    //if we give it a real small size, we expect it to fail while creating the AuthState
    for (reportSize = 0; reportSize < sizeof(unsigned int)+sizeof(int); ++reportSize) {
        if (!createAuthState(&buffer[0], reportSize, &temp)) {
            printf("   Could create AuthState from buffer.\n");
        }
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
        printf("   Could not create AuthState from buffer.\n");
        return;
    }

    if (!result) {
        printf("   AutState was not filled in.\n");
        return;
    }

    //write over the buffer, make sure that AuthState does not read our old buffer
    memset(&buffer[0], 3, sizeof(buffer));

    //let's purge the damn thing, nothing should have been deleted
    purgeAuthState(result, 5);

    if (getState(result) != CLEAR) {
        printf("   State was incorrect.\n");
    }
    if (getNofAttempts(result) != 10) {
        printf("   Number of attempts was incorrect.\n");
    }

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
        printf("   Could not create AuthState from buffer.\n");
        return;
    }

    if (!result) {
        printf("   AutState was not filled in.\n");
        return;
    }

    //write over the buffer, make sure that AuthState does not read our old buffer
    memset(&buffer[0], 3, sizeof(buffer));

    //let's purge the damn thing, some of them should be deleted
    purgeAuthState(result, 5);

    if (getState(result) != CLEAR) {
        printf("   State was incorrect.\n");
    }
    if (getNofAttempts(result) != 5) {
        printf("   Number of attempts was incorrect.\n");
    }

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
        printf("   Could not create AuthState from buffer.\n");
        return;
    }

    if (!result) {
        printf("   AutState was not filled in.\n");
        return;
    }

    //write over the buffer, make sure that AuthState does not read our old buffer
    memset(&buffer[0], 3, sizeof(buffer));

    //let's purge the damn thing, all but one should be removed
    purgeAuthState(result, 9);

    if (getState(result) != CLEAR) {
        printf("   State was incorrect.\n");
    }
    if (getNofAttempts(result) != 1) {
        printf("   Number of attempts was incorrect.\n");
    }

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
        printf("   Could not create AuthState from buffer.\n");
        return;
    }

    //purging will not do anything normally, because there is nothing to remove
    purgeAuthState(result, 9);

    if (getState(result) != CLEAR) {
        printf("   State was incorrect.\n");
    }
    if (getNofAttempts(result) != 0) {
        printf("   Number of attempts was incorrect.\n");
    }

    AuthAttempt attempt;
    if (!nextAttempt(result, &attempt)) {
        printf("   The first attempt could be retrieved.\n");
    }
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
        printf("   Could not create AuthState from buffer.\n");
        return;
    }

    if (!result) {
        printf("   AutState was not filled in.\n");
        return;
    }

    //write over the buffer, make sure that AuthState does not read our old buffer
    memset(&buffer[0], 3, sizeof(buffer));

    //let's purge the damn thing, all should be removed
    purgeAuthState(result, 1000);

    if (getState(result) != CLEAR) {
        printf("   State was incorrect.\n");
    }
    if (getNofAttempts(result) != 0) {
        printf("   Number of attempts was incorrect.\n");
    }

    AuthAttempt attempt;
    if (!nextAttempt(result, &attempt)) {
        printf("   The first attempt could be retrieved.\n");
    }

    destroyAuthState(result);
}

static void testPurgePerformance(int maxCount) {
    char *buffer = malloc(((maxCount / 1000)+1) * 50000); //for 1000 entries we will probably need something of a 35k, make it 50 to be sure
    char userBuffer[100];
    char serviceBuffer[100];
    char *bufferPtr = buffer;

    bufferPtr = writeHeader(bufferPtr, CLEAR, maxCount);

    clock_t begin = clock();
    int counter = 0;
    for (; counter < maxCount; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);
        bufferPtr = writeAttempt(bufferPtr, counter, AUTH_FAILED, &userBuffer[0], &serviceBuffer[0]);
    }
    AuthState *result;
    printf("      %d attempts costs us %d bytes.\n", maxCount, (int)(bufferPtr - buffer));
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
    printf("      Creating %d entries took us %f seconds.\n", maxCount, elapsed);

    begin = clock();
    purgeAuthState(result, maxCount + 1000);
    end = clock();
    elapsed = (double)(end - begin) / CLOCKS_PER_SEC;
    printf("      Iterating %d entries took us %f seconds.\n", maxCount, elapsed);

    destroyAuthState(result);
    free(buffer);
}

static void testAddAttemptLimitReached() {
    char userBuffer[100];
    char serviceBuffer[100];

    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        printf("   Could not create an empty AuthState.\n");
        return;
    }

    int counter = 1;
    unsigned int expected = 0;
    for (; counter <= 100; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);

        if (addAttempt(state, AUTH_FAILED, counter, &userBuffer[0], &serviceBuffer[0], 5, 10)) {
            printf("   Could not add an attempt.\n");
            return;
        }
        ++expected;
        if (expected == 11)
            expected = 5;
        unsigned int nof = getNofAttempts(state);
        if (nof != expected) {
            printf("   The count is wrong, expected %u, got %u.\n", expected, nof);
        } else {
            firstAttempt(state);
            int start = counter - expected + 1;
            AuthAttempt attempt;
            while (nextAttempt(state, &attempt) == 0) {
                sprintf(&userBuffer[0], "User_%d", start);
                if (strcmp(attempt.m_userOrHost, &userBuffer[0]) != 0) {
                    printf("   Expected username %s, got %s.\n", &userBuffer[0], attempt.m_userOrHost);
                    break;
                }
                ++start;
            }
            if (start != counter+1) {
                printf("   State is not fully iteratable.\n");
            }
        }
    }
    destroyAuthState(state);
}

static void testAddAttemptLowerLimitZero() {
    char userBuffer[100];
    char serviceBuffer[100];

    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        printf("   Could not create an empty AuthState.\n");
        return;
    }

    int counter = 1;
    unsigned int expected = 0;
    for (; counter <= 100; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);

        if (addAttempt(state, AUTH_FAILED, counter, &userBuffer[0], &serviceBuffer[0], 0, 10)) {
            printf("   Could not add an attempt.\n");
            return;
        }
        ++expected;
        if (expected == 11)
            expected = 1;
        unsigned int nof = getNofAttempts(state);
        if (nof != expected) {
            printf("   The count is wrong, expected %u, got %u.\n", expected, nof);
        } else {
            firstAttempt(state);
            int start = counter - expected + 1;
            AuthAttempt attempt;
            while (nextAttempt(state, &attempt) == 0) {
                sprintf(&userBuffer[0], "User_%d", start);
                if (strcmp(attempt.m_userOrHost, &userBuffer[0]) != 0) {
                    printf("   Expected username %s, got %s.\n", &userBuffer[0], attempt.m_userOrHost);
                    break;
                }
                ++start;
            }
            if (start != counter+1) {
                printf("   State is not fully iteratable.\n");
            }
        }
    }
    destroyAuthState(state);
}

static void testAddAttemptLimitsTheSame() {
    char userBuffer[100];
    char serviceBuffer[100];

    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        printf("   Could not create an empty AuthState.\n");
        return;
    }

    int counter = 1;
    for (; counter <= 100; ++counter) {
        sprintf(&userBuffer[0], "User_%d", counter);
        sprintf(&serviceBuffer[0], "Service_%d", counter);

        if (addAttempt(state, AUTH_FAILED, counter, &userBuffer[0], &serviceBuffer[0], 10, 10)) {
            printf("   Could not add an attempt.\n");
            return;
        }

        unsigned int nof = getNofAttempts(state);
        if (counter <= 10) {
            if ((int)nof != counter) {
                printf("   The count is wrong, expected %u, got %u.\n", counter, nof);
            }
        } else {
            if (nof != 10) {
                printf("   The count is wrong, expected 10, got %u.\n", nof);
            } else {
                firstAttempt(state);
                int start = counter - 10 + 1;
                AuthAttempt attempt;
                while (nextAttempt(state, &attempt) == 0) {
                    sprintf(&userBuffer[0], "User_%d", start);
                    if (strcmp(attempt.m_userOrHost, &userBuffer[0]) != 0) {
                        printf("   Expected username %s, got %s.\n", &userBuffer[0], attempt.m_userOrHost);
                        break;
                    }
                    ++start;
                }
                if (start != counter+1) {
                    printf("   State is not fully iteratable.\n");
                }
            }
        }
    }
    destroyAuthState(state);
}

void runTypeTests() {
    printf("Type test start.\n");
    printf(" Starting testCorrectOneAttempt.\n");
    testCorrectOneAttempt();
    printf(" Starting testEmptyAttempts.\n");
    testEmptyAttempts();
    printf(" Starting testCreateEmptyAttempt.\n");
    testCreateEmptyAttempt();
    printf(" Starting testInvalidSize.\n");
    testInvalidSize();
    printf(" Starting testMultipleAttempts.\n");
    testMultipleAttempts();
    printf(" Starting testMultipleAttemptsLastIncomplete.\n");
    testMultipleAttemptsLastIncomplete();
    printf(" Starting testAddAttempt.\n");
    testAddAttempt();
    printf(" Starting testAddAttemptLimitReached.\n");
    testAddAttemptLimitReached();
    printf(" Starting testAddAttemptLowerLimitZero.\n");
    testAddAttemptLowerLimitZero();
    printf(" Starting testAddAttemptLimitsTheSame.\n");
    testAddAttemptLimitsTheSame();
    printf(" Starting testEmptyService.\n");
    testEmptyService();
    printf(" Starting testPurgeNothingRemoved.\n");
    testPurgeNothingRemoved();
    printf(" Starting testPurgeSomeRemoved.\n");
    testPurgeSomeRemoved();
    printf(" Starting testPurgeAllButOneRemoved.\n");
    testPurgeAllButOneRemoved();
    printf(" Starting testPurgeEmptyAttemptList.\n");
    testPurgeEmptyAttemptList();
    printf(" Starting testPurgeAllRemoved.\n");
    testPurgeAllRemoved();
    printf(" Starting testPurgePerformance.\n");
    testPurgePerformance(1000);
    testPurgePerformance(100000);
    printf("Type tests end.\n");
}
