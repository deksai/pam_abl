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

#include "typefun.h"
#include <stdlib.h>
#include <string.h>

#define BYTES_FREE(state) (state->m_usedSize - (size_t)((char*)state->m_current - (char*)state->m_data))
#define SIZE_SMALLER(state, size) BYTES_FREE(state) < (size)

//the space in the buffer before the actual attempts start
#define HEADER_SIZE (sizeof(int)+sizeof(unsigned int))

//when we allocate memory for the data, allocate this much more for future attempts
// this will save us a realloc at the cost of this much more bytes
#define SPARE_SPACE 100
#define INCREASE_NOFATTEMPTS(state, x) ((*((unsigned int *)(((int*)(state->m_data))+1))) += x)
#define SET_NOFATTEMPTS(state, x) ((*((unsigned int *)(((int*)(state->m_data))+1))) = x)
#define ATTEMPS_START(state) (((char*)state->m_data) + HEADER_SIZE)

int createEmptyState(BlockState blockState, AuthState **state) {
    *state = NULL;
    AuthState *retValue = malloc(sizeof(AuthState));
    if (!retValue)
        return 1;
    memset(retValue, 0, sizeof(AuthState));
    //allocate some bytes more then we actually need
    //this way we can probably cope with an extra attempt without reallocating
    size_t bufferSize = HEADER_SIZE + SPARE_SPACE;
    void *allocatedData = malloc(bufferSize);
    if (!allocatedData) {
        free(retValue);
        return 1;
    }

    retValue->m_data = allocatedData;
    retValue->m_size = bufferSize;
    retValue->m_usedSize = HEADER_SIZE;
    char *bufferPtr = (char*)retValue->m_data;
    *((int*)bufferPtr) = blockState;
    bufferPtr += sizeof(int);
    *((unsigned int*)bufferPtr) = 0;
    bufferPtr += sizeof(int);
    firstAttempt(retValue);
    *state = retValue;
    return 0;
}

int createAuthState(void *data, size_t size, AuthState **state) {
    *state = NULL;
    if (!data || !size)
        return 1;

    if (size < HEADER_SIZE)
        return 1;

    AuthState *retValue = malloc(sizeof(AuthState));
    if (!retValue)
        return 1;
    memset(retValue, 0, sizeof(AuthState));
    //allocate some bytes more then we actually need
    //this way we can probably cope with an extra attempt without reallocating
    size_t bufferSize = size + SPARE_SPACE;
    void *allocatedData = malloc(bufferSize);
    if (!allocatedData) {
        free(retValue);
        return 1;
    }

    memcpy(allocatedData, data, size);
    retValue->m_data = allocatedData;
    retValue->m_size = bufferSize;
    retValue->m_usedSize = size;
    //the state is the first field, we need to skip this before the Attempts begin
    retValue->m_current = ATTEMPS_START(retValue);

    *state = retValue;
    return 0;
}

BlockState getState(AuthState *state) {
    if (!state || !state->m_data)
        return -1;
    int stateEnum = *((int*)(state->m_data));
    return stateEnum;
}

int setState(AuthState *state, BlockState blockState) {
    if (!state || !state->m_data)
        return 1;
    *((int*)(state->m_data)) = blockState;
    return 0;
}

unsigned int getNofAttempts(AuthState *state) {
    if (!state || !state->m_data)
        return 0;
    unsigned int nofAttempts = *(unsigned int *)(((int*)(state->m_data))+1);
    return nofAttempts;
}

int firstAttempt(AuthState *state) {
    if (!state || !state->m_data)
        return 1;
    state->m_current = ATTEMPS_START(state);
    return 0;
}

/*
    What does the raw data look like, it should have the following structure
     int: State
     unsigned int: number of attempts int the bytes after this
     (
       time_t the time of the failed authentication
       int blockreason
       zero terminated user or host
       zero terminated service
     )*
*/
//TODO difference between a faulty layout and the end of the chain
int nextAttempt(AuthState *state, AuthAttempt *attempt) {
    if (!state || !state->m_current)
        return 1;

    //is there still an attempt left to read?
    if (SIZE_SMALLER(state, sizeof(time_t))) {
        return 1;
    }
    time_t t = *((time_t*)state->m_current);
    state->m_current = ((time_t*)state->m_current) + 1;

    if (SIZE_SMALLER(state, sizeof(int))) {
        state->m_current = NULL;
        return 1;
    }
    int reason = *((int*)state->m_current);
    state->m_current = ((int*)(state->m_current)) + 1;

    char *userOrHost = (char*)state->m_current;
    size_t bytesFree = BYTES_FREE(state);

    size_t strLen = strnlen(userOrHost, bytesFree);
    if (strLen == bytesFree) {
        state->m_current = NULL;
        return 1;
    }
    state->m_current = ((char*)state->m_current) + strLen + 1;

    char *service = (char*)state->m_current;
    bytesFree = BYTES_FREE(state);
    strLen = strnlen(service, bytesFree);
    if (strLen == bytesFree) {
        state->m_current = NULL;
        return 1;
    }
    state->m_current = ((char*)state->m_current) + strLen + 1;

    //OK state->m_current should point to the next Attempt

    if (attempt) {
        attempt->m_time = t;
        attempt->m_reason = reason;
        attempt->m_service = service;
        attempt->m_userOrHost = userOrHost;
    }
    return 0;
}

void destroyAuthState(AuthState *state) {
    if (!state)
        return;
    free(state->m_data);
    state->m_data = NULL;
    state->m_current = NULL;
    state->m_size = 0;
    state->m_usedSize = 0;
    free(state);
}

static int limitAttempts(AuthState *state, unsigned int limit) {
    if (!state)
        return 1;
    unsigned int nofAttempts = getNofAttempts(state);
    if (nofAttempts <= limit)
        return 0;
    if (firstAttempt(state))
        return 1;
    if (limit == 0) {
        state->m_size = 0;
        state->m_usedSize = HEADER_SIZE;
        SET_NOFATTEMPTS(state, 0);
        firstAttempt(state);
    } else {
        unsigned int toRemove = nofAttempts - limit;
        AuthAttempt attempt;
        while (nextAttempt(state, &attempt) == 0) {
            --toRemove;
            if (toRemove == 0)
                break;
        }
        if (toRemove == 0) {
            //iterating went fine, just remove the extra attempts
            size_t bytesToMove = state->m_usedSize - (size_t)((char*)state->m_current - (char*)state->m_data);
            memmove(ATTEMPS_START(state), state->m_current, bytesToMove);
            SET_NOFATTEMPTS(state, limit);
            state->m_usedSize = bytesToMove + HEADER_SIZE;
            firstAttempt(state);
        } else {
            //iterating went wrong, pass the error along
            return 1;
        }
    }
    return 0;
}

int addAttempt(AuthState *state, BlockReason reason, time_t pTime, const char *userOrHost, const char *service, unsigned int lowerLimit, unsigned int upperLimit) {
    if (!userOrHost || !service || !state)
        return 1;
    if (upperLimit > 0 && getNofAttempts(state) + 1 > upperLimit) {
        if (limitAttempts(state, lowerLimit > 0 ? lowerLimit - 1 : 0))
            return 1;
    }
    //calculate how many space we need, perhaps we need to reallocate
    size_t userOrHostSize = strlen(userOrHost) + 1;
    size_t serviceSize = strlen(service) + 1;
    size_t neededSize = userOrHostSize + serviceSize + sizeof(time_t) + sizeof(int);

    if (neededSize > state->m_size - state->m_usedSize) {
        //damn, space left is too smalll, reallocate and move all the data
        //calculate a good new size for the block of memory (let's leave some spare room, for further enlargements)
        size_t newSize = state->m_usedSize + neededSize + SPARE_SPACE;
        void *newMem = realloc(state->m_data, newSize);
        if (!newMem)
            return 1;

        state->m_current = (char*)newMem + (size_t)((char*)state->m_current - (char*)state->m_data);
        state->m_size = newSize;
        state->m_data = newMem;
        // state->m_usedSize remains the same
    }

    char *bufferPtr = (char*)state->m_data + state->m_usedSize;
    *((time_t*)bufferPtr) = pTime;
    bufferPtr += sizeof(time_t);

    *((int*)bufferPtr) = reason;
    bufferPtr += sizeof(int);

    memcpy(bufferPtr, userOrHost, userOrHostSize);
    bufferPtr += userOrHostSize;

    memcpy(bufferPtr, service, serviceSize);
    bufferPtr += serviceSize;

    state->m_current = bufferPtr;
    state->m_usedSize += neededSize;
    INCREASE_NOFATTEMPTS(state, 1);
    if (state->m_usedSize != (size_t)((char*)state->m_current - (char*)state->m_data)) {
        return 0;
    }
    return 0;
}

void purgeAuthState(AuthState *state, time_t purgeTime) {
    if (!state || !state->m_data || firstAttempt(state)) {
        return;
    }
    AuthAttempt attempt;
    int endReached = 1;
    int nofAttemptsToRemove = 0;
    void *lastOld = state->m_current;
    while (!nextAttempt(state, &attempt)) {
        if (attempt.m_time >= purgeTime) {
            endReached = 0;
            break;
        }
        ++nofAttemptsToRemove;
        lastOld = state->m_current;
    }
    if (endReached) {
        state->m_usedSize = HEADER_SIZE;
        SET_NOFATTEMPTS(state, 0);
    } else {
        //lastOld should point to the first Attempt with a 'valid' time
        //first of all, do we need to move stuff?
        if (ATTEMPS_START(state) != lastOld) {
            size_t bytesToMove = state->m_usedSize - (size_t)((char*)lastOld - (char*)state->m_data);
            memmove(ATTEMPS_START(state), lastOld, bytesToMove);
            state->m_usedSize = bytesToMove + HEADER_SIZE;
        }
        if (nofAttemptsToRemove)
            INCREASE_NOFATTEMPTS(state, -1*nofAttemptsToRemove);
    }
    state->m_current = ATTEMPS_START(state);
}
