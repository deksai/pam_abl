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

#ifndef TYPEFUN_H
#define TYPEFUN_H

#include <time.h>

typedef enum {
    HOST_BLOCKED = 0x01,
    USER_BLOCKED = 0x02,
    BOTH_BLOCKED = 0x03,
    AUTH_FAILED  = 0x04
} BlockReason;

typedef enum {
    BLOCKED = 0x01,
    CLEAR = 0x02
} BlockState;

typedef struct AuthAttempt {
    BlockReason m_reason;
    time_t m_time;
    char *m_userOrHost;
    char *m_service;
} AuthAttempt;

typedef struct AuthState {
    void   *m_data;
    void   *m_current;  //a pointer to the first field of the next AuthAttempt
    size_t  m_size;     //the size of the memory block pointed to by m_data
    size_t  m_usedSize; //how many bytes of m_data are used
} AuthState;

/*
  Create an empty AuthState with the given blocking state
*/
int  createEmptyState(BlockState blockState, AuthState **state);

/*
  Create a AuthState based on the binary data blob.
  \param data: block of binary data that needs to be interpreted as being a AuthState
  \param size: the size in bytes of the memory pointed to by data
  \param state: the returned newly created AuthState
  \return 0 on succes, non zero on failure
*/
int  createAuthState(void *data, size_t size, AuthState **state);

/*
  What is the current block state of the given attempt
  on success the block state is returned otherwise -1
*/
BlockState  getState(AuthState *state);

/*
  Set the current blocking state
  \param state The AuthState to change
  \param blockState The new blocking state
  \return 0 on success, non zero otherwise
*/
int  setState(AuthState *state, BlockState blockState);

/*
  Get the number of attempts currently recorded in the AuthState
  \return The number of recorded attemps. If something is wrong with the state, zero is returned
  \note This returns a cached value. If something got corrupted, it can be that you can iterate through all of them.
*/
unsigned int getNofAttempts(AuthState *state);

/*
  Resets the iteration pointer to the first attempt
  \return 0 on success, non zero otherwise
*/
int  firstAttempt(AuthState *state);

/*
  retrieves the next attempt. This function can be used to iterate through attempts
  \param state The state you are traversing
  \param attempt The next attempt will be stored in this param. if attempt is zero, nothing will be filled in
  \return zero on success (next attempt is loaded), onterwise non zero. For the moment you can destinguish between no more attempts and something went wrong
  \note No copy will be taken. Do NOT destroy attempt. Do NOT use attempt after state is destroyed
*/
int  nextAttempt(AuthState *state, AuthAttempt *attempt);

/*
  Delete the given state, releasing all itś resources
  Do NOT use the state after calling this function
*/
void destroyAuthState(AuthState *state);

/*
  Add a authentication attempt to the list of attempts
  \param state The state to add the attemp to
  \param reason The block reason for the new attempt
  \param time The time of the new attempt. Make sure this time is newer or the same as any of the already added attempts
  \param userOrHost The data that needs to be stored with this attempt
  \param service The service the attempt was made against
  \param lowerLimit If the number of attempts goes above upperLimit, delete attempts till lowerLimit is reached. Oldest attempts are deleted first
  \param upperLimit The maximum nuber of attempts to keep, if this is 0, all attempts will be kept
  \note Adding attempt will not mess up any ongoing iterating
*/
int  addAttempt(AuthState *state, BlockReason reason, time_t time, const char *userOrHost, const char *service, unsigned int lowerLimit, unsigned int upperLimit);

/*
  Purge the current state according to the given time
  \note This will reset the current iterator
*/
void purgeAuthState(AuthState *state, time_t purgeTime);

#endif
