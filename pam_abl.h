/*
 *   pam_abl - a PAM module and program for automatic blacklisting of hosts
 *   and users
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

#ifndef PAM_ABL_H
#define PAM_ABL_H

#include "dbfun.h"
#include "config.h"
#include "typefun.h"
#include <sys/types.h>

typedef struct {
    BlockReason blockReason;
    const char *user;
    const char *host;
    const char *service;
} abl_info;


/*
  Call the desired scripts if possible
  \param bState Determines what script gets called (BLOCKED or CLEAR)
  \param info The current host/user/service
  \param logContext The context that will be used when reporting errors/warnings/...
  \return zero on success, otherwise non zero
*/
int runHostCommand(BlockState bState, abl_info *info);
int runUserCommand(BlockState bState, abl_info *info);

/*
    Returns the current state for the given attempt.
    This will:
        - calculate the current state
        - update the state saved in the database
        - run the required scripts
        - change the blockReason (by default this will be AUTH_FAILED), unless it could already be determined
    If something goes wrong while checking, CLEAR is returned
    and diagnostic messages are written using the given logContext.
*/
BlockState check_attempt(const abl_db *db, abl_info *info);

/*
    Record an authentication attempt.
    This will:
        - purge the db data for the given host and user
        - add an entry for the given host and user with as reason info->blockReason
    If something went wrong, a non zero value is returned and a diagnostic message is logged using the logContext
*/
int record_attempt(const abl_db *db, abl_info *info);

/*
  Following functions are only 'exported' for testing purposes
*/
int parseIP(const char *ipStr, size_t length, int *netmask, u_int32_t *ip);
int whitelistMatch(const char *subject, const char *whitelist, ablObjectType type);
int inSameSubnet(u_int32_t host, u_int32_t ip, int netmask);

#endif
