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

#ifndef PAM_ABL_H
#define PAM_ABL_H

#include "config.h"
#include "dbfun.h"

typedef struct PamAblDbEnv {
    DbEnvironment *m_environment;
    Database      *m_userDb;
    Database      *m_hostDb;
} PamAblDbEnv;


typedef struct {
    BlockReason blockReason;
    char *user;
    char *host;
    char *service;
} abl_info;

abl_info *createAblInfo();
void destroyAblInfo(abl_info *info);
void setInfo(abl_info *info, const char *user, const char *host, const char *service);

/*
  Given a full configuration open the required environment and databases
  \param args The config with all the db params
  \param logContext The loggin context to use when reporting errors/warnings/...
  \return a valid environment on success, otherwise a nullptr
  \note if something goes wrong, error messages are written to the logContext
*/
PamAblDbEnv *openPamAblDbEnvironment(abl_args *args, log_context *logContext);

/*
  Close a full environment. Make sure no transaction is open
  \note Do not use the env pointer anymore after calling this function
*/
void destroyPamAblDbEnvironment(PamAblDbEnv *env);

/*
  Call the desired scripts if possible
  \param bState Determines what script gets called (BLOCKED or CLEAR)
  \param args Holds the strings with the scripts
  \param info The current host/user/service
  \param logContext The context that will be used when reporting errors/warnings/...
  \return zero on success, otherwise non zero
*/
int runHostCommand(BlockState bState, const abl_args *args, abl_info *info, log_context *logContext);
int runUserCommand(BlockState bState, const abl_args *args, abl_info *info, log_context *logContext);

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
BlockState check_attempt(const PamAblDbEnv *dbEnv, const abl_args *args, abl_info *info, log_context *logContext);

/*
    Record an authentication attempt.
    This will:
        - purge the db data for the given host and user
        - add an entry for the given host and user with as reason info->blockReason
    If something went wrong, a non zero value is returned and a diagnostic message is logged using the logContext
*/
int record_attempt(const PamAblDbEnv *dbEnv, const abl_args *args, abl_info *info, log_context *logContext);


/*
  Following functions are only 'exported' for testing purposes
*/
int prepare_string(const char *str, const abl_info *info, char *result);
int parseIP(const char *ipStr, size_t length, int *netmask, u_int32_t *ip);
int whitelistMatch(const char *subject, const char *whitelist, int isHost);
int inSameSubnet(u_int32_t host, u_int32_t ip, int netmask);
int ablExec(char *const arg[]);
//the following function takes a pointer to a real exec function just for testing purpopes
//that way we don't actually have to run an external command just to test this function
int _runCommand(const char *origCommand, const abl_info *info, log_context *logContext, int (execFun)(char *const arg[]));

#endif
