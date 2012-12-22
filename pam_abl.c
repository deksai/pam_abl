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

#include "pam_abl.h"
#include "dbfun.h"
#include "rule.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define DB_NAME "state"
#define COMMAND_SIZE 1024

static int prepare_command(const char *cmd, const abl_info *info, char **string) {
    int i;
    int cmd_sz = strlen(cmd);
    int strstore_sz = 0;
    int host_sz = 0;
    int user_sz = 0;
    int service_sz = 0;
    char subst;
    char *strstore = *string; //Because double pointers get confusing

    if(info->host != NULL) host_sz = strlen(info->host);
    if(info->user != NULL) user_sz = strlen(info->user);
    if(info->service != NULL) service_sz = strlen(info->service);

    strstore = calloc(COMMAND_SIZE,sizeof(char));
    if (strstore == NULL) {
        log_error( "Could not allocate memory for running command");
        return -1;
    }

    for(i=0; i < cmd_sz; i++) {
        if(*(cmd + i)  == '%') {
            subst = *(cmd + i + 1); //grab substitution letter
            i += 2;                 //move index past '%x'
            switch(subst) {
                case 'u':
                    if(strstore_sz + user_sz >= COMMAND_SIZE) {
                        log_warning( "command length error: %d > %d.  Adjust COMMAND_SIZE in pam_abl.h\n",strlen(strstore)+user_sz,COMMAND_SIZE);
                        return(1);
                    }
                    else if (!info->user) {
                        log_warning( "No user to substitute: %s.",cmd);
                        return(1);
                    }
                    else {
                        strcat(strstore,info->user);
                        strstore_sz += user_sz;
                    }
                    break;
                case 'h':
                    if(strstore_sz + host_sz >= COMMAND_SIZE) {
                        log_warning( "command length error: %d > %d.  Adjust COMMAND_SIZE in pam_abl.h\n",strlen(strstore)+host_sz,COMMAND_SIZE);
                        return(1);
                    }
                    else if (!info->host) {
                        log_warning( "No host to substitute: %s.",cmd);
                        return(1);
                    }
                    else {
                        strcat(strstore,info->host);
                        strstore_sz += host_sz;
                    }
                    break;
                case 's':
                    if(strstore_sz + service_sz >= COMMAND_SIZE) {
                        log_warning( "command length error: %d > %d.  Adjust COMMAND_SIZE in pam_abl.h\n",strlen(strstore)+service_sz,COMMAND_SIZE);
                        return(1);
                    }
                    else if (!info->service) {
                        log_warning( "No service to substitute: %s.",cmd);
                        return(1);
                    }
                    else {
                        strcat(strstore,info->service);
                        strstore_sz += service_sz;
                    }
                    break;
                default:
                    break;
            }
        }
        *(strstore + strstore_sz) = *(cmd + i);
        strstore_sz++;
    }
    *string = strstore;
    return 0;
}

static int runCommand(const char *origCommand, const abl_info *info) {
    if (!origCommand || ! *origCommand)
        return 0;
    int  err = 0;
    char *command = NULL;

    err = prepare_command( origCommand, info, &command);
    if(err != 0) {
        log_warning( "Failed to run command.");
    } else if (command) {
        log_debug("running command %s",command);
        err = system(command);
        if (err == -1)
            log_warning( "Failed to run command: %s",command);
        free(command);
    } else if (!command)
        log_debug("No command to run for this situation.");
    return err;
}

int runHostCommand(BlockState bState, abl_info *info) {
    const char *command = NULL;
    if (bState == BLOCKED)
        command = args->host_blk_cmd;
    else if (bState == CLEAR)
        command = args->host_clr_cmd;
    return runCommand(command, info);
}

int runUserCommand(BlockState bState, abl_info *info) {
    const char *command = NULL;
    if (bState == BLOCKED)
        command = args->user_blk_cmd;
    else if (bState == CLEAR)
        command = args->user_clr_cmd;
    return runCommand(command, info);
}


static int update_status(const abl_db *db, const char *subject, const char *service, const char *rule, time_t tm,
                 BlockState *updatedState, int *stateChanged) {
    int err = 0;
    AuthState *subjectState = NULL;

    *stateChanged = 0; //assume the state will not change

    err = db->get(db, subject, &subjectState);
    
    //only update if we have a subjectState (It is already in the database and no error)
    if (subjectState) {
        *updatedState = rule_test( rule, subject, service, subjectState, tm);
        //is the state changed
        if (*updatedState != getState(subjectState)) {
            //update the BlockState in the subjectState
            if (setState(subjectState, *updatedState)) {
                log_error( "The state could not be updated.");
            } else {
                //save the subjectState
                err = db->put(db, subject, subjectState);
                if ( !err) {
                    *stateChanged = 1;
                }
            }
        }
        destroyAuthState(subjectState);
    }
    return err;
}

BlockState check_attempt(const abl_db *db, abl_info *info) {
    if (info)
        info->blockReason = AUTH_FAILED;

    if (!db || !args || !info)
        return CLEAR;
    time_t tm = time(NULL);
    const char *user = info->user;
    const char *host = info->host;
    const char *service = info->service;
    BlockState updatedHostState = CLEAR;
    BlockState updatedUserState = CLEAR;

    //fist check the host
    //do we need to update the host information?
    if (host && args->host_rule) {
        int hostStateChanged = 0;
        int err = update_status(db, host, service, args->host_rule, tm,
              &updatedHostState, &hostStateChanged);
        if (!err) {
            if (hostStateChanged)
                runHostCommand(updatedHostState, info);
        } else {
            //if something went wrong, we can't trust the value returned, so by default, do not block
            updatedHostState = CLEAR;
        }
    }

    //now check the user
    if (user && *user && args->user_rule) {
        int userStateChanged = 0;
        int err = update_status(db, user, service, args->user_rule, tm,
              &updatedUserState, &userStateChanged);
        if (!err) {
            if (userStateChanged)
                runUserCommand(updatedUserState, info);
        } else {
            //if something went wrong, do not trust the returned value
            //and by default do not block
            updatedUserState = CLEAR;
        }
    }

    //last but not least, update the blockreason
    info->blockReason = AUTH_FAILED;
    if (updatedHostState == BLOCKED && updatedUserState == BLOCKED) {
        info->blockReason = BOTH_BLOCKED;
        return BLOCKED;
    }
    if (updatedHostState == BLOCKED)
        info->blockReason = HOST_BLOCKED;
    if (updatedUserState == BLOCKED)
        info->blockReason = USER_BLOCKED;
    return updatedHostState == BLOCKED || updatedUserState == BLOCKED ? BLOCKED : CLEAR;
}

/*
static int whitelistMatch(const char *subject, const char *whitelist) {
    if (!subject || !whitelist)
        return 0;
    size_t subjLen = strlen(subject);
    const char *begin = whitelist;
    const char *end = NULL;
    while ((end = strchr(begin, ';')) != NULL) {
        size_t len = (size_t)(end - begin);
        if (subjLen == len) {
            if (memcmp(begin, subject, subjLen) == 0)
                return 1;
        }
        begin = end+1;
    }
    if (subjLen == strlen(begin)) {
        if (memcmp(begin, subject, subjLen) == 0)
            return 1;
    }
    return 0;
}
*/

static int parseNumber(const char *numberStr, size_t length, unsigned max, unsigned *number, size_t *consumedSize) {
    size_t x = 0;
    unsigned result = 0;
    while (x < length) {
        if (isdigit(numberStr[x])) {
            result *= 10;
            result += numberStr[x] - '0';
            if (result > max)
                return 1;
        } else {
            break;
        }
        ++x;
    }
    //if no characther parsed, just tell it failed
    if (!x)
        return 1;
    if (number)
        *number = result;
    if (consumedSize)
        *consumedSize = x;
    return 0;
}

/*
  Currently we only support ipv4 addresses
  If no netmask is found, the netmask param will be -1
*/
int parseIP(const char *ipStr, size_t length, int *netmask, u_int32_t *ip) {
    if (netmask)
        *netmask = -1;
    if (ip)
        *ip = 0;
    u_int32_t parsedIp = 0;

    size_t consumed = 0;
    //try to parse the 4 parts of the IP
    int i = 0;
    for (; i < 4; ++i) {
        //can we parse a number from the string
        size_t used = 0;
        unsigned parsed = 0;
        if (parseNumber(&ipStr[consumed], length - consumed, 255, &parsed, &used) != 0)
            return 1;
        //if we come here, we have a parsed number stored in parsed
        consumed += used;
        parsedIp <<= 8;
        parsedIp += parsed;
        //if it's not the last part, we expect there to be a '.'
        if (i < 3) {
            if (consumed >= length || ipStr[consumed] != '.')
                return 1;
            ++consumed;
        }
    }
    //check if there is still a netmask that we can parse
    if (consumed < length) {
        if (ipStr[consumed] != '/')
            return 1;
        ++consumed;
        size_t used = 0;
        unsigned parsed = 0;
        if (parseNumber(&ipStr[consumed], length - consumed, 32, &parsed, &used) != 0)
            return 1;
        consumed += used;
        if (netmask)
            *netmask = parsed;
    }
    //did we use every char? If not, it probably was something that looked like a ip, but wasn't
    if (consumed != length)
        return 1;
    if (ip)
        *ip = parsedIp;
    return 0;
}

/*
  Is the given host ip part of the subnet defined by ip and netmask
*/
int inSameSubnet(u_int32_t host, u_int32_t ip, int netmask) {
    //an invalid netmask never matches
    if (netmask < 0 || netmask > 32)
        return 0;
    //The behaviour of shifts is only defined if the value of the right
    //operand is less than the number of bits in the left operand.
    //So shifting a 32-bit value by 32 or more is undefined
    if (netmask == 0)
        return 1;

    host >>= (32-netmask);
    ip >>= (32-netmask);
    return host == ip;
}

int whitelistMatch(const char *subject, const char *whitelist, int isHost) {
    if (!subject || !whitelist)
        return 0;

    size_t subjLen = strlen(subject);
    int hostParsed = 0;
    u_int32_t ip = 0;
    if (isHost) {
        int netmask = 0;
        if (parseIP(subject, subjLen, &netmask, &ip) == 0 && netmask == -1)
            hostParsed = 1;
    }

    const char *begin = whitelist;
    const char *end = NULL;
    while ((end = strchr(begin, ';')) != NULL) {
        size_t len = (size_t)(end - begin);
        if (hostParsed) {
            int netmask = 0;
            u_int32_t netmaskIp = 0;
            if (parseIP(begin, len, &netmask, &netmaskIp) == 0) {
                if (ip == netmaskIp || (netmask >= 0 && inSameSubnet(ip, netmaskIp, netmask)))
                    return 1;
            }
        }
        if (subjLen == len && memcmp(begin, subject, subjLen) == 0)
                return 1;
        begin = end+1;
    }

    size_t len = strlen(begin);
    if (hostParsed) {
        int netmask = 0;
        u_int32_t netmaskIp = 0;
        if (parseIP(begin, len, &netmask, &netmaskIp) == 0) {
            if (ip == netmaskIp || (netmask >= 0 && inSameSubnet(ip, netmaskIp, netmask)))
                return 1;
        }
    }
    if (subjLen == len && memcmp(begin, subject, subjLen) == 0)
        return 1;
    return 0;
}

static int recordSubject(const abl_db *db, abl_info *info, int isHost) {
    if (!db || !args || !info)
        return 1;

    int         err       = 0;
    const char *subject   = info->user;
    const char *data      = info->host;
    const char *service   = info->service;
    const char *whitelist = args->user_whitelist;
    long purgeTimeout     = args->user_purge;

    if (isHost) {
        subject = info->host;
        data = info->user;
        purgeTimeout = args->host_purge;
        whitelist = args->host_whitelist;
    }
    if (!subject || !*subject)
        return 0;
    if (whitelistMatch(subject, whitelist, isHost))
        return 0;
    if (purgeTimeout <= 0)
        return 1;
    if (!data)
        data = "";
    if (!service)
        service = "";

    AuthState *subjectState = NULL;
    //all database actions need to be wrapped in a transaction
    err = db->get(db, subject, &subjectState);
    if (!err && !subjectState) {
        if (createEmptyState(CLEAR, &subjectState)) {
            log_error( "Could not create an empty entry.");
        }
    }

    if (subjectState) {
        time_t tm = time(NULL);
        time_t purgeTime = tm - purgeTimeout;
        //if it already existed in the db, we loaded it and otherwise we created an empty state.
        //first do a purge, this way we can make some room for our next attempt
        purgeAuthState(subjectState, purgeTime);
        if (addAttempt(subjectState, info->blockReason, tm, data, service, args->lowerlimit, args->upperlimit)) {
            log_error( "adding an attempt.");
        } else {
            err = db->put(db, subject, subjectState);
        }
        destroyAuthState(subjectState);
    }
    return err;
}

int record_attempt(const abl_db *db, abl_info *info) {
    if (!db || !args || !info)
        return 1;

    int addHostResult = 0;
    int addUserResult = 0;
    if (info->host && *info->host)
        addHostResult = recordSubject(db, info,  1);
    if (info->user && *info->user)
        addUserResult = recordSubject(db, info,  0);

    return addHostResult || addUserResult;
}
