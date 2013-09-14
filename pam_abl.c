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
#include <unistd.h>
#include <dlfcn.h>

#include <sys/types.h>
#include <sys/wait.h>

#define DB_NAME "state"
#define COMMAND_SIZE 1024

abl_info *createAblInfo() {
    abl_info *retValue = malloc(sizeof(abl_info));
    if (retValue)
        memset(retValue, 0, sizeof(abl_info));
    return retValue;
}

void destroyAblInfo(abl_info *info) {
    if (!info)
        return;
    if (info->user)
        free(info->user);
    if (info->host)
        free(info->host);
    if (info->service)
        free(info->service);
    info->user = NULL;
    info->host = NULL;
    info->service = NULL;
    free(info);
}

abl_info *copyAblInfo(abl_info *info) {
    if (!info)
        return NULL;
    abl_info *copy = createAblInfo();
    if (!copy)
        return NULL;
    if (info->user)
        copy->user = strdup(info->user);
    if (info->host)
        copy->host = strdup(info->host);
    if (info->service)
        copy->service = strdup(info->service);
    copy->blockReason = info->blockReason;
    return copy;
}

abl_db *setup_db() {
    abl_db *abldb = NULL;
    void *dblib = NULL;
    abl_db_open_ptr db_open = NULL;

    dblib = dlopen(args->db_module, RTLD_LAZY | RTLD_GLOBAL);
    if (!dblib) {
        log_error("%s opening database module",dlerror());
        return NULL;
    }
    dlerror();
    db_open = dlsym(dblib, "abl_db_open");
    abldb = db_open(args->db_home);
    if (!abldb) {
        log_error("The database environment could not be opened %p",abldb);
    }
    return abldb;
}

/*
 * Substitute the user/host/service in the given string
 * \param str: The string where we need to substitute in.
               '%' is the escape char, so if you want a '%' in your string you will need to add 2: '%%' => '%'
               If the char after the '%' is not in [uhs] then it is just copied to the output buffer '%r' => 'r'
               '%u' => info->user
               '%h' => info->host
               '%s' => info->service
 * \param info: The info that needs to be filled in
 * \param result: The buffer to write to. if this is NULL nothing will be written, only the number of bytes needed is returned
 * \return: The number of bytes needed to do the substitution, negative on failure. This will include the \0 char at the end
 */
int prepare_string(const char *str, const abl_info *info, char *result) {
    int host_sz = 0;
    int user_sz = 0;
    int service_sz = 0;

    if(info->host != NULL)
        host_sz = strlen(info->host);
    if(info->user != NULL)
        user_sz = strlen(info->user);
    if(info->service != NULL)
        service_sz = strlen(info->service);

    int inputIndex = 0;
    int outputIndex = 0;
    int percentSeen = 0;
    while (str[inputIndex]) {
        if (percentSeen) {
            percentSeen = 0;
            switch (str[inputIndex]) {
                case 'u':
                    if (result && info->user)
                        memcpy(result+outputIndex,info->user, user_sz);
                    outputIndex += user_sz;
                    break;
                case 'h':
                    if (result && info->host)
                        memcpy(result+outputIndex,info->host, host_sz);
                    outputIndex += host_sz;
                    break;
                case 's':
                    if (result && info->service)
                        memcpy(result+outputIndex,info->service, service_sz);
                    outputIndex += service_sz;
                    break;
                default:
                    //no special char, let's just add the char to the output buffer
                    if (result)
                        result[outputIndex] = str[inputIndex];
                    ++outputIndex;
                    break;
            }
        } else {
            if (str[inputIndex] == '%') {
                percentSeen = 1;
            } else {
                if (result)
                    result[outputIndex] = str[inputIndex];
                ++outputIndex;
            }
        }
        ++inputIndex;
    }
    if (result)
        result[outputIndex] = '\0';
    ++outputIndex;
    return outputIndex;
}

int ablExec(char *const arg[]) {
    if (arg == NULL || arg[0] == NULL || (arg[0])[0] == '\0')
        return -1;
    pid_t pid = fork();
    if (pid) {
        //parent
        int childStatus = 0;
        waitpid(pid, &childStatus, 0);
        return WEXITSTATUS(childStatus);
    } else if (pid == 0) {
        //child
        int result = execv(arg[0], arg);
        exit(result);
    } else {
        //fork failed
        return -1;
    }
}

int _runCommand(const char *origCommand, const abl_info *info, int (execFun)(char *const arg[])) {
    int  err = 0;
    int bufSize = 0;
    int argNum = 0;
    char** result = NULL;
    char** substResult = NULL;
    char *command = NULL;

    if (!origCommand || ! *origCommand)
        return 0;
    command = strdup(origCommand);
    if (!command)
        return 1;

    //first split the command in it's pieces
    argNum = splitCommand(command, NULL);
    //no real command
    if (argNum == 0)
        goto cleanup;
    if (argNum < 0) {
        err = 1;
        goto cleanup;
    }

    result = malloc((argNum+1) * sizeof(char*));
    substResult = malloc((argNum+1) * sizeof(char*));
    memset(result, 0, (argNum+1) * sizeof(char*));
    memset(substResult, 0, (argNum+1) * sizeof(char*));
    argNum = splitCommand(command, result);

    //now iterate over all the parts of the array and substitute everything
    int partIndex = 0;
    while (result[partIndex]) {
        bufSize = prepare_string(result[partIndex], info, NULL);
        if (bufSize <= 0) {
            //crap, something went wrong
            //the error should already been logged
            log_warning("failed to substitute %s.", result[partIndex]);
            err = 1;
            goto cleanup;
        }
        if (bufSize > COMMAND_SIZE) {
            log_warning("command length error.");
            goto cleanup;
        }
        substResult[partIndex] = malloc(bufSize * sizeof(char));
        if (substResult[partIndex] == NULL) {
            err = 1;
            goto cleanup;
        }
        bufSize = prepare_string(result[partIndex], info, substResult[partIndex]);
        ++partIndex;
    }

    //the first value in the substResult array is the command to execute
    //we should now execute the command
    err = execFun(substResult);

cleanup:
    //result does not hold dynamically allocated strings
    if (result) {
        free(result);
    }
    if (substResult) {
        partIndex = 0;
        while (substResult[partIndex]) {
            free(substResult[partIndex]);
            ++partIndex;
        }
        free(substResult);
    }
    if (command)
        free(command);
    return err;
}

static int runCommand(const char *origCommand, const abl_info *info) {
    return _runCommand(origCommand, info, ablExec);
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


static int update_status(const abl_db *db, const char *object, 
        ablObjectType type, const char *service, const char *rule, time_t tm, 
        BlockState *updatedState, int *stateChanged) {
    int err = 0;
    AuthState *objectState = NULL;

    *stateChanged = 0; //assume the state will not change

    err = db->start_transaction(db);
    if (err) {
        log_error("starting transaction to %s.", __func__);
        return err;
    }

    err = db->get(db, object, &objectState, type);
    
    //only update if we have a objectState (It is already in the database and no error)
    if (objectState) {
        *updatedState = rule_test( rule, object, service, objectState, tm);
        //is the state changed
        if (*updatedState != getState(objectState)) {
            //update the BlockState in the objectState
            if (setState(objectState, *updatedState)) {
                log_error( "The state could not be updated.");
            } else {
                //save the objectState
                err = db->put(db, object, objectState, type);
                if ( !err) {
                    *stateChanged = 1;
                }
            }
        }
        destroyAuthState(objectState);
    }
    if (err)
        db->abort_transaction(db);
    else
        db->commit_transaction(db);
    return err;
}

BlockState check_attempt(const abl_db *db, abl_info *info, ModuleAction subjects) {
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
    if ((subjects & ACTION_CHECK_HOST) && host && args->host_rule) {
        int hostStateChanged = 0;
        int err = update_status(db, host, HOST, service, args->host_rule, tm,
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
    if ((subjects & ACTION_CHECK_USER) && user && *user && args->user_rule) {
        int userStateChanged = 0;
        int err = update_status(db, user, USER, service, args->user_rule, tm,
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

int whitelistMatch(const char *object, const char *whitelist, ablObjectType type) {
    if (!object || !whitelist)
        return 0;

    size_t subjLen = strlen(object);
    int hostParsed = 0;
    u_int32_t ip = 0;
    if (type & HOST) {
        int netmask = 0;
        if (parseIP(object, subjLen, &netmask, &ip) == 0 && netmask == -1)
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
        if (subjLen == len && memcmp(begin, object, subjLen) == 0)
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
    if (subjLen == len && memcmp(begin, object, subjLen) == 0)
        return 1;
    return 0;
}

static int record_object(const abl_db *db, abl_info *info, ablObjectType type) {
    if (!db || !args || !info)
        return 1;

    int         err       = 0;
    int stateChanged      = 0;
    BlockState updatedState = CLEAR;
    const char *object    = info->user;
    const char *data      = info->host;
    const char *service   = info->service;
    const char *whitelist = args->user_whitelist;
    long purgeTimeout     = args->user_purge;
    const char *rule      = args->user_rule;

    if (type & HOST) {
        object = info->host;
        data = info->user;
        purgeTimeout = args->host_purge;
        whitelist = args->host_whitelist;
        rule = args->host_rule;
    }
    if (!object || !*object)
        return 0;
    if (whitelistMatch(object, whitelist, type))
        return 0;
    if (purgeTimeout <= 0)
        return 1;
    if (!data)
        data = "";
    if (!service)
        service = "";

    AuthState *objectState = NULL;

    err = db->start_transaction(db);
    if (err) {
        log_error("starting transaction to %s.", __func__);
        return err;
    }

    err = db->get(db, object, &objectState, type);
    if (!err && !objectState) {
        if (createEmptyState(CLEAR, &objectState)) {
            log_error( "Could not create an empty entry.");
        }
    }

    if (objectState) {
        time_t tm = time(NULL);
        time_t purgeTime = tm - purgeTimeout;
        //if it already existed in the db, we loaded it and otherwise we created an empty state.
        //first do a purge, this way we can make some room for our next attempt
        purgeAuthState(objectState, purgeTime);
        if (addAttempt(objectState, info->blockReason, tm, data, service, args->lowerlimit, args->upperlimit)) {
            log_error( "adding an attempt.");
        } else {
            //now determine if the subjects state has changed
            updatedState = rule_test( rule, object, service, objectState, tm);
            if (updatedState != getState(objectState)) {
                if (setState(objectState, updatedState)) {
                    log_error( "The state could not be updated.");
                } else {
                    stateChanged = 1;
                }
            }
            err = db->put(db, object, objectState, type);
        }
        destroyAuthState(objectState);
    }
    if (err)
        db->abort_transaction(db);
    else
        db->commit_transaction(db);
    //only run the custom command if we have no error
    if (!err && stateChanged) {
        if (type & HOST)
            runHostCommand(updatedState, info);
        else
            runUserCommand(updatedState, info);
    }
    return err;
}

int record_attempt(const abl_db *db, abl_info *info, ModuleAction subjects) {
    if (!db || !args || !info)
        return 1;

    int addHostResult = 0;
    int addUserResult = 0;
    if (subjects & ACTION_LOG_HOST && info->host && *info->host)
        addHostResult = record_object(db, info,  HOST);
    if (subjects & ACTION_LOG_USER && info->user && *info->user)
        addUserResult = record_object(db, info,  USER);

    return addHostResult || addUserResult;
}
