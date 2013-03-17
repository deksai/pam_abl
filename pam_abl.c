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
    //setting it with NULL effectively frees the memory
    setInfo(info, NULL, NULL, NULL);
    if (info)
        free(info);
}

void setInfo(abl_info *info, const char *user, const char *host, const char *service) {
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
    if (user)
        info->user = strdup(user);
    if (host)
        info->host = strdup(host);
    if (service)
        info->service = strdup(service);
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

int _runCommand(const char *origCommand, const abl_info *info, log_context *logContext, int (execFun)(char *const arg[])) {
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
    argNum = splitCommand(command, NULL, logContext);
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
    argNum = splitCommand(command, result, logContext);

    //now iterate over all the parts of the array and substitute everything
    int partIndex = 0;
    while (result[partIndex]) {
        bufSize = prepare_string(result[partIndex], info, NULL);
        if (bufSize <= 0) {
            //crap, something went wrong
            //the error should already been logged
            log_warning(logContext, "failed to substitute %s.", result[partIndex]);
            err = 1;
            goto cleanup;
        }
        if (bufSize > COMMAND_SIZE) {
            log_warning(logContext, "command length error.");
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

static int runCommand(const char *origCommand, const abl_info *info, log_context *logContext) {
    return _runCommand(origCommand, info, logContext, ablExec);
}

int runHostCommand(BlockState bState, const abl_args *args, abl_info *info, log_context *logContext) {
    const char *command = NULL;
    if (bState == BLOCKED)
        command = args->host_blk_cmd;
    else if (bState == CLEAR)
        command = args->host_clr_cmd;
    return runCommand(command, info, logContext);
}

int runUserCommand(BlockState bState, const abl_args *args, abl_info *info, log_context *logContext) {
    const char *command = NULL;
    if (bState == BLOCKED)
        command = args->user_blk_cmd;
    else if (bState == CLEAR)
        command = args->user_clr_cmd;
    return runCommand(command, info, logContext);
}

PamAblDbEnv *openPamAblDbEnvironment(abl_args *args, log_context *logContext) {
    if (!args || !args->db_home || !*args->db_home)
        return NULL;

    DbEnvironment *environment = NULL;
    Database *hostDb = NULL;
    Database *userDb = NULL;

    int err = createEnvironment(logContext, args->db_home, &environment);
    if (err) {
        log_db_error(logContext, err, "Creating database environment.");
        return NULL;
    }

    if (args->host_db && *args->host_db) {
        err = openDatabase(environment, args->host_db, DB_NAME, &hostDb);
        if (err) {
            log_db_error(logContext, err, "Creating host database.");
            goto open_fail;
        }
    }

    if (args->user_db && *args->user_db) {
        err = openDatabase(environment, args->user_db, DB_NAME, &userDb);
        if (err) {
            log_db_error(logContext, err, "Creating user database.");
            goto open_fail;
        }
    }

    PamAblDbEnv *retValue = malloc(sizeof(PamAblDbEnv));
    if (!retValue) {
        log_error(logContext, "Memory allocation failed while opening the databases.");
        goto open_fail;
    }
    memset(retValue, 0, sizeof(PamAblDbEnv));
    retValue->m_environment = environment;
    retValue->m_hostDb = hostDb;
    retValue->m_userDb = userDb;
    return retValue;

open_fail:
    if (hostDb)
        closeDatabase(hostDb);
    if (userDb)
        closeDatabase(userDb);
    if (environment)
        destroyEnvironment(environment);
    return NULL;
}

void destroyPamAblDbEnvironment(PamAblDbEnv *env) {
    if (!env)
        return;
    if (env->m_hostDb)
        closeDatabase(env->m_hostDb);
    if (env->m_userDb)
        closeDatabase(env->m_userDb);
    if (env->m_environment)
        destroyEnvironment(env->m_environment);
    free(env);
}

static int update_status(Database *db, const char *subject, const char *service, const char *rule, time_t tm,
                 log_context *logContext, BlockState *updatedState, int *stateChanged) {
    //assume the state will not change
    *stateChanged = 0;
    DbEnvironment *dbEnv = db->m_environment;
    AuthState *subjectState = NULL;
    //all database actions need to be wrapped in a transaction
    int err = startTransaction(dbEnv);
    if (err) {
        log_db_error(logContext, err, "starting transaction to update_status.");
        return err;
    }
    err = getUserOrHostInfo(db, subject, &subjectState);
    if (err)
        log_db_error(logContext, err, "retrieving information failed.");
    //only update if we have a subjectState (It is already in the database and no error)
    if (subjectState) {
        *updatedState = rule_test(logContext, rule, subject, service, subjectState, tm);
        //is the state changed
        if (*updatedState != getState(subjectState)) {
            //update the BlockState in the subjectState
            if (setState(subjectState, *updatedState)) {
                log_error(logContext, "The state could not be updated.");
            } else {
                //save the subjectState
                err = saveInfo(db, subject, subjectState);
                if (err) {
                    log_db_error(logContext, err, "saving the changed info.");
                } else {
                    *stateChanged = 1;
                }
            }
        }
        destroyAuthState(subjectState);
    }
    if (err)
        abortTransaction(dbEnv);
    else
        commitTransaction(dbEnv);
    return err;
}

BlockState check_attempt(const PamAblDbEnv *dbEnv, const abl_args *args, abl_info *info, log_context *logContext) {
    if (info)
        info->blockReason = AUTH_FAILED;

    if (!dbEnv || !args || !info)
        return CLEAR;
    time_t tm = time(NULL);
    const char *user = info->user;
    const char *host = info->host;
    const char *service = info->service;
    BlockState updatedHostState = CLEAR;
    BlockState updatedUserState = CLEAR;

    //fist check the host
    //do we need to update the host information?
    if (host && *host && dbEnv->m_hostDb && dbEnv->m_hostDb->m_environment && args->host_rule) {
        int hostStateChanged = 0;
        int err = update_status(dbEnv->m_hostDb, host, service, args->host_rule, tm,
             logContext, &updatedHostState, &hostStateChanged);
        if (!err) {
            if (hostStateChanged)
                runHostCommand(updatedHostState, args, info, logContext);
        } else {
            //if something went wrong, we can't trust the value returned, so by default, do not block
            updatedHostState = CLEAR;
        }
    }

    //now check the user
    if (user && *user && dbEnv->m_userDb && dbEnv->m_userDb->m_environment && args->user_rule) {
        int userStateChanged = 0;
        int err = update_status(dbEnv->m_userDb, user, service, args->user_rule, tm,
             logContext, &updatedUserState, &userStateChanged);
        if (!err) {
            if (userStateChanged)
                runUserCommand(updatedUserState, args, info, logContext);
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

static int recordSubject(const PamAblDbEnv *pamDb, const abl_args *args, abl_info *info, log_context *logContext, int isHost) {
    if (!pamDb || !args || !info)
        return 1;

    DbEnvironment *dbEnv = pamDb->m_environment;
    Database *db = pamDb->m_userDb;
    const char *subject = info->user;
    const char *data = info->host;
    const char *service = info->service;
    long purgeTimeout = args->user_purge;
    const char *whitelist = args->user_whitelist;
    if (isHost) {
        db = pamDb->m_hostDb;
        subject = info->host;
        data = info->user;
        purgeTimeout = args->host_purge;
        whitelist = args->host_whitelist;
    }
    //if the db was not opened, or nothing to record on => do nothing
    if (!db || !subject || !*subject)
        return 0;
    if (whitelistMatch(subject, whitelist, isHost))
        return 0;
    if (!dbEnv || purgeTimeout <= 0)
        return 1;
    if (!data)
        data = "";
    if (!service)
        service = "";

    AuthState *subjectState = NULL;
    //all database actions need to be wrapped in a transaction
    int err = startTransaction(dbEnv);
    if (err) {
        log_db_error(logContext, err, "starting the transaction to record_attempt.");
        return err;
    }
    err = getUserOrHostInfo(db, subject, &subjectState);
    if (err) {
        log_db_error(logContext, err, "retrieving information failed.");
    } else if (!subjectState) {
        if (createEmptyState(CLEAR, &subjectState)) {
            log_error(logContext, "Could not create an empty entry.");
        }
    }

    if (subjectState) {
        time_t tm = time(NULL);
        time_t purgeTime = tm - purgeTimeout;
        //if it already existed in the db, we loaded it and otherwise we created an empty state.
        //first do a purge, this way we can make some room for our next attempt
        purgeAuthState(subjectState, purgeTime);
        if (addAttempt(subjectState, info->blockReason, tm, data, service, args->lowerlimit, args->upperlimit)) {
            log_error(logContext, "adding an attempt.");
        } else {
            err = saveInfo(db, subject, subjectState);
            if (err)
                log_db_error(logContext, err, "saving the changed entry with added attempt.");
        }
        destroyAuthState(subjectState);
    }
    if (err)
        abortTransaction(pamDb->m_environment);
    else
        commitTransaction(pamDb->m_environment);
    return err;
}

int record_attempt(const PamAblDbEnv *dbEnv, const abl_args *args, abl_info *info, log_context *logContext) {
    if (!dbEnv || !args || !info)
        return 1;

    int addHostResult = 0;
    int addUserResult = 0;
    if (info->host && *info->host)
        addHostResult = recordSubject(dbEnv, args, info, logContext, 1);
    if (info->user && *info->user)
        addUserResult = recordSubject(dbEnv, args, info, logContext, 0);

    return addHostResult || addUserResult;
}
