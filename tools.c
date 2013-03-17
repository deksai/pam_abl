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
#include "rule.h"
#include "config.h"
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>

#define PAD "\t"
#define DEFAULT_CONFIG "/etc/security/pam_abl.conf"
#define MAXNAMES 200

typedef enum {
    FAIL,
    WHITELIST,
    CHECK,
    PURGE,
    SHOW,
    UPDATE,
    DEBUGCOMMAND
} CommandType;

static int relative  = 0;
static int verbose   = 0;
char *users[MAXNAMES];
char *hosts[MAXNAMES];
CommandType command=SHOW;
int num_users=0;
int num_hosts=0;

static void usage(const char *prg) {
    printf("Usage: %s [OPTION] [CONFIG]\n", prg);
    printf("Perform maintenance on the databases used by the pam_abl (auto blacklist)\n"
           "module. CONFIG is the name of the pam_abl config file (defaults to\n"
           DEFAULT_CONFIG "). The config file is read to discover the names\n"
           "of the pam_abl databases and the rules that control purging of old data\n"
           "from them. The following options are available:\n\n"
           "MAINTENANCE\n"
           "  -h, --help              See this message.\n"
           "  -d, --debugcommand      Print the block/clear commands split in arguments.\n"
           "  -p, --purge             Purge databases based on rules in config.\n"
           "  -r, --relative          Display times relative to now.\n"
           "  -v, --verbose           Verbose output.\n"
           "\n"
           "NON-PAM INTERACTION\n"
           "  -f  --fail\n"
           "      Fail user or host.\n"
           "  -w  --whitelist\n"
           "      Perform whitelisting (remove from blacklist, does not provide immunity).\n"
           "  -c  --check\n"
           "      Check status.  Returns non-zero if currently blocked\n"
           "      Prints 'name: status' if verboseness is specified.\n"
           "  -u  --update\n"
           "      Update the state of all users/hosts in the db.\n"
           "      This will also cause the appropriate scripts to be called.\n"
           "  -s  --service\n"
           "      Operate in context of specified service.  Defaults to 'none'.\n"
           "  -U  --user\n"
           "      Operate on user (wildcards are ok for whitelisting).\n"
           "  -H  --host\n"
           "      Operate on host (wildcards are ok for whitelisting).\n"
           "  -R  --reason\n"
           "      Only used when -f is provided (defaults to \"AUTH\").\n"
           "      Possible values are USER, HOST, BOTH, AUTH\n"
           "\n");
    exit(0);
}

static void mention(const char *msg, ...) {
    if (verbose > 0) {
        va_list ap;
        va_start(ap, msg);
        vprintf(msg, ap);
        printf("\n");
        va_end(ap);
    }
}

static int wildmatch(const char *key, const char *value, const char *end) {
    for (;;) {
        switch (*key) {
        case '\0':
            return value == end;
        case '*':
            key++;
            for (;;) {
                if (wildmatch(key, value, end)) {
                    return 1;
                }
                if (value == end) {
                    return 0;
                }
                value++;
            }
        case '?':
            if (value == end) {
                return 0;
            }
            break;
        default:
            if (value == end || *value++ != *key) {
                return 0;
            }
            break;
        }
        key++;
    }
}

static void reltime(long t) {
    long days    = t / (24 * 60 * 60);
    long hours   = t / (60 * 60) % 24;
    long minutes = t / 60 % 60;
    long seconds = t % 60;
    printf(PAD PAD "%ld/%02ld:%02ld:%02ld\n", days, hours, minutes, seconds);
}

static void showblocking(const char *rule, AuthState *history, time_t now, log_context *log) {
    int op = 0;
    while (*rule) {
        const char *up;
        const char *colon = strchr(rule, ':');
        if (NULL == colon) {
            break;
        }
        up = rule;
        rule = colon + 1;
        if (rule_matchperiods(log, history, now, &rule)) {
            if (!op) {
                printf(PAD PAD "Blocked based on rule [");
                op = 1;
            } else {
                printf("], [");
            }
            while (up != colon) {
               putchar(*up++);
            }
        }
        while (*rule != '\0' && !isspace(*rule)) {
            rule++;
        }
        while (*rule != '\0' && isspace(*rule)) {
            rule++;
        }
    }

    if (op) {
        printf("]\n");
    } else {
        printf(PAD PAD "Not blocking\n");
    }
}

static int doshow(const abl_args *args, PamAblDbEnv *dbEnv, log_context *logContext, int isHost) {
    DB *db=NULL;
    DBT key, data;
    DBC *cursor;
    int err = 0;
    u_int32_t bsz = 0;
    int cnt = 0;
    char *buf = NULL;
    char *thing = NULL;
    const char *rule = NULL;
    time_t now = time(NULL);

    if (args == NULL || dbEnv == NULL || dbEnv->m_environment == NULL) {
        return 0;
    }
    if(isHost) {
        db = dbEnv->m_hostDb ? dbEnv->m_hostDb->m_dbHandle : NULL;
        thing = "hosts";
        rule = args->host_rule;
    } else {
        db = dbEnv->m_userDb ? dbEnv->m_userDb->m_dbHandle : NULL;
        thing = "users";
        rule = args->user_rule;
    }

    //is there a db for this type?
    if (!db)
        return 0;

    //Section header for output
    printf("Failed %s:\n", thing);

    memset(&key,  0, sizeof(key));
    memset(&data, 0, sizeof(data));

    err = startTransaction(dbEnv->m_environment);
    if (err) {
        log_db_error(logContext, err, "starting transaction");
        goto doshow_fail;
    }
    DB_TXN *tid = dbEnv->m_environment->m_transaction;
    if (err = db->cursor(db, tid, &cursor, 0), 0 != err) {
        log_db_error(logContext, err, "creating cursor");
        goto doshow_fail;
    }

    for (;;) {
        err = cursor->c_get(cursor, &key, &data, DB_NEXT | DB_RMW);
        if (DB_NOTFOUND == err) {
            break;
        } else if (0 != err) {
            log_db_error(logContext, err, "iterating cursor");
            goto doshow_fail;
        }

        /* Print it out */
        if (bsz < key.size + 1) {
            char *nb;
            int ns = key.size + 80;
            if (nb = realloc(buf, ns), NULL == nb) {
                log_sys_error(logContext, ENOMEM, "displaying item");
                goto doshow_fail;
            }
            buf = nb;
            bsz = ns;
        }
        AuthState *state = NULL;
        err = createAuthState(data.data, data.size, &state);
        if (err) {
            log_error(logContext, "Could not parse the attempts in the database.");
            goto doshow_fail;
        }
        memcpy(buf, key.data, key.size);
        buf[key.size] = '\0';
        printf(PAD "%s (%u)\n", buf, getNofAttempts(state));
        cnt++;

        if (verbose) {
            AuthAttempt attempt;
            while (nextAttempt(state, &attempt) == 0) {
                if (relative) {
                    reltime((long) difftime(now, attempt.m_time));
                } else {
                    char *reason = NULL;
                    switch (attempt.m_reason) {
                        case USER_BLOCKED:
                            reason = "USER";
                            break;
                        case HOST_BLOCKED:
                            reason = "HOST";
                            break;
                        case BOTH_BLOCKED:
                            reason = "BOTH";
                            break;
                        case AUTH_FAILED:
                            reason = "AUTH";
                            break;
                        default:
                            reason = "<UNKNOWN>";
                    }
                    printf(PAD PAD "%s" PAD PAD "%s" PAD PAD "%s" PAD PAD "%s", attempt.m_service, attempt.m_userOrHost, reason, ctime(&attempt.m_time));
                }
            }
        } else if (NULL != rule) {
            showblocking(rule, state, now, logContext);
        }
        destroyAuthState(state);
    }

    if (0 == cnt) {
        printf("   <none>\n");
    }

    /* Cleanup */
doshow_fail:
#if DB_VERSION_MAJOR < 5
    if (cursor != NULL)
        cursor->c_close(cursor);
#else
    if (cursor != NULL)
        cursor->close(cursor);
#endif
    commitTransaction(dbEnv->m_environment);
    free(buf);
    return err;
}

static int dopurge(const abl_args *args, PamAblDbEnv *dbEnv, log_context *logContext, int isHost) {
    DB *db = NULL;
    DBT key, data;
    DBC *cursor;
    DB_TXN *tid = NULL;
    int err;
    time_t now = time(NULL);
    time_t purgeTime = now;
    char *buf = NULL;
    u_int32_t bsz = 0;

    if (!args || !dbEnv)
        return 1;

    if(isHost) {
        db = dbEnv->m_hostDb ? dbEnv->m_hostDb->m_dbHandle : NULL;
        purgeTime = now - args->host_purge;
    } else {
        db = dbEnv->m_userDb ? dbEnv->m_userDb->m_dbHandle : NULL;
        purgeTime = now - args->user_purge;
    }

    if (!db)
        return 0; //db was not opened, perhaps not specified in config => do nothing

    //Cheat, because get_dbname is broken starting on some version lower than 4.8
    mention("Purging %s", db->fname);

    memset(&key,  0, sizeof(key));
    memset(&data, 0, sizeof(data));

    err = startTransaction(dbEnv->m_environment);
    if (err) {
        log_db_error(logContext, err, "starting transaction");
        goto dopurge_fail;
    }
    tid = dbEnv->m_environment->m_transaction;
    if (err = db->cursor(db, tid, &cursor, 0), 0 != err) {
        log_db_error(logContext, err, "creating cursor");
        goto dopurge_fail;
    }

    for (;;) {
        err = cursor->c_get(cursor, &key, &data, DB_NEXT | DB_RMW);
        if (DB_NOTFOUND == err) {
            err = 0; //not really an error, just at the end
            break;
        } else if (0 != err) {
            log_db_error(logContext, err, "iterating cursor");
            goto dopurge_fail;
        }

        AuthState *state = NULL;
        err = createAuthState(data.data, data.size, &state);
        if (err) {
            log_error(logContext, "Could not parse the attempts in the database.");
            goto dopurge_fail;
        }
        purgeAuthState(state, purgeTime);
        if (getNofAttempts(state) == 0) {
            err = cursor->c_del(cursor, 0);
            if (err) {
                destroyAuthState(state);
                goto dopurge_fail;
            }
            if (getState(state) != CLEAR) {
                if (bsz < key.size + 1) {
                    char *nb;
                    int ns = key.size + 80;
                    if (nb = realloc(buf, ns), NULL == nb) {
                        err = 1;
                        log_sys_error(logContext, ENOMEM, "white listing items");
                        goto dopurge_fail;
                    }
                    buf = nb;
                    bsz = ns;
                }
                memcpy(buf, key.data, key.size);
                buf[key.size] = '\0';
                abl_info info;
                info.blockReason = CLEAR;
                info.user = NULL;
                info.host = NULL;
                info.service = NULL;
                if (isHost) {
                    info.host = &buf[0];
                    runHostCommand(CLEAR, args, &info, logContext);
                } else {
                    info.user = &buf[0];
                    runUserCommand(CLEAR, args, &info, logContext);
                }
            }
        } else {
            DBT newData;
            memset(&newData, 0, sizeof(newData));
            newData.data = state->m_data;
            newData.size = state->m_usedSize;
            err = cursor->c_put(cursor, &key, &newData, DB_CURRENT);
            if (err) {
                log_db_error(logContext, err, "saving purged result.");
                goto dopurge_fail;
            }
        }
        destroyAuthState(state);
    }

    // Cleanup
dopurge_fail:
    free(buf);
#if DB_VERSION_MAJOR < 5
    if (cursor)
        cursor->c_close(cursor);
#else
    if (cursor)
        cursor->close(cursor);
#endif

    if (tid) {
        if (err)
            abortTransaction(dbEnv->m_environment);
        else
            commitTransaction(dbEnv->m_environment);
    }
    return err;
}

static int doupdate(const abl_args *args, PamAblDbEnv *dbEnv, log_context *logContext, int isHost) {
    DB *db = NULL;
    DBT key, data;
    DBC *cursor;
    DB_TXN *tid = NULL;
    int err;
    time_t now = time(NULL);
    char *buf = NULL;
    const char *rule = NULL;
    u_int32_t bsz = 0;

    if (!args || !dbEnv)
        return 1;

    if(isHost) {
        db = dbEnv->m_hostDb ? dbEnv->m_hostDb->m_dbHandle : NULL;
        rule = args->host_rule;
    } else {
        db = dbEnv->m_userDb ? dbEnv->m_userDb->m_dbHandle : NULL;
        rule = args->user_rule;
    }

    if (!db)
        return 0; //db was not opened, perhaps not specified in config => do nothing

    memset(&key,  0, sizeof(key));
    memset(&data, 0, sizeof(data));

    err = startTransaction(dbEnv->m_environment);
    if (err) {
        log_db_error(logContext, err, "starting transaction");
        goto doupdate_fail;
    }
    tid = dbEnv->m_environment->m_transaction;
    if (err = db->cursor(db, tid, &cursor, 0), 0 != err) {
        log_db_error(logContext, err, "creating cursor");
        goto doupdate_fail;
    }

    for (;;) {
        err = cursor->c_get(cursor, &key, &data, DB_NEXT | DB_RMW);
        if (DB_NOTFOUND == err) {
            err = 0; //not really an error, just at the end
            break;
        } else if (0 != err) {
            log_db_error(logContext, err, "iterating cursor");
            goto doupdate_fail;
        }

        AuthState *state = NULL;
        err = createAuthState(data.data, data.size, &state);
        if (err) {
            log_error(logContext, "Could not parse the attempts in the database.");
            goto doupdate_fail;
        }
        if (bsz < key.size + 1) {
            char *nb;
            int ns = key.size + 80;
            if (nb = realloc(buf, ns), NULL == nb) {
                err = 1;
                log_sys_error(logContext, ENOMEM, "white updating items");
                goto doupdate_fail;
            }
            buf = nb;
            bsz = ns;
        }
        memcpy(buf, key.data, key.size);
        buf[key.size] = '\0';
        BlockState updatedState = rule_test(logContext, rule, &buf[0], NULL, state, now);
        //is the state changed
        if (updatedState != getState(state)) {
            //update the BlockState in the subjectState
            if (setState(state, updatedState)) {
                log_error(logContext, "The state could not be updated.");
            } else {
                DBT newData;
                memset(&newData, 0, sizeof(newData));
                newData.data = state->m_data;
                newData.size = state->m_usedSize;
                err = cursor->c_put(cursor, &key, &newData, DB_CURRENT);
                if (err) {
                    log_db_error(logContext, err, "saving purged result.");
                    goto doupdate_fail;
                }
                abl_info info;
                info.blockReason = CLEAR;
                info.user = NULL;
                info.host = NULL;
                info.service = NULL;
                if (isHost) {
                    info.host = &buf[0];
                    runHostCommand(updatedState, args, &info, logContext);
                } else {
                    info.user = &buf[0];
                    runUserCommand(updatedState, args, &info, logContext);
                }
            }
        }
        destroyAuthState(state);
    }

    // Cleanup
doupdate_fail:
    free(buf);
#if DB_VERSION_MAJOR < 5
    if (cursor)
        cursor->c_close(cursor);
#else
    if (cursor)
        cursor->close(cursor);
#endif

    if (tid) {
        if (err)
            abortTransaction(dbEnv->m_environment);
        else
            commitTransaction(dbEnv->m_environment);
    }
    return err;
}

static int whitelist(const abl_args *args, PamAblDbEnv *dbEnv, int isHost, char **permit, int count, log_context *logContext) {
    DB *db = NULL;
    int err = 0;
    DBT key, data;
    DBC *cursor = NULL;
    DB_TXN *tid = NULL;
    int del = 0;
    char *buf = NULL;
    u_int32_t bsz = 0;

    if (args == NULL || !dbEnv || !dbEnv->m_environment)
        return 0;

    if (isHost)
        db = dbEnv->m_hostDb ? dbEnv->m_hostDb->m_dbHandle : NULL;
    else
        db = dbEnv->m_userDb ? dbEnv->m_userDb->m_dbHandle : NULL;

    if (!db)
        return 0;

    memset(&key,  0, sizeof(key));
    memset(&data, 0, sizeof(data));

    if (startTransaction(dbEnv->m_environment)) {
        log_db_error(logContext, err, "starting transaction");
        goto whitelist_fail;
    }
    tid = dbEnv->m_environment->m_transaction;

    if (err = db->cursor(db, tid, &cursor, 0), 0 != err) {
        log_db_error(logContext, err, "creating cursor");
        goto whitelist_fail;
    }

    for (;;) {
        err = cursor->c_get(cursor, &key, &data, DB_NEXT | DB_RMW);
        if (DB_NOTFOUND == err) {
            //this is not actually an error
            err = 0;
            break;
        } else if (err) {
            log_db_error(logContext, err, "iterating cursor");
            goto whitelist_fail;
        }

        int n;
        int match = 0;
        for (n = 0; n < count; n++) {
            if (wildmatch(permit[n], (const char *) key.data, (const char *) key.data + key.size)) {
                match = 1;
                break;
            }
        }

        if (match) {
            AuthState *state = NULL;
            err = createAuthState(data.data, data.size, &state);
            if (err) {
                log_error(logContext, "Could not parse a attempts in the database.");
                continue;
            }
            err = cursor->c_del(cursor, 0);
            if (err) {
                goto whitelist_fail;
            }
            if (getState(state) != CLEAR) {
                if (bsz < key.size + 1) {
                    char *nb;
                    int ns = key.size + 80;
                    if (nb = realloc(buf, ns), NULL == nb) {
                        err = 1;
                        log_sys_error(logContext, ENOMEM, "white listing items");
                        goto whitelist_fail;
                    }
                    buf = nb;
                    bsz = ns;
                }
                memcpy(buf, key.data, key.size);
                buf[key.size] = '\0';
                abl_info info;
                info.blockReason = CLEAR;
                info.user = NULL;
                info.host = NULL;
                info.service = NULL;
                if (isHost) {
                    info.host = &buf[0];
                    runHostCommand(CLEAR, args, &info, logContext);
                } else {
                    info.user = &buf[0];
                    runUserCommand(CLEAR, args, &info, logContext);
                }
            }
            ++del;
            destroyAuthState(state);
        }
    }

    if (verbose && del > 0)
        printf("Deleted %d item%s\n", del, del == 1 ? "" : "s");

    // Cleanup
whitelist_fail:
    free(buf);
#if DB_VERSION_MAJOR < 5
    if (cursor != NULL)
        cursor->c_close(cursor);
#else
    if (cursor != NULL)
        cursor->close(cursor);
#endif
    if (tid) {
        if (err)
            abortTransaction(dbEnv->m_environment);
        else
            commitTransaction(dbEnv->m_environment);
    }
    return err;
}

static int fail(const PamAblDbEnv *dbEnv, const abl_args *args, abl_info *info, log_context *logContext) {
    if (args == NULL || info == NULL || dbEnv == NULL)
        return 0;

    int err = record_attempt(dbEnv, args, info, logContext);
    if (!err)
        check_attempt(dbEnv, args, info, logContext);
    return err;
}

static void printParsedCommand(const char *commandName, const char *origCommand, log_context *logContext) {
    char *commandCopy = NULL;
    char** result = NULL;
    int argNum = 0;
    if (!origCommand || ! *origCommand) {
        printf("%s: No command\n", commandName);
        return;
    }
    commandCopy = strdup(origCommand);
    if (!commandCopy) {
        log_error(logContext, "Could not duplicate string. Out of memory?");
        goto cleanup;
    }
    argNum = splitCommand(commandCopy, NULL, logContext);
    //no real command
    if (argNum == 0) {
        printf("%s: Parsing resulted in no command to run.\n", commandName);
        goto cleanup;
    }
    if (argNum < 0) {
        printf("%s: Parse error.\n", commandName);
        goto cleanup;
    }

    result = malloc((argNum+1) * sizeof(char*));
    memset(result, 0, (argNum+1) * sizeof(char*));
    argNum = splitCommand(commandCopy, result, logContext);

    int ix = 0;
    printf("%s: ", commandName);
    while (result[ix]) {
        printf("\"%s\" ", result[ix]);
        ++ix;
    }
    printf("\n");
cleanup:
    if (commandCopy)
        free(commandCopy);
    if (result)
        free(result);
}

int main(int argc, char **argv) {
    //assume everything will be ok
    int err = 0;
    int n, c;
    char *conf = NULL;
    char *service = "none";
    PamAblDbEnv *dbEnv = NULL;
    BlockReason bReason = AUTH_FAILED;
    abl_args *args = config_create();
    abl_info info;
    log_context *logContext = createLogContext();

    if (!args) {
        log_error(logContext, "Failed to allocate memory.");
        return 1;
    }

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"help",        0, 0,    'h' },
            {"debugcommand",0, 0,    'd' },
            {"purge",       0, 0,    'p' },
            {"update",      0, 0,    'u' },
            {"relative",    0, 0,    'r' },
            {"verbose",     0, 0,    'v' },
            {"fail",        1, 0,    'f' },
            {"whitelist",   1, 0,    'w' },
            {"check",       1, 0,    'c' },
            {"user",        1, 0,    'U' },
            {"host",        1, 0,    'H' },
            {"service",     1, 0,    's' },
            {"reason",      1, 0,    'R' },
            {0,             0, 0,     0  }
        };

        c = getopt_long(argc, argv, "hdrvpufwcU:H:s:R:",
                long_options, &option_index);
        if (c == -1)
            break;
        switch (c) {
            case 'h':
                usage(argv[0]);
                break;
            case 'd':
                command = DEBUGCOMMAND;
                break;
            case 'p':
                command = PURGE;
                break;
            case 'u':
                command = UPDATE;
                break;
            case 'r':
                relative=1;
                break;
            case 'v':
                verbose=1;
                break;
            case 'f':
                command = FAIL;
                break;
            case 'w':
                command = WHITELIST;
                break;
            case 'c':
                command = CHECK;
                break;
            case 'U':
                users[num_users++]=optarg;
                break;
            case 'H':
                hosts[num_hosts++]=optarg;
                break;
            case 's':
                service=optarg;
                break;
            case 'R':
                if (strcmp("USER", optarg) == 0) {
                    bReason = USER_BLOCKED;
                } else if (strcmp("HOST", optarg) == 0) {
                    bReason = HOST_BLOCKED;
                } else if (strcmp("BOTH", optarg) == 0) {
                    bReason = BOTH_BLOCKED;
                } else if (strcmp("AUTH", optarg) == 0) {
                    bReason = AUTH_FAILED;
                } else {
                    log_error(logContext, "No valid block reason given, defaulting to AUTH.");
                }
                break;
            case '?':
                break;

            default:
                printf("Unknown error parsing command line arguments: code 0%o\n", c);
        }
    }

    if (optind < argc) {
        conf = argv[optind++];
        while (optind < argc)
            mention("Ignored command line argument: %s\n",argv[optind++]);
    }
    if (NULL == conf) {
        conf = DEFAULT_CONFIG;
    }

    mention("Reading config from %s", conf);
    if (err = config_parse_file(conf, args, logContext), 0 != err) {
        return err;
    }

    if (command == DEBUGCOMMAND) {
        printParsedCommand("host_block_cmd", args->host_blk_cmd, logContext);
        printParsedCommand("host_clear_cmd", args->host_clr_cmd, logContext);
        printParsedCommand("user_block_cmd", args->user_blk_cmd, logContext);
        printParsedCommand("user_clear_cmd", args->user_clr_cmd, logContext);
        err = 0;
        goto main_done;
    }

    if (NULL == args->user_db) {
        mention("No user_db in %s", conf);
    }

    if (NULL == args->host_db) {
        mention("No host_db in %s", conf);
    }
    dump_args(args, logContext);

    for(n=0;n<num_users;n++){
        log_debug(logContext, "user: %s",users[n]);
    }
    for(n=0;n<num_hosts;n++){
        log_debug(logContext,"host: %s",hosts[n]);
    }
    memset(&info, 0, sizeof(abl_info));

    /* Most everything should be set, and it should be safe to open the
     * databases. */
    dbEnv = openPamAblDbEnvironment(args, logContext);
    if (!dbEnv) {
        return 1;
    }

    if (command == WHITELIST) {
        if (num_users > 0)
            whitelist(args, dbEnv, 0, users, num_users, logContext);
        if (num_hosts > 0)
            whitelist(args, dbEnv, 1, hosts, num_hosts, logContext);
        if (num_users == 0 && num_hosts == 0) {
            log_error(logContext, "Asked to whitelist but no hosts or users given!");
            err = 1;
            goto main_done;
        }
    } else if (command == FAIL) {
        if (num_users == 0 && num_hosts == 0) {
            log_error(logContext, "Asked to fail someone, but no hosts or users given!");
            err = 1;
            goto main_done;
        }
        if (num_users > 1 || num_hosts > 1) {
            log_warning(logContext, "Multiple hosts and/or users given, only the first will be used!");
        }
        info.service = service;
        info.blockReason = bReason;
        info.user = num_users > 0 ? users[0] : NULL;
        info.host = num_hosts > 0 ? hosts[0] : NULL;
        fail(dbEnv, args, &info, logContext);
    } else if (command == CHECK) {
        if (num_users == 0 && num_hosts == 0) {
            log_error(logContext, "Asked to check but no hosts or users given!");
            err = 1;
            goto main_done;
        }
        if (num_hosts > 1) {
            log_warning(logContext, "More than one host specified.  Only the first one will be used!");
        }
        if (num_users > 1) {
            log_warning(logContext, "More than one user specified.  Only the first one will be used!");
        }

        info.service = service;
        info.host = num_hosts > 0 ? hosts[0] : NULL;
        info.user = num_users > 0 ? users[0] : NULL;
        BlockState bState = check_attempt(dbEnv, args, &info, logContext);
        if (bState == BLOCKED)
            err = 1;
        else
            err = 0;
        goto main_done;
    } else if (command == UPDATE) {
        doupdate(args, dbEnv, logContext, 0);
        doupdate(args, dbEnv, logContext, 1);
    } else if (command == PURGE) {
        dopurge(args, dbEnv, logContext, 0);
        dopurge(args, dbEnv, logContext, 1);
    } else if (num_users == 0 && num_hosts == 0) {
        doshow(args, dbEnv, logContext, 0);
        doshow(args, dbEnv, logContext, 1);
    }

main_done:
    if (dbEnv)
        destroyPamAblDbEnvironment(dbEnv);
    if (args)
        config_free(args);
    if (logContext)
        destroyLogContext(logContext);
    return err;
}
