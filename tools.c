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
#include "config.h"
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <dlfcn.h>

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
const char *users[MAXNAMES];
const char *hosts[MAXNAMES];
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

static void showblocking(const char *rule, AuthState *history, time_t now) {
    int op = 0;
    while (*rule) {
        const char *up;
        const char *colon = strchr(rule, ':');
        if (NULL == colon) {
            break;
        }
        up = rule;
        rule = colon + 1;
        if (rule_matchperiods(history, now, &rule)) {
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

static int doshow(abl_db *db, ablObjectType type) {
    int         err     = 0;
    int         cnt     = 0;
    char        *buf    = NULL;
    char        *thing  = NULL;
    char        *key    = NULL;
    char        *data   = NULL;
    const char  *rule   = NULL;
    time_t      now     = time(NULL);
    u_int32_t   bsz     = 0;
    size_t      ksize   = 0;
    size_t      dsize   = 0;

    if (!args || !db) return 0;

    if(type && HOST) {
        thing = "hosts";
        rule = args->host_rule;
        db->c_open(db, HOST);
    } else {
        thing = "users";
        rule = args->user_rule;
        db->c_open(db, USER);
    }

    //Section header for output
    printf("Failed %s:\n", thing);

    for (;;) {
        if (db->c_get(db, &key, &ksize, &data, &dsize))
            break;

        /* Print it out */
        if (bsz < ksize + 1) {
            char *nb;
            int ns = ksize + 80;
            if (nb = realloc(buf, ns), NULL == nb) {
                log_sys_error(ENOMEM, "displaying item");
                goto doshow_fail;
            }
            buf = nb;
            bsz = ns;
        }
        AuthState *state = NULL;
        err = createAuthState(data, dsize, &state);
        if (err) {
            log_error("Could not parse the attempts in the database.");
            goto doshow_fail;
        }
        memcpy(buf, key, ksize);
        buf[ksize] = '\0';
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
            showblocking(rule, state, now);
        }
        destroyAuthState(state);
    }

    if (0 == cnt) {
        printf("   <none>\n");
    }

    /* Cleanup */
doshow_fail:
    db->c_close(db);
    free(buf);
    return err;
}

static int dopurge(abl_db *abldb, ablObjectType type) {
    int       err;
    char      *key = NULL, *data = NULL, *buf = NULL;
    time_t    now = time(NULL);
    time_t    purgeTime = now;
    size_t    ksize = 0, dsize = 0;
    u_int32_t bsz = 0;

    if (!abldb || !args)
        return 1; 

    if(type && HOST) {
        purgeTime = now - args->host_purge;
    } else {
        purgeTime = now - args->user_purge;
    }

    mention("Purging");
    if (err = abldb->c_open(abldb, type), 0 != err) {
        goto dopurge_fail;
    }

    for (;;) {
        err = abldb->c_get(abldb, &key, &ksize, &data, &dsize);
        if (err) 
            break;

        AuthState *authstate = NULL;
        err = createAuthState(data, dsize, &authstate);
        if (err) {
            log_error("Could not parse the attempts in the database.");
            goto dopurge_fail;
        }
        purgeAuthState(authstate, purgeTime);
        if (getNofAttempts(authstate) == 0) {
            err = abldb->del(abldb, key, type);
            if (err) {
                destroyAuthState(authstate);
                goto dopurge_fail;
            }
            if (getState(authstate) != CLEAR) {
                if (bsz < ksize + 1) {
                    char *nb;
                    int ns = ksize + 80;
                    if (nb = realloc(buf, ns), NULL == nb) {
                        err = 1;
                        log_sys_error(ENOMEM, "white listing items");
                        goto dopurge_fail;
                    }
                    buf = nb;
                    bsz = ns;
                }
                memcpy(buf, key, ksize);
                buf[ksize] = '\0';
                abl_info info;
                info.blockReason = CLEAR;
                info.user = NULL;
                info.host = NULL;
                info.service = NULL;
                if (type && HOST) {
                    info.host = &buf[0];
                    runHostCommand(CLEAR, &info);
                } else {
                    info.user = &buf[0];
                    runUserCommand(CLEAR, &info);
                }
            }
        } else {
            //err = cursor->c_put(cursor, &key, &newData, DB_CURRENT);
            err = abldb->put(abldb, key, authstate, type);
            if (err) {
                goto dopurge_fail;
            }
        }
        destroyAuthState(authstate);
    }

    // Cleanup
dopurge_fail:
    free(buf);
    abldb->c_close(abldb);
    return err;
}

static int doupdate(abl_db *abldb, ablObjectType type) {
    int         err;
    char        *buf    = NULL;
    char        *key    = NULL;
    char        *data   = NULL;
    const char  *rule   = NULL;
    time_t      now     = time(NULL);
    size_t      ksize   = 0;
    size_t      dsize   = 0;
    u_int32_t   bsz     = 0;

    if (!abldb || !args)
        return 1;

    if(type && HOST) {
        rule = args->host_rule;
    } else {
        rule = args->user_rule;
    }

    if (err = abldb->c_open(abldb, type), 0 != err) {
        goto doupdate_fail;
    }

    for (;;) {
        err = abldb->c_get(abldb, &key, &ksize, &data, &dsize);
        if (err) 
            break;

        AuthState *authstate = NULL;
        err = createAuthState(data, dsize, &authstate);
        if (err) {
            log_error("Could not parse the attempts in the database.");
            goto doupdate_fail;
        }
        if (bsz < ksize + 1) {
            char *nb;
            int ns = ksize + 80;
            if (nb = realloc(buf, ns), NULL == nb) {
                err = 1;
                log_sys_error(ENOMEM, "white updating items");
                goto doupdate_fail;
            }
            buf = nb;
            bsz = ns;
        }
        memcpy(buf, key, ksize);
        buf[ksize] = '\0';
        BlockState updatedState = rule_test(rule, &buf[0], NULL, authstate, now);
        //is the state changed
        if (updatedState != getState(authstate)) {
            //update the BlockState in the subjectState
            if (setState(authstate, updatedState)) {
                log_error("The state could not be updated.");
            } else {
                err = abldb->put(abldb, key, authstate, type);
                if (err) {
                    goto doupdate_fail;
                }
                abl_info info;
                info.blockReason = CLEAR;
                info.user = NULL;
                info.host = NULL;
                info.service = NULL;
                if (type && HOST) {
                    info.host = &buf[0];
                    runHostCommand(updatedState, &info);
                } else {
                    info.user = &buf[0];
                    runUserCommand(updatedState, &info);
                }
            }
        }
        destroyAuthState(authstate);
    }

    // Cleanup
doupdate_fail:
    free(buf);
    abldb->c_close(abldb);
    return err;
}

static int whitelist(abl_db *abldb, ablObjectType type, const char **permit, int count) {
    int       err   = 0;
    char      *key  = NULL;
    char      *data = NULL;
    int       del   = 0;
    char      *buf  = NULL;
    u_int32_t bsz   = 0;
    size_t    ksize = 0;
    size_t    dsize = 0;

    if (!abldb || !args)
        return 0;

    if (err = abldb->c_open(abldb, type), 0 != err) {
        goto whitelist_fail;
    }

    for (;;) {
        err = abldb->c_get(abldb, &key, &ksize, &data, &dsize);
        if (err) {
            break;
        } 

        int n;
        int match = 0;
        for (n = 0; n < count; n++) {
            if (wildmatch(permit[n], key, key + ksize)) {
                match = 1;
                break;
            }
        }

        if (match) {
            AuthState *authstate = NULL;
            err = createAuthState(data, dsize, &authstate);
            if (err) {
                log_error("Could not parse a attempts in the database.");
                continue;
            }
            err = abldb->del(abldb, key, type);
            if (err) {
                goto whitelist_fail;
            }
            if (getState(authstate) != CLEAR) {
                if (bsz < ksize + 1) {
                    char *nb;
                    int ns = ksize + 80;
                    if (nb = realloc(buf, ns), NULL == nb) {
                        err = 1;
                        log_sys_error(ENOMEM, "white listing items");
                        goto whitelist_fail;
                    }
                    buf = nb;
                    bsz = ns;
                }
                memcpy(buf, key, ksize);
                buf[ksize] = '\0';
                abl_info info;
                info.blockReason = CLEAR;
                info.user = NULL;
                info.host = NULL;
                info.service = NULL;
                if (type && HOST) {
                    info.host = &buf[0];
                    runHostCommand(CLEAR, &info);
                } else {
                    info.user = &buf[0];
                    runUserCommand(CLEAR, &info);
                }
            }
            ++del;
            destroyAuthState(authstate);
        }
    }

    if (verbose && del > 0)
        printf("Deleted %d item%s\n", del, del == 1 ? "" : "s");

    // Cleanup
whitelist_fail:
    free(buf);
    abldb->c_close(abldb);
    return err;
}

static int fail(const abl_db *abldb, abl_info *info) {
    if (args == NULL || info == NULL || abldb == NULL)
        return 0;

    int err = record_attempt(abldb, info);
    if (!err)
        check_attempt(abldb, info);
    return err;
}

static void printParsedCommand(const char *commandName, const char *origCommand) {
    char *commandCopy = NULL;
    char** result = NULL;
    int argNum = 0;
    if (!origCommand || ! *origCommand) {
        printf("%s: No command\n", commandName);
        return;
    }
    commandCopy = strdup(origCommand);
    if (!commandCopy) {
        log_error("Could not duplicate string. Out of memory?");
        goto cleanup;
    }
    argNum = splitCommand(commandCopy, NULL);
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
    argNum = splitCommand(commandCopy, result);

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
    abl_db   *abldb = NULL;
    config_create();
    abl_info info;
    BlockReason bReason = AUTH_FAILED;

    if (!args) {
        log_error("Failed to allocate memory.");
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
                    log_error("No valid block reason given, defaulting to AUTH.");
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
    if (err = config_parse_file(conf), 0 != err) {
        return err;
    }

    if (command == DEBUGCOMMAND) {
        printParsedCommand("host_block_cmd", args->host_blk_cmd);
        printParsedCommand("host_clear_cmd", args->host_clr_cmd);
        printParsedCommand("user_block_cmd", args->user_blk_cmd);
        printParsedCommand("user_clear_cmd", args->user_clr_cmd);
        err = 0;
        goto main_done;
    }

    if (NULL == args->db_module) {
        log_error("No db_module in %s", conf);
        goto main_done;
    }

    if (NULL == args->db_home) {
        log_error("No db_home in %s", conf);
        goto main_done;
    }
    dump_args();

    for(n=0;n<num_users;n++){
        log_debug("user: %s",users[n]);
    }
    for(n=0;n<num_hosts;n++){
        log_debug("host: %s",hosts[n]);
    }
    memset(&info, 0, sizeof(abl_info));

    /* Most everything should be set, and it should be safe to open the
     * databases. */
    void *dblib = NULL;
    abl_db *(*db_open)();

    dblib = dlopen(args->db_module, RTLD_LAZY);
    if (!dblib) {
        log_error("%s opening database module",dlerror());
        goto main_done;
    }
    dlerror();
    db_open = dlsym(dblib, "abl_db_open");
    abldb = db_open();
    if (!abldb) {
        return 1;
    }

    if (command == WHITELIST) {
        if (num_users > 0)
            whitelist(abldb, 0, users, num_users);
        if (num_hosts > 0)
            whitelist(abldb, 1, hosts, num_hosts);
        if (num_users == 0 && num_hosts == 0) {
            log_error("Asked to whitelist but no hosts or users given!");
            err = 1;
            goto main_done;
        }
    } else if (command == FAIL) {
        if (num_users == 0 && num_hosts == 0) {
            log_error("Asked to fail someone, but no hosts or users given!");
            err = 1;
            goto main_done;
        }
        if (num_users > 1 || num_hosts > 1) {
            log_warning("Multiple hosts and/or users given, only the first will be used!");
        }
        info.service = service;
        info.blockReason = bReason;
        info.user = num_users > 0 ? users[0] : NULL;
        info.host = num_hosts > 0 ? hosts[0] : NULL;
        fail(abldb, &info);
    } else if (command == CHECK) {
        if (num_users == 0 && num_hosts == 0) {
            log_error("Asked to check but no hosts or users given!");
            err = 1;
            goto main_done;
        }
        if (num_hosts > 1) {
            log_warning("More than one host specified.  Only the first one will be used!");
        }
        if (num_users > 1) {
            log_warning("More than one user specified.  Only the first one will be used!");
        }

        info.service = service;
        info.host = num_hosts > 0 ? hosts[0] : NULL;
        info.user = num_users > 0 ? users[0] : NULL;
        BlockState bState = check_attempt(abldb, &info);
        if (bState == BLOCKED)
            err = 1;
        else
            err = 0;
        goto main_done;
    } else if (command == UPDATE) {
        doupdate(abldb, 0);
        doupdate(abldb, 1);
    } else if (command == PURGE) {
        dopurge(abldb, 0);
        dopurge(abldb, 1);
    } else if (num_users == 0 && num_hosts == 0) {
        doshow(abldb, 0);
        doshow(abldb, 1);
    }

main_done:
    if (abldb)
        abldb->close(abldb);
    if (args)
        config_free();
    return err;
}
