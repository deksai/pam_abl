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

#include "config.h"
#include "rule.h"

#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>


#define HOURSECS    (60 * 60)
/* Host purge time in seconds */
#define HOST_PURGE  (HOURSECS * 24)
/* User purge time in seconds */
#define USER_PURGE  (HOURSECS * 24)

static size_t config_match(const char *pattern, const char *target, size_t len) {
    return len == strlen(pattern) && memcmp(pattern, target, len) == 0;
}

/* Check an arg string of the form arg=something and return either
 * NULL if the arg doesn't match the supplied name or
 * a pointer to 'something' if the arg matches
 */
static const char *is_arg(const char *name, const char *arg) {
    char *eq;

    if (eq = strchr(arg, '='), NULL == eq) {
        return NULL;
    }

    if (!config_match(name, arg, (size_t)(eq - arg))) {
        return NULL;
    }

    eq++;                                   /* skip '=' */
    while (*eq != '\0' && isspace(*eq)) {   /* skip spaces */
        eq++;
    }

    return eq;
}

static void config_clear(abl_args *args) {
    /* Init the args structure
     */
    args->db_home         = NULL;
    args->host_db         = NULL;
    args->host_rule       = NULL;
    args->host_purge      = HOST_PURGE;
    args->host_whitelist  = NULL;
    args->host_blk_cmd    = NULL;
    args->host_clr_cmd    = NULL;
    args->user_db         = NULL;
    args->user_rule       = NULL;
    args->user_purge      = USER_PURGE;
    args->user_whitelist  = NULL;
    args->user_blk_cmd    = NULL;
    args->user_clr_cmd    = NULL;
    args->upperlimit      = 0;
    args->lowerlimit      = 0;

    args->strs            = NULL;
}

abl_args *config_create() {
    abl_args *retValue = malloc(sizeof(abl_args));
    if (retValue)
        config_clear(retValue);
    return retValue;
}

static int parse_arg(const char *arg, abl_args *args, log_context *logContext) {
    const char *v;
    int err;

    if (0 == strcmp(arg, "debug")) {
        logContext->debug = 1;
    } else if (v = is_arg("db_home", arg), NULL != v) {
        args->db_home = v;
    } else if (v = is_arg("limits", arg), NULL != v) {
        long upper = 0;
        long lower = 0;
        long val = 0;
        short error = 1;
        const char *ptr = v;
        if (parse_long(&ptr, &val) == 0) {
            lower = val;
            if (*ptr == '-') {
                ++ptr;
                if (parse_long(&ptr, &val) == 0) {
                    upper = val;
                    if (upper >= 0 && lower >= 0 && upper >= lower)
                        error = 0;
                }
            }
        }
        if (error) {
            log_warning(logContext, "limits needs to have the following syntax: <lower>-<upper> with upper > lower.");
            args->upperlimit = 0;
            args->lowerlimit = 0;
        } else {
            args->upperlimit = upper;
            args->lowerlimit = lower;
        }
    } else if (v = is_arg("host_db", arg), NULL != v) {
        args->host_db = v;
    } else if (v = is_arg("host_rule", arg), NULL != v) {
        args->host_rule = v;
    } else if (v = is_arg("host_purge", arg), NULL != v) {
        if (err = rule_parse_time(v, &args->host_purge, HOURSECS), 0 != err) {
            log_error(logContext, "Illegal host_purge value: %s", v);
        }
    } else if (v = is_arg("host_blk_cmd", arg), NULL != v) {
        log_error(logContext, "host_blk_cmd is deprecated for security reasons, please use host_block_cmd.");
    } else if (v = is_arg("host_clr_cmd", arg), NULL != v) {
        log_error(logContext, "host_clr_cmd is deprecated for security reasons, please use host_clear_cmd.");
    } else if (v = is_arg("host_block_cmd", arg), NULL != v) { //we will check if it's valid when we try to run it
        args->host_blk_cmd = v;
    } else if (v = is_arg("host_clear_cmd", arg), NULL != v) { //we will check if it's valid when we try to run it
        args->host_clr_cmd = v;
    } else if (v = is_arg("host_whitelist", arg), NULL != v) {
        args->host_whitelist = v;
    } else if (v = is_arg("user_db", arg), NULL != v) {
        args->user_db = v;
    } else if (v = is_arg("user_rule", arg), NULL != v) {
        args->user_rule = v;
    } else if (v = is_arg("user_purge", arg), NULL != v) {
        if (err = rule_parse_time(v, &args->user_purge, HOURSECS), 0 != err) {
            log_error(logContext, "Illegal user_purge value: %s", v);
        }
    } else if (v = is_arg("user_blk_cmd", arg), NULL != v) {
        log_error(logContext, "user_blk_cmd is deprecated for security reasons, please use user_block_cmd.");
    } else if (v = is_arg("user_clr_cmd", arg), NULL != v) {
        log_error(logContext, "user_clr_cmd is deprecated for security reasons, please use user_clear_cmd.");
    } else if (v = is_arg("user_block_cmd", arg), NULL != v) { //we will check if it's valid when we try to run it
        args->user_blk_cmd = v;
    } else if (v = is_arg("user_clear_cmd", arg), NULL != v) { //we will check if it's valid when we try to run it
        args->user_clr_cmd = v;
    } else if (v = is_arg("user_whitelist", arg), NULL != v) {
        args->user_whitelist = v;
    } else if (v = is_arg("config", arg), NULL != v) {
        config_parse_file(v, args, logContext);
    } else {
        log_error(logContext, "Illegal option: %s", arg);
        return EINVAL;
    }
    return 0;
}

struct linebuf {
    char    *buf;
    int     len;
    int     size;
};

struct reader {
    FILE    *f;
    int     lc;
};

static int ensure(log_context *logContext, struct linebuf *b, int minfree) {
    if (b->size - b->len < minfree) {
        char *nb;
        int ns;
        if (minfree < 128) {
            minfree = 128;
        }
        ns = b->len + minfree;
        nb = realloc(b->buf, ns);
        if (NULL == nb) {
            log_sys_error(logContext, ENOMEM, "parsing config file");
            return ENOMEM;
        }
        b->size = ns;
        b->buf  = nb;
        /*log_debug(args, "Line buffer grown to %d", b->size);*/
    }

    return 0;
}

static int readc(struct reader *r) {
    int nc;

    for (;;) {
        nc    = r->lc;
        r->lc = (nc == EOF) ? EOF : getc(r->f);
        /* Handle line continuation */
        if (nc != '\\' || r->lc != '\n') {
            return nc;
        }
        /* No need for EOF check here */
        r->lc = getc(r->f);
    }
}

static int read_line(log_context *logContext, struct linebuf *b, struct reader *r) {
    int c, err;

    c = readc(r);
    b->len = 0;
    while (c != '\n' && c != EOF && c != '#') {
        while (c != '\n' && c != EOF && isspace(c)) {
            c = readc(r);
        }
        while (c != '\n' && c != EOF && c != '#') {
            if (err = ensure(logContext, b, 1), 0 != err) {
                return err;
            }
            b->buf[b->len++] = c;
            c = readc(r);
        }
    }
    while (c != '\n' && c != EOF) {
        c = readc(r);
    }

    /* Trim trailing spaces from line */
    while (b->len > 0 && isspace(b->buf[b->len-1])) {
        b->len--;
    }

    ensure(logContext, b, 1);
    b->buf[b->len++] = '\0';

    return 0;
}

static const char *dups(abl_args *args, const char *s) {
    int l = strlen(s);
    abl_string *str = malloc(sizeof(abl_string) + l + 1);
    memcpy(str + 1, s, l + 1);
    str->link = args->strs;
    args->strs = str;
    return (const char *) (str + 1);
}

/* Parse the contents of a config file */
int config_parse_file(const char *name, abl_args *args, log_context *logContext) {
    struct linebuf b;
    struct reader  r;
    int err = 0;
    const char *l;

    b.buf  = NULL;
    b.len  = 0;
    b.size = 0;

    if (r.f = fopen(name, "r"), NULL == r.f) {
        err = errno;
        goto done;
    }

    r.lc = getc(r.f);
    while (r.lc != EOF) {
        if (err = read_line(logContext, &b, &r), 0 != err) {
            goto done;
        }
        if (b.len > 1) {
            if (l = dups(args, b.buf), NULL == l) {
                err = ENOMEM;
                goto done;
            }
            log_debug(logContext, "%s: %s", name, l);
            if (err = parse_arg(l, args, logContext), 0 != err) {
                goto done;
            }
        }
    }

done:
    if (0 != err) {
        log_sys_error(logContext, err, "reading config file");
    }

    if (err == 0) {
        if (!args->db_home) {
            err = ENOENT;
            log_sys_error(logContext, err, "reading config file: No db_home dir specified");
        } else {
            struct stat sb;
            if (!(stat(args->db_home, &sb) == 0 && S_ISDIR(sb.st_mode))) {
                err = ENOTDIR;
                log_sys_error(logContext, err, "parsing the value of db_home");
            }
        }
    }

    if (NULL != r.f) {
        fclose(r.f);
    }

    free(b.buf);
    return err;
}

void dump_args(const abl_args *args, log_context *logContext) {
    abl_string *s;

    log_debug(logContext, "debug           = %d",  logContext->debug);

    log_debug(logContext, "db_home         = %s",  args->db_home);
    log_debug(logContext, "host_db         = %s",  args->host_db);
    log_debug(logContext, "host_rule       = %s",  args->host_rule);
    log_debug(logContext, "host_purge      = %ld", args->host_purge);
    log_debug(logContext, "host_block_cmd  = %s",  args->host_blk_cmd);
    log_debug(logContext, "host_clear_cmd  = %s",  args->host_clr_cmd);

    log_debug(logContext, "user_db         = %s",  args->user_db);
    log_debug(logContext, "user_rule       = %s",  args->user_rule);
    log_debug(logContext, "user_purge      = %ld", args->user_purge);
    log_debug(logContext, "user_block_cmd  = %s",  args->user_blk_cmd);
    log_debug(logContext, "user_clear_cmd  = %s",  args->user_clr_cmd);
    log_debug(logContext, "lower limit     = %ld", args->lowerlimit);
    log_debug(logContext, "upper limit     = %ld", args->upperlimit);
    for (s = args->strs; NULL != s; s = s->link) {
        log_debug(logContext, "str[%p] = %s", s, (char *) (s + 1));
    }
}

/* Parse our argments and populate an abl_args structure accordingly.
 */
int config_parse_args(int argc, const char **argv, abl_args *args, log_context *logContext) {
    int argn;
    int err;

    config_clear(args);

    for (argn = 0; argn < argc; argn++) {
        err = parse_arg(argv[argn], args, logContext);
        if (err) {
            return err;
        }
    }

    if (logContext->debug)
        dump_args(args, logContext);

    return 0;
}

/* Destroy any storage allocated by args
 */
void config_free(abl_args *args) {
    abl_string *s, *next;

    for (s = args->strs; s != NULL; s = next) {
        next = s->link;
        free(s);
    }
    args->strs = NULL;
    free(args);
}

int splitCommand(char *command, char* result[], log_context *logContext) {
    if (command == NULL)
        return 0;
    int nofParts = 0;
    int partStarted = 0;
    unsigned long inputIndex = 0;
    unsigned long outputIndex = 0;
    int lastCharWasEscape = 0;
    while (command[inputIndex]) {
        if (lastCharWasEscape) {
            lastCharWasEscape = 0;
        } else {
            switch(command[inputIndex]) {
                case '\\':
                    lastCharWasEscape = 1;
                    //only increase the inputIndex, do not copy the char
                    ++inputIndex;
                    continue;
                case '[':
                    if (partStarted) {
                        if (logContext)
                            log_error(logContext, "command syntax error: parsed '[' while already parsing a part in \"%s\"", command);
                        return -1;
                    }
                    if (result)
                        result[nofParts] = command+outputIndex+1;
                    ++nofParts;
                    partStarted = 1;
                    break;
                case ']':
                    if (!partStarted) {
                        if (logContext)
                            log_error(logContext, "command syntax error: parsed ']' without opening '[' in \"%s\"", command);
                        return -1;
                    }
                    partStarted = 0;
                    if (result)
                        command[inputIndex] = '\0'; //use inputIndex here so that the copy at the end of the while is correct
                    break;
                default:
                    break;
            };
        }
        if (result)
            command[outputIndex] = command[inputIndex];
        ++outputIndex;
        ++inputIndex;
    }
    //syntax error, we didn't see a final ']'
    if (partStarted) {
        if (logContext) {
            log_error(logContext, "command syntax error: no closing ] in \"%s\"", command);
        }
        return -1;
    }
    return nofParts;
}

