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

#include "rule.h"

#include <errno.h>
#include <ctype.h>
#include <string.h>

int parse_long(const char **sp, long *lp) {
    long l = 0;

    if (!isdigit(**sp)) {
        return EINVAL;
    }

    while (isdigit(**sp)) {
        l = l * 10 + *(*sp)++ - '0';
    }

    *lp = l;
    return 0;
}

/* Parse a time specification in the form
 * <digits>[s|m|h|d]
 */
static int parse_time(const char **sp, long *tp) {
    long t;
    int err;

    if (err = parse_long(sp, &t), 0 != err) {
        return err;
    }

    /* Handle the multiplier suffix */
    switch (**sp) {
    case 'd':
        t *= 24;
    case 'h':
        t *= 60;
    case 'm':
        t *= 60;
    case 's':
        (*sp)++;
    default:
        ;
    }

    *tp = t;

    return 0;
}

int rule_parse_time(const char *p, long *t, long min) {
    int err;

    if (err = parse_time(&p, t), 0 != err) {
        *t = min;
        return err;
    }

    if (*p != '\0') {
        *t = min;
        return EINVAL;
    }

    if (*t < min) {
        *t = min;
    }

    return 0;
}

static size_t wordlen(const char *rp) {
    size_t l = 0;
    while (*rp != '\0' &&
           *rp != '/'  &&
           *rp != '|'  &&
           *rp != ':'  &&
           !isspace(*rp)) {
        rp++;
        l++;
    }
    return l;
}

static int match(log_context *log, const char *pattern, const char *target, size_t len) {
    log_debug(log, "match('%s', '%s', %d)", pattern, target, len);
    if (!pattern)
        return 0;
    return (len == strlen(pattern)) && (memcmp(pattern, target, len) == 0);
}

static int matchname(log_context *log, const char *user, const char *service,
                     const char **rp) {
    size_t l = wordlen(*rp);
    int ok;

    log_debug(log, "Check %s/%s against %s(%d)", user, service, *rp, l);

    ok = (l != 0) && ((l == 1 && **rp == '*') || match(log, user, *rp, l));
    (*rp) += l;
    if (ok) {
        log_debug(log, "Name part matches, **rp = '%c'", **rp);
    }
    if (**rp == '/') {
        (*rp)++;
        l = wordlen(*rp);
        ok &= (l != 0) && ((l == 1 && **rp == '*') || match(log, service, *rp, l));
        (*rp) += l;
    }

    log_debug(log, "%satch!", ok ? "M" : "No m");

    return ok;
}

static int matchnames(log_context *log, const char *user, const char *service,
                      const char **rp) {
    int ok = matchname(log, user, service, rp);
    while (**rp == '|') {
        (*rp)++;
        ok |= matchname(log, user, service, rp);
    }
    return ok;
}

static long howmany(log_context *log, AuthState *history, time_t now, long limit) {
    if (firstAttempt(history))
        return -1;
    long i = 0;
    AuthAttempt attempt;
    while (!nextAttempt(history, &attempt)) {
        if (difftime(now, attempt.m_time) <= (double) limit)
            ++i;
    }
    log_debug(log, "howmany(%ld) = %ld", limit, i);
    return i;
}

static int matchperiod(log_context *log, AuthState *history, time_t now, const char **rp) {
    int err;
    long count, period;

    log_debug(log, "matchperiod(%p, %u, '%s')", history, getNofAttempts(history), *rp);

    if (err = parse_long(rp, &count), 0 != err) {
        return 0;
    }
    log_debug(log, "count is %ld, **rp='%c'", count, **rp);
    if (**rp != '/') {
        return 0;
    }
    (*rp)++;
    if (err = parse_time(rp, &period), 0 != err) {
        return 0;
    }
    log_debug(log, "period is %ld, **rp='%c'", period, **rp);
    log_debug(log, "Checking %ld/%ld", count, period);
    return howmany(log, history, now, period) >= count;
}

int rule_matchperiods(log_context *log, AuthState *history, time_t now, const char **rp) {
    if (matchperiod(log, history, now, rp)) {
        return 1;
    }
    while (**rp == ',') {
        (*rp)++;
        if (matchperiod(log, history, now, rp)) {
            return 1;
        }
    }
    return 0;
}

static int check_clause(log_context *log, const char **rp,
                        const char *user, const char *service,
                        AuthState *history, time_t now) {
    int inv = 0;

    if (**rp == '!') {
        inv = 1;
        (*rp)++;
    }

    if (!(inv ^ matchnames(log, user, service, rp))) {
        return 0;
    }

    log_debug(log, "Name matched, next char is '%c'", **rp);

    /* The name part matches so now check the trigger clauses */
    if (**rp != ':') {
        return 0;
    }

    (*rp)++;
    return rule_matchperiods(log, history, now, rp);
}

BlockState rule_test(log_context *log, const char *rule,
              const char *user, const char *service,
              AuthState *history, time_t now) {
    if (!rule)
        return CLEAR;
    const char *rp = rule;

    while (*rp != '\0') {
        if (check_clause(log, &rp, user, service, history, now)) {
            return BLOCKED;
        }
        while (*rp != '\0' && !isspace(*rp)) {
            rp++;
        }
        while (isspace(*rp)) {
            rp++;
        }
    }

    return CLEAR;
}

