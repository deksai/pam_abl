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

static int match(const char *pattern, const char *target, size_t len) {
    log_debug("match('%s', '%s', %d)", pattern, target, len);
    if (!pattern)
        return 0;
    return (len == strlen(pattern)) && (memcmp(pattern, target, len) == 0);
}

static int matchname(const char *user, const char *service,
                     const char **rp) {
    size_t l = wordlen(*rp);
    int ok;

    log_debug("Check %s/%s against %s(%d)", user, service, *rp, l);

    ok = (l != 0) && ((l == 1 && **rp == '*') || match(user, *rp, l));
    (*rp) += l;
    if (ok) {
        log_debug("Name part matches, **rp = '%c'", **rp);
    }
    if (**rp == '/') {
        (*rp)++;
        l = wordlen(*rp);
        ok &= (l != 0) && ((l == 1 && **rp == '*') || match(service, *rp, l));
        (*rp) += l;
    }

    log_debug("%satch!", ok ? "M" : "No m");

    return ok;
}

static int matchnames(const char *user, const char *service,
                      const char **rp) {
    int ok = matchname(user, service, rp);
    while (**rp == '|') {
        (*rp)++;
        ok |= matchname(user, service, rp);
    }
    return ok;
}

static long howmany(AuthState *history, time_t now, long limit) {
    if (firstAttempt(history))
        return -1;
    long i = 0;
    AuthAttempt attempt;
    while (!nextAttempt(history, &attempt)) {
        if (difftime(now, attempt.m_time) <= (double) limit)
            ++i;
    }
    log_debug("howmany(%ld) = %ld", limit, i);
    return i;
}

static int matchperiod(AuthState *history, time_t now, const char **rp) {
    int err;
    long count, period;

    log_debug("matchperiod(%p, %u, '%s')", history, getNofAttempts(history), *rp);

    if (err = parse_long(rp, &count), 0 != err) {
        return 0;
    }
    log_debug("count is %ld, **rp='%c'", count, **rp);
    if (**rp != '/') {
        return 0;
    }
    (*rp)++;
    if (err = parse_time(rp, &period), 0 != err) {
        return 0;
    }
    log_debug("period is %ld, **rp='%c'", period, **rp);
    log_debug("Checking %ld/%ld", count, period);
    return howmany(history, now, period) >= count;
}

int rule_matchperiods(AuthState *history, time_t now, const char **rp) {
    if (matchperiod(history, now, rp)) {
        return 1;
    }
    while (**rp == ',') {
        (*rp)++;
        if (matchperiod(history, now, rp)) {
            return 1;
        }
    }
    return 0;
}

static int check_clause(const char **rp,
                        const char *user, const char *service,
                        AuthState *history, time_t now) {
    int inv = 0;

    if (**rp == '!') {
        inv = 1;
        (*rp)++;
    }

    if (!(inv ^ matchnames(user, service, rp))) {
        return 0;
    }

    log_debug("Name matched, next char is '%c'", **rp);

    /* The name part matches so now check the trigger clauses */
    if (**rp != ':') {
        return 0;
    }

    (*rp)++;
    return rule_matchperiods(history, now, rp);
}

BlockState rule_test(const char *rule,
              const char *user, const char *service,
              AuthState *history, time_t now) {
    if (!rule)
        return CLEAR;
    const char *rp = rule;

    while (*rp != '\0') {
        if (check_clause(&rp, user, service, history, now)) {
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

