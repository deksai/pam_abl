#ifndef RULE_H
#define RULE_H

#include "log.h"
#include "typefun.h"

int parse_long(const char **sp, long *lp);
int rule_parse_time(const char *p, long *t, long min);
int rule_matchperiods(log_context *log, AuthState *history, time_t now, const char **rp);

BlockState rule_test(log_context *log, const char *rule,
              const char *user, const char *service,
              AuthState *history, time_t now);

#endif
