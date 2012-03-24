#ifndef RULE_H
#define RULE_H

#include "log.h"
#include "typefun.h"

/*
  Parses a long from the string pointed to by sp. On success sp will point to the char right after the long
  \param sp The string to parse a long with
  \param lp The found long
  \return zero on success, non zero otherwise
*/
int parse_long(const char **sp, long *lp);

/*
  Parse a time specification in the form
    * <digits>[s|m|h|d]
  \param p The string that holds the time to parse
  \param t The parsed time in seconds
  \param min The minimum time that needs to be returned
  \return zero on success, non zero otherwise
*/
int rule_parse_time(const char *p, long *t, long min);

/*
  Tries to match a comma seperated list of '<count>/<time>' rules with the given list of attempts
  \param log The log context to use for errors/warnings/...
  \param history The list of attempts
  \param now The time to use when matching attempts
  \param rp The string with the rule, rp will point to the first char after a clause
  \return zero when there is an error or no match, non zero otherwise
*/
int rule_matchperiods(log_context *log, AuthState *history, time_t now, const char **rp);

/* Apply a rule to a history record returning BLOCKED if the rule matches, CLEAR if the rule fails.
 *
 * Rule syntax is like:
 *
 * word         ::= /[^\s\|\/\*]+/
 * name         ::= word | '*'
 * username     ::= name
 * servicename  ::= name
 * userservice  ::= username
 *              |   username '/' servicename
 * namelist     ::= userservice
 *              |   userservice '|' namelist
 * userspec     ::= namelist
 *              |   '!' namelist
 * multiplier   ::= 's' | 'm' | 'h' | 'd'
 * number       ::= /\d+/
 * period       ::= number
 *              |   number multiplier
 * trigger      ::= number '/' period
 * triglist     ::= trigger
 *              |   trigger ',' triglist
 * userclause   ::= userspec ':' triglist
 * rule         ::= userclause
 *              |   userclause /\s+/ rule
 *
 * This gives rise to rules like
 *
 * !root|admin/sshd:10/1m,100/1d root:10/3m
 *
 * which means for accounts other than 'root' or 'admin' trigger if there were ten
 * or more events in the last minute or 100 or more events in the last day. For
 * 'root' trigger if there were ten or more events in the last three minutes.
 */
BlockState rule_test(log_context *log, const char *rule,
              const char *user, const char *service,
              AuthState *history, time_t now);

#endif
