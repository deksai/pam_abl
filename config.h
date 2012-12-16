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

#ifndef CONFIG_H
#define CONFIG_H

#include "log.h"

typedef struct abl_string {
    struct abl_string *link;
} abl_string;

typedef struct {
    /* Our args */
    const char      *db_home;
    const char      *host_db;
    const char      *host_rule;
    long             host_purge;
    const char      *host_whitelist;
    const char      *host_blk_cmd;
    const char      *host_clr_cmd;
    const char      *user_db;
    const char      *user_rule;
    long             user_purge;
    const char      *user_whitelist;
    const char      *user_blk_cmd;
    const char      *user_clr_cmd;
    unsigned int     upperlimit;
    unsigned int     lowerlimit;
    /* Storage */
    abl_string      *strs;
} abl_args;

abl_args *config_create();
void config_free(abl_args *args);
int config_parse_args(int argc, const char **argv, abl_args *args, log_context *logContext);
int config_parse_file(const char *name, abl_args *args, log_context *logContext);
void dump_args(const abl_args *args, log_context *logContext);

/*
 * Split a command based on what's between brackets, strings not in brackets are ignored
 * \param command: the command to split.
                   The command will be split to all fields between '[]'. If you want a '[' or ']' in your command, precede it by a '\'
                   If you want a '\', precede it by another '\': '\\' => '\'
                   All other escape chars are resolved to the char itself: '\c' => 'c'
 * \param result: if this value is not NULL, this array will be filled with pointers to the different parts.
 *                The pointers point to memory in the original command.
 *                Make sure it's big enough
 * \param logContext: if not NULL this will be used to log syntax errors.
 * \return: negative if there is a syntax error, otherwise the number of parts
 * NOTE: command will be modified if result != NULL, \0 will be inserted and escape chars are removed if followed by [ or ]
 * NOTE: syntax error message can be very cryptic if result != NULL => check with result == NULL for syntax errors first
 * example:
        cmd = "lol [command] ignored [arg1] [arg2]"
        will result in the following result:
            - result[0] = "command"
            - result[1] = "arg1"
            - result[2] = "arg2"
        with as return value 3
 */
int splitCommand(char *command, char* result[], log_context *logContext);
#endif
