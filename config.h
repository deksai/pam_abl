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

typedef struct abl_string {
    struct abl_string *link;
} abl_string;

typedef struct {
    /* Our args */
    const char      *db_home;
    const char      *db_module;
    const char      *host_rule;
    long             host_purge;
    const char      *host_whitelist;
    const char      *host_blk_cmd;
    const char      *host_clr_cmd;
    const char      *user_rule;
    long             user_purge;
    const char      *user_whitelist;
    const char      *user_blk_cmd;
    const char      *user_clr_cmd;
    unsigned int     upperlimit;
    unsigned int     lowerlimit;
    int              debug;
    /* Storage */
    abl_string      *strs;
} abl_args;

abl_args *args;

void config_create();
void config_free();
int config_parse_args(int argc, const char **argv);
int config_parse_file(const char *name);
void dump_args();
#endif
