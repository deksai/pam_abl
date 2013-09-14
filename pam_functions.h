/*
 *   pam_abl - a PAM module and program for automatic blacklisting of hosts
 *   and users
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

#ifndef PAM_FUNCTIONS_H
#define PAM_FUNCTIONS_H

#include "pam_abl.h"

typedef struct abl_context {
    abl_info     *attemptInfo;
} abl_context;

/*
 * Functions are only listed here for testing purposes
 */
void setup_and_log_attempt(abl_info *info);
int pam_inner_authenticate(abl_context *context, char *user, char *host, char *service, ModuleAction action);

#endif
