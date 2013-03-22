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
#ifndef PAM_DBFUN_H
#define PAM_DBFUN_H
#include "typefun.h"

typedef struct abl_db _abl_db;
typedef struct abl_db {
    void (*close)(_abl_db *db);
    int (*put)(const _abl_db *, const char *object, AuthState *, ablObjectType);
    int (*del)(const _abl_db *, const char *object, ablObjectType);
    int (*get)(const _abl_db *, const char *object, AuthState **, ablObjectType);
    int (*c_open)(_abl_db *, ablObjectType);
    int (*c_close)(_abl_db *);
    int (*c_get)(_abl_db *,char **key,size_t *ksize,char **data,size_t *dsize);
    int (*start_transaction)(const _abl_db *);
    int (*commit_transaction)(const _abl_db *);
    int (*abort_transaction)(const _abl_db *);
    void *state;
} abl_db;



/*
  Every module needs to have this function, which fills in the structure
  above.  
  Given a full configuration open the required environment and databases
  \return a valid abl_db on success, otherwise a nullptr
*/
abl_db* abl_db_open(const char *db_home);

#endif
