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

#ifndef KT_H
#define KT_H

#include "dbfun.h"
#include "log.h"

#include <kclangc.h>

typedef struct kc_state {
    KCDB *user;
    KCDB *host;
    KCCUR *cursor;
    char transaction;
} kc_state;

/*
  Log a Kytoto Cabinet db error. This will also lookup the string representation of err
  Make sure err is a value returned by a Kytoto Cabinet db function
*/
void log_db_error(int err, const char *what);

/*
  Close an open Database. Make sure that there are no transaction on this db.
  Do not use the db pointer after calling this function.
*/
void kc_close(abl_db *);

/*
  Get the authentication state for the given subject.
  \param abl_db The database to get the info from
  \param char The object to look for, this ptr has to be valid and not an empty string
  \param AuthState Returns the state of the object. If it is not found AuthState will be null
  \param ablObjectType Look for HOST or USER (HOST|USER perhaps in the future)
  \return zero on success, non zero otherwise
*/
int kc_get(const abl_db *, const char *, AuthState **, ablObjectType);

/*
  Save the given AuthState for the given subject in the given database
  \param abl_db The database to store the value in
  \param const_char The object to store. This needs to be valid and not an empty string
  \param AuthState The state to save, this needs to be a valid state
  \param ablObjectType Search for either HOST or USER
  \return zero on success, non zero otherwise
*/
int kc_put(const abl_db *, const char *, AuthState *, ablObjectType);

/*
  Remove a given subject out of the given database
  \param abl_db The database object to use.
  \param ablObjectType Search for either HOST or USER
  \return zero on success, non zero otherwise
*/
int kc_del(const abl_db *, const char *, ablObjectType type);

/*
  Open a cursor for the given type of database.
  \param abl_db The database object to use.
  \param ablObjectType Search for either HOST or USER
  \return zero on success, non zero otherwise
*/
int kc_c_open(abl_db *abldb, ablObjectType type);

/*
  Close the currently open cursor.
  \param abl_db The database object to use.
  \return zero on success, non zero otherwise
*/
int kc_c_close(abl_db *abldb);

/*
  Get the current object at the cursor.
  \param abl_db The database object to use.
  \param char** The key string will be set to the object's name as it was stored.
  \param int* This will be set to the size of the retrieved key.
  \param char** The binary data belonging to the above key.
  \param int* This will be set to the size of the above data.
  \return zero on success, non zero otherwise
*/
int kc_c_get(abl_db *abldb, char **key, size_t *ksize, char **data, size_t *dsize);

/*
  Start a transaction in the given database
  \return zero on success, otherwise non zero
  \note For the moment only on transaction can be active at the same time.
*/
int kc_start_transaction(const abl_db *db);

/*
  End a transaction started on the environment applying all the changes
  \return zero on success, otherwise non zero
  \note calling this function on an environment with no transaction started sill succeed
*/
int kc_commit_transaction(const abl_db *db);

/*
  End a transaction started on the environment discarding all the changes
  \return zero on success, otherwise non zero
  \note calling this function on an environment with no transaction started sill succeed
*/
int kc_abort_transaction(const abl_db *db);

#endif
