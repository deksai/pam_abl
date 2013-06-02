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

#ifndef BDB_H
#define BDB_H

#include "dbfun.h"
#include "log.h"

#include <db.h>

typedef struct bdb_environment {
    DB_ENV *m_envHandle_disabled;
    DB_TXN *m_transaction_disabled;
} bdb_environment;

typedef struct bdb_state {
    DB *m_uhandle;
    DB *m_hhandle;
    DBC *m_cursor;
    DB_ENV *m_environment;
    DB_TXN *m_transaction;
    //bdb_environment *m_environment;
} bdb_state;

/*
  Log a Berkeley db error. This will also lookup the string representation of err
  Make sure err is a value returned by a Kytoto Cabinet db function
*/
void log_db_error(int err, const char *what);


/*
  Close a full environment.
  \note Do not use the env pointer anymore after calling this function
*/
void destroy_environment(DB_ENV *env);


/*
  Create and open the database environment
  \param home The place where the Berkeley db can put itś locking files and such
  \param env The newly created environment will be returned through this pointer
  \return zero on success, otherwise non zero
  \note context can be a NULL ptr, do not delete context while the environment is still active
*/
int create_environment(const char *home, DB_ENV **env);


/*
  Close an open Database. Make sure that there are no transaction on this db.
  Do not use the db pointer after calling this function.
*/
void bdb_close(abl_db *);

/*
  Get the authentication state for the given subject.
  \param abl_db The database to get the info from
  \param char The object to look for, this ptr has te be valid and not an empty string
  \param AuthState Returns the state of the object. If it is not found AuthState will be null
  \param ablObjectType Look for HOST or USER (HOST|USER perhaps in the future)
  \return zero on success, non zero otherwise
*/
int bdb_get(const abl_db *, const char *, AuthState **, ablObjectType);

/*
  Save the given AuthState for the given subject in the given database
  \param abl_db The database to store the value in
  \param const_char The object to store. This needs to be valid and not an empty string
  \param AuthState The state to save, this needs to be a valid state
  \param ablObjectType Search for either HOST or USER
  \return zero on success, non zero otherwise
*/
int bdb_put(const abl_db *, const char *, AuthState *, ablObjectType);

/*
  Remove a given subject out of the given database
  \param abl_db The database object to use.
  \param ablObjectType Search for either HOST or USER
  \return zero on success, non zero otherwise
*/
int bdb_del(const abl_db *, const char *, ablObjectType type);

/*
  Open a cursor for the given type of database.
  \param abl_db The database object to use.
  \param ablObjectType Search for either HOST or USER
  \return zero on success, non zero otherwise
*/
int bdb_c_open(abl_db *abldb, ablObjectType type);

/*
  Close the currently open cursor.
  \param abl_db The database object to use.
  \return zero on success, non zero otherwise
*/
int bdb_c_close(abl_db *abldb);

//int bdb_c_del(abl_db *abldb);
//int bdb_c_replace(abl_db *abldb, char *data, unsigned dsize);

/*
  Get the current object at the cursor.
  \param abl_db The database object to use.
  \param char** The key string will be set to the object's name as it was stored.
  \param int* This will be set to the size of the retrieved key.
  \param char** The binary data belonging to the above key.
  \param int* This will be set to the size of the above data.
  \return zero on success, DB_CURSOR_END if no more records, other value otherwise
*/
int bdb_c_get(abl_db *abldb, char **key, size_t *ksize, char **data, size_t *dsize);

/*
  Start a transaction on the given environment
  \return zero on success, otherwise non zero
  \note For the moment only on transaction can be active at the same time.
*/
int bdb_start_transaction(const abl_db *db);

/*
  End a transaction started on the environment applying all the changes
  Make sure all cursors are closed before calling this function
  \return zero on success, otherwise non zero
  \note calling this function on an environment with no transaction started sill succeed
*/
int bdb_commit_transaction(const abl_db *db);

/*
  End a transaction started on the environment discarding all the changes
  Make sure all cursors are closed before calling this function
  \return zero on success, otherwise non zero
  \note calling this function on an environment with no transaction started sill succeed
*/
int bdb_abort_transaction(const abl_db *db);

#endif
