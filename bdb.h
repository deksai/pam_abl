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
    DB_ENV *m_envHandle;
    DB_TXN *m_transaction;
} bdb_environment;

typedef struct bdb_state {
    DB *m_handle;
    DBC *m_cursor;
    bdb_environment *m_environment;
} bdb_state;

/*
  Log a Berkeley db error. This will also lookup the string representation of err
  Make sure err is a value returned by a Berkeley db function
*/
void log_db_error(int err, const char *what);


/*
  Close a full environment. Make sure no transaction is open
  \note Do not use the env pointer anymore after calling this function
*/
void destroy_environment(bdb_environment *env);


/*
  Create and open the database environment
  \param home The place where the Berkeley db can put itś locking files and such
  \param env The newly created environment will be returned through this pointer
  \return zero on success, otherwise non zero
  \note context can be a NULL ptr, do not delete context while the environment is still active
*/
int create_environment(const char *home, bdb_environment **env);

/*
  Start a transaction on the given environment
  \return zero on success, otherwise non zero
  \note For the moment only on transaction can be active at the same time.
  \note ALL database actions need to be wrapped in a transaction for them to work.
*/
//int startTransaction(bdb_environment *env);

/*
  End a transaction started on the environment applying all the changes
  \return zero on success, otherwise non zero
  \note calling this function on an environment with no transaction started sill succeed
*/
//int commitTransaction(bdb_environment *env);

/*
  End a transaction started on the environment discarding all the changes
  \return zero on success, otherwise non zero
  \note calling this function on an environment with no transaction started sill succeed
*/
//int abortTransaction(bdb_environment *env);

/*
  Close an open Database. Make sure that there are no transaction on this db.
  Do not use the db pointer after calling this function.
*/
void bdb_close(abl_db *);

/*
  Get the authentication state for the given subject.
  Make sure that you already started a transaction before calling this method
  \param db The database to get the info from
  \param subject The subject to look for, this ptr has te be valid and not an empty string
  \subjectState Returns the state of the subject. If it is not found subjectState will be null
  \return zero on success, non zero otherwise
*/
int bdb_get(const abl_db *, const char *, AuthState **);

/*
  Save the given AuthState for the given subject in the given database
  Make sure that you already started a transaction before calling this method
  \param db The database to store the value in
  \param subject The subject to use to store the value. This needs to be valid and not an empty string
  \param subjectState The state to save, this needs to be a valid state
  \return zero on success, non zero otherwise
*/
int bdb_put(const abl_db *, const char *, AuthState *);

/*
  Remove a given subject out of the given database
  Make sure that you already started a transaction before calling this method
*/
int bdb_del(const abl_db *, const char *);

int bdb_c_open(abl_db *abldb);
int bdb_c_close(abl_db *abldb);
//int bdb_c_del(abl_db *abldb);
//int bdb_c_replace(abl_db *abldb, char *data, unsigned dsize);
int bdb_c_get(abl_db *abldb, char **key, unsigned *ksize, char **data, unsigned *dsize);
abl_db* abl_db_open(const abl_args *args);

#endif
