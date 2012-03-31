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

#ifndef DBFUN_H
#define DBFUN_H

#include "typefun.h"
#include "log.h"

#include <db.h>

typedef struct DbEnvironment {
    DB_ENV *m_envHandle;
    DB_TXN *m_transaction;
    log_context *m_logContext;
} DbEnvironment;

typedef struct Database {
    DB *m_dbHandle;
    DbEnvironment *m_environment;
} Database;

/*
  Create and open the database environment
  \param context The logger context to be used for all db actions in this environment
  \param home The place where the Berkeley db can put itś locking files and such
  \param env The newly created environment will be returned through this pointer
  \return zero on success, otherwise non zero
  \note context can be a NULL ptr, do not delete context while the environment is still active
*/
int createEnvironment(log_context *context, const char *home, DbEnvironment **env);

/*
  Cleanup the given environment, releasing all it's resources
  Do not use the env pointer after calling this
*/
void destroyEnvironment(DbEnvironment *env);

/*
  Start a transaction on the given environment
  \return zero on success, otherwise non zero
  \note For the moment only on transaction can be active at the same time.
  \note ALL database actions need to be wrapped in a transaction for them to work.
*/
int startTransaction(DbEnvironment *env);

/*
  End a transaction started on the environment applying all the changes
  \return zero on success, otherwise non zero
  \note calling this function on an environment with no transaction started sill succeed
*/
int commitTransaction(DbEnvironment *env);

/*
  End a transaction started on the environment discarding all the changes
  \return zero on success, otherwise non zero
  \note calling this function on an environment with no transaction started sill succeed
*/
int abortTransaction(DbEnvironment *env);



/*
  Open a database in the given environment. Locking occurs at environemnt level, so be sure to pass the right environment
  \param env The environment to open the db in.
  \param dbFile The file to use as storage for the db
  \param dbName The name of the db table
  \param db This param will be used to return the newly created db
  \return zero on success, otherwise non zero
  \note Opening a db will automatically be wrapped in a transaction
*/
int openDatabase(DbEnvironment *env, const char *dbfile, const char *dbname, Database **db);

/*
  Close an open Database. Make sure that there are no transaction on this db.
  Do not use the db pointer after calling this function.
*/
void closeDatabase(Database *db);



/*
  Get the authentication state for the given subject.
  Make sure that you already started a transaction before calling this method
  \param db The database to get the info from
  \param subject The subject to look for, this ptr has te be valid and not an empty string
  \subjectState Returns the state of the subject. If it is not fount subjectState will be a nullptr
  \return zero on success, non zero otherwise
*/
int getUserOrHostInfo(Database *db, const char *subject, AuthState **subjectState);

/*
  Save the given AuthState for the given subject in the given database
  Make sure that you already started a transaction before calling this method
  \param db The database to store the value in
  \param subject The subject to use to store the value. This needs to be valid and not an empty string
  \param subjectState The state to save, this needs to be a valid state
  \return zero on success, non zero otherwise
*/
int saveInfo(Database *db, const char *subject, AuthState *subjectState);

/*
  Remove a given subject out of the given database
  Make sure that you already started a transaction before calling this method
*/
int removeInfo(Database *db, const char *subject);

#endif
