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

#include "dbfun.h"

#include <stdlib.h>
#include <string.h>

#define DBPERM 0600
//do a checkpoint every 8MB of log
#define CHECKPOINTSIZE (8000)

//let's allocate a 'large' buffer
char largeBuffer[1024*50];

int createEnvironment(log_context *context, const char *home, DbEnvironment **env) {
    int ret = 0;
    *env = NULL;
    DB_ENV *dbenv = NULL;

    if ((ret = db_env_create(&dbenv, 0)) != 0) {
    	log_db_error(context, ret, "creating environment object");
        return ret;
    }
    dbenv->set_errpfx(dbenv, "pam-abl");
    if ((ret = dbenv->open(dbenv, home, DB_CREATE | DB_INIT_TXN | DB_INIT_LOCK | DB_INIT_MPOOL | DB_RECOVER | DB_REGISTER, 0)) != 0) {
        log_db_error(context, ret, "opening the database environment");
        dbenv->close(dbenv, 0);
        dbenv = 0;
    }
    if (dbenv) {
        /* Do deadlock detection internally. */
        if ((ret = dbenv->set_lk_detect(dbenv, DB_LOCK_DEFAULT)) != 0) {
            log_db_error(context, ret, "setting lock detection.");
        }
#if ((DB_VERSION_MAJOR >= 5)||(DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR >= 7))
        ret = dbenv->log_set_config(dbenv, DB_LOG_AUTO_REMOVE, 1);
#else
        ret = dbenv->set_flags(dbenv, DB_LOG_AUTOREMOVE, 1);
#endif
        if (ret != 0) {
            log_db_error(context, ret, "setting automatic log file removal.");
        }
        if ((ret = dbenv->txn_checkpoint(dbenv, CHECKPOINTSIZE, 0, 0)) != 0) {
            log_db_error(context, ret, "setting the automatic checkpoint option.");
        }
    }

    if (dbenv) {
        DbEnvironment *retValue = malloc(sizeof(DbEnvironment));
        memset(retValue, 0, sizeof(DbEnvironment));
        retValue->m_envHandle = dbenv;
        retValue->m_logContext = context;
        retValue->m_transaction = NULL;
        *env = retValue;
    }
    return ret;
}

void destroyEnvironment(DbEnvironment *env) {
    if (!env)
        return;
    if (env->m_envHandle)
        env->m_envHandle->close(env->m_envHandle, 0);
    env->m_envHandle = NULL;
    free(env);
}

int startTransaction(DbEnvironment *env) {
    if (!env || !env->m_envHandle)
        return 1;
    //for the moment we only support one transaction at the time
    if (env->m_transaction)
        return 0;

    DB_TXN *tid = NULL;
    int err = 0;
    if ((err = env->m_envHandle->txn_begin(env->m_envHandle, NULL, &tid, 0)) != 0) {
        log_db_error(env->m_logContext, err, "starting transaction");
        return err;
    }
    env->m_transaction = tid;
    return err;
}

int commitTransaction(DbEnvironment *env) {
    if (!env || !env->m_envHandle)
        return 1;
    //if we are not in a transaction, just ignore it
    if (!env->m_transaction)
        return 0;

    int err = env->m_transaction->commit(env->m_transaction, 0);
    env->m_transaction = NULL;
    return err;
}

int abortTransaction(DbEnvironment *env) {
    if (!env || !env->m_envHandle)
        return 1;
    //if we are not in a transaction, just ignore it
    if (!env->m_transaction)
        return 0;

    int err = env->m_transaction->abort(env->m_transaction);
    env->m_transaction = NULL;
    return err;
}

int openDatabase(DbEnvironment *env, const char *dbfile, const char *dbname, Database **db) {
    if (!env || !env->m_envHandle)
        return 1;

    *db = NULL;
    int err = 0;
    DB *dbHandle = NULL;
    if (err = db_create(&dbHandle, env->m_envHandle, 0), 0 != err) {
        log_db_error(env->m_logContext, err, "creating database object");
        return err;
    }

    DB_TXN *tid = 0;
    if ((err = env->m_envHandle->txn_begin(env->m_envHandle, NULL, &tid, 0)) != 0) {
        log_db_error(env->m_logContext, err, "starting transaction");
        return err;
    }

    if ((err = dbHandle->open(dbHandle, tid, dbfile, dbname, DB_BTREE, DB_CREATE, DBPERM)) != 0) {
        log_db_error(env->m_logContext, err, "opening or creating database");
        tid->abort(tid);
        return err;
    }

    if ((err = tid->commit(tid, 0))) {
        log_db_error(env->m_logContext, err, "committing transaction");
        return err;
    }

    log_debug(env->m_logContext, "%s opened", dbname);

    Database *retValue = malloc(sizeof(Database));
    memset(retValue, 0, sizeof(Database));
    retValue->m_dbHandle = dbHandle;
    retValue->m_environment = env;
    *db = retValue;
    return 0;
}

void closeDatabase(Database *db) {
    if (!db)
        return;
    if (db->m_dbHandle)
        db->m_dbHandle->close(db->m_dbHandle,0);
    db->m_dbHandle = NULL;
    free(db);
}

int getUserOrHostInfo(Database *db, const char *hostOrUser, AuthState **hostOrUserState) {
    *hostOrUserState = NULL;
    if (!db || !db->m_environment || !db->m_dbHandle || !hostOrUser)
        return 1;
    int err = 0;
    void *allocData = NULL;

    DBT dbtdata;
    memset(&dbtdata, 0, sizeof(DBT));
    dbtdata.flags = DB_DBT_USERMEM;
    dbtdata.data = &largeBuffer[0];
    dbtdata.ulen = sizeof(largeBuffer);

    DBT key;
    memset(&key, 0, sizeof(DBT));
    key.data = (void*)hostOrUser;
    key.size = strlen(hostOrUser);

    DB_TXN *tid = db->m_environment->m_transaction;

    err = db->m_dbHandle->get(db->m_dbHandle, tid, &key, &dbtdata, DB_RMW);
    /*Called with DB_DBT_USERMEM?  What was there wasn't enough*/
    if (err == DB_BUFFER_SMALL) {
        allocData = malloc(dbtdata.size);
        if (!allocData)
            return 1;
        dbtdata.data = allocData;
        dbtdata.ulen = dbtdata.size;
        dbtdata.size = 0;
        /* ...and try again. */
        err = db->m_dbHandle->get(db->m_dbHandle, tid, &key, &dbtdata, 0600);
    }

    if (err != 0 && err != DB_NOTFOUND) {
        db->m_dbHandle->err(db->m_dbHandle, err, "DB->get");
        if (allocData)
            free(allocData);
        return err;
    }

    if (err == DB_NOTFOUND) {
        //it was not in the db, just report no error and don't fill in the state
        if (allocData)
            free(allocData);
        return 0;
    }

    err = createAuthState(dbtdata.data, dbtdata.size, hostOrUserState);
    if (allocData)
        free(allocData);
    return err;
}

int saveInfo(Database *db, const char *hostOrUser, AuthState *hostOrUserState) {
    if (!db || !db->m_environment || !db->m_dbHandle || !hostOrUser || !*hostOrUser || !hostOrUserState)
        return 1;

    DB_TXN *tid = db->m_environment->m_transaction;

    DBT key, data;
    memset(&key, 0, sizeof(DBT));
    memset(&data, 0, sizeof(DBT));
    key.data = (void*)hostOrUser;
    key.size = strlen(hostOrUser);
    data.data = hostOrUserState->m_data;
    data.size = hostOrUserState->m_usedSize;
    int err = db->m_dbHandle->put(db->m_dbHandle, tid, &key, &data, 0);
    return err;
}

int removeInfo(Database *db, const char *hostOrUser) {
    if (!db || !db->m_environment || !db->m_dbHandle || !hostOrUser || !*hostOrUser)
        return 1;
    DB_TXN *tid = db->m_environment->m_transaction;

    DBT key;
    memset(&key, 0, sizeof(key));
    key.data = (void*)hostOrUser;
    key.size = strlen(hostOrUser);
    int err = db->m_dbHandle->del(db->m_dbHandle, tid, &key, 0);
    return err;
}
