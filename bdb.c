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

#include "bdb.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define DBPERM 0600

//let's allocate a 'large' buffer
char largeBuffer[1024*50];

void log_db_error(int err, const char *what) {
    log_error("%s (%d) while %s", db_strerror(err), err, what);
}

int create_environment(const char *home, bdb_environment **env) {
    int err = 0;
    *env = NULL;
    DB_ENV *dbenv = NULL;

    if ((err = db_env_create(&dbenv, 0)) != 0) {
    	log_db_error(err, "creating environment object");
        return err;
    }
    dbenv->set_errpfx(dbenv, "pam_abl");
    if ((err = dbenv->open(dbenv, home, DB_CREATE | DB_INIT_TXN | DB_INIT_LOCK | DB_INIT_MPOOL | DB_RECOVER | DB_REGISTER, 0)) != 0) {
        log_db_error(err, "opening the database environment");
        dbenv->close(dbenv, 0);
        dbenv = 0;
    }
    if (dbenv) {
        /* Do deadlock detection internally. */
        if ((err = dbenv->set_lk_detect(dbenv, DB_LOCK_DEFAULT)) != 0) {
            log_db_error(err, "setting lock detection.");
        }
    }

    if (dbenv) {
        bdb_environment *retValue = calloc(1, sizeof(bdb_environment));
        retValue->m_envHandle = dbenv;
        retValue->m_transaction = NULL;
        *env = retValue;
    }
    return err;
}

void destroy_environment(bdb_environment *env) {
    if (!env)
        return;
    if (env->m_envHandle)
        env->m_envHandle->close(env->m_envHandle, 0);
    env->m_envHandle = NULL;
    free(env);
}

/*
int startTransaction(bdb_environment *env) {
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

int commitTransaction(bdb_environment *env) {
    if (!env || !env->m_envHandle)
        return 1;
    //if we are not in a transaction, just ignore it
    if (!env->m_transaction)
        return 0;

    int err = env->m_transaction->commit(env->m_transaction, 0);
    env->m_transaction = NULL;
    return err;
}

int abortTransaction(bdb_environment *env) {
    if (!env || !env->m_envHandle)
        return 1;
    //if we are not in a transaction, just ignore it
    if (!env->m_transaction)
        return 0;

    int err = env->m_transaction->abort(env->m_transaction);
    env->m_transaction = NULL;
    return err;
}
*/

abl_db* abl_db_open(const abl_args *args) {
    if (!args || !args->db_home || !*args->db_home)
        return NULL;

    int             err         = 0;
    abl_db          *db         = NULL;
    bdb_environment *env        = NULL;
    bdb_state       *state      = NULL;
    DB              *dbHandle   = NULL;

    if (create_environment(args->db_home, &env))
        goto open_fail;
    if (db_create(&dbHandle, env->m_envHandle, 0))
        goto open_fail;

    if ((err = dbHandle->open(dbHandle, NULL, "db", "db", DB_BTREE, DB_CREATE|DB_AUTO_COMMIT|DB_MULTIVERSION, DBPERM)) != 0) {
        goto open_fail;
    }

    log_debug(args,"database opened");

    state = calloc(1,sizeof(bdb_state));
    if (state == NULL) goto open_fail;
    state->m_handle = dbHandle;
    state->m_environment = env;

    db = calloc(1,sizeof(abl_db));
    if (db == NULL) goto open_fail;
    db->state   = (void*) state;
    db->close   = bdb_close;
    db->put     = bdb_put;
    db->get     = bdb_get;
    db->del     = bdb_del;
    db->c_open  = bdb_c_open;
    db->c_close = bdb_c_close;
    db->c_get   = bdb_c_get;
    return db;
open_fail:
    log_db_error(err, "opening or creating database");
    return NULL;
}

void bdb_close(abl_db *abldb) {
    bdb_state *db = abldb->state;
    if (db && db->m_handle)
        db->m_handle->close(db->m_handle,0);
    destroy_environment(db->m_environment);
    db->m_handle = NULL;
    free(db);
    free(abldb);
}

int bdb_get(const abl_db *abldb, const char *hostOrUser, AuthState **hostOrUserState) {
    *hostOrUserState = NULL;
    bdb_state *db = (bdb_state*) abldb->state;
    if (!db || !db->m_environment || !db->m_handle || !hostOrUser)
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

    err = db->m_handle->get(db->m_handle, tid, &key, &dbtdata, DB_RMW);
    /*Called with DB_DBT_USERMEM?  What was there wasn't enough*/
    if (err == DB_BUFFER_SMALL) {
        allocData = malloc(dbtdata.size);
        if (!allocData)
            return 1;
        dbtdata.data = allocData;
        dbtdata.ulen = dbtdata.size;
        dbtdata.size = 0;
        /* ...and try again. */
        err = db->m_handle->get(db->m_handle, tid, &key, &dbtdata, 0600);
    }

    if (err != 0 && err != DB_NOTFOUND) {
        db->m_handle->err(db->m_handle, err, "DB->get");
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

int bdb_put(const abl_db *abldb, const char *hostOrUser, AuthState *hostOrUserState) {
    bdb_state *db = abldb->state;
    if (!db || !db->m_environment || !db->m_handle || !hostOrUser || !*hostOrUser || !hostOrUserState)
        return 1;

    DB_TXN *tid = db->m_environment->m_transaction;

    DBT key, data;
    memset(&key, 0, sizeof(DBT));
    memset(&data, 0, sizeof(DBT));
    key.data = (void*)hostOrUser;
    key.size = strlen(hostOrUser);
    data.data = hostOrUserState->m_data;
    data.size = hostOrUserState->m_usedSize;
    int err = db->m_handle->put(db->m_handle, tid, &key, &data, 0);
    return err;
}

int bdb_del(const abl_db *abldb, const char *hostOrUser) {
    bdb_state *db = abldb->state;
    if (!db || !db->m_environment || !db->m_handle || !hostOrUser || !*hostOrUser)
        return 1;
    DB_TXN *tid = db->m_environment->m_transaction;

    DBT key;
    memset(&key, 0, sizeof(key));
    key.data = (void*)hostOrUser;
    key.size = strlen(hostOrUser);
    int err = db->m_handle->del(db->m_handle, tid, &key, 0);
    return err;
}

int bdb_c_open(abl_db *abldb) {
    int err = 0;
    bdb_state *db = abldb->state;
    if (err = db->m_handle->cursor(db->m_handle, NULL, &db->m_cursor, DB_TXN_SNAPSHOT), 0 != err) {
        log_db_error(err, "creating cursor");
    }
    return err;
}

/*
int bdb_c_del(abl_db *abldb) {
    int err = 0;
    bdb_state *db = abldb->state;
    err = db->m_cursor->del(db->m_cursor);
    if ( 0 != err ) 
        log_db_error(err, "Deleting at cursor");
    return err;
}

int bdb_c_replace(abl_db *abldb, char *data, unsigned dsize) {
    int err = 0;
    DBT m_key;
    DBT m_data;
    bdb_state *db = abldb->state;

    memset(&m_key,0,sizeof(DBT));
    memset(&m_data,0,sizeof(DBT));
    m_data.data = data;
    m_data.size = dsize;

    err = db->m_cursor->c_get(db->m_cursor, &m_key, &m_data, DB_CURRENT);
    if (err) {
        log_db_error(err, "Replacing at cursor");
        return err;
    }
    return err;
}
*/

int bdb_c_get(abl_db *abldb, char **key, unsigned *ksize, char **data, unsigned *dsize) {
    int err = 0;
    DBT m_key;
    DBT m_data;
    memset(&m_key,0,sizeof(DBT));
    memset(&m_data,0,sizeof(DBT));
    bdb_state *db = abldb->state;
    err = db->m_cursor->c_get(db->m_cursor, &m_key, &m_data, DB_NEXT);
    if (DB_NOTFOUND == err) {
        return 1;
    }else if (err) {
        log_db_error(err, "Iterating cursor");
        return err;
    }
    *key    = m_key.data;
    *ksize  = m_key.size;
    *data   = m_data.data;
    *dsize  = m_data.size;
    return err;
}

int bdb_c_close(abl_db *abldb) {
    int err = 0;
    bdb_state *db = abldb->state;
    if (db->m_cursor) {
        err = db->m_cursor->close(db->m_cursor);
        if (err) log_db_error(err, "Closing cursor");
    }
    return err;
}
