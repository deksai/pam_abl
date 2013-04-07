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
//do a checkpoint every 8MB of log
#define CHECKPOINTSIZE (8000)

//let's allocate a 'large' buffer
char largeBuffer[1024*50];

void log_db_error(int err, const char *what) {
    log_error("%s (%d) while %s", db_strerror(err), err, what);
}

int create_environment(const char *home, DB_ENV **env) {
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

#if ((DB_VERSION_MAJOR >= 5)||(DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR >= 7))
        dbenv->log_set_config(dbenv, DB_LOG_AUTO_REMOVE, 1);
#else
        dbenv->set_flags(dbenv, DB_LOG_AUTOREMOVE, 1);
#endif

        err = dbenv->log_set_config(dbenv, DB_LOG_AUTO_REMOVE, 1);
        if (err != 0) {
            log_db_error(err, "setting automatic log file removal.");
        }
        if ((err = dbenv->txn_checkpoint(dbenv, CHECKPOINTSIZE, 0, 0)) != 0) {
            log_db_error(err, "setting the automatic checkpoint option.");
        }
    }

    *env = dbenv;
    return err;
}

void destroy_environment(DB_ENV *env) {
    if (!env)
        return;
    env->close(env, 0);
    env = NULL;
    free(env);
}

int bdb_start_transaction(const abl_db *abldb) {
    DB_TXN *tid = NULL;
    int err = 0;
    bdb_state *state = abldb->state;
    if (!state || !state->m_environment)
        return 1;
    //for the moment we only support one transaction at the time
    if (state->m_transaction)
        return 0;

    if ((err = state->m_environment->txn_begin(state->m_environment, NULL, &tid, 0)) != 0) {
        log_db_error(err, "starting transaction");
        return err;
    }
    state->m_transaction = tid;
    return err;
}

int bdb_commit_transaction(const abl_db *abldb) {
    bdb_state *env = abldb->state;
    if (!env || !env->m_environment)
        return 1;
    //if we are not in a transaction, just ignore it
    if (!env->m_transaction)
        return 0;

    int err = env->m_transaction->commit(env->m_transaction, 0);
    if (err == DB_LOCK_DEADLOCK) {
        env->m_transaction->abort(env->m_transaction);
    }
    env->m_transaction = NULL;
    return err;
}

int bdb_abort_transaction(const abl_db *abldb) {
    bdb_state *env = abldb->state;
    if (!env || !env->m_environment)
        return 1;
    //if we are not in a transaction, just ignore it
    if (!env->m_transaction)
        return 0;

    int err = env->m_transaction->abort(env->m_transaction);
    env->m_transaction = NULL;
    return err;
}

abl_db* abl_db_open(const char *db_home) {
    if ( !db_home || !*db_home )
        return NULL;

    int             err             = 0;
    abl_db          *db             = NULL;
    bdb_state       *state          = NULL;
    DB              *host_handle    = NULL;
    DB              *user_handle    = NULL;
    DB_ENV          *env            = NULL;

    if (create_environment(db_home, &env))
        goto open_fail;
    db = calloc(1,sizeof(abl_db));
    if (db == NULL) goto open_fail;

    state = calloc(1,sizeof(bdb_state));
    if (state == NULL) goto open_fail;
    db->state   = (void*) state;
    state->m_environment = env;
    state->m_transaction = NULL;

    if (db_create(&host_handle, env, 0))
        goto open_fail;
    if (db_create(&user_handle, env, 0))
        goto open_fail;

    bdb_start_transaction((const abl_db*)db);
    if ((err = host_handle->open(host_handle, state->m_transaction, "host", "db", DB_BTREE, DB_CREATE|DB_MULTIVERSION, DBPERM)) != 0) {
        goto open_fail;
    }
    if ((err = user_handle->open(user_handle, state->m_transaction, "user", "db", DB_BTREE, DB_CREATE|DB_MULTIVERSION, DBPERM)) != 0) {
        goto open_fail;
    }
    bdb_commit_transaction((const abl_db*)db);

    log_debug("databases opened");

    state->m_hhandle = host_handle;
    state->m_uhandle = user_handle;

    db->close   = bdb_close;
    db->put     = bdb_put;
    db->get     = bdb_get;
    db->del     = bdb_del;
    db->c_open  = bdb_c_open;
    db->c_close = bdb_c_close;
    db->c_get   = bdb_c_get;
    db->start_transaction  = bdb_start_transaction;
    db->commit_transaction = bdb_commit_transaction;
    db->abort_transaction  = bdb_abort_transaction;
    return db;
open_fail:
    if (host_handle)
        host_handle->close(host_handle,0);
    if (user_handle)
        user_handle->close(user_handle,0);
    if (state && state->m_environment && state->m_transaction) {
        // db exists if the above are true
        bdb_abort_transaction(db);
    }
    if(state)
        free(state);
    if(db)
        free(db);
    if(env)
        destroy_environment(env);

    log_db_error(err, "opening or creating database");
    return NULL;
}

void bdb_close(abl_db *abldb) {
    bdb_state *db = abldb->state;
    if (db && db->m_hhandle && db->m_uhandle)
        db->m_hhandle->close(db->m_hhandle,0);
        db->m_uhandle->close(db->m_uhandle,0);
    destroy_environment(db->m_environment);
    free(db);
    free(abldb);
}

int bdb_get(const abl_db *abldb, const char *hostOrUser, AuthState **hostOrUserState, ablObjectType type) {
    *hostOrUserState = NULL;
    bdb_state *db = abldb->state;
    if (!db || !db->m_environment || !db->m_hhandle || !db->m_uhandle || !hostOrUser)
        return 1;
    
    DB *db_handle = NULL;
    if ( type & HOST )
        db_handle = db->m_hhandle;
    else
        db_handle = db->m_uhandle;

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

    DB_TXN *tid = db->m_transaction;

    err = db_handle->get(db_handle, tid, &key, &dbtdata, 0);
    /*Called with DB_DBT_USERMEM?  What was there wasn't enough*/
    if (err == DB_BUFFER_SMALL) {
        allocData = malloc(dbtdata.size);
        if (!allocData)
            return 1;
        dbtdata.data = allocData;
        dbtdata.ulen = dbtdata.size;
        dbtdata.size = 0;
        /* ...and try again. */
        err = db_handle->get(db_handle, tid, &key, &dbtdata, 0);
    }

    if (err != 0 && err != DB_NOTFOUND) {
        db_handle->err(db_handle, err, "DB->get");
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

int bdb_put(const abl_db *abldb, const char *hostOrUser, AuthState *hostOrUserState, ablObjectType type) {
    bdb_state *state = abldb->state;
    if (!state || !state->m_environment || 
        !state->m_hhandle || !state->m_uhandle || 
        !hostOrUser || !*hostOrUser || !hostOrUserState)
        return 1;
    DB *db_handle = NULL;
    if ( type & HOST )
        db_handle = state->m_hhandle;
    else
        db_handle = state->m_uhandle;


    DBT key, data;
    memset(&key, 0, sizeof(DBT));
    memset(&data, 0, sizeof(DBT));
    key.data = (void*)hostOrUser;
    key.size = strlen(hostOrUser);
    data.data = hostOrUserState->m_data;
    data.size = hostOrUserState->m_usedSize;
    int err = db_handle->put(db_handle, state->m_transaction, &key, &data, 0);
    return err;
}

int bdb_del(const abl_db *abldb, const char *hostOrUser, ablObjectType type) {
    bdb_state *db = abldb->state;
    if (!db || !db->m_environment || !db->m_hhandle || !db->m_uhandle || !hostOrUser || !*hostOrUser)
        return 1;
    DBT key;
    DB *db_handle = NULL;
    if ( type & HOST )
        db_handle = db->m_hhandle;
    else
        db_handle = db->m_uhandle;

    memset(&key, 0, sizeof(key));
    key.data = (void*)hostOrUser;
    key.size = strlen(hostOrUser);
    int err = db_handle->del(db_handle, db->m_transaction, &key, 0);
    return err;
}

int bdb_c_open(abl_db *abldb, ablObjectType type) {
    int err = 0;
    bdb_state *db = abldb->state;
    if (!db->m_hhandle || !db->m_uhandle)
        return 1;
    DB *db_handle = NULL;
    if ( type & HOST )
        db_handle = db->m_hhandle;
    else
        db_handle = db->m_uhandle;
    
    if (err = db_handle->cursor(db_handle, db->m_transaction, &db->m_cursor, DB_TXN_SNAPSHOT), 0 != err) {
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

int bdb_c_get(abl_db *abldb, char **key, size_t *ksize, char **data, size_t *dsize) {
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
#if DB_VERSION_MAJOR < 5
        err = db->m_cursor->c_close(db->m_cursor);
#else
        err = db->m_cursor->close(db->m_cursor);
#endif

        if (err) log_db_error(err, "Closing cursor");
    }
    return err;
}
