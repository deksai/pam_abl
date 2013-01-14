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

#include "kc.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define DBPERM 0600

void log_db_error(int err, const char *what) {
    log_error("%s (%d) while %s",kcecodename(err), err, what);
}

abl_db* abl_db_open() {
    if (!args || !args->db_home || !*args->db_home)
        return NULL;

    int       err             = 0;
    int       bytes           = 0;
    char      path[256];
    abl_db   *db             = NULL;
    kc_state *state          = NULL;
    KCDB     *host_handle    = NULL;
    KCDB     *user_handle    = NULL;

    host_handle = kcdbnew();
    user_handle = kcdbnew();

    bytes = snprintf(path, sizeof(path), "%s/host.kch",args->db_home);
    if (sizeof(path) == bytes) goto open_fail;
    if (!kcdbopen(host_handle, path, KCOWRITER | KCOCREATE | KCOAUTOTRAN)) {
        err = kcdbecode(host_handle);
        goto open_fail;
    }
    bytes = snprintf(path, sizeof(path), "%s/user.kch",args->db_home);
    if (sizeof(path) == bytes) goto open_fail;
    if (!kcdbopen(user_handle, path, KCOWRITER | KCOCREATE | KCOAUTOTRAN)) {
        err = kcdbecode(user_handle);
        goto open_fail;
    }

    log_debug("databases opened");

    state = calloc(1,sizeof(kc_state));
    if (state == NULL) goto open_fail;
    state->host = host_handle;
    state->user = user_handle;

    db = calloc(1,sizeof(abl_db));
    if (db == NULL) goto open_fail;
    db->state   = (void*) state;
    db->close   = kc_close;
    db->put     = kc_put;
    db->get     = kc_get;
    db->del     = kc_del;
    db->c_open  = kc_c_open;
    db->c_close = kc_c_close;
    db->c_get   = kc_c_get;
    db->start_transaction = kc_start_transaction;
    db->commit_transaction = kc_commit_transaction;
    db->abort_transaction = kc_abort_transaction;
    return db;
open_fail:
    if (host_handle)
        kcdbdel(host_handle);
    if (host_handle)
        kcdbdel(host_handle);
    log_db_error(err, "opening or creating database");
    return NULL;
}

void kc_close(abl_db *abldb) {
    //if (abl_db && db && db->host && db->user) {
        kc_state *db = abldb->state;
        kcdbclose(db->host);
        kcdbclose(db->user);
        kcdbdel(db->host);
        kcdbdel(db->user);
        free(db);
        free(abldb);
    //}
}

int kc_get(const abl_db *abldb, const char *hostOrUser, AuthState **hostOrUserState, ablObjectType type) {
    *hostOrUserState = NULL;
    kc_state *db = abldb->state;
    if (!db || !db->host || !db->user || !hostOrUser)
        return 1;
    
    KCDB *db_handle = NULL;
    if ( type & HOST )
        db_handle = db->host;
    else
        db_handle = db->user;

    int err = 0;
    char *data = NULL;
    size_t  dsize;

    data = kcdbget(db_handle, hostOrUser, strlen(hostOrUser), &dsize);

    // Not found?
    if (NULL == data) {
        return 0;
    }

    err = createAuthState(data, dsize, hostOrUserState);
    if (data)
        kcfree(data);
    return err;
}

int kc_put(const abl_db *abldb, const char *hostOrUser, AuthState *hostOrUserState, ablObjectType type) {
    int err = 0;

    kc_state *db = abldb->state;
    if (!db || !db->host || !db->user || !hostOrUser || !*hostOrUser || !hostOrUserState)
        return 1;

    KCDB *db_handle = NULL;
    if ( type & HOST )
        db_handle = db->host;
    else
        db_handle = db->user;

    err = !kcdbset(db_handle, 
            hostOrUser, 
            strlen(hostOrUser),
            hostOrUserState->m_data, 
            hostOrUserState->m_usedSize
            );
    return err;
}

int kc_del(const abl_db *abldb, const char *hostOrUser, ablObjectType type) {
    kc_state *db = abldb->state;
    if (!db || !db->host || !db->user || !hostOrUser || !*hostOrUser)
        return 1;
    KCDB *db_handle = NULL;
    if ( type & HOST )
        db_handle = db->host;
    else
        db_handle = db->user;

    // Returns true on success
    int err = !kcdbremove(db_handle, hostOrUser, strlen(hostOrUser));
    return err;
}

int kc_c_open(abl_db *abldb, ablObjectType type) {
    int err = 0;
    kc_state *db = abldb->state;
    if (!db->host || !db->user)
        return 1;
    KCDB *db_handle = NULL;
    if ( type & HOST )
        db_handle = db->host;
    else
        db_handle = db->user;

    db->cursor = kcdbcursor(db_handle);
    if (NULL == db->cursor) {
        log_db_error(kcdbecode(db_handle), "creating cursor");
    }
    kccurjump(db->cursor);
    return err;
}


int kc_c_get(abl_db *abldb, char **key, size_t *ksize, char **data, size_t *dsize) {
    int err = 0;
    static char* _key = NULL;
    static char* _data = NULL;
    if (_key) {
        kcfree(_key);
        _key = NULL;
    }
    if (_data) {
        kcfree(_key);
        _key = NULL;
    }
    kc_state *db = abldb->state;
    *key = kccurget(db->cursor, ksize, (const char **)data, dsize, 1);
    if (NULL == *key || NULL == *data) {
        log_debug("Iterating cursor: %s",kccurecode(db->cursor));
        return 1;
    }
    _key = *key;
    _data = *data;
    return err;
}

int kc_c_close(abl_db *abldb) {
    kc_state *db = abldb->state;
    if (db->cursor) {
        kccurdel(db->cursor);
    }
    return 0;
}

int kc_start_transaction(const abl_db *abldb) {
    int success = 0;
    kc_state *state = abldb->state;
    if (!state || !state->host || !state->user)
        return 1;
    if (state->transaction)
        return 0;

    success =  kcdbbegintran(state->host,0);
    if (!success) return 1;
    success = kcdbbegintran(state->user,0);
    if (!success) return 1;

    state->transaction = 1;
    return 0;
}

int kc_commit_transaction(const abl_db *abldb) {
    int success = 0;
    kc_state *state = abldb->state;
    if (!state || !state->host || !state->user)
        return 1;
    if (!state->transaction)
        return 0;

    success = kcdbendtran(state->host, 1);
    if (!success) return 1;
    success = kcdbendtran(state->user, 1);
    if (!success) return 1;

    state->transaction = 0;
    return 1;
}

int kc_abort_transaction(const abl_db *abldb) {
    int success = 0;
    kc_state *state = abldb->state;
    if (!state || !state->host || !state->user)
        return 1;
    if (!state->transaction)
        return 0;

    success =  kcdbendtran(state->host, 0);
    if (!success) return 1;
    success &= kcdbendtran(state->user, 0);
    if (!success) return 1;

    state->transaction = 0;
    return 1;
}
