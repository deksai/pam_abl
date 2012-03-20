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

int  createEnvironment(log_context *context, const char *home, DbEnvironment **env);
void destroyEnvironment(DbEnvironment *env);
int  startTransaction(DbEnvironment *env);
int  commitTransaction(DbEnvironment *env);
int  abortTransaction(DbEnvironment *env);


int  openDatabase(DbEnvironment *env, const char *dbfile, const char *dbname, Database **db);
void closeDatabase(Database *db);

int getUserOrHostInfo(Database *db, const char *host, AuthState **hostOrUserState);
int saveInfo(Database *db, const char *hostOrUser, AuthState *hostOrUserState);
int removeInfo(Database *db, const char *hostOrUser);

#endif
