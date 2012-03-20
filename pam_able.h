#ifndef PAM_ABLE_H
#define PAM_ABLE_H

#include "config.h"
#include "dbfun.h"

typedef struct PamAbleDbEnv {
    DbEnvironment *m_environment;
    Database      *m_userDb;
    Database      *m_hostDb;
} PamAbleDbEnv;


typedef struct {
    BlockReason blockReason;
    const char *user;
    const char *host;
    const char *service;
} abl_info;

PamAbleDbEnv *openPamAbleDbEnvironment(abl_args *args, log_context *logContext);
void destroyPamAbleDbEnvironment(PamAbleDbEnv *env);

int runHostCommand(BlockState bState, const abl_args *args, abl_info *info, log_context *logContext);
int runUserCommand(BlockState bState, const abl_args *args, abl_info *info, log_context *logContext);

/*
    Returns the current state for the given attempt.
    This will:
        - calculate the current state
        - update the state saved in the database
        - run the required scripts
        - change the blockReason (by default this will be AUTH_FAILED), unless it could already be determined
    If something goes wrong while checking, CLEAR is returned
    and diagnostic messages are written using the given logContext.
*/
BlockState check_attempt(const PamAbleDbEnv *dbEnv, const abl_args *args, abl_info *info, log_context *logContext);

/*
    Record an authentication attempt.
    This will:
        - purge the db data for the given host and user
        - add an entry for the given host and user with as reason info->blockReason
    If something went wrong, a non zero value is returned and a diagnostic message is logged using the logContext
*/
int record_attempt(const PamAbleDbEnv *dbEnv, const abl_args *args, abl_info *info, log_context *logContext);
#endif
