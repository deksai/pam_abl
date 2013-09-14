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

#include "pam_functions.h"
#include "pam_abl.h"
#include "config.h"
#include "dbfun.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>

#define MODULE_NAME "pam-abl"

void setup_and_log_attempt(abl_info *info) {
    if (!info)
        return;

    abl_db *abldb = setup_db();
    if (abldb) {
        int recordResult = record_attempt(abldb, info, ACTION_LOG_USER | ACTION_LOG_HOST);
        log_debug("record returned %d", recordResult);
        abldb->close(abldb);
    }
}

static void cleanup(pam_handle_t *pamh, void *data, int err) {
    (void)(pamh);
    //if we are replacing our data pointer, ignore the cleanup.
    //the function replacing our data should handle the cleanup
    if (err & PAM_DATA_REPLACE)
        return;

    if (data) {
        log_debug("In cleanup, err is %08x", err);
        abl_context *context = data;
        if (err && context->attemptInfo)
            setup_and_log_attempt(context->attemptInfo);
        destroyAblInfo(context->attemptInfo);
        if (args)
            config_free();
        free(context);
    }
}

int pam_inner_authenticate(abl_context *context, char *user, char *host, char *service, ModuleAction action) {
    int err = PAM_BUF_ERR;
    abl_db *abldb = NULL;

    abl_info attemptInfo;
    memset(&attemptInfo, 0, sizeof(abl_info));
    attemptInfo.user = user;
    attemptInfo.host = host;
    attemptInfo.service = service;

    abldb = setup_db();
    if (!abldb)
        goto psa_fail;

    //if we have a previous context and that context has an attempt in it
    if (context && context->attemptInfo) {
        //we have a previous data pointer. We will ASSUME that it was from a previous failed attempt
        //a good example is sshd, when you try to login, you are given 3 attempts, so this function
        //can be called up to three times before the cleanup function is called.
        int recordResult = record_attempt(abldb, context->attemptInfo, ACTION_LOG_USER | ACTION_LOG_HOST);
        log_debug("record from authenticate returned %d", recordResult);
        //we don't need this info anymore, we have a new attempt
        destroyAblInfo(context->attemptInfo);
        context->attemptInfo = NULL;
    }

    ModuleAction checkAction = action;
    if (action == ACTION_NONE) {
        checkAction = ACTION_CHECK_USER | ACTION_CHECK_HOST;
        if (!context) {
            log_debug("context should have been set, coder error");
        } else {
            context->attemptInfo = copyAblInfo(&attemptInfo);
        }
    }

    //add the user/host attempt (if needed)
    if (action & (ACTION_LOG_USER | ACTION_LOG_HOST)) {
        //we first need to call check_attempt,
        //it will set the block reason to the correct state
        //we do not care what the current block state is
        ModuleAction checkSubject = ACTION_NONE;
        if (action & ACTION_LOG_USER)
            checkSubject |= ACTION_CHECK_USER;
        if (action & ACTION_LOG_HOST)
            checkSubject |= ACTION_CHECK_HOST;
        check_attempt(abldb, &attemptInfo, checkSubject);
        int recordResult = record_attempt(abldb, &attemptInfo, action);
        log_debug("record_attempt returned %d", recordResult);
    }

    //let's assume that the user/host is not blocked, if they are, we will change err again
    err = PAM_SUCCESS;

    //secondly check if we need to check if the user/host is blocked
    if (checkAction & (ACTION_CHECK_USER | ACTION_CHECK_HOST)) {
        BlockState bState = check_attempt(abldb, &attemptInfo, checkAction);
        if (bState == BLOCKED) {
            log_info("Blocking access from %s to service %s, user %s", attemptInfo.host, attemptInfo.service, attemptInfo.user);
            err = PAM_AUTH_ERR;
        } else {
            err = PAM_SUCCESS;
        }
    }

psa_fail:
    if (abldb)
        abldb->close(abldb);
    return err;
}

/* Authentication management functions */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)(flags);
    int err = PAM_BUF_ERR;
    abl_context *context = NULL;
    ModuleAction action = ACTION_NONE;
    char *user = NULL;
    char *host = NULL;
    char *service = NULL;

    //one of the first things we need to do is check if we have a previous context
    //as this determines if the args struct will need to be freed or not
    err = pam_get_data(pamh, MODULE_NAME, (const void **)(&context));
    if (err != PAM_SUCCESS) {
        context = NULL;
    }

    //always start with a new config structure
    config_free();
    config_create();
    if (!args) {
        err = PAM_BUF_ERR;
        goto pam_sm_authenticate_fail;
    }

    err = config_parse_module_args(argc, argv, &action);
    if (err != 0) {
        err = PAM_SERVICE_ERR;
        log_error("Could not parse the config.");
        goto pam_sm_authenticate_fail;
    }

    //get the user again, it can be that another module has changed the username or something else
    err = pam_get_item(pamh, PAM_USER, (const void **) &user);
    if (err != PAM_SUCCESS) {
        log_pam_error(pamh, err, "getting PAM_USER");
        goto pam_sm_authenticate_fail;
    }

    err = pam_get_item(pamh, PAM_SERVICE, (const void **) &service);
    if (err != PAM_SUCCESS) {
        log_pam_error(pamh, err, "getting PAM_SERVICE");
        goto pam_sm_authenticate_fail;
    }

    err = pam_get_item(pamh, PAM_RHOST, (const void **) &host);
    if (err != PAM_SUCCESS) {
        log_pam_error(pamh, err, "getting PAM_RHOST");
        goto pam_sm_authenticate_fail;
    }
    if (action == ACTION_NONE) {
        if (!context) {
            context = malloc(sizeof(abl_context));
            if (!context) {
                err = PAM_BUF_ERR;
                goto pam_sm_authenticate_fail;
            }
            memset(context, 0, sizeof(abl_context));
            err = pam_set_data(pamh, MODULE_NAME, context, cleanup);
            if (err != PAM_SUCCESS) {
                log_pam_error(pamh, err, "setting PAM data");
                goto pam_sm_authenticate_fail;
            }
        }
    }
    int pamResult = pam_inner_authenticate(context, user, host, service, action);
    if (args && !context)
        config_free();
    return pamResult;

pam_sm_authenticate_fail:
    return err;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)(argc);
    (void)(argv);
    (void)(flags);
    return pam_set_data(pamh, MODULE_NAME, NULL, cleanup);
}

/* Init structure for static modules */
#ifdef PAM_STATIC
struct pam_module _pam_abl_modstruct = {
    MODULE_NAME,
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL
};
#endif
