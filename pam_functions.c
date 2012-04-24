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

#include "pam_abl.h"
#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>

#define MODULE_NAME "pam-abl"

typedef struct abl_context {
    abl_args     *args;
    abl_info     *attemptInfo;
    PamAblDbEnv *dbEnv;
    log_context  *logContext;
} abl_context;

static void cleanup(pam_handle_t *pamh, void *data, int err) {
    (void)(pamh);
    if (NULL != data) {
        abl_context *context = data;
        log_debug(context->logContext, "In cleanup, err is %08x", err);

        if (err && (err & PAM_DATA_REPLACE) == 0) {
            int recordResult = record_attempt(context->dbEnv, context->args, context->attemptInfo, context->logContext);
            log_debug(context->logContext, "record returned %d", recordResult);
        }
        if (context->dbEnv)
            destroyPamAblDbEnvironment(context->dbEnv);
        if (context->attemptInfo)
            free(context->attemptInfo);
        if (context->args)
            config_free(context->args);
        if (context->logContext)
            destroyLogContext(context->logContext);
        free(context);
    }
}

/* Authentication management functions */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)(flags);
    int err = PAM_BUF_ERR;
    PamAblDbEnv *dbEnv = NULL;
    abl_info *info = malloc(sizeof(abl_info));
    abl_context *context = malloc(sizeof(abl_context));
    abl_args *args = config_create();
    log_context *logContext = createLogContext();
    if (!info || ! context || !args || !logContext) {
        err = PAM_BUF_ERR;
        goto psa_fail;
    }
    memset(info, 0, sizeof(abl_info));
    memset(context, 0, sizeof(abl_context));

    err = config_parse_args(argc, argv, args, logContext);
    if (err == 0) {
        /* We now keep the database open from the beginning to avoid the cost
         * of opening them repeatedly. */
        dbEnv = openPamAblDbEnvironment(args, logContext);
        if (!dbEnv) {
            log_error(logContext, "The database environment could not be opened");
            goto psa_fail;
        }
        context->args = args;
        context->attemptInfo = info;
        context->logContext = logContext;
        context->dbEnv = dbEnv;

        err = pam_set_data(pamh, MODULE_NAME, context, cleanup);
        if (err != PAM_SUCCESS) {
            log_pam_error(logContext, pamh, err, "setting PAM data");
            goto psa_fail;
        }

        err = pam_get_item(pamh, PAM_USER, (const void **) &info->user);
        if (err != PAM_SUCCESS) {
            log_pam_error(logContext, pamh, err, "getting PAM_USER");
            goto psa_fail;
        }

        err = pam_get_item(pamh, PAM_SERVICE, (const void **) &info->service);
        if (err != PAM_SUCCESS) {
            log_pam_error(logContext, pamh, err, "getting PAM_SERVICE");
            goto psa_fail;
        }

        err = pam_get_item(pamh, PAM_RHOST, (const void **) &info->host);
        if (err != PAM_SUCCESS) {
            log_pam_error(logContext, pamh, err, "getting PAM_RHOST");
            goto psa_fail;
        }

        //BlockState check_attempt(const PamAblDbEnv *dbEnv, const abl_args *args, abl_info *info, log_context *logContext);
        BlockState bState = check_attempt(dbEnv, args, info, logContext);
        if (bState == BLOCKED) {
            log_info(logContext, "Blocking access from %s to service %s, user %s", info->host, info->service, info->user);
            return PAM_AUTH_ERR;
        } else {
            return PAM_SUCCESS;
        }
    } else {
        err = PAM_SERVICE_ERR;
        log_error(logContext, "Could not parse the config.");
    }

psa_fail:
    if (dbEnv)
        destroyPamAblDbEnvironment(dbEnv);
    if (info)
        free(info);
    if (context)
        free(context);
    if (args)
        config_free(args);
    if (logContext)
        destroyLogContext(logContext);
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
