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
#include "dbfun.h"
#include "log.h"

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>

#define MODULE_NAME "pam-abl"

typedef struct abl_context {
    abl_args     *args;
    abl_info     *attemptInfo;
    abl_db       *abldb;
} abl_context;

static void cleanup(pam_handle_t *pamh, void *data, int err) {
    (void)(pamh);
    //if we are replacing our data pointer, ignore the cleanup.
    //the function replacing our data should handle the cleanup
    if (err & PAM_DATA_REPLACE)
        return;

    if (NULL != data) {
        abl_context *context = data;
        log_debug("In cleanup, err is %08x", err);

        if (err) {
            int recordResult = record_attempt(context->abldb, context->attemptInfo);
            log_debug("record returned %d", recordResult);
        }
        if (context->abldb)
            context->abldb->close(context->abldb);
        if (context->attemptInfo)
            free(context->attemptInfo);
        if (context->args)
            config_free(context->args);
        free(context);
    }
}

/* Authentication management functions */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)(flags);
    int err = PAM_BUF_ERR;
    abl_context *context = NULL;

    err = pam_get_data(pamh, MODULE_NAME, (const void **)(&context));
    if (err != PAM_SUCCESS) {
        context = NULL;
	}

    if (!context) {
        context = malloc(sizeof(abl_context));
        if (!context) {
            err = PAM_BUF_ERR;
            goto psa_fail;
        }
        memset(context, 0, sizeof(abl_context));
        context->attemptInfo = malloc(sizeof(abl_info));
        config_create();
        context->args = args;
        if (!context->attemptInfo || !context->args) {
            err = PAM_BUF_ERR;
            goto psa_fail;
        }
        memset(context->attemptInfo, 0, sizeof(abl_info));

        err = config_parse_args(argc, argv);
        if (err != 0) {
            err = PAM_SERVICE_ERR;
            log_error("Could not parse the config.");
            goto psa_fail;
        }
        /* We now keep the database open from the beginning to avoid the cost
         * of opening them repeatedly. */
        void *dblib = NULL;
        abl_db *(*db_open)();

        dblib = dlopen(args->db_module, RTLD_LAZY|RTLD_GLOBAL);
        if (!dblib) {
            log_error("%s opening database module",dlerror());
            goto psa_fail;
        }
        dlerror();
        db_open = dlsym(dblib, "abl_db_open");
        context->abldb = db_open(args->db_home);
        if (!context->abldb) {
            log_error("The database environment could not be opened %p",context->abldb);
            goto psa_fail;
        }

        err = pam_set_data(pamh, MODULE_NAME, context, cleanup);
        if (err != PAM_SUCCESS) {
            log_pam_error(pamh, err, "setting PAM data");
            goto psa_fail;
        }
    } else {
        //we have a previous data pointer. We will ASSUME that it was from a previous failed attempt
        //a good example is sshd, when you try to login, you are given 3 attempts, so this function
        //can be called up to three times before the cleanup function is called.
        int recordResult = record_attempt(context->abldb, context->attemptInfo);
        log_debug("record from authenticate returned %d", recordResult);
    }

    //get the user again, it can be that another module has changed the username or something else
    err = pam_get_item(pamh, PAM_USER, (const void **) &context->attemptInfo->user);
    if (err != PAM_SUCCESS) {
        log_pam_error(pamh, err, "getting PAM_USER");
        goto psa_fail;
    }

    err = pam_get_item(pamh, PAM_SERVICE, (const void **) &context->attemptInfo->service);
    if (err != PAM_SUCCESS) {
        log_pam_error(pamh, err, "getting PAM_SERVICE");
        goto psa_fail;
    }

    err = pam_get_item(pamh, PAM_RHOST, (const void **) &context->attemptInfo->host);
    if (err != PAM_SUCCESS) {
        log_pam_error(pamh, err, "getting PAM_RHOST");
        goto psa_fail;
    }

    BlockState bState = check_attempt(context->abldb, context->attemptInfo);
    if (bState == BLOCKED) {
        log_info("Blocking access from %s to service %s, user %s", context->attemptInfo->host, context->attemptInfo->service, context->attemptInfo->user);
        return PAM_AUTH_ERR;
    } else {
        return PAM_SUCCESS;
    }

psa_fail:
    if (context) {
        if (context->abldb)
            context->abldb->close(context->abldb);
        if (context->attemptInfo)
            free(context->attemptInfo);
        if (context->args)
            config_free();
        free(context);
        //it can be that we already set the data pointer, let's remove it
        pam_set_data(pamh, MODULE_NAME, NULL, NULL);
    }
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
