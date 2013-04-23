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

static abl_db *setup_db() {
    abl_db *abldb = NULL;
    void *dblib = NULL;
    abl_db_open_ptr db_open = NULL;

    dblib = dlopen(args->db_module, RTLD_LAZY|RTLD_GLOBAL);
    if (!dblib) {
        log_error("%s opening database module",dlerror());
        return NULL;
    }
    dlerror();
    db_open = dlsym(dblib, "abl_db_open");
    abldb = db_open(args->db_home);
    if (!abldb) {
        log_error("The database environment could not be opened %p",abldb);
    }
    return abldb;
}

/* Authentication management functions */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)(flags);
    int err = PAM_BUF_ERR;
    abl_info *attemptInfo = NULL;
    abl_db *abldb = NULL;
    ModuleAction action = ACTION_NONE;

    attemptInfo = malloc(sizeof(abl_info));
    config_create();
    if (!attemptInfo || !args) {
        err = PAM_BUF_ERR;
        goto psa_fail;
    }
    memset(attemptInfo, 0, sizeof(abl_info));

    err = config_parse_module_args(argc, argv, &action);
    if (err != 0) {
        err = PAM_SERVICE_ERR;
        log_error("Could not parse the config.");
        goto psa_fail;
    }
    if (action == ACTION_NONE) {
        err = PAM_SERVICE_ERR;
        log_error("No action given. Aborting.");
        goto psa_fail;
    }

    abldb = setup_db();
    if (!abldb)
        goto psa_fail;

    //get the user again, it can be that another module has changed the username or something else
    err = pam_get_item(pamh, PAM_USER, (const void **) &attemptInfo->user);
    if (err != PAM_SUCCESS) {
        log_pam_error(pamh, err, "getting PAM_USER");
        goto psa_fail;
    }

    err = pam_get_item(pamh, PAM_SERVICE, (const void **) &attemptInfo->service);
    if (err != PAM_SUCCESS) {
        log_pam_error(pamh, err, "getting PAM_SERVICE");
        goto psa_fail;
    }

    err = pam_get_item(pamh, PAM_RHOST, (const void **) &attemptInfo->host);
    if (err != PAM_SUCCESS) {
        log_pam_error(pamh, err, "getting PAM_RHOST");
        goto psa_fail;
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
        check_attempt(abldb, attemptInfo, checkSubject);
        int recordResult = record_attempt(abldb, attemptInfo, action);
        log_debug("record_attempt returned %d", recordResult);
    }

    //let's assume that the user/host is not blocked, if they are, we will change err again
    err = PAM_SUCCESS;

    //secondly check if we need to check if the user/host is blocked
    if (action & (ACTION_CHECK_USER | ACTION_CHECK_HOST)) {
        BlockState bState = check_attempt(abldb, attemptInfo, action);
        if (bState == BLOCKED) {
            log_info("Blocking access from %s to service %s, user %s", attemptInfo->host, attemptInfo->service, attemptInfo->user);
            err = PAM_AUTH_ERR;
        } else {
            err = PAM_SUCCESS;
        }
    }

psa_fail:
    if (abldb)
        abldb->close(abldb);
    if (attemptInfo)
        free(attemptInfo);
    if (args)
        config_free();
    return err;
}

/* Init structure for static modules */
#ifdef PAM_STATIC
struct pam_module _pam_abl_modstruct = {
    MODULE_NAME,
    pam_sm_authenticate,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};
#endif
