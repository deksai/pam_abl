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

#include "log.h"
#include <stdlib.h>
#include <sys/types.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>

#include <db.h>

#define MODULE_NAME "pam-abl"

#define UNUSED(x) (void)(x)

log_context *createLogContext() {
    log_context *retValue = malloc(sizeof(log_context));
    retValue->debug = 0;
    return retValue;
}

void destroyLogContext(log_context *context) {
    free(context);
}

static void log_out(int pri, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
#if defined(TEST) || defined(TOOLS)
    UNUSED(pri); //to please the compiler when TEST or TOOLS is defined
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
#else
    openlog(MODULE_NAME, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
    vsyslog(pri, format, ap);
    closelog();
#endif
    va_end(ap);
}

#if !defined(TOOLS) && !defined(TEST)
void log_pam_error(log_context *context, pam_handle_t *handle, int err, const char *what) {
    UNUSED(context);
    log_out(LOG_ERR, "%s (%d) while %s", pam_strerror(handle, err), err, what);
}
#endif

void log_sys_error(log_context *context, int err, const char *what) {
    UNUSED(context);
    log_out(LOG_ERR, "%s (%d) while %s", strerror(err), err, what);
}

void log_db_error(log_context *context, int err, const char *what) {
    UNUSED(context);
    log_out(LOG_ERR, "%s (%d) while %s", db_strerror(err), err, what);
}

void log_info(log_context *context, const char *format, ...) {
    UNUSED(context);
    va_list ap;
    va_start(ap, format);
#if defined(TEST) || defined(TOOLS)
    fprintf(stderr, "INFO: ");
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
#else
    openlog(MODULE_NAME, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
    vsyslog(LOG_INFO, format, ap);
    closelog();
#endif
    va_end(ap);
}

void log_error(log_context *context, const char *format, ...) {
    UNUSED(context);
    va_list ap;
    va_start(ap, format);
#if defined(TEST) || defined(TOOLS)
    fprintf(stderr, "ERROR: ");
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
#else
    openlog(MODULE_NAME, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
    vsyslog(LOG_WARNING, format, ap);
    closelog();
#endif
    va_end(ap);
}

void log_warning(log_context *context, const char *format, ...) {
    UNUSED(context);
    va_list ap;
    va_start(ap, format);
#if defined(TEST) || defined(TOOLS)
    fprintf(stderr, "WARNING: ");
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
#else
    openlog(MODULE_NAME, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
    vsyslog(LOG_WARNING, format, ap);
    closelog();
#endif
    va_end(ap);
}

void log_debug(log_context *context, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    if (context == NULL || context->debug) {
#if defined(TEST) || defined(TOOLS)
#   ifndef TEST
        fprintf(stderr, "DEBUG: ");
        vfprintf(stderr, format, ap);
        fprintf(stderr, "\n");
#   endif
#else
        openlog(MODULE_NAME, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
        vsyslog(LOG_DEBUG, format, ap);
        closelog();
#endif
    }
    va_end(ap);
}
