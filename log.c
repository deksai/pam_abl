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
#include <execinfo.h>
#include <stdlib.h>
#include <sys/types.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define MODULE_NAME "pam_abl"

#define UNUSED(x) (void)(x)

//pure for testing. We expect to get errors during testing
//we should not complain about them
int log_quiet_mode = 0;

static void log_out(int pri, const char *format, ...) {
    if (log_quiet_mode)
        return;
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

#if !defined(TOOLS)
void log_pam_error(pam_handle_t *handle, int err, const char *what) {
    log_out(LOG_ERR, "%s (%d) while %s", pam_strerror(handle, err), err, what);
}
#endif

void log_sys_error(int err, const char *what) {
    log_out(LOG_ERR, "%s (%d) while %s", strerror(err), err, what);
}

void log_info(const char *format, ...) {
    if (log_quiet_mode)
        return;
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

void log_error(const char *format, ...) {
    if (log_quiet_mode)
        return;
    va_list ap;
    va_start(ap, format);

#if defined(TEST) || defined(TOOLS)
    //void *buffer[64];
    fprintf(stderr, "ERROR: ");
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
    //backtrace(buffer,64);
    //backtrace_symbols_fd(buffer,64,STDERR_FILENO);
#else
    openlog(MODULE_NAME, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
    vsyslog(LOG_WARNING, format, ap);
    closelog();
#endif
    va_end(ap);
}

void log_warning(const char *format, ...) {
    if (log_quiet_mode)
        return;
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

void log_debug(const char *format, ...) {
    if (log_quiet_mode)
        return;
    va_list ap;
    va_start(ap, format);
    if (args != NULL && args->debug) {
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
