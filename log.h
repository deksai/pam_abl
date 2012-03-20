#ifndef LOG_H
#define LOG_H

#include <security/pam_appl.h>

typedef struct log_context {
    short debug;
} log_context;

log_context *createLogContext();
void destroyLogContext(log_context *context);

void log_out(int pri, const char *format, ...);
void log_sys_error(log_context *context, int err, const char *what);
void log_db_error(log_context *context, int err, const char *what);
void log_info(log_context *context, const char *format, ...);
void log_error(log_context *context, const char *format, ...);
void log_warning(log_context *context, const char *format, ...);
void log_debug(log_context *context, const char *format, ...);

#if !defined(TOOLS) && !defined(TEST)
void log_pam_error(log_context *context, pam_handle_t *handle, int err, const char *what);
#endif

#endif
