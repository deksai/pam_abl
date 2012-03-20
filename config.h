#ifndef CONFIG_H
#define CONFIG_H

#include "log.h"

typedef struct abl_string {
    struct abl_string *link;
} abl_string;

typedef struct {
    /* Our args */
    const char      *db_home;
    const char      *host_db;
    const char      *host_rule;
    long             host_purge;
    const char      *host_whitelist;
    const char      *host_blk_cmd;
    const char      *host_clr_cmd;
    const char      *user_db;
    const char      *user_rule;
    long             user_purge;
    const char      *user_whitelist;
    const char      *user_blk_cmd;
    const char      *user_clr_cmd;
    unsigned int     upperlimit;
    unsigned int     lowerlimit;
    /* Storage */
    abl_string      *strs;
} abl_args;

abl_args *config_create();
void config_free(abl_args *args);
int config_parse_args(int argc, const char **argv, abl_args *args, log_context *logContext);
int config_parse_file(const char *name, abl_args *args, log_context *logContext);
void dump_args(const abl_args *args, log_context *logContext);
#endif
