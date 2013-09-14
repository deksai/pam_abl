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

#include "config.h"
#include "test.h"
#include "dbfun.h"
#include "log.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>


void removeDir(const char *dirname) {
    DIR *dir;
    size_t dirNameSize = strlen(dirname);
    struct dirent *entry;
    dir = opendir(dirname);
    if (dir == NULL)
        return;

    //According to POSIX.1-2001 a buffer of size PATH_MAX suffices,
    //but PATH_MAX need not be a defined constant
    //Asking pathconf(3) does not really help, since, on the one hand
    //POSIX warns that the result of pathconf(3) may be huge and unsuitable
    //for mallocing memory, and on the other hand pathconf(3) may return -1
    //to signify that PATH_MAX is not bounded.
    //as a last resort, just alloc some memory
    size_t pathSize = 512;
    char *path = malloc(sizeof(char)*pathSize);
    if (path == NULL) {
        closedir(dir);
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
            // + 2, the '/' and a \0 char
            size_t neededSize = dirNameSize + strlen(entry->d_name) + 2;
            if (neededSize > pathSize) {
                //allocate a little more, it will hopefullly catch future reallocs
                pathSize = neededSize + 512;
                path = realloc(path, pathSize);
                if (path == NULL) {
                    closedir(dir);
                    return;
                }
            }
            snprintf(path, pathSize, "%s/%s", dirname, entry->d_name);
            if (entry->d_type == DT_DIR) {
                removeDir(path);
            } else {
                unlink(path);
            }
        }
    }
    closedir(dir);
    rmdir(dirname);
    free(path);
    return;
}

void makeDir(const char *dirname) {
    mkdir(dirname, S_IRWXU);
}

int main(int argc, const char *argv[]) {

    //During testCommand, we call this very program as a test since it is
    //guaranteed to exist.  When called this way, it is called with -e as the
    //first argument, in which case we merely exit with the given number.
    if (argc >= 3) {
        if (strcmp(argv[1], "-e") == 0) {
            int exitCode = atoi(argv[2]);
            exit(exitCode);
        }
    }
    if (argc < 2) {
        printf("Please specify a database module to use.\n");
        return 1;
    }
    log_quiet_mode = 1;
    if (CU_initialize_registry() != CUE_SUCCESS)
        return 1;
    addTypeTests();
    addDatabaseTests();
    addRuleTests();
    addExternalCommandTests(argv[0]);
    addRunCommandTests();
    addConfigTests();
    addAblTests(argv[1]);
    addPamFunctionsTests(argv[1]);
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    printf("\n");
    runPerformanceTest();
    return 0;
}
