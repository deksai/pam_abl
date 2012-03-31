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

#include "test.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>

#include "dbfun.h"

void removeDir(const char *dirname) {
    DIR *dir;
    struct dirent *entry;
    char path[PATH_MAX];

    dir = opendir(dirname);
    if (dir == NULL)
        return;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
            snprintf(path, (size_t) PATH_MAX, "%s/%s", dirname, entry->d_name);
            if (entry->d_type == DT_DIR) {
                removeDir(path);
            } else {
                unlink(path);
            }
        }
    }
    closedir(dir);
    rmdir(dirname);
    return;
}

void makeDir(const char *dirname) {
    mkdir(dirname, S_IRWXU);
}

int main() {
    printf("Using db version \"%s\" %d.%d.%d\n", DB_VERSION_STRING, DB_VERSION_MAJOR, DB_VERSION_MINOR, DB_VERSION_PATCH);
    runTypeTests();
    runDatabaseTests();
    runtRuleTests();
    testAble();
    return 0;
}
