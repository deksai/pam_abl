#include "test.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>

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
    runTypeTests();
    runDatabaseTests();
    runtRuleTests();
    testAble();
    return 0;
}
