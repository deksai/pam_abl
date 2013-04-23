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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static void testSplit(const char *cmd, int nofParts, const char **parts) {
    char *command = strdup(cmd);
    int nof = splitCommand(command, NULL);
    if (nof != nofParts) {
        printf("   The number of parts for \"%s\" is not %d.\n", command, nofParts);
        free(command);
        return;
    }
    if (nofParts > 0) {
        char **resultParts = malloc(sizeof(char*)*nofParts);
        int p = 0;
        //just fill in something random, that will crash if accessed
        for (; p<nofParts; ++p)
            resultParts[p] = (char*)(0x1);
        nof = splitCommand(command, resultParts);
        if (nof != nofParts) {
            printf("   While actually parsing: The number of parts for \"%s\" is not %d.\n", command, nofParts);
            free(command);
            free(resultParts);
            return;
        }
        int i = 0;
        for (i = 0; i < nofParts; ++i) {
            if (strcmp(parts[i], resultParts[i]) != 0) {
                printf("   While comparing parts: \"%s\" != \"%s\"\n", resultParts[i], parts[i]);
                free(command);
                free(resultParts);
                return;
            }
        }
        free(resultParts);
    }
    free(command);
    return;
}

static void testSplitExpectError(const char *cmd) {
    char *command = strdup(cmd);
    int nof = splitCommand(command, NULL);
    if (nof >= 0)
        printf("   Expected an error while splitting \"%s\".\n", command);
    free(command);
}

static void testCommandNormal() {
    const char *expected[] = {
        "ping",
        "-c",
        "10",
        "127.0.0.1"
    };
    testSplit("[ping][-c][10][127.0.0.1]", 4, expected);
    testSplit("[ping] [-c] [10] [127.0.0.1]", 4, expected);
}

static void testIgnoreNonEnclosed() {
    const char *expected[] = {
        "command",
        "arg1",
        "arg2",
        "arg3"
    };
    testSplit("command[command]arg[arg1]arg[arg2]arg[arg3]argie", 4, expected);
    testSplit("   [command]   [arg1]   [arg2]   [arg3]   ", 4, expected);
    testSplit("lol[command] sdfsdfsdf eerer  sder [arg1]sdfsdfasd[arg2]_sdfaewr+adfasdf sdd [arg3] sdfsdfwer", 4, expected);
}

static void testEmpty() {
    const char *expected[] = {
        "",
        "arg1",
        "",
        ""
    };
    testSplit("[][arg1][][]", 4, expected);
    testSplit("command[]arg[arg1]arg[]arg[]argie", 4, expected);
}

static void testWithEscapeChars() {
    const char *expected[] = {
        "command",
        "arg1",
        "arg\\2",
        "arg3"
    };
    testSplit("\\n \\b  [command]   [arg\\1] \\c  [arg\\\\2]   [arg\\3]   ", 4, expected);
}

static void testEscapeBracket() {
    const char *expected[] = {
        "command[]",
        "[]arg1",
        "[arg2]",
        "][arg\\3]["
    };
    testSplit("[command\\[\\]] [\\[\\]arg1] [\\[arg2\\]] [\\]\\[arg\\\\3\\]\\[]", 4, expected);
}

static void testMultipleOpen() {
    testSplitExpectError("[[command] [arg]");
    testSplitExpectError("[[command]] [arg]");
    testSplitExpectError("[command] [[arg]");
    testSplitExpectError("[command] [arg] [lol");
    testSplitExpectError("[command] [arg] [");
}

static void testNoClosing() {
    testSplitExpectError("[command [arg]");
    testSplitExpectError("[command] [arg");
    testSplitExpectError("[command] [arg [arg]");
}

static void testEmptyBrackets() {
    const char *expected[] = {
        "",
        "arg",
        "",
        "arg2"
    };
    testSplit("[] [arg] [] [arg2]", 4, expected);
}

static void testNoCommand() {
    testSplit("blaat blaat \\[ \\] this should all be ignored", 0, NULL);
    testSplit("", 0, NULL);
}

static void testGoodModuleArgsNoFile() {
    int x, x1, x2, x3, x4, x5, x6, debugEnabled;
    const char *argv[7];
    for (x = 0; x <= 6; ++x)
        argv[x] = NULL;
    for (x1 = 0; x1 < 2; ++x1) {
        for (x2 = 0; x2 < 2; ++x2) {
            for (x3 = 0; x3 < 2; ++x3) {
                for (x4 = 0; x4 < 2; ++x4) {
                    for (x5 = 0; x5 < 2; ++x5) {
                        for (x6 = 0; x6 < 2; ++x6) {
                            for (debugEnabled = 0; debugEnabled < 2; ++debugEnabled) {
                                //fillup the array
                                x = 0;
                                ModuleAction expectedResult = ACTION_NONE;
                                if (x1) {
                                    argv[x++] = "check_user";
                                    expectedResult |= ACTION_CHECK_USER;
                                }
                                if (x2) {
                                    argv[x++] = "check_host";
                                    expectedResult |= ACTION_CHECK_HOST;
                                }
                                if (x3) {
                                    argv[x++] = "check_both";
                                    expectedResult |= ACTION_CHECK_USER | ACTION_CHECK_HOST;
                                }
                                if (x4) {
                                    argv[x++] = "log_user";
                                    expectedResult |= ACTION_LOG_USER;
                                }
                                if (x5) {
                                    argv[x++] = "log_host";
                                    expectedResult |= ACTION_LOG_HOST;
                                }
                                if (x6) {
                                    argv[x++] = "log_both";
                                    expectedResult |= ACTION_LOG_USER | ACTION_LOG_HOST;
                                }
                                if (debugEnabled) {
                                    argv[x++] = "debug";
                                }
                                ModuleAction result;
                                if (args)
                                    config_free();
                                config_create();
                                if (config_parse_module_args(x, argv, &result)) {
                                    printf("   the module arguments failed to parse\n");
                                } else {
                                    if (result != expectedResult) {
                                        printf("   not all arguments were parsed correctly\n");
                                    }
                                    if (debugEnabled && !args->debug) {
                                        printf("   debug was not enabled\n");
                                    }
                                    if (!debugEnabled && args->debug) {
                                        printf("   debug was enabled\n");
                                    }
                                }
                                config_free();
                            }
                        }
                    }
                }
            }
        }
    }
}

static void testInvalidModuleArgsNoFile() {
    config_free();
    config_create();
    const char *testSet[] = {
        "debug",
        "log_both",
        "NON_EXISTING_OPTION",
        "log_both"
    };
    ModuleAction result;
    if (config_parse_module_args(4, (const char **)(&testSet), &result) == 0) {
        printf("   the invalid module arguments parsed correctly\n");
    }
    config_free();
}

static void testValidModuleArgsInvalidFile() {
    config_free();
    config_create();
    const char *testSet[] = {
        "debug",
        "log_both",
        "config=/non-existing-dir/foobar_vnfitri5948sj",
        "log_both"
    };
    ModuleAction result;
    if (config_parse_module_args(4, (const char **)(&testSet), &result) == 0) {
        printf("   the invalid module arguments parsed correctly\n");
    }
    config_free();
}

void testConfig() {
    printf("Config test start.\n");
    printf(" Starting testCommandNormal.\n");
    testCommandNormal();
    printf(" Starting testIgnoreNonEnclosed.\n");
    testIgnoreNonEnclosed();
    printf(" Starting testEmpty.\n");
    testEmpty();
    printf(" Starting testWithEscapeChars.\n");
    testWithEscapeChars();
    printf(" Starting testEscapeBracket.\n");
    testEscapeBracket();
    printf(" Starting testMultipleOpen.\n");
    testMultipleOpen();
    printf(" Starting testNoClosing.\n");
    testNoClosing();
    printf(" Starting testEmptyBrackets.\n");
    testEmptyBrackets();
    printf(" Starting testNoCommand.\n");
    testNoCommand();
    printf(" Starting testGoodModuleArgsNoFile.\n");
    testGoodModuleArgsNoFile();
    printf(" Starting testInvalidModuleArgsNoFile.\n");
    testInvalidModuleArgsNoFile();
    printf(" Starting testValidModuleArgsInvalidFile.\n");
    testValidModuleArgsInvalidFile();
    printf("Config test end.\n");
}
