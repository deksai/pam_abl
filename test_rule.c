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
#include "typefun.h"
#include "rule.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void testRuleNoAttempts() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        printf("   Could not create an empty state.\n");
        return;
    }
    if (rule_test("*:10/1s", "user", "service", state, 10) == BLOCKED)
        printf("   No attempts should never match.\n");
    destroyAuthState(state);
}

static void testEmptyRule() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        printf("   Could not create an empty state.\n");
        return;
    }
    size_t i = 0;
    for (; i < 5; ++i) {
        if (addAttempt(state, USER_BLOCKED, i*2, "MyUser", "Service1", 0, 0))
            printf("   Could not add an attempt.\n");
    }
    if (rule_test("", "user", "service", state, 5) == BLOCKED)
        printf("   The empty rule matched.\n");
    if (rule_test(NULL, "user", "service", state, 5) == BLOCKED)
        printf("   The empty rule matched.\n");
    destroyAuthState(state);
}

static void testNoMatch() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        printf("   Could not create an empty state.\n");
        return;
    }
    size_t i = 0;
    for (; i < 5; ++i) {
        if (addAttempt(state, USER_BLOCKED, i*2, "MyUser", "Service1", 0, 0))
            printf("   Could not add an attempt.\n");
    }
    if (rule_test("*:6/10s", "user", "service", state, 10) == BLOCKED)
        printf("   The rule matched.\n");
    if (rule_test("*:10/8s", "user", "service", state, 10) == BLOCKED)
        printf("   The rule matched.\n");
    destroyAuthState(state);
}

static void testMatch() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        printf("   Could not create an empty state.\n");
        return;
    }
    size_t i = 0;
    for (; i < 5; ++i) {
        if (addAttempt(state, USER_BLOCKED, i*2, "MyUser", "Service1", 0, 0))
            printf("   Could not add an attempt.\n");
    }
    if (rule_test("*:5/10s", "user", "service", state, 10) == CLEAR)
        printf("   The rule did not match.\n");
    if (rule_test("*:3/10s", "user", "service", state, 10) == CLEAR)
        printf("   The rule did not match.\n");
    destroyAuthState(state);
}

static void testMatchService() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        printf("   Could not create an empty state.\n");
        return;
    }
    size_t i = 0;
    for (; i < 5; ++i) {
        if (addAttempt(state, USER_BLOCKED, i*2, "MyUser", "Service1", 0, 0))
            printf("   Could not add an attempt.\n");
    }
    if (rule_test("*/Service1:5/10s *:10/1h", "MyUser", "Service1", state, 10) == CLEAR)
        printf("   The special service rule did not match.\n");
    if (rule_test("*/Service1:10/1h", "MyUser", "Service1", state, 10) == BLOCKED)
        printf("   The rule matched.\n");
    destroyAuthState(state);
}

static void testNoService() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        printf("   Could not create an empty state.\n");
        return;
    }
    size_t i = 0;
    for (; i < 5; ++i) {
        if (addAttempt(state, USER_BLOCKED, i*2, "MyUser", "Service1", 0, 0))
            printf("   Could not add an attempt.\n");
    }
    if (rule_test("*/Service1:5/10s *:8/1h", "MyUser", NULL, state, 10) == BLOCKED)
        printf("   The rule matched.\n");
    if (rule_test("*:5/1h", "MyUser", NULL, state, 10) == CLEAR)
        printf("   The rule dit not match.\n");
    destroyAuthState(state);
}

static void testMatchUser() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        printf("   Could not create an empty state.\n");
        return;
    }
    size_t i = 0;
    for (; i < 5; ++i) {
        if (addAttempt(state, USER_BLOCKED, i*2, "MyUser", "Service1", 0, 0))
            printf("   Could not add an attempt.\n");
    }
    if (rule_test("MyUser:5/10s *:10/1h", "MyUser", "Service1", state, 10) == CLEAR)
        printf("   The rule did not match.\n");
    if (rule_test("user2:1/1h *:10/1h", "MyUser", "Service1", state, 10) == BLOCKED)
        printf("   The rule did match.\n");
    destroyAuthState(state);
}

static void testInvert() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        printf("   Could not create an empty state.\n");
        return;
    }
    size_t i = 0;
    for (; i < 5; ++i) {
        if (addAttempt(state, USER_BLOCKED, i*2, "MyUser", "Service1", 0, 0))
            printf("   Could not add an attempt.\n");
    }
    if (rule_test("!MyUser:1/10s *:10/1h", "MyUser", "Service1", state, 10) == BLOCKED)
        printf("   The rule did match.\n");
    if (rule_test("MyUser:1/10s !MyUser:10/1h", "MyUser", "Service1", state, 10) == CLEAR)
        printf("   The rule did not match.\n");
    destroyAuthState(state);
}

void runRuleTests() {
    printf("Rule test start.\n");
    printf(" Starting testRuleNoAttempts.\n");
    testRuleNoAttempts();
    printf(" Starting testEmptyRule.\n");
    testEmptyRule();
    printf(" Starting testNoMatch.\n");
    testNoMatch();
    printf(" Starting testMatch.\n");
    testMatch();
    printf(" Starting testMatchService.\n");
    testMatchService();
    printf(" Starting testMatchUser.\n");
    testMatchUser();
    printf(" Starting testInvert.\n");
    testInvert();
    printf(" Starting testNoService.\n");
    testNoService();
    printf("Rule test end.\n");
}
