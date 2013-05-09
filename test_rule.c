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
        CU_FAIL("Could not create an empty state.");
        return;
    }
    CU_ASSERT_EQUAL(rule_test("*:10/1s", "user", "service", state, 10), CLEAR);
    destroyAuthState(state);
}

static void testEmptyRule() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        CU_FAIL("Could not create an empty state.");
        return;
    }
    size_t i = 0;
    for (; i < 5; ++i) {
        CU_ASSERT_FALSE(addAttempt(state, USER_BLOCKED, i*2, "MyUser", "Service1", 0, 0));
    }
    CU_ASSERT_EQUAL(rule_test("", "user", "service", state, 5), CLEAR);
    CU_ASSERT_EQUAL(rule_test(NULL, "user", "service", state, 5), CLEAR);
    destroyAuthState(state);
}

static void testNoMatch() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        CU_FAIL("Could not create an empty state.");
        return;
    }
    size_t i = 0;
    for (; i < 5; ++i) {
        CU_ASSERT_FALSE(addAttempt(state, USER_BLOCKED, i*2, "MyUser", "Service1", 0, 0));
    }
    CU_ASSERT_EQUAL(rule_test("*:6/10s", "user", "service", state, 10), CLEAR);
    CU_ASSERT_EQUAL(rule_test("*:10/8s", "user", "service", state, 10), CLEAR);
    destroyAuthState(state);
}

static void testMatch() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        CU_FAIL("Could not create an empty state.");
        return;
    }
    size_t i = 0;
    for (; i < 5; ++i) {
        CU_ASSERT_FALSE(addAttempt(state, USER_BLOCKED, i*2, "MyUser", "Service1", 0, 0));
    }
    CU_ASSERT_EQUAL(rule_test("*:5/10s", "user", "service", state, 10), BLOCKED);
    CU_ASSERT_EQUAL(rule_test("*:3/10s", "user", "service", state, 10), BLOCKED);
    destroyAuthState(state);
}

static void testMatchService() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        CU_FAIL("Could not create an empty state.");
        return;
    }
    size_t i = 0;
    for (; i < 5; ++i) {
        CU_ASSERT_FALSE(addAttempt(state, USER_BLOCKED, i*2, "MyUser", "Service1", 0, 0));
    }
    CU_ASSERT_EQUAL(rule_test("*/Service1:5/10s *:10/1h", "MyUser", "Service1", state, 10), BLOCKED);
    CU_ASSERT_EQUAL(rule_test("*/Service1:10/1h", "MyUser", "Service1", state, 10), CLEAR);
    destroyAuthState(state);
}

static void testNoService() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        CU_FAIL("Could not create an empty state.");
        return;
    }
    size_t i = 0;
    for (; i < 5; ++i) {
        CU_ASSERT_FALSE(addAttempt(state, USER_BLOCKED, i*2, "MyUser", "Service1", 0, 0));
    }
    CU_ASSERT_EQUAL(rule_test("*/Service1:5/10s *:8/1h", "MyUser", NULL, state, 10), CLEAR);
    CU_ASSERT_EQUAL(rule_test("*:5/1h", "MyUser", NULL, state, 10), BLOCKED);
    destroyAuthState(state);
}

static void testMatchUser() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        CU_FAIL("Could not create an empty state.");
        return;
    }
    size_t i = 0;
    for (; i < 5; ++i) {
        CU_ASSERT_FALSE(addAttempt(state, USER_BLOCKED, i*2, "MyUser", "Service1", 0, 0));
    }
    CU_ASSERT_EQUAL(rule_test("MyUser:5/10s *:10/1h", "MyUser", "Service1", state, 10), BLOCKED);
    CU_ASSERT_EQUAL(rule_test("user2:1/1h *:10/1h", "MyUser", "Service1", state, 10), CLEAR);
    destroyAuthState(state);
}

static void testInvert() {
    AuthState *state = NULL;
    if (createEmptyState(CLEAR, &state)) {
        CU_FAIL("Could not create an empty state.");
        return;
    }
    size_t i = 0;
    for (; i < 5; ++i) {
        CU_ASSERT_FALSE(addAttempt(state, USER_BLOCKED, i*2, "MyUser", "Service1", 0, 0));
    }
    CU_ASSERT_EQUAL(rule_test("!MyUser:1/10s *:10/1h", "MyUser", "Service1", state, 10), CLEAR);
    CU_ASSERT_EQUAL(rule_test("MyUser:1/10s !MyUser:10/1h", "MyUser", "Service1", state, 10), BLOCKED);
    destroyAuthState(state);
}

void addRuleTests() {
    CU_pSuite pSuite = NULL;
    pSuite = CU_add_suite("RuleTest", NULL, NULL);
    if (NULL == pSuite)
        return;
    CU_add_test(pSuite, "testRuleNoAttempts", testRuleNoAttempts);
    CU_add_test(pSuite, "testEmptyRule", testEmptyRule);
    CU_add_test(pSuite, "testNoMatch", testNoMatch);
    CU_add_test(pSuite, "testMatch", testMatch);
    CU_add_test(pSuite, "testMatchService", testMatchService);
    CU_add_test(pSuite, "testMatchUser", testMatchUser);
    CU_add_test(pSuite, "testInvert", testInvert);
    CU_add_test(pSuite, "testNoService", testNoService);
}
