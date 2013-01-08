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

#ifndef TEST_H
#define TEST_H

//some helper functions
void removeDir(const char *dirname);
void makeDir(const char *dirname);


//The actual test functions
//run all the tests
void runTests();
//tests that have to do with the custom types.
void runTypeTests();
//test the database functions
void runDatabaseTests();
//test to test the purging and rule matching
void runtRuleTests();
//test to test how an attempt should be handled
void testAbl();
//test the running of external commands
void testExternalCommand(const char *cmd);
//test the integrated parsing of external commands
void testRunCommand();
//test the config parsing
void testConfig();

#endif
