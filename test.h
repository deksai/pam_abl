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
//test to test how an attempot should be handled
void testAble();

#endif
