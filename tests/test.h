#ifndef VNCPWD_TEST_H
#define VNCPWD_TEST_H

#include <stdio.h>
#include <string.h>

void test_begin(const char *name);
void test_end(void);
void test_fail(const char *file, int line, const char *expr);
void test_note(const char *fmt, ...);
void test_summary(void);
int  test_failed_count(void);

#define CHECK(expr)                                                          \
    do {                                                                     \
        if (!(expr)) test_fail(__FILE__, __LINE__, #expr);                   \
    } while (0)

#define CHECK_STR_EQ(actual, expected)                                       \
    do {                                                                     \
        if (strcmp((actual), (expected)) != 0) {                             \
            test_fail(__FILE__, __LINE__, #actual " == " #expected);         \
            test_note("got \"%s\", expected \"%s\"", (actual), (expected));  \
        }                                                                    \
    } while (0)

#define CHECK_MEM_EQ(actual, expected, len)                                  \
    do {                                                                     \
        if (memcmp((actual), (expected), (len)) != 0) {                      \
            test_fail(__FILE__, __LINE__, #actual " == " #expected);         \
        }                                                                    \
    } while (0)

#define RUN_TEST(fn)                                                         \
    do {                                                                     \
        test_begin(#fn);                                                     \
        fn();                                                                \
        test_end();                                                          \
    } while (0)

/* Suites */
void test_des(void);
void test_encoding(void);
void test_validator(void);
void test_detector(void);
void test_ini(void);
void test_connection(void);
void test_report(void);

#endif /* VNCPWD_TEST_H */
