/* Minimal assertion harness: no external framework, so CI has no dependencies. */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "test.h"

static int tests_run = 0;
static int tests_failed = 0;
static int current_failed = 0;

void test_begin(const char *name) {
    current_failed = 0;
    tests_run++;
    printf("  %-58s", name);
    fflush(stdout);
}

void test_end(void) {
    if (current_failed) {
        tests_failed++;
        printf("FAIL\n");
    } else {
        printf("ok\n");
    }
}

void test_fail(const char *file, int line, const char *expr) {
    current_failed = 1;
    printf("\n    %s:%d: assertion failed: %s\n", file, line, expr);
}

void test_note(const char *fmt, ...) {
    va_list ap;
    printf("      ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

void test_summary(void) {
    printf("\n%d test(s), %d failure(s)\n", tests_run, tests_failed);
}

int test_failed_count(void) { return tests_failed; }
