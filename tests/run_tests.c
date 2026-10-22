#include "test.h"

int main(void) {
    printf("vncpwd test suite\n");
    printf("\nDES\n");
    test_des();
    printf("\nEncoding\n");
    test_encoding();
    printf("\nValidation\n");
    test_validator();
    printf("\nDetection\n");
    test_detector();
    printf("\nINI parser\n");
    test_ini();
    printf("\nConnection files\n");
    test_connection();
    printf("\nReporting\n");
    test_report();

    test_summary();
    return test_failed_count() ? 1 : 0;
}
