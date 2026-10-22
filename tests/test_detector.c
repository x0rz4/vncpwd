#include "test.h"

#include "detector.h"
#include "registry.h"

#include <string.h>

static void test_hex_reg_sz(void) {
    const char *value = "dbd83cfd727a1458";
    vnc_detection det;

    CHECK(vnc_detect_value((const uint8_t *)value, strlen(value), VNC_REG_SZ,
                           VNC_ENC_AUTO, &det) == VNC_DETECT_OK);
    CHECK(det.encoding == VNC_ENC_HEX);
    CHECK(det.cipher_len == 8);
    CHECK(det.recovered == 1);
    CHECK_STR_EQ((const char *)det.validation.plain, "password");
}

static void test_binary_reg_binary(void) {
    static const uint8_t blob[8] = {0xdb, 0xd8, 0x3c, 0xfd, 0x72, 0x7a, 0x14, 0x58};
    vnc_detection det;

    CHECK(vnc_detect_value(blob, 8, VNC_REG_BINARY, VNC_ENC_AUTO, &det) == VNC_DETECT_OK);
    CHECK(det.encoding == VNC_ENC_BINARY);
    CHECK(det.recovered == 1);
    CHECK_STR_EQ((const char *)det.validation.plain, "password");
}

static void test_absent_password_value(void) {
    /* UltraVNC writes eight zero bytes when no password is configured. */
    static const uint8_t zeros[8] = {0};
    vnc_detection det;

    CHECK(vnc_detect_value(zeros, 8, VNC_REG_BINARY, VNC_ENC_AUTO, &det) == VNC_DETECT_OK);
    CHECK(det.recovered == 0);
}

static void test_wrong_length_hex(void) {
    const char *value = "dbd83cfd727a14"; /* 7 bytes */
    vnc_detection det;

    CHECK(vnc_detect_value((const uint8_t *)value, strlen(value), VNC_REG_SZ,
                           VNC_ENC_AUTO, &det) == VNC_DETECT_ERR_LENGTH);
    CHECK(det.recovered == 0);
    CHECK(det.cipher_len == 7);
}

static void test_malformed_value(void) {
    const char *value = "zzz";
    vnc_detection det;

    CHECK(vnc_detect_value((const uint8_t *)value, strlen(value), VNC_REG_SZ,
                           VNC_ENC_AUTO, &det) != VNC_DETECT_OK);
    CHECK(det.recovered == 0);
}

static void test_empty_value(void) {
    vnc_detection det;
    CHECK(vnc_detect_value((const uint8_t *)"", 0, VNC_REG_SZ, VNC_ENC_AUTO, &det)
              == VNC_DETECT_ERR_EMPTY);
}

static void test_reg_sz_wrong_type(void) {
    /* A DWORD value is not a password; infer_registry_encoding must say so. */
    uint8_t dword[4] = {1, 0, 0, 0};
    vnc_detection det;

    CHECK(vnc_detect_value(dword, 4, VNC_REG_DWORD, VNC_ENC_AUTO, &det) != VNC_DETECT_OK);
    CHECK(det.recovered == 0);
}

static void test_two_block_hex(void) {
    const char *value = "db8ab02565e3b4c2f0e43164f6c2e373";
    vnc_detection det;

    CHECK(vnc_detect_value((const uint8_t *)value, strlen(value), VNC_REG_SZ,
                           VNC_ENC_AUTO, &det) == VNC_DETECT_OK);
    CHECK(det.cipher_len == 16);
    CHECK(det.recovered == 1);
    CHECK_STR_EQ((const char *)det.validation.plain, "abcdefgh12345678");
}

static void test_garbage_that_decrypts_is_rejected(void) {
    /* Random 8 bytes decrypt to control characters; the validator must say no. */
    const char *value = "0011223344556677";
    vnc_detection det;

    CHECK(vnc_detect_value((const uint8_t *)value, strlen(value), VNC_REG_SZ,
                           VNC_ENC_AUTO, &det) == VNC_DETECT_OK);
    CHECK(det.cipher_len == 8);
    CHECK(det.recovered == 0);
    CHECK(det.validation.confidence < VNC_CONFIDENCE_ACCEPT);
}

void test_detector(void) {
    RUN_TEST(test_hex_reg_sz);
    RUN_TEST(test_binary_reg_binary);
    RUN_TEST(test_absent_password_value);
    RUN_TEST(test_wrong_length_hex);
    RUN_TEST(test_malformed_value);
    RUN_TEST(test_empty_value);
    RUN_TEST(test_reg_sz_wrong_type);
    RUN_TEST(test_two_block_hex);
    RUN_TEST(test_garbage_that_decrypts_is_rejected);
}
