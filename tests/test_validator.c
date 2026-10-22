#include "test.h"

#include "format_validator.h"

#include <string.h>

static void hex_to_bytes(const char *hex, uint8_t *out, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + i * 2, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void test_accepts_password(void) {
    uint8_t cipher[8];
    vnc_validation v;

    hex_to_bytes("dbd83cfd727a1458", cipher, 8);
    CHECK(vnc_validate_ciphertext(cipher, 8, &v) == 0);
    CHECK(v.valid == 1);
    CHECK(v.length == 8);
    CHECK(v.printable_ratio == 100);
    CHECK(v.padding_ok == 1);
    CHECK(v.confidence >= VNC_CONFIDENCE_ACCEPT);
    CHECK_STR_EQ((const char *)v.plain, "password");
}

static void test_short_password_still_valid(void) {
    uint8_t cipher[8];
    vnc_validation v;

    hex_to_bytes("9c0a172d3482e122", cipher, 8);
    CHECK(vnc_validate_ciphertext(cipher, 8, &v) == 0);
    CHECK(v.length == 3);
    CHECK(v.valid == 1);
    CHECK(v.confidence >= VNC_CONFIDENCE_ACCEPT);
}

static void test_empty_block_is_not_a_password(void) {
    uint8_t cipher[8];
    vnc_validation v;

    hex_to_bytes("5ab2cdc0badcaf13", cipher, 8);
    CHECK(vnc_validate_ciphertext(cipher, 8, &v) == 0);
    CHECK(v.length == 0);
    CHECK(v.valid == 0);
    CHECK(v.confidence < VNC_CONFIDENCE_ACCEPT);
}

static void test_rejects_wrong_length(void) {
    uint8_t cipher[16];
    vnc_validation v;
    int len;

    memset(cipher, 0x41, sizeof(cipher));
    for (len = 0; len <= 16; len++) {
        if (len == 8 || len == 16) continue;
        CHECK(vnc_validate_ciphertext(cipher, (size_t)len, &v) == 0);
        CHECK(v.valid == 0);
        CHECK(v.reason != NULL);
    }
}

static void test_rejects_control_bytes(void) {
    static const uint8_t junk[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    vnc_validation v;

    CHECK(vnc_validate_plaintext(junk, 8, &v) == 0);
    CHECK(v.valid == 0);
    CHECK(v.confidence < 0.2);
    CHECK(v.reason != NULL);
}

static void test_embedded_nul_is_not_padding(void) {
    static const uint8_t embedded[8] = {'a', 'b', 0, 'c', 'd', 'e', 'f', 'g'};
    vnc_validation v;

    CHECK(vnc_validate_plaintext(embedded, 8, &v) == 0);
    CHECK(v.padding_ok == 0);
    CHECK(v.valid == 0);
}

static void test_confidence_bounds(void) {
    static const uint8_t pw[8] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
    vnc_validation v;

    CHECK(vnc_validate_plaintext(pw, 8, &v) == 0);
    CHECK(v.confidence >= 0.0 && v.confidence <= 1.0);
    CHECK(v.confidence >= VNC_CONFIDENCE_ACCEPT);
}

static void test_oversize_plaintext_rejected(void) {
    uint8_t big[VNC_MAX_PASSWORD + 4];
    vnc_validation v;

    memset(big, 'x', sizeof(big));
    CHECK(vnc_validate_plaintext(big, sizeof(big), &v) == 0);
    CHECK(v.valid == 0);
    CHECK(v.confidence == 0.0);
}

void test_validator(void) {
    RUN_TEST(test_accepts_password);
    RUN_TEST(test_short_password_still_valid);
    RUN_TEST(test_empty_block_is_not_a_password);
    RUN_TEST(test_rejects_wrong_length);
    RUN_TEST(test_rejects_control_bytes);
    RUN_TEST(test_embedded_nul_is_not_padding);
    RUN_TEST(test_confidence_bounds);
    RUN_TEST(test_oversize_plaintext_rejected);
}
