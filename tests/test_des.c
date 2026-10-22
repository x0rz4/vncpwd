#include "test.h"

#include "des.h"
#include "legacy_des.h"

#include <stdint.h>
#include <string.h>

static const uint8_t fixed_key[8] = {23, 82, 107, 6, 35, 78, 88, 7};

static void check_vector(const uint8_t plain[8], const char *hex_cipher) {
    uint8_t expect[8];
    uint8_t got[8];
    int i;

    for (i = 0; i < 8; i++) {
        unsigned v;
        sscanf(hex_cipher + i * 2, "%2x", &v);
        expect[i] = (uint8_t)v;
    }

    des_key(fixed_key, DES_MODE_ENCRYPT);
    des_block(plain, got);
    CHECK_MEM_EQ(got, expect, 8);

    des_key(fixed_key, DES_MODE_DECRYPT);
    des_block(expect, got);
    CHECK_MEM_EQ(got, plain, 8);
}

static void test_des_vectors(void) {
    static const uint8_t p_password[8] = {'p','a','s','s','w','o','r','d'};
    static const uint8_t p_digits[8]   = {'1','2','3','4','5','6','7','8'};
    static const uint8_t p_abc[8]      = {'a','b','c',0,0,0,0,0};
    static const uint8_t p_empty[8]    = {0,0,0,0,0,0,0,0};
    static const uint8_t p_bytes[8]    = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    static const uint8_t p_ff[8]       = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    static const uint8_t p_mypass[8]   = {'M','y','P','a','s','s','1','2'};

    /* Vector provenance: openssl enc -des-ecb -K e84ad660c4721ae0 -nopad */
    check_vector(p_password, "dbd83cfd727a1458");
    check_vector(p_digits,   "f0e43164f6c2e373");
    check_vector(p_abc,      "9c0a172d3482e122");
    check_vector(p_empty,    "5ab2cdc0badcaf13");
    check_vector(p_bytes,    "e94a5c1b0496539d");
    check_vector(p_ff,       "0f08059014763411");
    check_vector(p_mypass,   "3eb26c8473828fc4");
}

static void hex_to_bytes(const char *hex, uint8_t *out, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + i * 2, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void test_decrypt_single_block(void) {
    uint8_t cipher[8];
    vnc_des_result r;

    hex_to_bytes("dbd83cfd727a1458", cipher, 8);
    CHECK(vnc_des_decrypt(cipher, 8, &r) == VNC_DES_OK);
    CHECK(r.length == 8);
    CHECK(r.blocks == 1);
    CHECK_STR_EQ((const char *)r.plain, "password");
}

static void test_decrypt_short_password(void) {
    uint8_t cipher[8];
    vnc_des_result r;

    hex_to_bytes("9c0a172d3482e122", cipher, 8);
    CHECK(vnc_des_decrypt(cipher, 8, &r) == VNC_DES_OK);
    CHECK(r.length == 3);
    CHECK_STR_EQ((const char *)r.plain, "abc");
}

static void test_decrypt_empty_block(void) {
    uint8_t cipher[8];
    vnc_des_result r;

    hex_to_bytes("5ab2cdc0badcaf13", cipher, 8);
    CHECK(vnc_des_decrypt(cipher, 8, &r) == VNC_DES_OK);
    CHECK(r.length == 0);
}

static void test_decrypt_two_blocks(void) {
    uint8_t cipher[16];
    vnc_des_result r;

    hex_to_bytes("db8ab02565e3b4c2f0e43164f6c2e373", cipher, 16);
    CHECK(vnc_des_decrypt(cipher, 16, &r) == VNC_DES_OK);
    CHECK(r.length == 16);
    CHECK(r.blocks == 2);
    CHECK_STR_EQ((const char *)r.plain, "abcdefgh12345678");
}

static void test_reject_bad_length(void) {
    uint8_t buf[16];
    vnc_des_result r;

    memset(buf, 0, sizeof(buf));
    CHECK(vnc_des_decrypt(buf, 0, &r) == VNC_DES_ERR_LENGTH);
    CHECK(vnc_des_decrypt(buf, 7, &r) == VNC_DES_ERR_LENGTH);
    CHECK(vnc_des_decrypt(buf, 9, &r) == VNC_DES_ERR_LENGTH);
    CHECK(vnc_des_decrypt(buf, 15, &r) == VNC_DES_ERR_LENGTH);
    CHECK(vnc_des_decrypt(buf, 17, &r) == VNC_DES_ERR_LENGTH);
    CHECK(vnc_des_decrypt(NULL, 8, &r) == VNC_DES_ERR_NULL);
}

static void test_encrypt_roundtrip(void) {
    uint8_t cipher[16];
    uint8_t plain[VNC_MAX_PASSWORD];
    vnc_des_result r;
    int n;

    memcpy(plain, "abc", 3);
    n = vnc_des_encrypt(plain, 3, cipher, sizeof(cipher));
    CHECK(n == 8);
    CHECK(vnc_des_decrypt(cipher, (size_t)n, &r) == VNC_DES_OK);
    CHECK_STR_EQ((const char *)r.plain, "abc");

    memcpy(plain, "abcdefgh12345678", 16);
    n = vnc_des_encrypt(plain, 16, cipher, sizeof(cipher));
    CHECK(n == 16);
    CHECK(vnc_des_decrypt(cipher, (size_t)n, &r) == VNC_DES_OK);
    CHECK_STR_EQ((const char *)r.plain, "abcdefgh12345678");
}

static void test_encrypt_rejects_oversize(void) {
    uint8_t plain[VNC_MAX_PASSWORD + 1];
    uint8_t out[16];

    memset(plain, 'x', sizeof(plain));
    CHECK(vnc_des_encrypt(plain, sizeof(plain), out, sizeof(out)) == VNC_DES_ERR_LENGTH);
}

static void test_fixed_key_is_public_constant(void) {
    static const uint8_t expect[8] = {23, 82, 107, 6, 35, 78, 88, 7};
    CHECK_MEM_EQ(vnc_fixed_des_key, expect, 8);
}

void test_des(void) {
    RUN_TEST(test_des_vectors);
    RUN_TEST(test_decrypt_single_block);
    RUN_TEST(test_decrypt_short_password);
    RUN_TEST(test_decrypt_empty_block);
    RUN_TEST(test_decrypt_two_blocks);
    RUN_TEST(test_reject_bad_length);
    RUN_TEST(test_encrypt_roundtrip);
    RUN_TEST(test_encrypt_rejects_oversize);
    RUN_TEST(test_fixed_key_is_public_constant);
}
