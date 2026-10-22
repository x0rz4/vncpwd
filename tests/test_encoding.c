#include "test.h"

#include "encoding.h"

#include <string.h>

static void test_hex_decode(void) {
    uint8_t out[16];
    size_t n;

    n = vnc_hex_decode("dbd83cfd727a1458", 16, out, sizeof(out));
    CHECK(n == 8);
    CHECK(out[0] == 0xdb && out[7] == 0x58);

    n = vnc_hex_decode("DBD83CFD727A1458", 16, out, sizeof(out));
    CHECK(n == 8);
    CHECK(out[0] == 0xdb);
}

static void test_hex_decode_rejects_malformed(void) {
    uint8_t out[16];

    CHECK(vnc_hex_decode("dbd83cfd727a145", 15, out, sizeof(out)) == 0); /* odd */
    CHECK(vnc_hex_decode("dbd83cfd727a145z", 16, out, sizeof(out)) == 0); /* bad nibble */
    CHECK(vnc_hex_decode("", 0, out, sizeof(out)) == 0);
    CHECK(vnc_hex_decode("dbd83cfd727a1458", 16, out, 4) == 0); /* too small */
}

static void test_hex_is_valid(void) {
    CHECK(vnc_hex_is_valid("dbd83cfd727a1458", 16) == 1);
    CHECK(vnc_hex_is_valid("dbd83cfd727a145", 15) == 0);
    CHECK(vnc_hex_is_valid("dbd83cfd727a1458 ", 17) == 0);
    CHECK(vnc_hex_is_valid("", 0) == 0);
}

static void test_base64_decode(void) {
    uint8_t out[64];
    size_t n;

    /* "password" */
    n = vnc_base64_decode("cGFzc3dvcmQ=", 12, out, sizeof(out));
    CHECK(n == 8);
    CHECK(memcmp(out, "password", 8) == 0);

    /* Unpadded input is not a complete base64 group, so it is rejected
     * rather than guessed at.  Callers that know the payload is unpadded
     * must pad it themselves. */
    n = vnc_base64_decode("cGFzc3dvcmQ", 11, out, sizeof(out));
    CHECK(n == 0);

    /* An unpadded string whose length is already a multiple of four and
     * carries no leftover bits is accepted (6 bytes from 8 characters). */
    n = vnc_base64_decode("cGFzc3dv", 8, out, sizeof(out));
    CHECK(n == 6);
    CHECK(memcmp(out, "passwo", 6) == 0);
}

static void test_base64_rejects_garbage(void) {
    uint8_t out[32];
    CHECK(vnc_base64_decode("!!!!", 4, out, sizeof(out)) == 0);
    CHECK(vnc_base64_decode("cGFzc3dvcmQ=x", 13, out, sizeof(out)) == 0);
    CHECK(vnc_base64_decode("cGFzc3dvcmQ==", 13, out, sizeof(out)) == 0);
}

/*
 * Remmina stores base64 of the hex string.  Decoding once yields ASCII hex,
 * which the caller then decodes again.  This test fixes that two-step shape.
 */
static void test_remmina_double_decode(void) {
    uint8_t stage1[64];
    uint8_t stage2[16];
    size_t n1, n2;

    /* base64("dbd83cfd727a1458") */
    n1 = vnc_base64_decode("ZGJkODNjZmQ3MjdhMTQ1OA==", 24, stage1, sizeof(stage1));
    CHECK(n1 == 16);
    CHECK(memcmp(stage1, "dbd83cfd727a1458", 16) == 0);

    n2 = vnc_hex_decode((const char *)stage1, n1, stage2, sizeof(stage2));
    CHECK(n2 == 8);
    CHECK(stage2[0] == 0xdb);
}

static void test_auto_detect(void) {
    uint8_t out[16];

    /* Auto mode must prefer the textual reading: 16 characters is two DES
     * blocks in hex, not 16 raw bytes.  That ambiguity is what vncpwd 0.2
     * got wrong. */
    CHECK(vnc_decode_ciphertext("dbd83cfd727a1458", 16, VNC_ENC_AUTO,
                                out, sizeof(out)) == 8);
    CHECK(vnc_decode_ciphertext("dbd83cfd727a1458", 16, VNC_ENC_HEX,
                                out, sizeof(out)) == 8);
    CHECK(vnc_decode_ciphertext("dbd83cfd727a1458", 16, VNC_ENC_BINARY,
                                out, sizeof(out)) == 16);

    /* Not valid hex or base64, but exactly 8 bytes: raw ciphertext. */
    CHECK(vnc_decode_ciphertext("\xdb\xd8\x3c\xfd\x72\x7a\x14\x58", 8,
                                VNC_ENC_AUTO, out, sizeof(out)) == 8);
}

static void test_encoding_names(void) {
    vnc_encoding enc;

    CHECK_STR_EQ(vnc_encoding_name(VNC_ENC_HEX), "hex");
    CHECK_STR_EQ(vnc_encoding_name(VNC_ENC_BINARY), "binary");
    CHECK_STR_EQ(vnc_encoding_name(VNC_ENC_BASE64), "base64");
    CHECK(vnc_encoding_parse("HEX", &enc) == 0 && enc == VNC_ENC_HEX);
    CHECK(vnc_encoding_parse("Base64", &enc) == 0 && enc == VNC_ENC_BASE64);
    CHECK(vnc_encoding_parse("nonsense", &enc) == -1);
}

void test_encoding(void) {
    RUN_TEST(test_hex_decode);
    RUN_TEST(test_hex_decode_rejects_malformed);
    RUN_TEST(test_hex_is_valid);
    RUN_TEST(test_base64_decode);
    RUN_TEST(test_base64_rejects_garbage);
    RUN_TEST(test_remmina_double_decode);
    RUN_TEST(test_auto_detect);
    RUN_TEST(test_encoding_names);
}
