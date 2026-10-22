#include "test.h"

#include "report.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Read a stdio handle into a heap string.  Kept local because tests must not
 * depend on the tool's file helpers, which is what they are here to check. */
static char *slurp(FILE *f) {
    long len;
    char *buf;

    if (!f) return NULL;
    fflush(f);
    if (fseek(f, 0, SEEK_END) != 0) return NULL;
    len = ftell(f);
    if (len < 0) return NULL;
    if (fseek(f, 0, SEEK_SET) != 0) return NULL;

    buf = (char *)malloc((size_t)len + 1);
    if (!buf) return NULL;
    if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        return NULL;
    }
    buf[len] = 0;
    return buf;
}

static void add_sample(vnc_report *r, int with_secret) {
    vnc_credential *c = vnc_report_add_credential(r);
    CHECK(c != NULL);
    if (!c) return;
    snprintf(c->product, sizeof(c->product), "RealVNC");
    snprintf(c->location, sizeof(c->location), "SOFTWARE\\RealVNC\\vncserver");
    snprintf(c->value, sizeof(c->value), "Password");
    snprintf(c->hive, sizeof(c->hive), "HKEY_LOCAL_MACHINE");
    c->encoding = VNC_ENC_HEX;
    c->reg_type = 1;
    c->cipher_len = 8;
    c->auth = VNC_AUTH_VNC_PASSWORD;
    c->confidence = 0.95;
    if (with_secret) {
        memcpy(c->secret, "password", 8);
        c->secret[8] = 0;
        c->secret_len = 8;
        c->recovered = 1;
    }
}

static void test_redacted_by_default(void) {
    vnc_report r;
    FILE *f = tmpfile();
    char *out;

    vnc_report_init(&r, 0);
    add_sample(&r, 1);
    CHECK(vnc_report_write_json(&r, f) == 0);
    out = slurp(f);
    fclose(f);

    CHECK(out != NULL);
    if (!out) { vnc_report_free(&r); return; }
    CHECK(strstr(out, "\"secrets_included\": false") != NULL);
    CHECK(strstr(out, "\"password\": \"p***") != NULL);
    /* The raw secret must never appear in the redacted document. */
    CHECK(strstr(out, "\"password\": \"password\"") == NULL);
    free(out);
    vnc_report_free(&r);
}

static void test_show_includes_secret(void) {
    vnc_report r;
    FILE *f = tmpfile();
    char *out;

    vnc_report_init(&r, 1);
    add_sample(&r, 1);
    CHECK(vnc_report_write_json(&r, f) == 0);
    out = slurp(f);
    fclose(f);

    CHECK(out != NULL);
    if (out) {
        CHECK(strstr(out, "\"secrets_included\": true") != NULL);
        CHECK(strstr(out, "\"password\": \"password\"") != NULL);
    }
    free(out);
    vnc_report_free(&r);
}

static void test_json_escaping(void) {
    vnc_report r;
    FILE *f = tmpfile();
    char *out;
    vnc_credential *c;

    vnc_report_init(&r, 0);
    c = vnc_report_add_credential(&r);
    CHECK(c != NULL);
    if (c) snprintf(c->product, sizeof(c->product), "a\"b\\c\nd");
    CHECK(vnc_report_write_json(&r, f) == 0);
    out = slurp(f);
    fclose(f);

    CHECK(out != NULL);
    if (out) CHECK(strstr(out, "a\\\"b\\\\c\\nd") != NULL);
    free(out);
    vnc_report_free(&r);
}

static void test_text_redaction(void) {
    vnc_report r;
    FILE *f = tmpfile();
    char *out;

    vnc_report_init(&r, 0);
    add_sample(&r, 1);
    CHECK(vnc_report_write_text(&r, f) == 0);
    out = slurp(f);
    fclose(f);

    CHECK(out != NULL);
    if (out) {
        CHECK(strstr(out, "p***") != NULL);
        CHECK(strstr(out, "  password: password") == NULL);
        CHECK(strstr(out, "Use --show") != NULL);
    }
    free(out);
    vnc_report_free(&r);
}

static void test_csv_header_and_redaction(void) {
    vnc_report r;
    FILE *f = tmpfile();
    char *out;

    vnc_report_init(&r, 0);
    add_sample(&r, 1);
    CHECK(vnc_report_write_csv(&r, f) == 0);
    out = slurp(f);
    fclose(f);

    CHECK(out != NULL);
    if (out) {
        CHECK(strncmp(out, "product,hive,location,value,encoding,auth", 41) == 0);
        CHECK(strstr(out, "\"p***") != NULL);
        CHECK(strstr(out, "\"password\"") == NULL);
    }
    free(out);
    vnc_report_free(&r);
}

static void test_max_risk(void) {
    vnc_report r;

    vnc_report_init(&r, 0);
    CHECK(vnc_report_max_risk(&r) == VNC_RISK_INFO);
    CHECK(vnc_report_add_issue(&r, VNC_RISK_MEDIUM, "X", "P", "", "m") == 0);
    CHECK(vnc_report_max_risk(&r) == VNC_RISK_MEDIUM);
    CHECK(vnc_report_add_issue(&r, VNC_RISK_CRITICAL, "Y", "P", "", "c") == 0);
    CHECK(vnc_report_max_risk(&r) == VNC_RISK_CRITICAL);
    CHECK(r.issue_count == 2);
    vnc_report_free(&r);
}

static void test_capacity_limit(void) {
    vnc_report r;
    int i;

    vnc_report_init(&r, 0);
    for (i = 0; i < VNC_REPORT_MAX_FINDINGS + 10; i++) {
        if (!vnc_report_add_credential(&r)) break;
    }
    CHECK(r.cred_count == VNC_REPORT_MAX_FINDINGS);
    vnc_report_free(&r);
}

static void test_mask_secret(void) {
    char out[64];

    vnc_mask_secret("password", 8, 0, out, sizeof(out));
    CHECK(strncmp(out, "p***", 4) == 0);
    CHECK(strstr(out, "len 8") != NULL);

    vnc_mask_secret("password", 8, 1, out, sizeof(out));
    CHECK_STR_EQ(out, "password");

    vnc_mask_secret("", 0, 0, out, sizeof(out));
    CHECK_STR_EQ(out, "(empty)");
}

void test_report(void) {
    RUN_TEST(test_redacted_by_default);
    RUN_TEST(test_show_includes_secret);
    RUN_TEST(test_json_escaping);
    RUN_TEST(test_text_redaction);
    RUN_TEST(test_csv_header_and_redaction);
    RUN_TEST(test_max_risk);
    RUN_TEST(test_capacity_limit);
    RUN_TEST(test_mask_secret);
}
