#include "test.h"

#include "parsers.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int keys;
    int sections;
    char last_section[64];
    char password[128];
    char passwd[128];
    char host[128];
    int  saw_admin;
} collect_ctx;

static void on_section(void *vctx, const char *section) {
    collect_ctx *c = (collect_ctx *)vctx;
    c->sections++;
    snprintf(c->last_section, sizeof(c->last_section), "%s", section);
    if (strcmp(section, "admin") == 0) c->saw_admin = 1;
}

static void on_key(void *vctx, const char *section, const char *key, const char *value) {
    collect_ctx *c = (collect_ctx *)vctx;
    (void)section;
    c->keys++;
    if (vnc_str_ieq(key, "password")) snprintf(c->password, sizeof(c->password), "%s", value);
    if (vnc_str_ieq(key, "passwd")) snprintf(c->passwd, sizeof(c->passwd), "%s", value);
    if (vnc_str_ieq(key, "Host")) snprintf(c->host, sizeof(c->host), "%s", value);
}

static void parse(const char *text, collect_ctx *c) {
    vnc_ini_cb cb;
    char err[128];

    memset(c, 0, sizeof(*c));
    cb.on_section = on_section;
    cb.on_key = on_key;
    CHECK(vnc_ini_parse_buffer(text, strlen(text), &cb, c, err, sizeof(err)) == 0);
}

static void test_basic_parse(void) {
    collect_ctx c;
    parse(
        "; comment\n"
        "# another comment\n"
        "[Connection]\n"
        "Host=example.org:5900\n"
        "Password=dbd83cfd727a1458\n",
        &c);

    CHECK(c.sections == 1);
    CHECK_STR_EQ(c.last_section, "Connection");
    CHECK(c.keys == 2);
    CHECK_STR_EQ(c.host, "example.org:5900");
    CHECK_STR_EQ(c.password, "dbd83cfd727a1458");
}

static void test_crlf_and_whitespace(void) {
    collect_ctx c;
    parse(
        "[Connection]\r\n"
        "  Host = example.org:5900  \r\n"
        "  Password =   dbd83cfd727a1458 \r\n",
        &c);

    CHECK_STR_EQ(c.host, "example.org:5900");
    CHECK_STR_EQ(c.password, "dbd83cfd727a1458");
}

static void test_quoted_values(void) {
    collect_ctx c;
    parse("[Connection]\nPassword=\"dbd83cfd727a1458\"\n", &c);
    CHECK_STR_EQ(c.password, "dbd83cfd727a1458");
}

static void test_sections_and_admin(void) {
    collect_ctx c;
    parse(
        "passwd=1111111111111111\n"
        "[admin]\n"
        "passwd=2222222222222222\n",
        &c);

    CHECK(c.saw_admin == 1);
    CHECK(c.sections == 1);
    CHECK(c.keys == 2);
}

static void test_utf8_bom(void) {
    collect_ctx c;
    vnc_ini_cb cb;
    char err[128];
    const char *text = "\xef\xbb\xbf[Connection]\nHost=h:1\n";
    size_t len = strlen(text);

    memset(&c, 0, sizeof(c));
    cb.on_section = on_section;
    cb.on_key = on_key;
    /* vnc_ini_parse_buffer does not sniff encodings; the file reader strips the
     * BOM.  Parsing raw BOM bytes must not crash, and the section header after
     * the BOM is still not required to be recognised. */
    CHECK(vnc_ini_parse_buffer(text, len, &cb, &c, err, sizeof(err)) == 0);
    CHECK(c.host[0] == 0 || vnc_str_ieq(c.host, "h:1"));
}

static void test_lines_without_equals_ignored(void) {
    collect_ctx c;
    parse("[section]\nnot a pair\nalso not a pair\n", &c);
    CHECK(c.keys == 0);
}

static void test_value_with_equals(void) {
    collect_ctx c;
    parse("[Connection]\nHost=a=b=c\n", &c);
    CHECK_STR_EQ(c.host, "a=b=c");
}

static void write_file(const char *path, const char *text) {
    FILE *f = fopen(path, "wb");
    CHECK(f != NULL);
    if (!f) return;
    fwrite(text, 1, strlen(text), f);
    fclose(f);
}

static void test_ini_get_from_file(void) {
    const char *path = "test_ini_tmp.ini";
    char out[128];

    /* UltraVNC puts the server passwords in the unnamed section and an
     * administrative password in [admin].  The unnamed keys must come first:
     * everything after a section header belongs to that section. */
    write_file(path,
        "passwd=primaryhash\r\npasswd2=viewhash\r\nMSLogonRequired=1\r\n\r\n"
        "[admin]\r\npasswd=adminhash\r\n");

    CHECK(vnc_ini_get(path, "", "passwd", out, sizeof(out)) == 0);
    CHECK_STR_EQ(out, "primaryhash");
    CHECK(vnc_ini_get(path, "admin", "passwd", out, sizeof(out)) == 0);
    CHECK_STR_EQ(out, "adminhash");
    CHECK(vnc_ini_get(path, "", "passwd2", out, sizeof(out)) == 0);
    CHECK_STR_EQ(out, "viewhash");
    CHECK(vnc_ini_get(path, "", "MSLogonRequired", out, sizeof(out)) == 0);
    CHECK_STR_EQ(out, "1");
    CHECK(vnc_ini_get(path, "", "missing", out, sizeof(out)) != 0);

    remove(path);
}

static void test_ini_get_missing_file(void) {
    char out[16];
    CHECK(vnc_ini_get("does-not-exist.ini", "", "passwd", out, sizeof(out)) != 0);
}

void test_ini(void) {
    RUN_TEST(test_basic_parse);
    RUN_TEST(test_crlf_and_whitespace);
    RUN_TEST(test_quoted_values);
    RUN_TEST(test_sections_and_admin);
    RUN_TEST(test_utf8_bom);
    RUN_TEST(test_lines_without_equals_ignored);
    RUN_TEST(test_value_with_equals);
    RUN_TEST(test_ini_get_from_file);
    RUN_TEST(test_ini_get_missing_file);
}
