#include "test.h"

#include "parsers.h"
#include "encoding.h"

#include <stdio.h>
#include <string.h>

static void write_file(const char *path, const char *text) {
    FILE *f = fopen(path, "wb");
    CHECK(f != NULL);
    if (!f) return;
    fwrite(text, 1, strlen(text), f);
    fclose(f);
}

static void test_vnc_connection_file(void) {
    const char *path = "test_conn_tmp.vnc";
    vnc_connection conn;
    char err[128];

    write_file(path,
        "[Connection]\r\n"
        "Host=192.0.2.10:5901\r\n"
        "Password=dbd83cfd727a1458\r\n"
        "SecurityTypes=VncAuth\r\n");

    CHECK(vnc_connection_parse(path, &conn, err, sizeof(err)) == 0);
    CHECK_STR_EQ(conn.host, "192.0.2.10");
    CHECK_STR_EQ(conn.port, "5901");
    CHECK_STR_EQ(conn.password, "dbd83cfd727a1458");
    CHECK_STR_EQ(conn.security, "VncAuth");
    remove(path);
}

static void test_remmina_file(void) {
    const char *path = "test_conn_tmp.remmina";
    vnc_connection conn;
    char err[128];

    write_file(path,
        "[remmina]\r\n"
        "protocol=VNC\r\n"
        "server=203.0.113.5:5900\r\n"
        "password=ZGJkODNjZmQ3MjdhMTQ1OA==\r\n");

    CHECK(vnc_connection_parse(path, &conn, err, sizeof(err)) == 0);
    CHECK_STR_EQ(conn.host, "203.0.113.5");
    CHECK_STR_EQ(conn.port, "5900");
    CHECK_STR_EQ(conn.security, "VNC");
    CHECK_STR_EQ(conn.password, "ZGJkODNjZmQ3MjdhMTQ1OA==");
    remove(path);
}

static void test_host_without_port(void) {
    const char *path = "test_conn_tmp.vnc";
    vnc_connection conn;
    char err[128];

    write_file(path, "[Connection]\nHost=vnc.example.com\nPassword=00\n");
    CHECK(vnc_connection_parse(path, &conn, err, sizeof(err)) == 0);
    CHECK_STR_EQ(conn.host, "vnc.example.com");
    CHECK_STR_EQ(conn.port, "");
    remove(path);
}

static void test_missing_password_is_empty(void) {
    const char *path = "test_conn_tmp.vnc";
    vnc_connection conn;
    char err[128];

    write_file(path, "[Connection]\nHost=example.org:5900\n");
    CHECK(vnc_connection_parse(path, &conn, err, sizeof(err)) == 0);
    CHECK(conn.password[0] == 0);
    CHECK_STR_EQ(conn.host, "example.org");
    remove(path);
}

static void test_remmina_password_two_step_decode(void) {
    uint8_t step1[64];
    uint8_t step2[16];
    size_t n1, n2;

    n1 = vnc_base64_decode("ZGJkODNjZmQ3MjdhMTQ1OA==", 24, step1, sizeof(step1));
    CHECK(n1 == 16);
    n2 = vnc_hex_decode((const char *)step1, n1, step2, sizeof(step2));
    CHECK(n2 == 8);
    CHECK(step2[0] == 0xdb && step2[7] == 0x58);
}

void test_connection(void) {
    RUN_TEST(test_vnc_connection_file);
    RUN_TEST(test_remmina_file);
    RUN_TEST(test_host_without_port);
    RUN_TEST(test_missing_password_is_empty);
    RUN_TEST(test_remmina_password_two_step_decode);
}
