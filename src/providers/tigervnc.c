/*
 * TigerVNC for Windows.
 *
 *   HKCU\Software\TigerVNC\WinVNC4      Password, SecurityTypes
 *   HKLM\SOFTWARE\TigerVNC\WinVNC4      Password, SecurityTypes
 *
 * Password is hex REG_SZ (or REG_BINARY in older builds).  SecurityTypes is a
 * REG_SZ comma separated list -- "VeNCrypt,VncAuth" etc. -- not a bitmask;
 * valid names are None, VncAuth, Plain, TLSNone, TLSVnc, TLSPlain, X509None,
 * X509Vnc, X509Plain, RA2, RA2ne, RA2_256, RA2ne_256.
 *
 * RA2/RA2_256 (TigerVNC 1.13+) and the VeNCrypt types change how the
 * password crosses the wire.  They do not change the local store, so the
 * Password value remains recoverable with the public key when present.
 */
#include "inspector.h"
#include "provider.h"
#include "registry.h"
#include "util.h"

#include <string.h>

#define TIGERVNC_KEY_CU "Software\\TigerVNC\\WinVNC4"
#define TIGERVNC_KEY_LM "SOFTWARE\\TigerVNC\\WinVNC4"

static int token_eq(const char *start, size_t len, const char *token) {
    size_t tlen = strlen(token);
    size_t i;
    if (len != tlen) return 0;
    for (i = 0; i < len; i++) {
        char a = start[i], b = token[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return 1;
}

static int list_has(const char *list, const char *token) {
    const char *p = list;
    while (*p) {
        const char *start, *end;
        while (*p == ' ' || *p == ',' || *p == ';') p++;
        start = p;
        while (*p && *p != ',' && *p != ';') p++;
        end = p;
        while (end > start && end[-1] == ' ') end--;
        if (token_eq(start, (size_t)(end - start), token)) return 1;
    }
    return 0;
}

static void audit_security_types(vnc_report *report, vnc_hive hive, int view,
                                 const char *path) {
    char types[256], location[VNC_MAX_STR];
    char err[256];

    if (vnc_reg_read_string(hive, view, path, "SecurityTypes", types, sizeof(types),
                            err, sizeof(err)) != 0) {
        return;
    }
    snprintf(location, sizeof(location), "%s\\SecurityTypes", path);

    if (list_has(types, "None")) {
        vnc_report_add_issue(report, VNC_RISK_CRITICAL, "AUTH-NONE", "TigerVNC", location,
                             "SecurityTypes includes None: unauthenticated "
                             "connections are accepted");
    }
    if (list_has(types, "VncAuth")) {
        vnc_report_add_issue(report, VNC_RISK_HIGH, "AUTH-VNC-PASSWORD-ONLY", "TigerVNC",
                             location,
                             "SecurityTypes includes VncAuth: the weakest offered "
                             "type may be negotiated, and it carries no encryption");
    }
    if (list_has(types, "Plain") || list_has(types, "TLSPlain") ||
        list_has(types, "X509Plain")) {
        vnc_report_add_issue(report, VNC_RISK_MEDIUM, "AUTH-PLAIN", "TigerVNC", location,
                             "a Plain security type is enabled: the user name and "
                             "password are sent inside the session");
    }
    if (!list_has(types, "RA2") && !list_has(types, "RA2ne") &&
        !list_has(types, "RA2_256") && !list_has(types, "RA2ne_256") &&
        !list_has(types, "TLSVnc") && !list_has(types, "X509Vnc") &&
        !list_has(types, "VeNCrypt")) {
        vnc_report_add_issue(report, VNC_RISK_MEDIUM, "NO-STRONG-AUTH", "TigerVNC",
                             location,
                             "no RA2, RA2_256 or VeNCrypt TLS type is configured");
    }
}

static int tigervnc_scan(vnc_report *report, const void *opts) {
    int added = 0;
    int views[2] = { VNC_REG_VIEW_DEFAULT, VNC_REG_VIEW_64 };
    int v;

    (void)opts;

    for (v = 0; v < 2; v++) {
        vnc_location loc;
        memset(&loc, 0, sizeof(loc));
        loc.product = "TigerVNC";
        loc.hive = VNC_HIVE_CURRENT_USER;
        loc.view = views[v];
        loc.path = TIGERVNC_KEY_CU;
        loc.value = "Password";
        loc.encoding = VNC_ENC_AUTO;
        loc.auth = VNC_AUTH_VNC_PASSWORD;
        loc.note = "local password store";
        added += vnc_location_resolve(report, &loc) > 0;
        audit_security_types(report, VNC_HIVE_CURRENT_USER, views[v], TIGERVNC_KEY_CU);

        loc.hive = VNC_HIVE_LOCAL_MACHINE;
        loc.path = TIGERVNC_KEY_LM;
        added += vnc_location_resolve(report, &loc) > 0;
        audit_security_types(report, VNC_HIVE_LOCAL_MACHINE, views[v], TIGERVNC_KEY_LM);
    }

    if (opts && ((const vnc_inspect_opts *)opts)->recursive) {
        added += vnc_provider_walk(report, "TigerVNC", VNC_HIVE_CURRENT_USER,
                                   VNC_REG_VIEW_DEFAULT, TIGERVNC_KEY_CU, -1);
        added += vnc_provider_walk(report, "TigerVNC", VNC_HIVE_LOCAL_MACHINE,
                                   VNC_REG_VIEW_64, TIGERVNC_KEY_LM, -1);
    }
    return added;
}

const vnc_provider vnc_provider_tigervnc = {
    "tigervnc",
    "TigerVNC",
    "TigerVNC WinVNC4 keys, including RA2 / VeNCrypt SecurityTypes audit",
    tigervnc_scan
};
