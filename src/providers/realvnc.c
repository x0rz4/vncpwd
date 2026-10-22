/*
 * RealVNC / VNC Ltd.
 *
 * Registry layout (under the product's own key, not ORL):
 *   HKLM\SOFTWARE\RealVNC\vncserver            Password, Authentication,
 *                                              Encryption, SecurityTypes
 *   HKLM\SOFTWARE\RealVNC\vncserver4           same, 4.x naming
 *   HKLM\SOFTWARE\RealVNC\VNC Server           installer-created alias
 *   HKCU\Software\RealVNC\vncserver            user overrides
 *   HKLM\SOFTWARE\Policies\RealVNC\vncserver   group policy overrides
 *
 * Parameter storage notes, verified against RealVNC's own documentation:
 *   - Password is REG_SZ containing lowercase hex of the 8-byte DES blob
 *     (older 4.x builds used REG_BINARY).
 *   - SecurityTypes is NOT a numeric bitmask: it is a REG_SZ comma separated
 *     list of names such as "None", "VncAuth", "RA2", "RA2ne".
 *   - RealVNC 5.3 deprecated SecurityTypes in favour of two REG_SZ values,
 *     Authentication (VncAuth | SystemAuth | InteractiveSystemAuth |
 *     SingleSignOn) and Encryption (AlwaysOn | AlwaysOff | PreferOn | ...).
 *
 * RealVNC 7/8 in SystemAuth or SingleSignOn mode stores no VNC password at
 * all.  When that is what the configuration says, the tool reports it rather
 * than presenting an absent value as a missing password.
 */
#include "inspector.h"
#include "provider.h"
#include "registry.h"
#include "util.h"

#include <string.h>

static const char *const realvnc_keys[] = {
    "SOFTWARE\\RealVNC\\vncserver",
    "SOFTWARE\\RealVNC\\vncserver4",
    "SOFTWARE\\RealVNC\\VNC Server",
};

/* Case-insensitive search for a whole comma separated token. */
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

static void audit_modern(vnc_report *report, vnc_hive hive, int view, const char *path) {
    char auth[128], enc[128], location[VNC_MAX_STR];
    char err[256];
    int have_auth = 0, have_enc = 0;

    have_auth = vnc_reg_read_string(hive, view, path, "Authentication",
                                    auth, sizeof(auth), err, sizeof(err)) == 0;
    have_enc = vnc_reg_read_string(hive, view, path, "Encryption",
                                   enc, sizeof(enc), err, sizeof(err)) == 0;

    snprintf(location, sizeof(location), "%s\\Authentication", path);

    if (have_auth) {
        if (vnc_str_ieq(auth, "SystemAuth") || vnc_str_ieq(auth, "InteractiveSystemAuth")) {
            vnc_report_add_issue(report, VNC_RISK_INFO, "AUTH-SYSTEM", "RealVNC", location,
                                 "Windows account authentication is in use; no VNC "
                                 "password is stored for this server");
        } else if (vnc_str_ieq(auth, "SingleSignOn")) {
            vnc_report_add_issue(report, VNC_RISK_INFO, "AUTH-SSO", "RealVNC", location,
                                 "RealVNC Connect cloud identity (SSO); credentials "
                                 "are not present locally");
        } else if (vnc_str_ieq(auth, "VncAuth")) {
            vnc_report_add_issue(report, VNC_RISK_HIGH, "AUTH-VNC-PASSWORD-ONLY",
                                 "RealVNC", location,
                                 "VncAuth alone: the password is capped at 8 "
                                 "characters and is not a credential for any "
                                 "other system");
        } else {
            vnc_report_add_issue(report, VNC_RISK_MEDIUM, "AUTH-UNKNOWN-VALUE",
                                 "RealVNC", location,
                                 "Authentication parameter has an unrecognized value");
        }
    }

    if (have_enc) {
        snprintf(location, sizeof(location), "%s\\Encryption", path);
        if (vnc_str_ieq(enc, "AlwaysOff") || vnc_str_ieq(enc, "Off")) {
            vnc_report_add_issue(report, VNC_RISK_HIGH, "ENCRYPTION-OFF", "RealVNC",
                                 location,
                                 "Encryption is disabled: the session and the "
                                 "authentication exchange are in cleartext");
        } else if (vnc_str_ieq(enc, "PreferOff")) {
            vnc_report_add_issue(report, VNC_RISK_MEDIUM, "ENCRYPTION-PREFER-OFF",
                                 "RealVNC", location,
                                 "encryption is preferred off, so unencrypted "
                                 "sessions are the default");
        }
    }
}

static void audit_legacy(vnc_report *report, vnc_hive hive, int view, const char *path) {
    char types[256], location[VNC_MAX_STR];
    char err[256];

    if (vnc_reg_read_string(hive, view, path, "SecurityTypes", types, sizeof(types),
                            err, sizeof(err)) != 0) {
        return;
    }
    snprintf(location, sizeof(location), "%s\\SecurityTypes", path);

    if (list_has(types, "None")) {
        vnc_report_add_issue(report, VNC_RISK_CRITICAL, "AUTH-NONE", "RealVNC", location,
                             "SecurityTypes includes None: the server accepts "
                             "unauthenticated connections");
    }
    if (list_has(types, "VncAuth")) {
        vnc_report_add_issue(report, VNC_RISK_HIGH, "AUTH-VNC-PASSWORD-ONLY", "RealVNC",
                             location,
                             "SecurityTypes includes VncAuth: the connection may "
                             "negotiate the 8 character password scheme");
    }
    if (!list_has(types, "RA2") && !list_has(types, "RA2ne") &&
        !list_has(types, "RA2_256") && !list_has(types, "TLSVnc") &&
        !list_has(types, "X509Vnc") && !list_has(types, "TLSNone") &&
        !list_has(types, "X509None")) {
        vnc_report_add_issue(report, VNC_RISK_MEDIUM, "NO-STRONG-AUTH", "RealVNC", location,
                             "no TLS, RA2 or X.509 security type is configured");
    }
}

static int is_deep(const void *opts) {
    const vnc_inspect_opts *o = (const vnc_inspect_opts *)opts;
    return o && o->recursive;
}

static int realvnc_scan(vnc_report *report, const void *opts) {
    size_t i;
    int added = 0;
    int views[2] = { VNC_REG_VIEW_64, VNC_REG_VIEW_32 };
    int v;

    for (i = 0; i < VNC_ARRAY_LEN(realvnc_keys); i++) {
        for (v = 0; v < 2; v++) {
            vnc_location loc;
            memset(&loc, 0, sizeof(loc));
            loc.product = "RealVNC";
            loc.hive = VNC_HIVE_LOCAL_MACHINE;
            loc.view = views[v];
            loc.path = realvnc_keys[i];
            loc.value = "Password";
            loc.encoding = VNC_ENC_AUTO;
            loc.auth = VNC_AUTH_VNC_PASSWORD;
            added += vnc_location_resolve(report, &loc) > 0;

            audit_modern(report, VNC_HIVE_LOCAL_MACHINE, views[v], realvnc_keys[i]);
            audit_legacy(report, VNC_HIVE_LOCAL_MACHINE, views[v], realvnc_keys[i]);
        }
        if (is_deep(opts)) {
            added += vnc_provider_walk(report, "RealVNC", VNC_HIVE_LOCAL_MACHINE,
                                       VNC_REG_VIEW_64, realvnc_keys[i], -1);
        }
    }

    /* RealVNC also honours a user-level override key. */
    {
        vnc_location loc;
        memset(&loc, 0, sizeof(loc));
        loc.product = "RealVNC";
        loc.hive = VNC_HIVE_CURRENT_USER;
        loc.path = "Software\\RealVNC\\vncserver";
        loc.value = "Password";
        loc.encoding = VNC_ENC_AUTO;
        loc.auth = VNC_AUTH_VNC_PASSWORD;
        added += vnc_location_resolve(report, &loc) > 0;
    }

    return added;
}

const vnc_provider vnc_provider_realvnc = {
    "realvnc",
    "RealVNC",
    "RealVNC 4-8 server keys, Authentication/Encryption and SecurityTypes audit",
    realvnc_scan
};
