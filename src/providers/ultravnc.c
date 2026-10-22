/*
 * UltraVNC.  Unlike the others, the server keeps its configuration in an INI
 * file, not the registry:
 *
 *   %ProgramFiles%\UltraVNC\ultravnc.ini
 *   %ProgramFiles(x86)%\UltraVNC\ultravnc.ini
 *   <install dir>\ultravnc.ini for portable/older layouts
 *
 * Relevant keys (all in the unnamed section unless noted):
 *   passwd         primary password, hex of the 8-byte DES blob
 *   passwd2        view-only password, same format
 *   [admin] passwd administrative password
 *   MSLogonRequired=1   use MS-Logon (Windows accounts) instead
 *   NewMSLogon=1        MS-Logon II (DSM capable)
 *   DSMPlugin=...       encryption plugin; without one, the session is clear
 *   UseRegistry=1       settings are read from HKLM\SOFTWARE\ORL\WinVNC3
 *                       instead, so the INI may be stale or absent
 *   AllowLoopback, AuthRequired, LoopbackOnly ...
 *
 * vncpwd 0.2 only matched a key literally named "Password", which UltraVNC
 * never writes, so its UltraVNC support in the README never worked.
 */
#include "inspector.h"
#include "provider.h"
#include "detector.h"
#include "parsers.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const ultra_ini_dirs[] = {
    "C:\\Program Files\\UltraVNC",
    "C:\\Program Files (x86)\\UltraVNC",
    "%ProgramFiles%\\UltraVNC",
    "%ProgramFiles(x86)%\\UltraVNC",
    "%ProgramW6432%\\UltraVNC",
};

#define ULTRA_KEY "SOFTWARE\\ORL\\WinVNC3"

/* Values that hold a recoverable password. */
static const struct {
    const char *key;
    const char *label;
} ultra_ini_values[] = {
    { "passwd",  "primary password" },
    { "passwd2", "view-only password" },
};

static void record_ini_value(vnc_report *report, const char *ini_path, const char *section,
                             const char *key, const char *value) {
    vnc_detection det;
    vnc_credential *cred;
    char location[VNC_MAX_STR];
    int rc;

    if (section && section[0]) {
        snprintf(location, sizeof(location), "%s [%s] %s", ini_path, section, key);
    } else {
        snprintf(location, sizeof(location), "%s [%s]", ini_path, key);
    }

    rc = vnc_detect_value((const uint8_t *)value, strlen(value), VNC_REG_NONE,
                          VNC_ENC_HEX, &det);
    report->scanned_items++;

    cred = vnc_report_add_credential(report);
    if (!cred) return;

    vnc_copy(cred->product, sizeof(cred->product), "UltraVNC");
    vnc_copy(cred->location, sizeof(cred->location), location);
    vnc_copy(cred->value, sizeof(cred->value), key);
    cred->encoding = VNC_ENC_HEX;
    cred->reg_type = VNC_REG_NONE;
    cred->cipher_len = det.cipher_len;
    cred->auth = VNC_AUTH_VNC_PASSWORD;
    cred->confidence = det.validation.confidence;

    if (rc == VNC_DETECT_OK && det.recovered) {
        cred->recovered = 1;
        cred->secret_len = det.validation.length;
        memcpy(cred->secret, det.validation.plain, cred->secret_len);
        cred->secret[cred->secret_len] = 0;
        vnc_report_add_issue(report, VNC_RISK_HIGH, "RECOVERABLE-VNC-PASSWORD",
                             "UltraVNC", location,
                             "INI password uses the public fixed DES key; the file "
                             "is usually world-readable");
        if (cred->secret_len < 6) {
            vnc_report_add_issue(report, VNC_RISK_MEDIUM, "WEAK-PASSWORD", "UltraVNC",
                                 location, "password is shorter than 6 characters");
        }
    } else {
        vnc_copy(cred->note, sizeof(cred->note),
                 "value is present but does not decode to a classic VNC DES blob");
        if (rc == VNC_DETECT_ERR_LENGTH) {
            vnc_report_add_issue(report, VNC_RISK_INFO, "UNRECOGNIZED-FORMAT",
                                 "UltraVNC", location,
                                 "value is not 8 or 16 ciphertext bytes");
        }
    }
}

static void audit_ini(vnc_report *report, const char *ini_path) {
    char value[256];

    if (vnc_ini_get(ini_path, "", "MSLogonRequired", value, sizeof(value)) == 0 &&
        (vnc_str_ieq(value, "1") || vnc_str_ieq(value, "true"))) {
        vnc_report_add_issue(report, VNC_RISK_INFO, "AUTH-MSDOMAIN", "UltraVNC", ini_path,
                             "MS-Logon is enabled: clients authenticate against "
                             "Windows accounts, so passwd/passwd2 may be unused");
    }
    if (vnc_ini_get(ini_path, "", "UseRegistry", value, sizeof(value)) == 0 &&
        (vnc_str_ieq(value, "1") || vnc_str_ieq(value, "true"))) {
        vnc_report_add_issue(report, VNC_RISK_INFO, "CONFIG-IN-REGISTRY", "UltraVNC",
                             ini_path,
                             "UseRegistry=1: the live configuration is in "
                             "HKLM\\SOFTWARE\\ORL\\WinVNC3 and this INI may be stale");
    }
    if (vnc_ini_get(ini_path, "", "DSMPlugin", value, sizeof(value)) != 0 ||
        value[0] == 0) {
        vnc_report_add_issue(report, VNC_RISK_HIGH, "NO-ENCRYPTION-PLUGIN", "UltraVNC",
                             ini_path,
                             "no DSM plugin is configured: the VNC session, "
                             "including the login exchange, is unencrypted");
    }
    if (vnc_ini_get(ini_path, "", "AuthRequired", value, sizeof(value)) == 0 &&
        (vnc_str_ieq(value, "0") || vnc_str_ieq(value, "false"))) {
        vnc_report_add_issue(report, VNC_RISK_CRITICAL, "AUTH-NONE", "UltraVNC",
                             ini_path, "AuthRequired=0: authentication is disabled");
    }
}

/* Keys are looked up one at a time so the section handling stays explicit;
 * UltraVNC writes passwd/passwd2 in the unnamed section and an administrative
 * passwd in [admin]. */
static int ultravnc_scan_ini(vnc_report *report, const char *ini_path,
                             const char *const *sections, size_t nsections) {
    int added = 0;
    size_t i, s;
    char value[512];

    for (s = 0; s < nsections; s++) {
        for (i = 0; i < VNC_ARRAY_LEN(ultra_ini_values); i++) {
            if (vnc_ini_get(ini_path, sections[s], ultra_ini_values[i].key,
                            value, sizeof(value)) != 0) {
                continue;
            }
            if (value[0] == 0) continue;
            record_ini_value(report, ini_path, sections[s], ultra_ini_values[i].key, value);
            added++;
        }
    }
    return added;
}

static int ultravnc_scan(vnc_report *report, const void *opts) {
    size_t i;
    int added = 0;
    static const char *const sections[] = { "", "admin" };
    int found_any = 0;

    for (i = 0; i < VNC_ARRAY_LEN(ultra_ini_dirs); i++) {
        char path[1024];
        char expanded[1024];

        snprintf(path, sizeof(path), "%s\\ultravnc.ini", ultra_ini_dirs[i]);
        if (vnc_expand_path(path, expanded, sizeof(expanded)) < 0) continue;
        if (!vnc_file_exists(expanded)) continue;

        found_any = 1;
        added += ultravnc_scan_ini(report, expanded, sections,
                                    VNC_ARRAY_LEN(sections));
        audit_ini(report, expanded);
    }

    if (!found_any) {
        vnc_report_add_issue(report, VNC_RISK_INFO, "PRODUCT-NOT-FOUND", "UltraVNC", "",
                             "no ultravnc.ini found in the default install "
                             "locations; the product may not be installed, or it "
                             "may use UseRegistry=1");
    }

    /* When UltraVNC runs with UseRegistry=1 it keeps the same layout in the
     * registry, which is also the classic ORL path used by older VNC builds. */
    {
        int views[2] = { VNC_REG_VIEW_64, VNC_REG_VIEW_32 };
        int v;
        for (v = 0; v < 2; v++) {
            vnc_location loc;
            vnc_location loc2;

            memset(&loc, 0, sizeof(loc));
            loc.product = "UltraVNC";
            loc.hive = VNC_HIVE_LOCAL_MACHINE;
            loc.view = views[v];
            loc.path = ULTRA_KEY;
            loc.value = "passwd";
            loc.encoding = VNC_ENC_AUTO;
            loc.auth = VNC_AUTH_VNC_PASSWORD;
            loc.note = "UseRegistry=1 configuration";
            added += vnc_location_resolve(report, &loc) > 0;

            memset(&loc2, 0, sizeof(loc2));
            loc2 = loc;
            loc2.value = "passwd2";
            loc2.note = "UseRegistry=1 view-only password";
            added += vnc_location_resolve(report, &loc2) > 0;
        }
    }

    if (opts && ((const vnc_inspect_opts *)opts)->recursive) {
        added += vnc_provider_walk(report, "UltraVNC", VNC_HIVE_LOCAL_MACHINE,
                                   VNC_REG_VIEW_64, "SOFTWARE\\ORL", -1);
        added += vnc_provider_walk(report, "UltraVNC", VNC_HIVE_CURRENT_USER,
                                   VNC_REG_VIEW_DEFAULT, "Software\\ORL", -1);
    }

    return added;
}

const vnc_provider vnc_provider_ultravnc = {
    "ultravnc",
    "UltraVNC",
    "UltraVNC ultravnc.ini (passwd, passwd2, [admin]) and ORL registry fallback",
    ultravnc_scan
};
