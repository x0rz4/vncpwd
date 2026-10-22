/*
 * TightVNC 2.x for Windows.
 *
 *   HKCU\Software\TightVNC\Server  Password, PasswordViewOnly, RfbPort,
 *                                  UseVncAuthentication, UseUnixLogon
 *   HKLM\Software\TightVNC\Server  same, for service mode
 *
 * Password and PasswordViewOnly are 8-byte REG_BINARY blobs (newer builds)
 * or hex REG_SZ (older builds).  There is no "Control" password in TightVNC;
 * the read-only credential is PasswordViewOnly.
 */
#include "inspector.h"
#include "provider.h"
#include "registry.h"
#include "util.h"

#include <string.h>

static const struct {
    const char *key;
    const char *value;
    vnc_auth_type auth;
    const char *note;
} tightvnc_values[] = {
    { "Software\\TightVNC\\Server", "Password", VNC_AUTH_VNC_PASSWORD,
      "primary password" },
    { "Software\\TightVNC\\Server", "PasswordViewOnly", VNC_AUTH_VNC_PASSWORD,
      "view-only password" },
};

static int tightvnc_scan(vnc_report *report, const void *opts) {
    size_t i;
    int added = 0;
    int views[2] = { VNC_REG_VIEW_DEFAULT, VNC_REG_VIEW_64 };

    for (i = 0; i < VNC_ARRAY_LEN(tightvnc_values); i++) {
        vnc_location loc;
        int v;

        for (v = 0; v < 2; v++) {
            memset(&loc, 0, sizeof(loc));
            loc.product = "TightVNC";
            loc.hive = (v == 0) ? VNC_HIVE_CURRENT_USER : VNC_HIVE_LOCAL_MACHINE;
            loc.view = views[v];
            loc.path = tightvnc_values[i].key;
            loc.value = tightvnc_values[i].value;
            loc.encoding = VNC_ENC_AUTO;
            loc.auth = tightvnc_values[i].auth;
            loc.note = tightvnc_values[i].note;
            added += vnc_location_resolve(report, &loc) > 0;
        }
    }

    if (opts && ((const vnc_inspect_opts *)opts)->recursive) {
        added += vnc_provider_walk(report, "TightVNC", VNC_HIVE_CURRENT_USER,
                                   VNC_REG_VIEW_DEFAULT, "Software\\TightVNC", -1);
        added += vnc_provider_walk(report, "TightVNC", VNC_HIVE_LOCAL_MACHINE,
                                   VNC_REG_VIEW_64, "Software\\TightVNC", -1);
    }
    return added;
}

const vnc_provider vnc_provider_tightvnc = {
    "tightvnc",
    "TightVNC",
    "TightVNC 2.x Server keys in HKCU and HKLM",
    tightvnc_scan
};
