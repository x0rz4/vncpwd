/*
 * Saved connection files.  These hold the credential a *viewer* used, which
 * is a different secret class from a server-side password even when the bytes
 * look identical.
 *
 *   RealVNC / TigerVNC / UltraVNC viewer:
 *     %APPDATA%\RealVNC\vncviewer4\*.vnc
 *     %APPDATA%\vnc\*.vnc
 *     %USERPROFILE%\.vnc\<name>.vnc
 *     ~/.vnc/<name>.vnc
 *     [Connection] Host=... Password=<hex>
 *
 *   Remmina:
 *     ~/.remmina/<name>.remmina
 *     [remmina] server=... password=<base64 of the hex string>
 *
 * Remmina's password field is base64 text *of the hex string*, i.e. it takes
 * two decoding steps.  The detector's auto mode tries hex first and base64
 * second; a base64 payload that happens to be valid hex is astronomically
 * unlikely, but the connection parser retries explicitly when the first
 * attempt does not yield a plausible password.
 */
#include "provider.h"
#include "detector.h"
#include "encoding.h"
#include "parsers.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    vnc_report *report;
    int         count;
} conn_scan_ctx;

/* Returns 1 when a credential was recorded. */
static int record_connection(vnc_report *report, const char *path, const char *product,
                             vnc_auth_type auth) {
    vnc_connection conn;
    vnc_detection det;
    vnc_credential *cred;
    char err[256];
    char location[VNC_MAX_STR];
    int rc;

    if (vnc_connection_parse(path, &conn, err, sizeof(err)) != 0) return 0;

    /* Only files that actually carry a credential are interesting. */
    if (conn.password[0] == 0) return 0;

    report->scanned_items++;
    snprintf(location, sizeof(location), "%s", path);

    rc = vnc_detect_value((const uint8_t *)conn.password, strlen(conn.password),
                          VNC_REG_NONE, VNC_ENC_HEX, &det);
    if (rc != VNC_DETECT_OK || !det.recovered) {
        rc = vnc_detect_value((const uint8_t *)conn.password, strlen(conn.password),
                              VNC_REG_NONE, VNC_ENC_BASE64, &det);
    }

    cred = vnc_report_add_credential(report);
    if (!cred) return 0;

    vnc_copy(cred->product, sizeof(cred->product), product);
    vnc_copy(cred->location, sizeof(cred->location), location);
    vnc_copy(cred->value, sizeof(cred->value), "Password");
    cred->encoding = det.encoding;
    cred->cipher_len = det.cipher_len;
    cred->auth = auth;
    cred->confidence = det.validation.confidence;

    if (conn.host[0]) {
        snprintf(cred->note, sizeof(cred->note), "saved connection to %s%s%s",
                 conn.host,
                 conn.port[0] ? ":" : "", conn.port);
    }

    if (rc == VNC_DETECT_OK && det.recovered) {
        cred->recovered = 1;
        cred->secret_len = det.validation.length;
        memcpy(cred->secret, det.validation.plain, cred->secret_len);
        cred->secret[cred->secret_len] = 0;
        vnc_report_add_issue(report, VNC_RISK_HIGH, "SAVED-VIEWER-CREDENTIAL",
                             product, location,
                             "the viewer saved the server password locally; it "
                             "decrypts with the public fixed DES key");
    } else {
        vnc_copy(cred->note, sizeof(cred->note),
                 "saved connection file holds a password that is not a classic "
                 "VNC DES blob (it may be protected by a viewer master password "
                 "or stored by a newer client)");
    }
    return 1;
}

static int on_vnc_file(void *vctx, const char *path) {
    conn_scan_ctx *ctx = (conn_scan_ctx *)vctx;
    ctx->count += record_connection(ctx->report, path, "VNC viewer",
                                    VNC_AUTH_VNC_PASSWORD);
    return 0;
}

static int on_remmina_file(void *vctx, const char *path) {
    conn_scan_ctx *ctx = (conn_scan_ctx *)vctx;
    vnc_connection conn;
    char err[256];

    if (vnc_connection_parse(path, &conn, err, sizeof(err)) != 0) return 0;
    /* Skip Remmina entries for other protocols. */
    if (conn.security[0] && !vnc_str_icontains(conn.security, "vnc")) return 0;
    ctx->count += record_connection(ctx->report, path, "Remmina",
                                    VNC_AUTH_VNC_PASSWORD);
    return 0;
}

/* Candidate directories for .vnc files, in order of likelihood. */
static const char *const vnc_file_dirs[] = {
    "%APPDATA%\\RealVNC\\vncviewer4",
    "%APPDATA%\\vnc",
    "%USERPROFILE%\\.vnc",
    "~/.vnc",
    "~/.tigervnc",
};

static int connections_scan(vnc_report *report, const void *opts) {
    conn_scan_ctx ctx;
    size_t i;

    (void)opts;
    ctx.report = report;
    ctx.count = 0;

    for (i = 0; i < VNC_ARRAY_LEN(vnc_file_dirs); i++) {
        char dir[1024];
        if (vnc_expand_path(vnc_file_dirs[i], dir, sizeof(dir)) < 0) continue;
        vnc_list_dir(dir, ".vnc", on_vnc_file, &ctx);
    }

    {
        char dir[1024];
        if (vnc_expand_path("~/.remmina", dir, sizeof(dir)) == 0) {
            vnc_list_dir(dir, ".remmina", on_remmina_file, &ctx);
        }
    }

    return ctx.count;
}

const vnc_provider vnc_provider_connection_files = {
    "connections",
    "Saved VNC connections",
    ".vnc and .remmina viewer connection files",
    connections_scan
};
