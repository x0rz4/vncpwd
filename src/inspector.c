#include "inspector.h"
#include "detector.h"
#include "encoding.h"
#include "parsers.h"
#include "provider.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void add_literal_credential(vnc_report *report, const uint8_t *data, size_t len,
                                   vnc_encoding hint, const char *label, uint32_t reg_type) {
    vnc_detection det;
    vnc_credential *cred;
    int rc = vnc_detect_value(data, len, reg_type, hint, &det);

    cred = vnc_report_add_credential(report);
    if (!cred) return;

    vnc_copy(cred->product, sizeof(cred->product), "command line");
    vnc_copy(cred->location, sizeof(cred->location), label);
    vnc_copy(cred->value, sizeof(cred->value), "");
    cred->encoding = det.encoding;
    cred->reg_type = reg_type;
    cred->cipher_len = det.cipher_len;
    cred->auth = VNC_AUTH_VNC_PASSWORD;
    cred->confidence = det.validation.confidence;

    if (rc == VNC_DETECT_OK && det.recovered) {
        cred->recovered = 1;
        cred->secret_len = det.validation.length;
        memcpy(cred->secret, det.validation.plain, cred->secret_len);
        cred->secret[cred->secret_len] = 0;
        vnc_report_add_issue(report, VNC_RISK_INFO, "DECRYPTED-INPUT",
                             "command line", label,
                             "input decrypted with the public fixed VNC DES key");
        if (cred->secret_len < 6) {
            vnc_report_add_issue(report, VNC_RISK_MEDIUM, "WEAK-PASSWORD",
                                 "command line", label,
                                 "password is shorter than 6 characters");
        }
    } else {
        vnc_copy(cred->note, sizeof(cred->note), det.reason ? det.reason
                                                            : "input is not a VNC DES blob");
        if (det.cipher_len && det.cipher_len != 8 && det.cipher_len != 16) {
            vnc_report_add_issue(report, VNC_RISK_INFO, "UNRECOGNIZED-FORMAT",
                                 "command line", label,
                                 "input does not decode to 8 or 16 ciphertext bytes");
        }
    }
}

int vnc_inspect_literal(const vnc_inspect_opts *opts, vnc_report *report) {
    if (!opts || !report) return -1;

    if (opts->hex) {
        size_t len = strlen(opts->hex);
        vnc_encoding hint = VNC_ENC_HEX;
        const char *hex = opts->hex;
        size_t hexlen = len;

        /* Tolerate "0x" and embedded separators. */
        if (hexlen > 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
            hex += 2;
            hexlen -= 2;
        }
        if (!vnc_hex_is_valid(hex, hexlen)) {
            fprintf(stderr, "vncpwd: --hex expects an even number of hexadecimal digits\n");
            return -1;
        }
        add_literal_credential(report, (const uint8_t *)hex, hexlen, hint,
                               "hex argument", VNC_REG_NONE);
        return 0;
    }

    if (opts->raw) {
        size_t len = strlen(opts->raw);
        if (len != 8 && len != 16) {
            fprintf(stderr, "vncpwd: --raw expects exactly 8 or 16 bytes, got %u\n",
                    (unsigned)len);
            return -1;
        }
        add_literal_credential(report, (const uint8_t *)opts->raw, len,
                               VNC_ENC_BINARY, "raw argument", VNC_REG_NONE);
        return 0;
    }

    return -1;
}

static int is_connection_file(const char *path) {
    return vnc_str_iends(path, ".vnc") || vnc_str_iends(path, ".remmina") ||
           vnc_str_iends(path, ".ini");
}

int vnc_inspect_file(const vnc_inspect_opts *opts, vnc_report *report) {
    const char *path = opts->file;
    char err[256];

    if (!path || !report) return -1;

    if (is_connection_file(path)) {
        vnc_connection conn;
        int is_ini = vnc_str_iends(path, ".ini");

        if (vnc_connection_parse(path, &conn, err, sizeof(err)) != 0) {
            fprintf(stderr, "vncpwd: %s\n", err[0] ? err : "cannot parse file");
            return -1;
        }

        /* UltraVNC configuration files use passwd/passwd2, not Password.  A
         * server-side INI is handled here so `inspect --file ultravnc.ini`
         * does not silently report "no password". */
        if (conn.password[0] == 0 && is_ini) {
            static const char *const keys[] = { "passwd", "passwd2" };
            static const char *const sections[] = { "", "admin" };
            size_t k, s;
            for (s = 0; s < 2; s++) {
                for (k = 0; k < 2; k++) {
                    char value[512];
                    char label[VNC_MAX_STR];
                    if (vnc_ini_get(path, sections[s], keys[k], value, sizeof(value)) != 0 ||
                        value[0] == 0) {
                        continue;
                    }
                    if (sections[s][0]) {
                        snprintf(label, sizeof(label), "%s [%s] %s", path,
                                 sections[s], keys[k]);
                    } else {
                        snprintf(label, sizeof(label), "%s [%s]", path, keys[k]);
                    }
                    add_literal_credential(report, (const uint8_t *)value, strlen(value),
                                           VNC_ENC_HEX, label, VNC_REG_NONE);
                }
            }
            if (report->cred_count > 0) return 0;
        }

        if (conn.password[0] == 0) {
            fprintf(stderr, "vncpwd: no password field in %s\n", path);
            return -1;
        }
        add_literal_credential(report, (const uint8_t *)conn.password,
                               strlen(conn.password), VNC_ENC_AUTO, path, VNC_REG_NONE);
        if (conn.host[0]) {
            vnc_credential *cred = report->cred_count ? &report->creds[report->cred_count - 1]
                                                      : NULL;
            if (cred) {
                snprintf(cred->note, sizeof(cred->note), "connection to %s%s%s",
                         conn.host, conn.port[0] ? ":" : "", conn.port);
            }
        }
        return 0;
    }

    {
        char *raw = NULL;
        size_t len = vnc_read_file(path, &raw, 4096);
        if (len == (size_t)-1) {
            fprintf(stderr, "vncpwd: cannot read %s\n", path);
            return -1;
        }
        /* Binary passwd files end with a newline in some writers. */
        if (len > 0 && raw[len - 1] == '\n') len--;
        add_literal_credential(report, (const uint8_t *)raw, len, VNC_ENC_AUTO,
                               path, VNC_REG_NONE);
        free(raw);
        return 0;
    }
}

int vnc_scan_run(const vnc_inspect_opts *opts, vnc_report *report) {
    size_t count, i;
    const vnc_provider *const *list;
    int added = 0;

    if (!report) return -1;
    list = vnc_providers(&count);

    for (i = 0; i < count; i++) {
        if (opts && opts->product && opts->product[0]) {
            if (!vnc_str_ieq(opts->product, list[i]->id) &&
                !vnc_str_ieq(opts->product, list[i]->display)) {
                continue;
            }
        }
        if (!list[i]->scan) continue;
        added += list[i]->scan(report, opts);
    }
    return added;
}
