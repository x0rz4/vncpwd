/*
 * The classic Unix passwd file: ~/.vnc/passwd.
 *
 * Shared by x11vnc, libvncserver, TigerVNC and TurboVNC on Unix.  The file is
 * either 8 raw bytes (the DES blob written by vncpasswd) or, in some builds, 8
 * or 16 bytes in a text encoding.  The file mode matters as much as the
 * content: 0600 is expected, anything world-readable is a finding.
 *
 * TurboVNC keeps the same file plus turbovncserver.conf; x11vnc also accepts
 * ~/.x11vncrc and command-line -rfbauth.  libvncserver-based applications
 * pass the path themselves, so the conventional location is a best effort.
 */
#include "provider.h"
#include "detector.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#  include <sys/stat.h>
#endif

typedef struct {
    const char *product;
    const char *dir;      /* directory, ~ and %VAR% expanded */
    const char *filename;
    const char *note;
} passwd_file_spot;

static const passwd_file_spot vnc_common_passwd[] = {
    { "x11vnc",       "~/.vnc", "passwd", "x11vnc -rfbauth default location" },
    { "libvncserver", "~/.vnc", "passwd", "conventional libvncserver password file" },
};

static const passwd_file_spot tigervnc_passwd[] = {
    { "TigerVNC", "~/.vnc", "passwd", "written by TigerVNC vncpasswd" },
};

static const passwd_file_spot turbovnc_passwd[] = {
    { "TurboVNC", "~/.vnc", "passwd", "TurboVNC uses the TigerVNC passwd format" },
};

static void check_permissions(vnc_report *report, const char *path, const char *product) {
#ifndef _WIN32
    struct stat st;
    if (stat(path, &st) != 0) return;
    if (st.st_mode & (S_IRGRP | S_IROTH)) {
        vnc_report_add_issue(report, VNC_RISK_HIGH, "PASSWORD-FILE-READABLE",
                             product, path,
                             "passwd file is readable by group or others; it should "
                             "be mode 0600 and owned by the VNC user");
    }
#else
    (void)report; (void)path; (void)product;
#endif
}

static int scan_passwd_files(vnc_report *report, const passwd_file_spot *spots,
                             size_t count) {
    size_t i;
    int added = 0;

    for (i = 0; i < count; i++) {
        char dir[1024], path[1024], expanded[1200];
        char *raw = NULL;
        size_t len;
        vnc_detection det;
        vnc_credential *cred;
        int rc;

        if (vnc_expand_path(spots[i].dir, dir, sizeof(dir)) != 0) continue;
        snprintf(path, sizeof(path), "%s/%s", dir, spots[i].filename);
        if (vnc_expand_path(path, expanded, sizeof(expanded)) < 0) continue;
        if (!vnc_file_exists(expanded)) continue;

        len = vnc_read_file(expanded, &raw, 4096);
        if (len == (size_t)-1 || len == 0) {
            free(raw);
            continue;
        }

        rc = vnc_detect_value((const uint8_t *)raw, len, VNC_REG_NONE,
                              VNC_ENC_AUTO, &det);
        report->scanned_items++;

        cred = vnc_report_add_credential(report);
        if (!cred) {
            free(raw);
            continue;
        }
        vnc_copy(cred->product, sizeof(cred->product), spots[i].product);
        vnc_copy(cred->location, sizeof(cred->location), expanded);
        vnc_copy(cred->note, sizeof(cred->note), spots[i].note);
        cred->encoding = det.encoding;
        cred->reg_type = VNC_REG_NONE;
        cred->cipher_len = det.cipher_len;
        cred->auth = VNC_AUTH_VNC_PASSWORD;
        cred->confidence = det.validation.confidence;

        if (rc == VNC_DETECT_OK && det.recovered) {
            cred->recovered = 1;
            cred->secret_len = det.validation.length;
            memcpy(cred->secret, det.validation.plain, cred->secret_len);
            cred->secret[cred->secret_len] = 0;
            added++;
            vnc_report_add_issue(report, VNC_RISK_HIGH, "RECOVERABLE-VNC-PASSWORD",
                                 spots[i].product, expanded,
                                 "password file decrypts with the public fixed DES key");
            if (cred->secret_len < 6) {
                vnc_report_add_issue(report, VNC_RISK_MEDIUM, "WEAK-PASSWORD",
                                     spots[i].product, expanded,
                                     "password is shorter than 6 characters");
            }
        } else {
            vnc_copy(cred->note, sizeof(cred->note),
                     "file does not contain a classic 8/16 byte VNC DES blob");
        }

        check_permissions(report, expanded, spots[i].product);
        free(raw);
    }
    return added;
}

static int x11vnc_scan(vnc_report *report, const void *opts) {
    (void)opts;
    return scan_passwd_files(report, vnc_common_passwd, VNC_ARRAY_LEN(vnc_common_passwd));
}

static int tigervnc_file_scan(vnc_report *report, const void *opts) {
    (void)opts;
    return scan_passwd_files(report, tigervnc_passwd, VNC_ARRAY_LEN(tigervnc_passwd));
}

static int turbovnc_scan(vnc_report *report, const void *opts) {
    (void)opts;
    return scan_passwd_files(report, turbovnc_passwd, VNC_ARRAY_LEN(turbovnc_passwd));
}

const vnc_provider vnc_provider_x11vnc = {
    "x11vnc",
    "x11vnc / libvncserver",
    "x11vnc and libvncserver passwd files, including file permissions",
    x11vnc_scan
};

/* TigerVNC on Unix shares the same passwd file; the Windows provider covers
 * the registry side, so this one is registered under a distinct id. */
const vnc_provider vnc_provider_tigervnc_file = {
    "tigervnc-file",
    "TigerVNC (Unix)",
    "~/.vnc/passwd written by TigerVNC vncpasswd",
    tigervnc_file_scan
};

const vnc_provider vnc_provider_turbovnc = {
    "turbovnc",
    "TurboVNC",
    "TurboVNC password file (TigerVNC-compatible format)",
    turbovnc_scan
};
