/*
 * vncpwd 2.0 - VNC Credential & Security Inspector
 *
 * Reads VNC configuration that is already on this machine, identifies the
 * authentication scheme in use, and reports which stored secrets can be
 * recovered with the public fixed VNC DES key.  It does not contact a network
 * service, does not attempt logins, and does not implement the RSA-AES or
 * VeNCrypt handshakes.
 *
 * Original vncpwd: Copyright 2006 Luigi Auriemma, GPL-2.0-or-later.
 */
#include "auth_type.h"
#include "inspector.h"
#include "provider.h"
#include "report.h"
#include "util.h"
#include "version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out, const char *argv0) {
    fprintf(out,
        "\n%s %s - %s\n"
        "\n"
        "Usage:\n"
        "  %s scan [options]                 inspect this machine\n"
        "  %s inspect --hex <hex>            decode a ciphertext blob\n"
        "  %s inspect --raw <8|16 bytes>     decode a raw blob\n"
        "  %s inspect --file <path>          decode a .vnc / passwd file\n"
        "  %s audit [--json]                 scan and report findings only\n"
        "\n"
        "Options:\n"
        "  --product <id>   limit to one provider (realvnc, tightvnc, tigervnc,\n"
        "                   tigervnc-file, ultravnc, x11vnc, turbovnc, connections)\n"
        "  --show           print recovered passwords instead of redacting them\n"
        "  --json           machine readable output\n"
        "  --csv            comma separated credentials table\n"
        "  -q, --quiet      suppress the banner\n"
        "  -h, --help       this help\n"
        "  -V, --version    version\n"
        "\n"
        "Exit status: 0 no high-risk findings, 1 high or critical findings,\n"
        "             2 usage or I/O error.\n"
        "\n"
        "Only inspect systems you are authorized to assess.  Recovered\n"
        "passwords are credentials for the VNC server, not for the OS account.\n"
        "\n",
        argv0, VNCPWD_NAME, VNCPWD_VERSION, argv0, argv0, argv0, argv0, argv0);
}

static void banner(FILE *out) {
    fprintf(out,
        "\n%s %s\n"
        "VNC Credential & Security Inspector\n"
        "based on vncpwd 0.2 by Luigi Auriemma\n\n",
        VNCPWD_TOOL, VNCPWD_VERSION);
}

static int emit(const vnc_inspect_opts *opts, const vnc_report *report) {
    if (opts->json) return vnc_report_write_json(report, stdout);
    if (opts->csv)  return vnc_report_write_csv(report, stdout);
    return vnc_report_write_text(report, stdout);
}

static int exit_code(const vnc_report *report) {
    vnc_risk max = vnc_report_max_risk(report);
    if (max >= VNC_RISK_HIGH) return 1;
    if (report->errors && report->cred_count == 0 && report->scanned_items == 0) return 2;
    return 0;
}

int main(int argc, char **argv) {
    vnc_inspect_opts opts;
    vnc_report report;
    const char *command = NULL;
    int i, rc = 0;
    int audit_only = 0;

    memset(&opts, 0, sizeof(opts));
    vnc_report_init(&report, 0);

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout, argv[0]);
            return 0;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", VNCPWD_TOOL, VNCPWD_VERSION);
            return 0;
        } else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) {
            opts.quiet = 1;
        } else if (!strcmp(a, "--show")) {
            opts.show = 1;
            report.include_secrets = 1;
        } else if (!strcmp(a, "--json")) {
            opts.json = 1;
        } else if (!strcmp(a, "--csv")) {
            opts.csv = 1;
        } else if (!strcmp(a, "--deep")) {
            opts.recursive = 1;
        } else if (!strcmp(a, "--hex") && i + 1 < argc) {
            opts.hex = argv[++i];
        } else if (!strncmp(a, "--hex=", 6)) {
            opts.hex = a + 6;
        } else if (!strcmp(a, "--raw") && i + 1 < argc) {
            opts.raw = argv[++i];
        } else if (!strncmp(a, "--raw=", 6)) {
            opts.raw = a + 6;
        } else if (!strcmp(a, "--file") && i + 1 < argc) {
            opts.file = argv[++i];
        } else if (!strncmp(a, "--file=", 7)) {
            opts.file = a + 7;
        } else if (!strcmp(a, "--product") && i + 1 < argc) {
            opts.product = argv[++i];
        } else if (!strncmp(a, "--product=", 10)) {
            opts.product = a + 10;
        } else if (a[0] == '-') {
            fprintf(stderr, "vncpwd: unknown option %s\n", a);
            usage(stderr, argv[0]);
            return 2;
        } else if (!command) {
            command = a;
        } else if (!opts.file && !opts.hex && !opts.raw) {
            /* Bare path after the command is accepted as --file. */
            opts.file = a;
        } else {
            fprintf(stderr, "vncpwd: unexpected argument %s\n", a);
            return 2;
        }
    }

    if (!command) {
        usage(stdout, argv[0]);
        return 0;
    }

    if (!opts.quiet && !opts.json && !opts.csv) banner(stdout);

    if (!strcmp(command, "inspect")) {
        if (opts.hex || opts.raw) {
            rc = vnc_inspect_literal(&opts, &report);
        } else if (opts.file) {
            rc = vnc_inspect_file(&opts, &report);
        } else {
            fprintf(stderr, "vncpwd: inspect needs --hex, --raw or --file\n");
            vnc_report_free(&report);
            return 2;
        }
    } else if (!strcmp(command, "scan")) {
        vnc_scan_run(&opts, &report);
    } else if (!strcmp(command, "audit")) {
        audit_only = 1;
        vnc_scan_run(&opts, &report);
    } else if (!strcmp(command, "list")) {
        size_t count, j;
        const vnc_provider *const *list = vnc_providers(&count);
        for (j = 0; j < count; j++) {
            printf("%-16s %s\n", list[j]->id, list[j]->display);
        }
        vnc_report_free(&report);
        return 0;
    } else {
        fprintf(stderr, "vncpwd: unknown command %s\n", command);
        usage(stderr, argv[0]);
        vnc_report_free(&report);
        return 2;
    }

    if (rc != 0) {
        vnc_report_free(&report);
        return 2;
    }

    /* -q suppresses the banner, never the answer: a scan that prints nothing
     * is indistinguishable from a scan that failed. */
    if (audit_only && (opts.json || opts.csv)) {
        /* A machine-readable audit still uses the report serialisers, so
         * callers get the same document shape as `scan --json`. */
        emit(&opts, &report);
    } else if (audit_only) {
        size_t j;
        for (j = 0; j < report.issue_count; j++) {
            const vnc_issue *it = &report.issues[j];
            printf("[%-8s] %-24s %s\n", vnc_risk_name(it->risk), it->code, it->message);
            if (it->location[0]) printf("           at %s\n", it->location);
        }
        printf("\nmax risk: %s\n", vnc_risk_name(vnc_report_max_risk(&report)));
    } else {
        emit(&opts, &report);
    }

    rc = exit_code(&report);
    vnc_report_free(&report);
    return rc;
}
