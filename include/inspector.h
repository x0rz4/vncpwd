#ifndef VNCPWD_INSPECTOR_H
#define VNCPWD_INSPECTOR_H

#include <stddef.h>
#include "report.h"

typedef struct {
    /* Input forms.  Exactly one is used, in this order of precedence. */
    const char *hex;        /* --hex */
    const char *raw;        /* --raw */
    const char *file;       /* --file */
    const char *product;    /* --product, limits scan/inspect */
    int         json;       /* --json */
    int         csv;        /* --csv */
    int         show;       /* --show, do not redact */
    int         recursive;  /* --deep, recurse into registry subtrees */
    int         quiet;
} vnc_inspect_opts;

/* Decode a value the user supplied on the command line. */
int vnc_inspect_literal(const vnc_inspect_opts *opts, vnc_report *report);
/* Parse a .vnc / connection file. */
int vnc_inspect_file(const vnc_inspect_opts *opts, vnc_report *report);

/* Run all providers (or one, when opts->product is set). */
int vnc_scan_run(const vnc_inspect_opts *opts, vnc_report *report);

#endif /* VNCPWD_INSPECTOR_H */
