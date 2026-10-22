#ifndef VNCPWD_PROVIDER_H
#define VNCPWD_PROVIDER_H

#include <stddef.h>
#include "registry.h"
#include "report.h"

/*
 * A provider knows where one VNC product keeps its configuration.  It does
 * not know how to decrypt: it reports every location it found, hands the raw
 * stored value to the format-detection layer, and records audit issues.
 *
 * Providers are driven by the location table in provider.c.  Adding a product
 * means adding table entries, not another source file, unless the product
 * needs genuinely different traversal (e.g. recursively scanning HKCU).
 */

typedef struct vnc_provider {
    const char *id;          /* stable machine-readable name, e.g. "realvnc" */
    const char *display;     /* "RealVNC" */
    const char *description;
    /* Scan the host for this product.  Returns the number of credentials added. */
    int (*scan)(vnc_report *report, const void *opts);
} vnc_provider;

extern const vnc_provider vnc_provider_realvnc;
extern const vnc_provider vnc_provider_tightvnc;
extern const vnc_provider vnc_provider_tigervnc;
extern const vnc_provider vnc_provider_tigervnc_file;
extern const vnc_provider vnc_provider_ultravnc;
extern const vnc_provider vnc_provider_x11vnc;
extern const vnc_provider vnc_provider_turbovnc;
extern const vnc_provider vnc_provider_connection_files;

const vnc_provider *const *vnc_providers(size_t *count);
const vnc_provider *vnc_provider_find(const char *id);

/* Shared helper used by providers for a single known location. */
typedef struct {
    const char *product;
    vnc_hive    hive;
    int         view;
    const char *path;
    const char *value;
    vnc_encoding encoding;
    vnc_auth_type auth;
    const char *note;
} vnc_location;

/* Resolve one location: read, decode, decrypt, validate, and record. */
int vnc_location_resolve(vnc_report *report, const vnc_location *loc);

/* Walk root recursively and resolve every value whose name contains "pass".
 * Used when --deep is given; max_depth of -1 walks the whole subtree. */
int vnc_provider_walk(vnc_report *report, const char *product, vnc_hive hive, int view,
                      const char *root, int max_depth);

#endif /* VNCPWD_PROVIDER_H */
