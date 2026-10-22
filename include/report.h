#ifndef VNCPWD_REPORT_H
#define VNCPWD_REPORT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "auth_type.h"
#include "encoding.h"
#include "legacy_des.h"

#define VNC_REPORT_MAX_FINDINGS 128
#define VNC_REPORT_MAX_ISSUES    64
#define VNC_MAX_STR             512

typedef struct {
    char          product[64];
    char          location[VNC_MAX_STR];   /* registry path or file path */
    char          value[128];              /* value name, empty for files */
    char          hive[32];
    vnc_encoding  encoding;
    uint32_t      reg_type;
    size_t        cipher_len;
    size_t        secret_len;
    char          secret[VNC_MAX_PASSWORD + 1];
    double        confidence;
    int           recovered;
    vnc_auth_type auth;
    char          note[VNC_MAX_STR];
} vnc_credential;

typedef struct {
    vnc_risk risk;
    char     code[32];
    char     product[64];
    char     location[VNC_MAX_STR];
    char     message[VNC_MAX_STR];
} vnc_issue;

typedef struct {
    int             include_secrets;
    vnc_credential *creds;
    size_t          cred_count;
    size_t          cred_cap;
    vnc_issue      *issues;
    size_t          issue_count;
    size_t          issue_cap;
    int             scanned_items;
    int             errors;
} vnc_report;

void vnc_report_init(vnc_report *r, int include_secrets);
void vnc_report_free(vnc_report *r);

vnc_credential *vnc_report_add_credential(vnc_report *r);
int             vnc_report_add_issue(vnc_report *r, vnc_risk risk, const char *code,
                                     const char *product, const char *location,
                                     const char *message);

vnc_risk vnc_report_max_risk(const vnc_report *r);
int      vnc_report_write_json(const vnc_report *r, FILE *out);
int      vnc_report_write_text(const vnc_report *r, FILE *out);
int      vnc_report_write_csv(const vnc_report *r, FILE *out);

/* Print an ASCII table for credentials from a single provider, used by inspect. */
void vnc_report_print_credential(const vnc_credential *c, FILE *out);

#endif /* VNCPWD_REPORT_H */
