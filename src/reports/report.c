#include "report.h"
#include "util.h"
#include "version.h"

#include <stdlib.h>
#include <string.h>

void vnc_report_init(vnc_report *r, int include_secrets) {
    if (!r) return;
    memset(r, 0, sizeof(*r));
    r->include_secrets = include_secrets;
}

void vnc_report_free(vnc_report *r) {
    if (!r) return;
    free(r->creds);
    free(r->issues);
    memset(r, 0, sizeof(*r));
}

vnc_credential *vnc_report_add_credential(vnc_report *r) {
    vnc_credential *c;

    if (!r) return NULL;
    if (r->cred_count == r->cred_cap) {
        size_t ncap = r->cred_cap ? r->cred_cap * 2 : 8;
        vnc_credential *grown;
        if (ncap > VNC_REPORT_MAX_FINDINGS) ncap = VNC_REPORT_MAX_FINDINGS;
        if (ncap <= r->cred_cap) return NULL;
        grown = (vnc_credential *)realloc(r->creds, ncap * sizeof(*grown));
        if (!grown) return NULL;
        r->creds = grown;
        r->cred_cap = ncap;
    }
    c = &r->creds[r->cred_count++];
    memset(c, 0, sizeof(*c));
    return c;
}

int vnc_report_add_issue(vnc_report *r, vnc_risk risk, const char *code,
                         const char *product, const char *location, const char *message) {
    vnc_issue *i;

    if (!r) return -1;

    /* A finding that is raised twice for the same place is noise: registry
     * view loops and overlapping providers both produce duplicates. */
    {
        size_t k;
        for (k = 0; k < r->issue_count; k++) {
            if (r->issues[k].risk == risk &&
                vnc_str_ieq(r->issues[k].code, code) &&
                vnc_str_ieq(r->issues[k].location, location ? location : "")) {
                return 0;
            }
        }
    }

    if (r->issue_count == r->issue_cap) {
        size_t ncap = r->issue_cap ? r->issue_cap * 2 : 8;
        vnc_issue *grown;
        if (ncap > VNC_REPORT_MAX_ISSUES) ncap = VNC_REPORT_MAX_ISSUES;
        if (ncap <= r->issue_cap) return -1;
        grown = (vnc_issue *)realloc(r->issues, ncap * sizeof(*grown));
        if (!grown) return -1;
        r->issues = grown;
        r->issue_cap = ncap;
    }
    i = &r->issues[r->issue_count++];
    memset(i, 0, sizeof(*i));
    i->risk = risk;
    vnc_copy(i->code, sizeof(i->code), code);
    vnc_copy(i->product, sizeof(i->product), product);
    vnc_copy(i->location, sizeof(i->location), location);
    vnc_copy(i->message, sizeof(i->message), message);
    return 0;
}

vnc_risk vnc_report_max_risk(const vnc_report *r) {
    vnc_risk max = VNC_RISK_INFO;
    size_t i;
    if (!r) return VNC_RISK_INFO;
    for (i = 0; i < r->issue_count; i++) {
        if (r->issues[i].risk > max) max = r->issues[i].risk;
    }
    return max;
}

static void json_string(FILE *out, const char *s) {
    fputc('"', out);
    if (s) {
        for (; *s; s++) {
            unsigned char c = (unsigned char)*s;
            switch (c) {
            case '"':  fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\n': fputs("\\n", out); break;
            case '\r': fputs("\\r", out); break;
            case '\t': fputs("\\t", out); break;
            default:
                if (c < 0x20) fprintf(out, "\\u%04x", c);
                else fputc((char)c, out);
            }
        }
    }
    fputc('"', out);
}

int vnc_report_write_json(const vnc_report *r, FILE *out) {
    size_t i;

    if (!r || !out) return -1;

    fputs("{\n", out);
    fputs("  \"tool\": {\"name\": \"vncpwd\", \"version\": \"" VNCPWD_VERSION "\"},\n", out);
    fprintf(out, "  \"summary\": {\"credentials\": %u, \"issues\": %u, "
                 "\"max_risk\": \"%s\", \"secrets_included\": %s},\n",
            (unsigned)r->cred_count, (unsigned)r->issue_count,
            vnc_risk_name(vnc_report_max_risk(r)),
            r->include_secrets ? "true" : "false");

    fputs("  \"credentials\": [", out);
    for (i = 0; i < r->cred_count; i++) {
        const vnc_credential *c = &r->creds[i];
        fputs(i ? ",\n" : "\n", out);
        fputs("    {\"product\": ", out);
        json_string(out, c->product);
        fputs(", \"location\": ", out);
        json_string(out, c->location);
        fputs(", \"hive\": ", out);
        json_string(out, c->hive);
        fputs(", \"value\": ", out);
        json_string(out, c->value);
        fprintf(out, ", \"encoding\": \"%s\", \"registry_type\": %lu",
                vnc_encoding_name(c->encoding), (unsigned long)c->reg_type);
        fprintf(out, ", \"cipher_bytes\": %u, \"auth\": \"%s\"",
                (unsigned)c->cipher_len, vnc_auth_name(c->auth));
        fprintf(out, ", \"recovered\": %s, \"confidence\": %.2f",
                c->recovered ? "true" : "false", c->confidence);
        if (c->recovered) {
            char masked[128];
            vnc_mask_secret(c->secret, c->secret_len, r->include_secrets,
                            masked, sizeof(masked));
            fputs(", \"password\": ", out);
            json_string(out, masked);
        }
        if (c->note[0]) {
            fputs(", \"note\": ", out);
            json_string(out, c->note);
        }
        fputc('}', out);
    }
    fputs(r->cred_count ? "\n  ],\n" : "],\n", out);

    fputs("  \"issues\": [", out);
    for (i = 0; i < r->issue_count; i++) {
        const vnc_issue *it = &r->issues[i];
        fputs(i ? ",\n" : "\n", out);
        fprintf(out, "    {\"risk\": \"%s\", \"code\": ", vnc_risk_name(it->risk));
        json_string(out, it->code);
        fputs(", \"product\": ", out);
        json_string(out, it->product);
        fputs(", \"location\": ", out);
        json_string(out, it->location);
        fputs(", \"message\": ", out);
        json_string(out, it->message);
        fputc('}', out);
    }
    fputs(r->issue_count ? "\n  ]\n" : "]\n", out);
    fputs("}\n", out);
    return 0;
}

void vnc_report_print_credential(const vnc_credential *c, FILE *out) {
    char masked[128];

    if (!c || !out) return;
    vnc_mask_secret(c->secret, c->secret_len, 1, masked, sizeof(masked));
    fprintf(out, "  Product    %s\n", c->product);
    if (c->hive[0]) fprintf(out, "  Hive       %s\n", c->hive);
    fprintf(out, "  Location   %s\n", c->location);
    if (c->value[0]) fprintf(out, "  Value      %s\n", c->value);
    fprintf(out, "  Encoding   %s (%u bytes ciphertext)\n",
            vnc_encoding_name(c->encoding), (unsigned)c->cipher_len);
    fprintf(out, "  Auth       %s - %s\n", vnc_auth_name(c->auth),
            vnc_auth_description(c->auth));
    if (c->recovered) {
        fprintf(out, "  Password   %s\n", masked);
        fprintf(out, "  Confidence %.0f%%\n", c->confidence * 100.0);
    } else {
        fprintf(out, "  Password   (not recoverable from this store)\n");
    }
    if (c->note[0]) fprintf(out, "  Note       %s\n", c->note);
}

int vnc_report_write_text(const vnc_report *r, FILE *out) {
    size_t i;
    int recovered = 0;

    if (!r || !out) return -1;

    for (i = 0; i < r->cred_count; i++) {
        const vnc_credential *c = &r->creds[i];
        char masked[128];

        if (i) fputc('\n', out);
        if (c->recovered) recovered++;
        vnc_mask_secret(c->secret, c->secret_len, r->include_secrets,
                        masked, sizeof(masked));
        fprintf(out, "[%s] %s", c->product, c->location);
        if (c->value[0]) fprintf(out, " \\ %s", c->value);
        fputc('\n', out);
        fprintf(out, "  auth: %s  encoding: %s  cipher: %u bytes\n",
                vnc_auth_name(c->auth), vnc_encoding_name(c->encoding),
                (unsigned)c->cipher_len);
        if (c->recovered) {
            fprintf(out, "  password: %s  (confidence %.0f%%)\n",
                    masked, c->confidence * 100.0);
        } else {
            fprintf(out, "  password: not recoverable from this store\n");
        }
        if (c->note[0]) fprintf(out, "  note: %s\n", c->note);
    }

    if (r->issue_count) {
        fputs("\nFindings\n--------\n", out);
        for (i = 0; i < r->issue_count; i++) {
            const vnc_issue *it = &r->issues[i];
            fprintf(out, "  [%-8s] %-22s %s\n", vnc_risk_name(it->risk), it->code,
                    it->message);
            if (it->location[0]) fprintf(out, "             at %s\n", it->location);
        }
    }

    fprintf(out, "\nSummary: %u credential(s), %u recovered, %u finding(s), "
                 "max risk: %s\n",
            (unsigned)r->cred_count, (unsigned)recovered, (unsigned)r->issue_count,
            vnc_risk_name(vnc_report_max_risk(r)));
    if (!r->include_secrets && recovered) {
        fputs("Secrets are redacted. Use --show to print them, and keep that "
              "output off shared logs.\n", out);
    }
    return 0;
}

static void csv_field(FILE *out, const char *s) {
    fputc('"', out);
    for (; s && *s; s++) {
        if (*s == '"') fputc('"', out);
        fputc(*s, out);
    }
    fputc('"', out);
}

int vnc_report_write_csv(const vnc_report *r, FILE *out) {
    size_t i;

    if (!r || !out) return -1;
    fputs("product,hive,location,value,encoding,auth,recovered,confidence,password\n", out);
    for (i = 0; i < r->cred_count; i++) {
        const vnc_credential *c = &r->creds[i];
        char masked[128];
        vnc_mask_secret(c->secret, c->secret_len, r->include_secrets,
                        masked, sizeof(masked));
        csv_field(out, c->product);
        fputc(',', out);
        csv_field(out, c->hive);
        fputc(',', out);
        csv_field(out, c->location);
        fputc(',', out);
        csv_field(out, c->value);
        fputc(',', out);
        csv_field(out, vnc_encoding_name(c->encoding));
        fputc(',', out);
        csv_field(out, vnc_auth_name(c->auth));
        fprintf(out, ",%s,%.2f,", c->recovered ? "true" : "false", c->confidence);
        csv_field(out, c->recovered ? masked : "");
        fputc('\n', out);
    }
    return 0;
}
