/*
 * Provider registry and the shared per-location resolver.
 *
 * Every product except RealVNC and the connection-file scanner resolves
 * through vnc_location_resolve(): read the value, detect its format, record
 * the credential and any audit issues that follow from it.
 */
#include "provider.h"
#include "detector.h"
#include "registry.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

const vnc_provider *const *vnc_providers(size_t *count) {
    static const vnc_provider *const list[] = {
        &vnc_provider_realvnc,
        &vnc_provider_tightvnc,
        &vnc_provider_tigervnc,
        &vnc_provider_tigervnc_file,
        &vnc_provider_ultravnc,
        &vnc_provider_x11vnc,
        &vnc_provider_turbovnc,
        &vnc_provider_connection_files,
    };
    if (count) *count = VNC_ARRAY_LEN(list);
    return list;
}

const vnc_provider *vnc_provider_find(const char *id) {
    size_t n, i;
    const vnc_provider *const *list = vnc_providers(&n);
    if (!id) return NULL;
    for (i = 0; i < n; i++) {
        if (vnc_str_ieq(list[i]->id, id)) return list[i];
    }
    return NULL;
}

static int is_weak_password(const char *pw, size_t len) {
    size_t i;
    int letters = 0, digits = 0, others = 0;

    if (len == 0) return 1;
    if (len < 6) return 1;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)pw[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) letters++;
        else if (c >= '0' && c <= '9') digits++;
        else others++;
    }
    if (letters && !digits && !others) return 1;      /* all letters */
    if (digits && !letters && !others) return 1;      /* all digits */
    return 0;
}

/* HKCU\Software is not subject to WOW64 redirection, so scanning both registry
 * views for a user-hive value reads the same bytes twice.  Skip locations that
 * have already been recorded rather than reporting the same secret again. */
static int already_recorded(const vnc_report *report, const vnc_location *loc) {
    size_t i;
    for (i = 0; i < report->cred_count; i++) {
        const vnc_credential *c = &report->creds[i];
        if (vnc_str_ieq(c->location, loc->path) &&
            vnc_str_ieq(c->value, loc->value ? loc->value : "") &&
            vnc_str_ieq(c->hive, vnc_reg_hive_name(loc->hive))) {
            return 1;
        }
    }
    return 0;
}

int vnc_location_resolve(vnc_report *report, const vnc_location *loc) {
    uint8_t raw[VNC_DETECT_TEXT_MAX];
    size_t len = 0;
    uint32_t type = VNC_REG_NONE;
    char err[256];
    char location[VNC_MAX_STR];
    vnc_detection det;
    vnc_credential *cred;
    int rc;

    if (!report || !loc) return -1;
    if (already_recorded(report, loc)) return 0;

    if (loc->value && loc->value[0]) {
        snprintf(location, sizeof(location), "%s\\%s", loc->path, loc->value);
    } else {
        vnc_copy(location, sizeof(location), loc->path);
    }

    rc = vnc_reg_read_value(loc->hive, loc->view, loc->path, loc->value,
                            raw, sizeof(raw) - 1, &len, &type, err, sizeof(err));
    /* On non-Windows builds the registry backend is a stub.  That is an
     * expected condition, not a scan error, so it must not influence the exit
     * status or make a clean Linux host look broken. */
    if (rc == VNC_REG_ERR_UNSUPPORTED) return -1;
    if (rc != VNC_REG_OK) {
        /* A missing value is normal on a machine that does not run the product. */
        if (rc != VNC_REG_ERR_NOT_FOUND) report->errors++;
        return -1;
    }

    report->scanned_items++;

    rc = vnc_detect_value(raw, len, type, loc->encoding, &det);

    cred = vnc_report_add_credential(report);
    if (!cred) return -1;

    vnc_copy(cred->product, sizeof(cred->product), loc->product);
    vnc_copy(cred->location, sizeof(cred->location), loc->path);
    vnc_copy(cred->value, sizeof(cred->value), loc->value ? loc->value : "");
    vnc_copy(cred->hive, sizeof(cred->hive), vnc_reg_hive_name(loc->hive));
    vnc_copy(cred->note, sizeof(cred->note), loc->note ? loc->note : "");
    cred->encoding = det.encoding;
    cred->reg_type = type;
    cred->cipher_len = det.cipher_len;
    cred->auth = loc->auth;
    cred->confidence = det.validation.confidence;

    if (rc == VNC_DETECT_OK && det.recovered) {
        cred->recovered = 1;
        cred->secret_len = det.validation.length;
        memcpy(cred->secret, det.validation.plain, det.validation.length);
        cred->secret[det.validation.length] = 0;
        cred->confidence = det.validation.confidence;

        vnc_report_add_issue(report, VNC_RISK_HIGH, "RECOVERABLE-VNC-PASSWORD",
                             loc->product, location,
                             vnc_auth_locally_recoverable(loc->auth)
                                 ? "password stored with the public fixed DES key; "
                                   "anyone who can read this value owns the console"
                                 : "stored value decrypts with the public VNC key");
        if (is_weak_password((const char *)cred->secret, cred->secret_len)) {
            vnc_report_add_issue(report, VNC_RISK_MEDIUM, "WEAK-PASSWORD",
                                 loc->product, location,
                                 "password is short or uses a single character class");
        }
        if (cred->secret_len == 8) {
            vnc_report_add_issue(report, VNC_RISK_INFO, "MAX-LENGTH-PASSWORD",
                                 loc->product, location,
                                 "protocol caps the password at 8 characters; "
                                 "anything beyond that was discarded");
        }
    } else {
        cred->recovered = 0;
        if (rc == VNC_DETECT_ERR_LENGTH) {
            vnc_copy(cred->note, sizeof(cred->note),
                     "value is present but is not 8 or 16 ciphertext bytes; "
                     "it may use a newer scheme, or authentication may be "
                     "delegated to the OS");
            vnc_report_add_issue(report, VNC_RISK_INFO, "UNRECOGNIZED-FORMAT",
                                 loc->product, location,
                                 "value does not match the classic VNC DES format");
        } else if (rc == VNC_DETECT_ERR_FORMAT) {
            vnc_copy(cred->note, sizeof(cred->note),
                     "value could not be decoded as hex, base64 or raw bytes");
        } else if (!det.recovered) {
            vnc_copy(cred->note, sizeof(cred->note),
                     "decrypted bytes are not a plausible ASCII password "
                     "(the password may have been set by a client that uses "
                     "a different scheme)");
        }
    }

    /* A stored password says nothing about how clients authenticate: RA2 and
     * VeNCrypt servers still keep a Password value.  The authentication audit
     * belongs with the provider, which can read SecurityTypes/Authentication.
     * Reporting "weak auth" here produced false positives on TigerVNC servers
     * configured for RA2. */
    return cred->recovered ? 1 : 0;
}

/* --deep: walk a product's registry subtree and resolve every value whose name
 * looks like a password.  This catches renamed or vendor-customised keys that
 * the fixed table in a provider does not know about. */
typedef struct {
    vnc_report *report;
    const char *product;
    vnc_hive    hive;
} walk_ctx;

static int deep_visit(void *vctx, const char *key_path, const char *value_name,
                      uint32_t type, const uint8_t *data, size_t len) {
    walk_ctx *ctx = (walk_ctx *)vctx;
    vnc_location loc;
    (void)data;
    (void)len;
    (void)type;

    if (!vnc_str_icontains(value_name, "pass")) return 0;

    memset(&loc, 0, sizeof(loc));
    loc.product = ctx->product;
    loc.hive = ctx->hive;
    loc.path = key_path;
    loc.value = value_name;
    loc.encoding = VNC_ENC_AUTO;
    loc.auth = VNC_AUTH_VNC_PASSWORD;
    loc.note = "found by --deep registry walk";
    vnc_location_resolve(ctx->report, &loc);
    return 0;
}

int vnc_provider_walk(vnc_report *report, const char *product, vnc_hive hive, int view,
                      const char *root, int max_depth) {
    walk_ctx ctx;
    int before;

    if (!report || !root) return 0;
    before = (int)report->cred_count;

    ctx.report = report;
    ctx.product = product ? product : "registry walk";
    ctx.hive = hive;

    vnc_reg_walk(hive, view, root, max_depth, deep_visit, &ctx);
    return (int)report->cred_count - before;
}
