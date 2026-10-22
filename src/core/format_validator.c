#include "format_validator.h"

#include <string.h>

/* Characters VNC clients and servers actually accept in a password.  The
 * protocol truncates to 8 bytes and passes them through untouched, so any
 * printable ASCII is possible; control bytes are the signal of a wrong guess. */
static int is_printable(uint8_t c) {
    return c >= 0x20 && c <= 0x7e;
}

int vnc_validate_plaintext(const uint8_t *plain, size_t len, vnc_validation *out) {
    size_t i, printable = 0;
    int has_control = 0;

    if (!plain || !out) return -1;
    memset(out, 0, sizeof(*out));
    out->length = len;

    if (len > VNC_MAX_PASSWORD) {
        out->reason = "plaintext longer than any VNC password";
        return 0;
    }
    memcpy(out->plain, plain, len);
    out->plain[len] = 0;

    for (i = 0; i < len; i++) {
        if (plain[i] == 0) { has_control = 1; continue; }
        if (is_printable(plain[i])) printable++;
        else has_control = 1;
    }
    out->printable_ratio = len ? (int)((printable * 100) / len) : 0;
    out->padding_ok = !has_control;

    if (len == 0) {
        /* An all-zero ciphertext block is a legitimate "no password", but a
         * genuinely empty password is indistinguishable from a wrong key. */
        out->confidence = 0.35;
        out->reason = "decrypts to an empty password (likely no password set)";
        out->valid = 0;
        return 0;
    }
    if (has_control) {
        out->confidence = 0.05;
        out->reason = "plaintext contains non-printable bytes";
        out->valid = 0;
        return 0;
    }

    /* Longer printable plaintext that is exactly 8 bytes and fully printable
     * is a strong hit; a 1-2 character result is more likely a coincidence. */
    out->confidence = 0.55;
    if (out->printable_ratio == 100) out->confidence += 0.25;
    if (len == 8) out->confidence += 0.10;
    if (len >= 4) out->confidence += 0.05;
    if (out->confidence > 1.0) out->confidence = 1.0;

    out->valid = out->confidence >= VNC_CONFIDENCE_ACCEPT;
    out->reason = out->valid ? "printable ASCII password"
                             : "short printable sequence, possibly a false positive";
    return 0;
}

int vnc_validate_ciphertext(const uint8_t *cipher, size_t len, vnc_validation *out) {
    vnc_des_result res;
    int rc;

    if (!cipher || !out) return -1;
    memset(out, 0, sizeof(*out));

    rc = vnc_des_decrypt(cipher, len, &res);
    if (rc == VNC_DES_ERR_LENGTH) {
        out->reason = "ciphertext must be exactly 8 or 16 bytes";
        out->confidence = 0.0;
        return 0;
    }
    if (rc != VNC_DES_OK) {
        out->reason = "decryption failed";
        return 0;
    }
    return vnc_validate_plaintext(res.plain, res.length, out);
}
