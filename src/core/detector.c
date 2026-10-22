/*
 * Format-detection layer.  A provider hands over the raw bytes it found in a
 * configuration store; this module decides how they are encoded, decodes the
 * ciphertext, decrypts it with the fixed VNC key, and scores the result.
 *
 * Nothing here trusts the store.  Every step returns an error rather than
 * proceeding with a truncated or oversized buffer.
 */
#include "detector.h"
#include "encoding.h"
#include "format_validator.h"
#include "legacy_des.h"
#include "util.h"

#include <string.h>

/* REG_SZ values arrive as text; REG_BINARY as bytes.  When the caller does
 * not know the type (INI files, .vnc files, hex on the command line), the
 * encoding is inferred from the content. */
static vnc_encoding infer_registry_encoding(uint32_t reg_type, const uint8_t *data,
                                            size_t len) {
    if (reg_type == VNC_REG_BINARY) return VNC_ENC_BINARY;
    if (reg_type == VNC_REG_SZ || reg_type == VNC_REG_EXPAND) {
        char text[64];
        if (len == 0 || len >= sizeof(text)) return VNC_ENC_UNKNOWN;
        memcpy(text, data, len);
        text[len] = 0;
        if (vnc_hex_is_valid(text, len)) return VNC_ENC_HEX;
        return VNC_ENC_UNKNOWN;
    }
    return VNC_ENC_UNKNOWN;
}

int vnc_detect_value(const uint8_t *data, size_t len, uint32_t reg_type,
                     vnc_encoding hint, vnc_detection *out) {
    char text[VNC_DETECT_TEXT_MAX];
    uint8_t cipher[VNC_CIPHERTEXT_MAX];
    size_t cipher_len = 0;
    vnc_encoding enc;

    if (!data || !out) return VNC_DETECT_ERR_ARG;
    memset(out, 0, sizeof(*out));

    if (len == 0) {
        out->reason = "empty value";
        return VNC_DETECT_ERR_EMPTY;
    }
    if ((hint != VNC_ENC_BINARY && hint != VNC_ENC_AUTO) && len >= sizeof(text)) {
        out->reason = "value too long to be a VNC password";
        return VNC_DETECT_ERR_FORMAT;
    }

    if (hint == VNC_ENC_AUTO || hint == VNC_ENC_UNKNOWN) {
        enc = infer_registry_encoding(reg_type, data, len);
        if (enc == VNC_ENC_UNKNOWN) {
            /* Not a registry value: try the content heuristics. */
            memcpy(text, data, len);
            text[len] = 0;
            if (vnc_hex_is_valid(text, len)) enc = VNC_ENC_HEX;
            else if (len == 8 || len == 16) enc = VNC_ENC_BINARY;
            else enc = VNC_ENC_BASE64;
        }
    } else {
        enc = hint;
    }

    out->encoding = enc;

    if (enc == VNC_ENC_BINARY) {
        if (len > sizeof(cipher)) {
            out->reason = "binary ciphertext larger than two DES blocks";
            return VNC_DETECT_ERR_FORMAT;
        }
        memcpy(cipher, data, len);
        cipher_len = len;
    } else {
        size_t tlen = len;
        if (tlen >= sizeof(text)) {
            out->reason = "value too long";
            return VNC_DETECT_ERR_FORMAT;
        }
        memcpy(text, data, len);
        text[len] = 0;
        vnc_trim(text);
        tlen = strlen(text);
        cipher_len = vnc_decode_ciphertext(text, tlen, enc, cipher, sizeof(cipher));
        if (cipher_len == 0) {
            out->reason = "value is not valid hex/base64 or is empty";
            return VNC_DETECT_ERR_FORMAT;
        }
    }

    if (cipher_len != 8 && cipher_len != 16) {
        out->reason = "decoded ciphertext is not 8 or 16 bytes";
        out->cipher_len = cipher_len;
        memcpy(out->cipher, cipher, cipher_len);
        return VNC_DETECT_ERR_LENGTH;
    }

    memcpy(out->cipher, cipher, cipher_len);
    out->cipher_len = cipher_len;

    vnc_validate_ciphertext(cipher, cipher_len, &out->validation);
    out->recovered = out->validation.valid &&
                     out->validation.confidence >= VNC_CONFIDENCE_ACCEPT;
    out->reason = out->validation.reason ? out->validation.reason : "";
    return VNC_DETECT_OK;
}
