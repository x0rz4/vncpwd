#include "encoding.h"
#include "util.h"

#include <string.h>

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

const char *vnc_encoding_name(vnc_encoding enc) {
    switch (enc) {
    case VNC_ENC_BINARY: return "binary";
    case VNC_ENC_HEX:    return "hex";
    case VNC_ENC_BASE64: return "base64";
    case VNC_ENC_AUTO:   return "auto";
    default:             return "unknown";
    }
}

int vnc_encoding_parse(const char *name, vnc_encoding *out) {
    if (!name || !out) return -1;
    if (vnc_str_ieq(name, "binary") || vnc_str_ieq(name, "raw")) {
        *out = VNC_ENC_BINARY;
    } else if (vnc_str_ieq(name, "hex")) {
        *out = VNC_ENC_HEX;
    } else if (vnc_str_ieq(name, "base64") || vnc_str_ieq(name, "b64")) {
        *out = VNC_ENC_BASE64;
    } else if (vnc_str_ieq(name, "auto")) {
        *out = VNC_ENC_AUTO;
    } else {
        return -1;
    }
    return 0;
}

int vnc_hex_is_valid(const char *in, size_t inlen) {
    size_t i;
    if (!in || inlen == 0 || (inlen % 2) != 0) return 0;
    for (i = 0; i < inlen; i++) {
        if (hex_nibble((unsigned char)in[i]) < 0) return 0;
    }
    return 1;
}

size_t vnc_hex_decode(const char *in, size_t inlen, uint8_t *out, size_t outcap) {
    size_t i, n = 0;
    int hi, lo;

    if (!in || !out || (inlen % 2) != 0) return 0;
    if (inlen / 2 > outcap) return 0;

    for (i = 0; i < inlen; i += 2) {
        hi = hex_nibble((unsigned char)in[i]);
        lo = hex_nibble((unsigned char)in[i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

static int b64_value(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

size_t vnc_base64_decode(const char *in, size_t inlen, uint8_t *out, size_t outcap) {
    size_t i, n = 0, data_chars = 0;
    uint32_t acc = 0;
    int bits = 0, v, pad = 0;

    if (!in || !out) return 0;

    for (i = 0; i < inlen; i++) {
        int c = (unsigned char)in[i];
        if (c == '=') {
            pad++;
            continue;
        }
        if (pad) return 0; /* data after padding */
        v = b64_value(c);
        if (v < 0) {
            /* tolerate whitespace and line breaks */
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
            return 0;
        }
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        data_chars++;
        if (bits >= 8) {
            bits -= 8;
            if (n >= outcap) return 0;
            out[n++] = (uint8_t)((acc >> bits) & 0xff);
        }
    }

    /* A base64 group is four characters.  pad must make the total a multiple
     * of four, and the bits left over after the last whole byte must be zero;
     * without these checks "cGFzc3dvcmQ==" would decode as if it were valid. */
    if (pad > 2) return 0;
    if ((data_chars + (size_t)pad) % 4 != 0) return 0;
    if (pad > 0 && (acc & ((1u << bits) - 1u)) != 0) return 0;
    return n;
}

size_t vnc_decode_ciphertext(const char *in, size_t inlen, vnc_encoding enc,
                             uint8_t *out, size_t outcap) {
    if (!in || !out) return 0;

    switch (enc) {
    case VNC_ENC_HEX:
        return vnc_hex_decode(in, inlen, out, outcap);
    case VNC_ENC_BASE64:
        return vnc_base64_decode(in, inlen, out, outcap);
    case VNC_ENC_BINARY:
        if (inlen > outcap) return 0;
        memcpy(out, in, inlen);
        return inlen;
    case VNC_ENC_AUTO:
    default:
        break;
    }

    /* Text representations are tried before the raw-bytes interpretation.
     * Inferring "binary" from a 16 character string was exactly the mistake
     * vncpwd 0.2 made: a hex value of two DES blocks was read as 16 raw
     * bytes.  Binary is only assumed when nothing textual decodes. */
    if (vnc_hex_is_valid(in, inlen) && inlen / 2 <= outcap) {
        return vnc_hex_decode(in, inlen, out, outcap);
    }
    if (inlen % 4 == 0) {
        size_t n = vnc_base64_decode(in, inlen, out, outcap);
        if (n) return n;
    }
    if ((inlen == 8 || inlen == 16) && inlen <= outcap) {
        memcpy(out, in, inlen);
        return inlen;
    }
    return 0;
}
