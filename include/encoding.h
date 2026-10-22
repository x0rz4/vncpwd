#ifndef VNCPWD_ENCODING_H
#define VNCPWD_ENCODING_H

#include <stddef.h>
#include <stdint.h>

/* How a stored ciphertext is represented in the configuration store. */
typedef enum {
    VNC_ENC_UNKNOWN = 0,
    VNC_ENC_BINARY,   /* 8 (or 16) raw bytes, e.g. REG_BINARY */
    VNC_ENC_HEX,      /* ASCII hex, e.g. REG_SZ "dbd83cfd727a1458" */
    VNC_ENC_BASE64,   /* base64 of the hex string, e.g. Remmina */
    VNC_ENC_AUTO
} vnc_encoding;

const char *vnc_encoding_name(vnc_encoding enc);
int         vnc_encoding_parse(const char *name, vnc_encoding *out);

/* Returns the number of bytes decoded, or 0 when the input is malformed.
 * Hex input must have an even number of digits and contain only [0-9a-fA-F]. */
size_t vnc_hex_decode(const char *in, size_t inlen, uint8_t *out, size_t outcap);
size_t vnc_base64_decode(const char *in, size_t inlen, uint8_t *out, size_t outcap);
int    vnc_hex_is_valid(const char *in, size_t inlen);

/* Decode a stored value into ciphertext bytes.  VNC_ENC_AUTO accepts binary,
 * hex and base64 and picks the representation that decodes cleanly. */
size_t vnc_decode_ciphertext(const char *in, size_t inlen, vnc_encoding enc,
                             uint8_t *out, size_t outcap);

#endif /* VNCPWD_ENCODING_H */
