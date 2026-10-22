#ifndef VNCPWD_FORMAT_VALIDATOR_H
#define VNCPWD_FORMAT_VALIDATOR_H

#include <stddef.h>
#include <stdint.h>
#include "legacy_des.h"

/*
 * DES will happily decrypt any 8-byte blob into 8 bytes.  There is no MAC
 * and no padding check, so "it decrypted" says nothing.  Validation is
 * therefore heuristic: a real VNC password is 1..8 printable ASCII bytes
 * followed by NUL padding.  The confidence value exposes how well the
 * plaintext matches that shape, so callers can refuse to print garbage.
 */
typedef struct {
    int     valid;
    double  confidence;      /* 0.0 .. 1.0 */
    int     printable_ratio; /* 0 .. 100 */
    int     padding_ok;      /* trailing bytes after the password are NUL */
    size_t  length;
    uint8_t plain[VNC_MAX_PASSWORD + 1];
    const char *reason;
} vnc_validation;

/* Validate ciphertext length, then decrypt and score the plaintext. */
int vnc_validate_ciphertext(const uint8_t *cipher, size_t len, vnc_validation *out);

/* Score an already decrypted plaintext. */
int vnc_validate_plaintext(const uint8_t *plain, size_t len, vnc_validation *out);

/* Confidence at or above this value is treated as "a password was found". */
#define VNC_CONFIDENCE_ACCEPT 0.60

#endif /* VNCPWD_FORMAT_VALIDATOR_H */
