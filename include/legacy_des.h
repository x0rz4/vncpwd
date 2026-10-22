#ifndef VNCPWD_LEGACY_DES_H
#define VNCPWD_LEGACY_DES_H

#include <stddef.h>
#include <stdint.h>

/* The fixed key every VNC implementation has shipped since 1998. */
extern const uint8_t vnc_fixed_des_key[8];

#define VNC_CIPHERTEXT_MIN 8
#define VNC_CIPHERTEXT_MAX 16
#define VNC_MAX_PASSWORD   16

typedef struct {
    uint8_t plain[VNC_MAX_PASSWORD + 1]; /* NUL terminated for convenience */
    size_t  length;                      /* number of significant bytes */
    int     blocks;                      /* 1 or 2 */
} vnc_des_result;

enum {
    VNC_DES_OK = 0,
    VNC_DES_ERR_NULL = -1,
    VNC_DES_ERR_LENGTH = -2,   /* not 8 or 16 bytes */
};

/* Decrypt one or two 8-byte blocks.  Blocks that decrypt to an all-zero
 * plaintext contribute no characters, which is how a password shorter than
 * 8 bytes is represented on the wire. */
int vnc_des_decrypt(const uint8_t *cipher, size_t cipher_len, vnc_des_result *out);

/* Encrypt a password the way VNC clients do: zero padded to a block. */
int vnc_des_encrypt(const uint8_t *plain, size_t plain_len, uint8_t *out, size_t outcap);

#endif /* VNCPWD_LEGACY_DES_H */
