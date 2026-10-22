#include "legacy_des.h"
#include "des.h"

#include <string.h>

/*
 * Every VNC implementation has used this key since the original AT&T code.
 * It is public: the "encryption" of a stored VNC password provides no
 * confidentiality, only obfuscation.  That is the point of the audit.
 */
const uint8_t vnc_fixed_des_key[8] = {23, 82, 107, 6, 35, 78, 88, 7};

int vnc_des_decrypt(const uint8_t *cipher, size_t cipher_len, vnc_des_result *out) {
    uint8_t block[DES_BLOCK_SIZE];
    size_t off, i, n = 0;

    if (!cipher || !out) return VNC_DES_ERR_NULL;
    if (cipher_len != 8 && cipher_len != 16) return VNC_DES_ERR_LENGTH;

    memset(out, 0, sizeof(*out));
    out->blocks = (int)(cipher_len / 8);

    des_key(vnc_fixed_des_key, DES_MODE_DECRYPT);

    for (off = 0; off < cipher_len; off += 8) {
        des_block(cipher + off, block);
        for (i = 0; i < 8; i++) {
            /* A trailing all-zero block carries no password bytes. */
            if (off == 8 && n == 8) {
                int zero = 1;
                size_t k;
                for (k = 0; k < 8; k++) {
                    if (block[k] != 0) { zero = 0; break; }
                }
                if (zero) break;
            }
            out->plain[n++] = block[i];
        }
    }

    /* Trim only the trailing zero padding; embedded NULs are preserved so the
     * validator can flag them. */
    while (n > 0 && out->plain[n - 1] == 0) n--;
    out->plain[n] = 0;
    out->length = n;
    return VNC_DES_OK;
}

int vnc_des_encrypt(const uint8_t *plain, size_t plain_len, uint8_t *out, size_t outcap) {
    uint8_t block[DES_BLOCK_SIZE];
    size_t blocks, i;

    if (!plain || !out) return VNC_DES_ERR_NULL;
    if (plain_len > VNC_MAX_PASSWORD) return VNC_DES_ERR_LENGTH;
    blocks = (plain_len + 7) / 8;
    if (blocks == 0) blocks = 1;
    if (blocks * 8 > outcap) return VNC_DES_ERR_LENGTH;

    des_key(vnc_fixed_des_key, DES_MODE_ENCRYPT);
    for (i = 0; i < blocks; i++) {
        memset(block, 0, sizeof(block));
        if (i == 0) {
            size_t take = plain_len < 8 ? plain_len : 8;
            memcpy(block, plain, take);
        } else {
            size_t start = 8;
            size_t take = plain_len - start;
            if (take > 8) take = 8;
            memcpy(block, plain + start, take);
        }
        des_block(block, out + i * 8);
    }
    return (int)(blocks * 8);
}
