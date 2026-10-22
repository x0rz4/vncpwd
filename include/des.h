/*
 * DES (single-length key) derived from D3DES V5.09 by Richard Outerbridge,
 * as modified for VNC by AT&T Laboratories Cambridge and Luigi Auriemma.
 *
 * The arithmetic has been narrowed to uint32_t.  The original code used
 * `unsigned long`, which is 64-bit on LP64 platforms and silently produced
 * wrong results there (rotations wrapped at 64 bits instead of 32).
 */
#ifndef VNCPWD_DES_H
#define VNCPWD_DES_H

#include <stdint.h>
#include <stddef.h>

#define DES_BLOCK_SIZE 8

#define DES_MODE_ENCRYPT 0
#define DES_MODE_DECRYPT 1

void des_key(const uint8_t key[DES_BLOCK_SIZE], int mode);
void des_block(const uint8_t in[DES_BLOCK_SIZE], uint8_t out[DES_BLOCK_SIZE]);

#endif /* VNCPWD_DES_H */
