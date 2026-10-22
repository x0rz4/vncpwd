/*
 * DES (single-length key, no 3DES support) derived from D3DES V5.09.
 *
 * Original: Copyright (c) 1988,1989,1990,1991,1992 Richard Outerbridge.
 * VNC changes: Copyright (C) 1999 AT&T Laboratories Cambridge.
 *
 * Rewritten to use uint32_t throughout: the original relied on `unsigned
 * long` being 32 bits, which holds on Windows/ILP32 but not on Linux/macOS
 * LP64, where the rotations and the 0xffffffff mask are wrong and every
 * decryption produces garbage.
 */
#include "des.h"

#include <string.h>

static uint32_t key_schedule[32];

static const uint8_t bytebit[8] = {01, 02, 04, 010, 020, 040, 0100, 0200};

static const uint32_t bigbyte[24] = {
    0x800000UL, 0x400000UL, 0x200000UL, 0x100000UL,
    0x80000UL,  0x40000UL,  0x20000UL,  0x10000UL,
    0x8000UL,   0x4000UL,   0x2000UL,   0x1000UL,
    0x800UL,    0x400UL,    0x200UL,    0x100UL,
    0x80UL,     0x40UL,     0x20UL,     0x10UL,
    0x8UL,      0x4UL,      0x2UL,      0x1UL
};

static const uint8_t pc1[56] = {
    56, 48, 40, 32, 24, 16,  8,   0, 57, 49, 41, 33, 25, 17,
     9,  1, 58, 50, 42, 34, 26,  18, 10,  2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14,   6, 61, 53, 45, 37, 29, 21,
    13,  5, 60, 52, 44, 36, 28,  20, 12,  4, 27, 19, 11,  3
};

static const uint8_t totrot[16] = {
    1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
};

static const uint8_t pc2[48] = {
    13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
    22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
    40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
};

static const uint32_t SP1[64] = {
    0x01010400UL, 0x00000000UL, 0x00010000UL, 0x01010404UL,
    0x01010004UL, 0x00010404UL, 0x00000004UL, 0x00010000UL,
    0x00000400UL, 0x01010400UL, 0x01010404UL, 0x00000400UL,
    0x01000404UL, 0x01010004UL, 0x01000000UL, 0x00000004UL,
    0x00000404UL, 0x01000400UL, 0x01000400UL, 0x00010400UL,
    0x00010400UL, 0x01010000UL, 0x01010000UL, 0x01000404UL,
    0x00010004UL, 0x01000004UL, 0x01000004UL, 0x00010004UL,
    0x00000000UL, 0x00000404UL, 0x00010404UL, 0x01000000UL,
    0x00010000UL, 0x01010404UL, 0x00000004UL, 0x01010000UL,
    0x01010400UL, 0x01000000UL, 0x01000000UL, 0x00000400UL,
    0x01010004UL, 0x00010000UL, 0x00010400UL, 0x01000004UL,
    0x00000400UL, 0x00000004UL, 0x01000404UL, 0x00010404UL,
    0x01010404UL, 0x00010004UL, 0x01010000UL, 0x01000404UL,
    0x01000004UL, 0x00000404UL, 0x00010404UL, 0x01010400UL,
    0x00000404UL, 0x01000400UL, 0x01000400UL, 0x00000000UL,
    0x00010004UL, 0x00010400UL, 0x00000000UL, 0x01010004UL
};

static const uint32_t SP2[64] = {
    0x80108020UL, 0x80008000UL, 0x00008000UL, 0x00108020UL,
    0x00100000UL, 0x00000020UL, 0x80100020UL, 0x80008020UL,
    0x80000020UL, 0x80108020UL, 0x80108000UL, 0x80000000UL,
    0x80008000UL, 0x00100000UL, 0x00000020UL, 0x80100020UL,
    0x00108000UL, 0x00100020UL, 0x80008020UL, 0x00000000UL,
    0x80000000UL, 0x00008000UL, 0x00108020UL, 0x80100000UL,
    0x00100020UL, 0x80000020UL, 0x00000000UL, 0x00108000UL,
    0x00008020UL, 0x80108000UL, 0x80100000UL, 0x00008020UL,
    0x00000000UL, 0x00108020UL, 0x80100020UL, 0x00100000UL,
    0x80008020UL, 0x80100000UL, 0x80108000UL, 0x00008000UL,
    0x80100000UL, 0x80008000UL, 0x00000020UL, 0x80108020UL,
    0x00108020UL, 0x00000020UL, 0x00008000UL, 0x80000000UL,
    0x00008020UL, 0x80108000UL, 0x00100000UL, 0x80000020UL,
    0x00100020UL, 0x80008020UL, 0x80000020UL, 0x00100020UL,
    0x00108000UL, 0x00000000UL, 0x80008000UL, 0x00008020UL,
    0x80000000UL, 0x80100020UL, 0x80108020UL, 0x00108000UL
};

static const uint32_t SP3[64] = {
    0x00000208UL, 0x08020200UL, 0x00000000UL, 0x08020008UL,
    0x08000200UL, 0x00000000UL, 0x00020208UL, 0x08000200UL,
    0x00020008UL, 0x08000008UL, 0x08000008UL, 0x00020000UL,
    0x08020208UL, 0x00020008UL, 0x08020000UL, 0x00000208UL,
    0x08000000UL, 0x00000008UL, 0x08020200UL, 0x00000200UL,
    0x00020200UL, 0x08020000UL, 0x08020008UL, 0x00020208UL,
    0x08000208UL, 0x00020200UL, 0x00020000UL, 0x08000208UL,
    0x00000008UL, 0x08020208UL, 0x00000200UL, 0x08000000UL,
    0x08020200UL, 0x08000000UL, 0x00020008UL, 0x00000208UL,
    0x00020000UL, 0x08020200UL, 0x08000200UL, 0x00000000UL,
    0x00000200UL, 0x00020008UL, 0x08020208UL, 0x08000200UL,
    0x08000008UL, 0x00000200UL, 0x00000000UL, 0x08020008UL,
    0x08000208UL, 0x00020000UL, 0x08000000UL, 0x08020208UL,
    0x00000008UL, 0x00020208UL, 0x00020200UL, 0x08000008UL,
    0x08020000UL, 0x08000208UL, 0x00000208UL, 0x08020000UL,
    0x00020208UL, 0x00000008UL, 0x08020008UL, 0x00020200UL
};

static const uint32_t SP4[64] = {
    0x00802001UL, 0x00002081UL, 0x00002081UL, 0x00000080UL,
    0x00802080UL, 0x00800081UL, 0x00800001UL, 0x00002001UL,
    0x00000000UL, 0x00802000UL, 0x00802000UL, 0x00802081UL,
    0x00000081UL, 0x00000000UL, 0x00800080UL, 0x00800001UL,
    0x00000001UL, 0x00002000UL, 0x00800000UL, 0x00802001UL,
    0x00000080UL, 0x00800000UL, 0x00002001UL, 0x00002080UL,
    0x00800081UL, 0x00000001UL, 0x00002080UL, 0x00800080UL,
    0x00002000UL, 0x00802080UL, 0x00802081UL, 0x00000081UL,
    0x00800080UL, 0x00800001UL, 0x00802000UL, 0x00802081UL,
    0x00000081UL, 0x00000000UL, 0x00000000UL, 0x00802000UL,
    0x00002080UL, 0x00800080UL, 0x00800081UL, 0x00000001UL,
    0x00802001UL, 0x00002081UL, 0x00002081UL, 0x00000080UL,
    0x00802081UL, 0x00000081UL, 0x00000001UL, 0x00002000UL,
    0x00800001UL, 0x00002001UL, 0x00802080UL, 0x00800081UL,
    0x00002001UL, 0x00002080UL, 0x00800000UL, 0x00802001UL,
    0x00000080UL, 0x00800000UL, 0x00002000UL, 0x00802080UL
};

static const uint32_t SP5[64] = {
    0x00000100UL, 0x02080100UL, 0x02080000UL, 0x42000100UL,
    0x00080000UL, 0x00000100UL, 0x40000000UL, 0x02080000UL,
    0x40080100UL, 0x00080000UL, 0x02000100UL, 0x40080100UL,
    0x42000100UL, 0x42080000UL, 0x00080100UL, 0x40000000UL,
    0x02000000UL, 0x40080000UL, 0x40080000UL, 0x00000000UL,
    0x40000100UL, 0x42080100UL, 0x42080100UL, 0x02000100UL,
    0x42080000UL, 0x40000100UL, 0x00000000UL, 0x42000000UL,
    0x02080100UL, 0x02000000UL, 0x42000000UL, 0x00080100UL,
    0x00080000UL, 0x42000100UL, 0x00000100UL, 0x02000000UL,
    0x40000000UL, 0x02080000UL, 0x42000100UL, 0x40080100UL,
    0x02000100UL, 0x40000000UL, 0x42080000UL, 0x02080100UL,
    0x40080100UL, 0x00000100UL, 0x02000000UL, 0x42080000UL,
    0x42080100UL, 0x00080100UL, 0x42000000UL, 0x42080100UL,
    0x02080000UL, 0x00000000UL, 0x40080000UL, 0x42000000UL,
    0x00080100UL, 0x02000100UL, 0x40000100UL, 0x00080000UL,
    0x00000000UL, 0x40080000UL, 0x02080100UL, 0x40000100UL
};

static const uint32_t SP6[64] = {
    0x20000010UL, 0x20400000UL, 0x00004000UL, 0x20404010UL,
    0x20400000UL, 0x00000010UL, 0x20404010UL, 0x00400000UL,
    0x20004000UL, 0x00404010UL, 0x00400000UL, 0x20000010UL,
    0x00400010UL, 0x20004000UL, 0x20000000UL, 0x00004010UL,
    0x00000000UL, 0x00400010UL, 0x20004010UL, 0x00004000UL,
    0x00404000UL, 0x20004010UL, 0x00000010UL, 0x20400010UL,
    0x20400010UL, 0x00000000UL, 0x00404010UL, 0x20404000UL,
    0x00004010UL, 0x00404000UL, 0x20404000UL, 0x20000000UL,
    0x20004000UL, 0x00000010UL, 0x20400010UL, 0x00404000UL,
    0x20404010UL, 0x00400000UL, 0x00004010UL, 0x20000010UL,
    0x00400000UL, 0x20004000UL, 0x20000000UL, 0x00004010UL,
    0x20000010UL, 0x20404010UL, 0x00404000UL, 0x20400000UL,
    0x00404010UL, 0x20404000UL, 0x00000000UL, 0x20400010UL,
    0x00000010UL, 0x00004000UL, 0x20400000UL, 0x00404010UL,
    0x00004000UL, 0x00400010UL, 0x20004010UL, 0x00000000UL,
    0x20404000UL, 0x20000000UL, 0x00400010UL, 0x20004010UL
};

static const uint32_t SP7[64] = {
    0x00200000UL, 0x04200002UL, 0x04000802UL, 0x00000000UL,
    0x00000800UL, 0x04000802UL, 0x00200802UL, 0x04200800UL,
    0x04200802UL, 0x00200000UL, 0x00000000UL, 0x04000002UL,
    0x00000002UL, 0x04000000UL, 0x04200002UL, 0x00000802UL,
    0x04000800UL, 0x00200802UL, 0x00200002UL, 0x04000800UL,
    0x04000002UL, 0x04200000UL, 0x04200800UL, 0x00200002UL,
    0x04200000UL, 0x00000800UL, 0x00000802UL, 0x04200802UL,
    0x00200800UL, 0x00000002UL, 0x04000000UL, 0x00200800UL,
    0x04000000UL, 0x00200800UL, 0x00200000UL, 0x04000802UL,
    0x04000802UL, 0x04200002UL, 0x04200002UL, 0x00000002UL,
    0x00200002UL, 0x04000000UL, 0x04000800UL, 0x00200000UL,
    0x04200800UL, 0x00000802UL, 0x00200802UL, 0x04200800UL,
    0x00000802UL, 0x04000002UL, 0x04200802UL, 0x04200000UL,
    0x00200800UL, 0x00000000UL, 0x00000002UL, 0x04200802UL,
    0x00000000UL, 0x00200802UL, 0x04200000UL, 0x00000800UL,
    0x04000002UL, 0x04000800UL, 0x00000800UL, 0x00200002UL
};

static const uint32_t SP8[64] = {
    0x10001040UL, 0x00001000UL, 0x00040000UL, 0x10041040UL,
    0x10000000UL, 0x10001040UL, 0x00000040UL, 0x10000000UL,
    0x00040040UL, 0x10040000UL, 0x10041040UL, 0x00041000UL,
    0x10041000UL, 0x00041040UL, 0x00001000UL, 0x00000040UL,
    0x10040000UL, 0x10000040UL, 0x10001000UL, 0x00001040UL,
    0x00041000UL, 0x00040040UL, 0x10040040UL, 0x10041000UL,
    0x00001040UL, 0x00000000UL, 0x00000000UL, 0x10040040UL,
    0x10000040UL, 0x10001000UL, 0x00041040UL, 0x00040000UL,
    0x00041040UL, 0x00040000UL, 0x10041000UL, 0x00001000UL,
    0x00000040UL, 0x10040040UL, 0x00001000UL, 0x00041040UL,
    0x10001000UL, 0x00000040UL, 0x10000040UL, 0x10040000UL,
    0x10040040UL, 0x10000000UL, 0x00040000UL, 0x10001040UL,
    0x00000000UL, 0x10041040UL, 0x00040040UL, 0x10000040UL,
    0x10040000UL, 0x10001000UL, 0x10001040UL, 0x00000000UL,
    0x10041040UL, 0x00041000UL, 0x00041000UL, 0x00001040UL,
    0x00001040UL, 0x00040040UL, 0x10000000UL, 0x10041000UL
};

static uint32_t rol32(uint32_t v, unsigned n) {
    return (v << n) | (v >> (32 - n));
}

void des_key(const uint8_t key[DES_BLOCK_SIZE], int mode) {
    uint8_t pc1m[56], pcr[56];
    uint32_t kn[32];
    int i, j, l, m, n;

    for (j = 0; j < 56; j++) {
        l = pc1[j];
        pc1m[j] = (key[l >> 3] & bytebit[l & 07]) ? 1 : 0;
    }

    for (i = 0; i < 16; i++) {
        m = (mode == DES_MODE_DECRYPT) ? ((15 - i) << 1) : (i << 1);
        n = m + 1;
        kn[m] = kn[n] = 0;

        for (j = 0; j < 28; j++) {
            l = j + totrot[i];
            pcr[j] = pc1m[(l < 28) ? l : (l - 28)];
        }
        for (j = 28; j < 56; j++) {
            l = j + totrot[i];
            pcr[j] = pc1m[(l < 56) ? l : (l - 28)];
        }
        for (j = 0; j < 24; j++) {
            if (pcr[pc2[j]])      kn[m] |= bigbyte[j];
            if (pcr[pc2[j + 24]]) kn[n] |= bigbyte[j];
        }
    }

    /* cook */
    {
        uint32_t dough[32];
        uint32_t *raw1 = kn;
        uint32_t *cook = dough;
        uint32_t *raw0;
        for (i = 0; i < 16; i++) {
            raw0 = raw1++;
            *cook    = (raw0[0] & 0x00fc0000UL) << 6;
            *cook   |= (raw0[0] & 0x00000fc0UL) << 10;
            *cook   |= (raw1[0] & 0x00fc0000UL) >> 10;
            *cook++ |= (raw1[0] & 0x00000fc0UL) >> 6;
            *cook    = (raw0[0] & 0x0003f000UL) << 12;
            *cook   |= (raw0[0] & 0x0000003fUL) << 16;
            *cook   |= (raw1[0] & 0x0003f000UL) >> 4;
            *cook++ |= (raw1[0] & 0x0000003fUL);
            raw1++;
        }
        memcpy(key_schedule, dough, sizeof(key_schedule));
    }
}

static void des_body(uint32_t block[2]) {
    uint32_t fval, work, right, leftt;
    const uint32_t *keys = key_schedule;
    int round;

    leftt = block[0];
    right = block[1];

    work = ((leftt >> 4) ^ right) & 0x0f0f0f0fUL;
    right ^= work;
    leftt ^= (work << 4);
    work = ((leftt >> 16) ^ right) & 0x0000ffffUL;
    right ^= work;
    leftt ^= (work << 16);
    work = ((right >> 2) ^ leftt) & 0x33333333UL;
    leftt ^= work;
    right ^= (work << 2);
    work = ((right >> 8) ^ leftt) & 0x00ff00ffUL;
    leftt ^= work;
    right ^= (work << 8);
    right = rol32(right, 1);
    work = (leftt ^ right) & 0xaaaaaaaaUL;
    leftt ^= work;
    right ^= work;
    leftt = rol32(leftt, 1);

    for (round = 0; round < 8; round++) {
        work  = rol32(right, 28);
        work ^= *keys++;
        fval  = SP7[ work         & 0x3fUL];
        fval |= SP5[(work >>  8) & 0x3fUL];
        fval |= SP3[(work >> 16) & 0x3fUL];
        fval |= SP1[(work >> 24) & 0x3fUL];
        work  = right ^ *keys++;
        fval |= SP8[ work         & 0x3fUL];
        fval |= SP6[(work >>  8) & 0x3fUL];
        fval |= SP4[(work >> 16) & 0x3fUL];
        fval |= SP2[(work >> 24) & 0x3fUL];
        leftt ^= fval;

        work  = rol32(leftt, 28);
        work ^= *keys++;
        fval  = SP7[ work         & 0x3fUL];
        fval |= SP5[(work >>  8) & 0x3fUL];
        fval |= SP3[(work >> 16) & 0x3fUL];
        fval |= SP1[(work >> 24) & 0x3fUL];
        work  = leftt ^ *keys++;
        fval |= SP8[ work         & 0x3fUL];
        fval |= SP6[(work >>  8) & 0x3fUL];
        fval |= SP4[(work >> 16) & 0x3fUL];
        fval |= SP2[(work >> 24) & 0x3fUL];
        right ^= fval;
    }

    right = ((right >> 1) | (right << 31));
    work = (leftt ^ right) & 0xaaaaaaaaUL;
    leftt ^= work;
    right ^= work;
    leftt = ((leftt >> 1) | (leftt << 31));
    work = ((leftt >> 8) ^ right) & 0x00ff00ffUL;
    right ^= work;
    leftt ^= (work << 8);
    work = ((leftt >> 2) ^ right) & 0x33333333UL;
    right ^= work;
    leftt ^= (work << 2);
    work = ((right >> 16) ^ leftt) & 0x0000ffffUL;
    leftt ^= work;
    right ^= (work << 16);
    work = ((right >> 4) ^ leftt) & 0x0f0f0f0fUL;
    leftt ^= work;
    right ^= (work << 4);

    block[0] = right;
    block[1] = leftt;
}

void des_block(const uint8_t in[DES_BLOCK_SIZE], uint8_t out[DES_BLOCK_SIZE]) {
    uint32_t work[2];

    work[0] = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
              ((uint32_t)in[2] << 8)  |  (uint32_t)in[3];
    work[1] = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) |
              ((uint32_t)in[6] << 8)  |  (uint32_t)in[7];

    des_body(work);

    out[0] = (uint8_t)(work[0] >> 24);
    out[1] = (uint8_t)(work[0] >> 16);
    out[2] = (uint8_t)(work[0] >> 8);
    out[3] = (uint8_t)(work[0]);
    out[4] = (uint8_t)(work[1] >> 24);
    out[5] = (uint8_t)(work[1] >> 16);
    out[6] = (uint8_t)(work[1] >> 8);
    out[7] = (uint8_t)(work[1]);
}
