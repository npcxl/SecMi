/**
 * SM3 密码杂凑算法实现（GB/T 32905-2016）
 * 单块 512 bit，输出 256 bit。
 */
#include "sm3.h"
#include <stdlib.h>
#include <string.h>

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static uint32_t P0(uint32_t x) {
    return x ^ ROL32(x, 9) ^ ROL32(x, 17);
}

static uint32_t P1(uint32_t x) {
    return x ^ ROL32(x, 15) ^ ROL32(x, 23);
}

static uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16)
        return x ^ y ^ z;
    return (x & y) | (x & z) | (y & z);
}

static uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16)
        return x ^ y ^ z;
    return (x & y) | ((~x) & z);
}

static void sm3_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[68];
    uint32_t W1[64];
    int j;
    for (j = 0; j < 16; j++) {
        const uint8_t *p = block + j * 4;
        W[j] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }
    for (j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROL32(W[j - 3], 15)) ^
               ROL32(W[j - 13], 7) ^ W[j - 6];
    }
    for (j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j + 4];
    }

    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

    for (j = 0; j < 64; j++) {
        uint32_t T = (j < 16) ? 0x79CC4519u : 0x7A879D8Au;
        uint32_t SS1 = ROL32((ROL32(A, 12) + E + ROL32(T, (unsigned)j)) & 0xFFFFFFFFu, 7);
        uint32_t SS2 = SS1 ^ ROL32(A, 12);
        uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];
        D = C;
        C = ROL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROL32(F, 19);
        F = E;
        E = P0(TT2);
    }

    state[0] ^= A;
    state[1] ^= B;
    state[2] ^= C;
    state[3] ^= D;
    state[4] ^= E;
    state[5] ^= F;
    state[6] ^= G;
    state[7] ^= H;
}

void sm3_digest(const uint8_t *msg, size_t len, uint8_t out[SM3_DIGEST_SIZE]) {
    /* 初始值 IV（GB/T 32905-2016） */
    uint32_t state[8] = {
        0x7380166Fu, 0x4914B2B9u, 0x172442D7u, 0xDA8A0600u,
        0xA96F30BCu, 0x163138AAu, 0xE38DEE4Du, 0xB0FB0E4Eu
    };

    uint8_t block[64];
    size_t i = 0;
    /* 按 64 字节块处理（除最后一块） */
    while (len - i >= 64) {
        sm3_compress(state, msg + i);
        i += 64;
    }

    size_t rem = len - i;
    memcpy(block, msg + i, rem);
    block[rem] = 0x80;
    if (rem + 1 <= 56) {
        memset(block + rem + 1, 0, 55 - rem);
    } else {
        memset(block + rem + 1, 0, 64 - rem - 1);
        sm3_compress(state, block);
        memset(block, 0, 56);
    }
    /* 比特长度：len * 8，64 位大端 */
    uint64_t bitlen = (uint64_t)len * 8u;
    for (int k = 0; k < 8; k++) {
        block[56 + k] = (uint8_t)((bitlen >> (56 - 8 * k)) & 0xFFu);
    }
    sm3_compress(state, block);

    for (int k = 0; k < 8; k++) {
        out[k * 4 + 0] = (uint8_t)((state[k] >> 24) & 0xFFu);
        out[k * 4 + 1] = (uint8_t)((state[k] >> 16) & 0xFFu);
        out[k * 4 + 2] = (uint8_t)((state[k] >> 8) & 0xFFu);
        out[k * 4 + 3] = (uint8_t)(state[k] & 0xFFu);
    }
}

#define SM3_HMAC_B 64

void sm3_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
              uint8_t out[SM3_DIGEST_SIZE]) {
    uint8_t k[SM3_HMAC_B];
    memset(k, 0, sizeof k);
    if (key_len > SM3_HMAC_B) {
        sm3_digest(key, key_len, k);
        key_len = SM3_DIGEST_SIZE;
    } else if (key_len) {
        memcpy(k, key, key_len);
    }
    uint8_t ipad[SM3_HMAC_B], opad[SM3_HMAC_B];
    size_t i;
    for (i = 0; i < SM3_HMAC_B; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    size_t inner_len = SM3_HMAC_B + msg_len;
    uint8_t *inner_buf = (uint8_t *)malloc(inner_len);
    if (!inner_buf) {
        memset(out, 0, SM3_DIGEST_SIZE);
        return;
    }
    memcpy(inner_buf, ipad, SM3_HMAC_B);
    memcpy(inner_buf + SM3_HMAC_B, msg, msg_len);
    uint8_t inner_hash[SM3_DIGEST_SIZE];
    sm3_digest(inner_buf, inner_len, inner_hash);
    free(inner_buf);

    uint8_t outer_buf[SM3_HMAC_B + SM3_DIGEST_SIZE];
    memcpy(outer_buf, opad, SM3_HMAC_B);
    memcpy(outer_buf + SM3_HMAC_B, inner_hash, SM3_DIGEST_SIZE);
    sm3_digest(outer_buf, SM3_HMAC_B + SM3_DIGEST_SIZE, out);
}
