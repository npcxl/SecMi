/**
 * SM4 分组密码实现（GM/T 0002-2012）
 */
#include "sm4.h"
#include <string.h>

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/*
 * S 盒现行版（与 GmSSL/OpenSSL 256 字节表一致，末行末四字节为勘误值 d7 cb 39 48）。
 */
static const uint8_t sm4_sbox_table_modern[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

/*
 * 早期印刷版 S 盒：前 208 字节与现行相同；末两行按旧表分列为 0x89 行、0x18…（末四字节 7c 37 6f 81）、
 * 以及独立末行 b2…0e（与现行合并末行不同）。
 */
static const uint8_t sm4_sbox_table_legacy[256] = {
    /* 0..207：与现行表相同（前 13 行） */
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    /* 208..255：早期印刷版末三行（前 208 字节同现行 0..207，不含现行表中随后的 0x0a 行） */
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0x7c, 0x37, 0x6f, 0x81,
    0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35, 0x1e, 0x24, 0x0e
};

static const uint8_t *sm4_sbox_active = sm4_sbox_table_modern;

void sm4_set_sbox_version(sm4_sbox_version_t ver) {
    sm4_sbox_active = (ver == SM4_SBOX_VER_LEGACY_PRINT) ? sm4_sbox_table_legacy : sm4_sbox_table_modern;
}

static const uint32_t SM4_FK[4] = {
    0xa3b1bac6u, 0x56aa3350u, 0x677d9197u, 0xb27022dcu
};

static const uint32_t SM4_CK[32] = {
    0x00070e15u, 0x1c232a31u, 0x383f464du, 0x545b6269u,
    0x70777e85u, 0x8c939aa1u, 0xa8afb6bdu, 0xc4cbd2d9u,
    0xe0e7eef5u, 0xfc030a11u, 0x181f262du, 0x343b4249u,
    0x50575e65u, 0x6c737a81u, 0x888f969du, 0xa4abb2b9u,
    0xc0c7ced5u, 0xdce3eaf1u, 0xf8ff060du, 0x141b2229u,
    0x30373e45u, 0x4c535a61u, 0x686f767du, 0x848b9299u,
    0xa0a7aeb5u, 0xbcc3cad1u, 0xd8dfe6edu, 0xf4fb0209u,
    0x10171e25u, 0x2c333a41u, 0x484f565du, 0x646b7279u
};

static uint32_t sm4_tau(uint32_t a) {
    uint8_t b0 = (uint8_t)(a >> 24), b1 = (uint8_t)(a >> 16);
    uint8_t b2 = (uint8_t)(a >> 8), b3 = (uint8_t)a;
    uint32_t sb = ((uint32_t)sm4_sbox_active[b0] << 24) | ((uint32_t)sm4_sbox_active[b1] << 16) |
                  ((uint32_t)sm4_sbox_active[b2] << 8) | (uint32_t)sm4_sbox_active[b3];
    return sb;
}

static uint32_t sm4_L(uint32_t b) {
    return b ^ ROL32(b, 2) ^ ROL32(b, 10) ^ ROL32(b, 18) ^ ROL32(b, 24);
}

static uint32_t sm4_L_key(uint32_t b) {
    return b ^ ROL32(b, 13) ^ ROL32(b, 23);
}

static uint32_t sm4_T(uint32_t x) {
    return sm4_L(sm4_tau(x));
}

static uint32_t sm4_T_key(uint32_t x) {
    return sm4_L_key(sm4_tau(x));
}

static uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

void sm4_set_key(const uint8_t key[SM4_KEY_SIZE], uint32_t rk[32]) {
    uint32_t mk[4];
    int i;
    for (i = 0; i < 4; i++) {
        mk[i] = load_be32(key + i * 4) ^ SM4_FK[i];
    }
    uint32_t k[36];
    k[0] = mk[0];
    k[1] = mk[1];
    k[2] = mk[2];
    k[3] = mk[3];
    for (i = 0; i < 32; i++) {
        k[i + 4] = k[i] ^ sm4_T_key(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]);
        rk[i] = k[i + 4];
    }
}

void sm4_encrypt_block(const uint32_t rk[32], const uint8_t plain[SM4_BLOCK_SIZE],
                       uint8_t cipher[SM4_BLOCK_SIZE]) {
    uint32_t x0 = load_be32(plain);
    uint32_t x1 = load_be32(plain + 4);
    uint32_t x2 = load_be32(plain + 8);
    uint32_t x3 = load_be32(plain + 12);
    int i;
    for (i = 0; i < 32; i++) {
        uint32_t t = sm4_T(x1 ^ x2 ^ x3 ^ rk[i]);
        uint32_t x4 = x0 ^ t;
        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = x4;
    }
    store_be32(cipher, x3);
    store_be32(cipher + 4, x2);
    store_be32(cipher + 8, x1);
    store_be32(cipher + 12, x0);
}

void sm4_decrypt_block(const uint32_t rk[32], const uint8_t cipher[SM4_BLOCK_SIZE],
                       uint8_t plain[SM4_BLOCK_SIZE]) {
    uint32_t drk[32];
    int i;
    for (i = 0; i < 32; i++) {
        drk[i] = rk[31 - i];
    }
    sm4_encrypt_block(drk, cipher, plain);
}

size_t sm4_cbc_encrypt_pkcs7(const uint8_t key[SM4_KEY_SIZE],
                             const uint8_t iv[SM4_BLOCK_SIZE],
                             const uint8_t *in, size_t in_len,
                             uint8_t *out) {
    uint32_t rk[32];
    sm4_set_key(key, rk);

    size_t pad = SM4_BLOCK_SIZE - (in_len % SM4_BLOCK_SIZE);
    if (pad == 0) {
        pad = SM4_BLOCK_SIZE;
    }
    size_t total = in_len + pad;
    uint8_t buf[SM4_BLOCK_SIZE];
    uint8_t chain[SM4_BLOCK_SIZE];
    memcpy(chain, iv, SM4_BLOCK_SIZE);

    size_t offset = 0;
    size_t remaining = in_len;
    const uint8_t *p = in;

    while (remaining >= SM4_BLOCK_SIZE) {
        size_t j;
        for (j = 0; j < SM4_BLOCK_SIZE; j++) {
            buf[j] = p[j] ^ chain[j];
        }
        sm4_encrypt_block(rk, buf, out + offset);
        memcpy(chain, out + offset, SM4_BLOCK_SIZE);
        offset += SM4_BLOCK_SIZE;
        p += SM4_BLOCK_SIZE;
        remaining -= SM4_BLOCK_SIZE;
    }

    memset(buf, 0, SM4_BLOCK_SIZE);
    memcpy(buf, p, remaining);
    {
        size_t j;
        for (j = remaining; j < SM4_BLOCK_SIZE; j++) {
            buf[j] = (uint8_t)pad;
        }
    }
    {
        size_t j;
        for (j = 0; j < SM4_BLOCK_SIZE; j++) {
            buf[j] ^= chain[j];
        }
    }
    sm4_encrypt_block(rk, buf, out + offset);

    return total;
}

size_t sm4_cbc_decrypt_pkcs7(const uint8_t key[SM4_KEY_SIZE],
                             const uint8_t iv[SM4_BLOCK_SIZE],
                             const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t out_cap) {
    if (in_len == 0 || (in_len % SM4_BLOCK_SIZE) != 0) {
        return 0;
    }
    if (out_cap < in_len) {
        return 0;
    }

    uint32_t rk[32];
    sm4_set_key(key, rk);

    uint8_t chain[SM4_BLOCK_SIZE];
    memcpy(chain, iv, SM4_BLOCK_SIZE);

    size_t blocks = in_len / SM4_BLOCK_SIZE;
    size_t b;
    for (b = 0; b < blocks; b++) {
        uint8_t ct[SM4_BLOCK_SIZE];
        memcpy(ct, in + b * SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);
        uint8_t pt[SM4_BLOCK_SIZE];
        sm4_decrypt_block(rk, ct, pt);
        size_t j;
        for (j = 0; j < SM4_BLOCK_SIZE; j++) {
            out[b * SM4_BLOCK_SIZE + j] = pt[j] ^ chain[j];
        }
        memcpy(chain, ct, SM4_BLOCK_SIZE);
    }

    uint8_t pad = out[in_len - 1];
    if (pad == 0 || pad > SM4_BLOCK_SIZE) {
        return 0;
    }
    if (in_len < pad) {
        return 0;
    }
    size_t j;
    for (j = 0; j < pad; j++) {
        if (out[in_len - 1 - j] != pad) {
            return 0;
        }
    }
    return in_len - pad;
}

size_t sm4_ecb_encrypt_pkcs7(const uint8_t key[SM4_KEY_SIZE], const uint8_t *in, size_t in_len,
                             uint8_t *out) {
    uint32_t rk[32];
    sm4_set_key(key, rk);

    size_t pad = SM4_BLOCK_SIZE - (in_len % SM4_BLOCK_SIZE);
    if (pad == 0) {
        pad = SM4_BLOCK_SIZE;
    }
    size_t total = in_len + pad;
    uint8_t buf[SM4_BLOCK_SIZE];

    size_t offset = 0;
    size_t remaining = in_len;
    const uint8_t *p = in;

    while (remaining >= SM4_BLOCK_SIZE) {
        memcpy(buf, p, SM4_BLOCK_SIZE);
        sm4_encrypt_block(rk, buf, out + offset);
        offset += SM4_BLOCK_SIZE;
        p += SM4_BLOCK_SIZE;
        remaining -= SM4_BLOCK_SIZE;
    }

    memset(buf, 0, SM4_BLOCK_SIZE);
    memcpy(buf, p, remaining);
    {
        size_t j;
        for (j = remaining; j < SM4_BLOCK_SIZE; j++) {
            buf[j] = (uint8_t)pad;
        }
    }
    sm4_encrypt_block(rk, buf, out + offset);

    return total;
}

size_t sm4_ecb_decrypt_pkcs7(const uint8_t key[SM4_KEY_SIZE], const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t out_cap) {
    if (in_len == 0 || (in_len % SM4_BLOCK_SIZE) != 0) {
        return 0;
    }
    if (out_cap < in_len) {
        return 0;
    }

    uint32_t rk[32];
    sm4_set_key(key, rk);

    size_t blocks = in_len / SM4_BLOCK_SIZE;
    size_t b;
    for (b = 0; b < blocks; b++) {
        sm4_decrypt_block(rk, in + b * SM4_BLOCK_SIZE, out + b * SM4_BLOCK_SIZE);
    }

    uint8_t pad = out[in_len - 1];
    if (pad == 0 || pad > SM4_BLOCK_SIZE) {
        return 0;
    }
    if (in_len < pad) {
        return 0;
    }
    size_t j;
    for (j = 0; j < pad; j++) {
        if (out[in_len - 1 - j] != pad) {
            return 0;
        }
    }
    return in_len - pad;
}

static void sm4_ctr_inc(uint8_t ctr[SM4_BLOCK_SIZE]) {
    int i;
    for (i = (int)SM4_BLOCK_SIZE - 1; i >= 0; i--) {
        if (++ctr[i]) {
            return;
        }
    }
}

void sm4_ctr_crypt(const uint8_t key[SM4_KEY_SIZE], const uint8_t iv[SM4_BLOCK_SIZE],
                   const uint8_t *in, size_t in_len, uint8_t *out) {
    uint32_t rk[32];
    sm4_set_key(key, rk);
    uint8_t ctr[SM4_BLOCK_SIZE];
    memcpy(ctr, iv, SM4_BLOCK_SIZE);
    size_t off = 0;
    while (off < in_len) {
        uint8_t ks[SM4_BLOCK_SIZE];
        sm4_encrypt_block(rk, ctr, ks);
        size_t chunk = in_len - off;
        if (chunk > SM4_BLOCK_SIZE) {
            chunk = SM4_BLOCK_SIZE;
        }
        size_t j;
        for (j = 0; j < chunk; j++) {
            out[off + j] = (uint8_t)(in[off + j] ^ ks[j]);
        }
        off += chunk;
        sm4_ctr_inc(ctr);
    }
}

void sm4_ofb128_crypt(const uint8_t key[SM4_KEY_SIZE], const uint8_t iv[SM4_BLOCK_SIZE],
                      const uint8_t *in, size_t in_len, uint8_t *out) {
    uint32_t rk[32];
    sm4_set_key(key, rk);
    uint8_t chain[SM4_BLOCK_SIZE];
    memcpy(chain, iv, SM4_BLOCK_SIZE);
    size_t off = 0;
    while (off < in_len) {
        uint8_t o[SM4_BLOCK_SIZE];
        sm4_encrypt_block(rk, chain, o);
        size_t chunk = in_len - off;
        if (chunk > SM4_BLOCK_SIZE) {
            chunk = SM4_BLOCK_SIZE;
        }
        size_t j;
        for (j = 0; j < chunk; j++) {
            out[off + j] = (uint8_t)(in[off + j] ^ o[j]);
        }
        off += chunk;
        memcpy(chain, o, SM4_BLOCK_SIZE);
    }
}

size_t sm4_cfb128_crypt(const uint8_t key[SM4_KEY_SIZE], const uint8_t iv[SM4_BLOCK_SIZE],
                        const uint8_t *in, size_t in_len, uint8_t *out) {
    if (in_len % SM4_BLOCK_SIZE != 0) {
        return 0;
    }
    uint32_t rk[32];
    sm4_set_key(key, rk);
    uint8_t chain[SM4_BLOCK_SIZE];
    memcpy(chain, iv, SM4_BLOCK_SIZE);
    size_t nb = in_len / SM4_BLOCK_SIZE;
    size_t b;
    for (b = 0; b < nb; b++) {
        uint8_t o[SM4_BLOCK_SIZE];
        sm4_encrypt_block(rk, chain, o);
        size_t j;
        for (j = 0; j < SM4_BLOCK_SIZE; j++) {
            out[b * SM4_BLOCK_SIZE + j] = (uint8_t)(in[b * SM4_BLOCK_SIZE + j] ^ o[j]);
        }
        memcpy(chain, out + b * SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);
    }
    return in_len;
}
