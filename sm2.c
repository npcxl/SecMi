/**
 * SM2 签名与验签（GB/T 32918.2-2016）
 * 曲线参数与 G 为推荐曲线 sm2p256v1。
 */
#include "sm2.h"
#include "sm3.h"
#include "sm2_z256.h"
#include <stdlib.h>
#include <string.h>

/* KDF(Z, klen_bits)：Z 为 64 字节，计数器为 32 位大端自 1 递增（GB/T 32918.4-2016）。 */
static int sm2_kdf(const uint8_t z[64], size_t klen_bits, uint8_t *out)
{
    if (klen_bits == 0) {
        return 1;
    }
    size_t out_bytes = (klen_bits + 7u) / 8u;
    uint32_t ct = 1u;
    size_t off = 0;
    while (off < out_bytes) {
        uint8_t ha[32];
        uint8_t in[68];
        memcpy(in, z, 64);
        in[64] = (uint8_t)(ct >> 24);
        in[65] = (uint8_t)(ct >> 16);
        in[66] = (uint8_t)(ct >> 8);
        in[67] = (uint8_t)ct;
        sm3_digest(in, 68, ha);
        size_t need = out_bytes - off;
        size_t copy = need > 32u ? 32u : need;
        memcpy(out + off, ha, copy);
        off += copy;
        ct++;
        if (ct == 0u) {
            return 0;
        }
    }
    size_t rem = klen_bits % 8u;
    if (rem != 0u) {
        out[out_bytes - 1] &= (uint8_t)(0xffu << (8u - rem));
    }
    return 1;
}

static int sm2_t_all_zero(const uint8_t *t, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        if (t[i] != 0) {
            return 0;
        }
    }
    return 1;
}

size_t sm2_encrypt(const uint8_t pub[64], const uint8_t *msg, size_t msg_len,
                   const uint8_t rand_k[32], uint8_t *out, size_t out_cap, int order_c1c3c2)
{
    size_t need = 96u + msg_len;
    if (!msg && msg_len > 0) {
        return 0;
    }
    if (out_cap < need) {
        return 0;
    }

    sm2_z256_t k;
    SM2_Z256_POINT PB, C1, S;
    uint8_t xy[64];
    uint8_t *tbuf = NULL;

    sm2_z256_from_bytes(k, rand_k);
    if (sm2_z256_is_zero(k) || sm2_z256_cmp(k, sm2_z256_order()) >= 0) {
        return 0;
    }

    sm2_z256_point_mul_generator(&C1, k);
    if (sm2_z256_point_to_bytes(&C1, xy) != 1) {
        return 0;
    }
    memcpy(out, xy, 64);

    if (sm2_z256_point_from_bytes(&PB, pub) != 1 || !sm2_z256_point_is_on_curve(&PB)) {
        return 0;
    }
    sm2_z256_point_mul(&S, k, &PB);
    if (sm2_z256_point_to_bytes(&S, xy) != 1) {
        return 0;
    }

    size_t klen_bits = msg_len * 8u;
    tbuf = (uint8_t *)malloc(msg_len ? msg_len : 1u);
    if (!tbuf) {
        return 0;
    }
    if (!sm2_kdf(xy, klen_bits, tbuf)) {
        free(tbuf);
        return 0;
    }
    if (msg_len > 0 && sm2_t_all_zero(tbuf, msg_len)) {
        free(tbuf);
        return 0;
    }

    uint8_t *c2 = out + 64;
    uint8_t *c3 = out + 64 + msg_len;
    if (order_c1c3c2) {
        c2 = out + 64 + 32;
        c3 = out + 64;
    }

    size_t i;
    for (i = 0; i < msg_len; i++) {
        c2[i] = (uint8_t)(msg[i] ^ tbuf[i]);
    }
    free(tbuf);

    {
        size_t c3_inlen = 32u + msg_len + 32u;
        uint8_t *c3_in = (uint8_t *)malloc(c3_inlen ? c3_inlen : 1u);
        if (!c3_in) {
            return 0;
        }
        memcpy(c3_in, xy, 32);
        if (msg_len) {
            memcpy(c3_in + 32, msg, msg_len);
        }
        memcpy(c3_in + 32 + msg_len, xy + 32, 32);
        sm3_digest(c3_in, c3_inlen, c3);
        free(c3_in);
    }

    return need;
}

size_t sm2_decrypt(const uint8_t priv[32], const uint8_t *cipher, size_t cipher_len,
                   uint8_t *out, size_t out_cap, int order_c1c3c2)
{
    if (cipher_len < 96u) {
        return 0;
    }
    size_t mlen = cipher_len - 96u;
    if (out_cap < mlen) {
        return 0;
    }

    const uint8_t *c1 = cipher;
    const uint8_t *c2;
    const uint8_t *c3;
    if (order_c1c3c2) {
        c3 = cipher + 64;
        c2 = cipher + 64 + 32;
    } else {
        c2 = cipher + 64;
        c3 = cipher + 64 + mlen;
    }

    sm2_z256_t d;
    SM2_Z256_POINT C1pt, S;
    uint8_t xy[64];
    uint8_t *tbuf = NULL;

    sm2_z256_from_bytes(d, priv);
    if (sm2_z256_is_zero(d) || sm2_z256_cmp(d, sm2_z256_order()) >= 0) {
        return 0;
    }
    if (sm2_z256_point_from_bytes(&C1pt, c1) != 1 || !sm2_z256_point_is_on_curve(&C1pt)) {
        return 0;
    }

    sm2_z256_point_mul(&S, d, &C1pt);
    if (sm2_z256_point_to_bytes(&S, xy) != 1) {
        return 0;
    }

    size_t klen_bits = mlen * 8u;
    tbuf = (uint8_t *)malloc(mlen ? mlen : 1u);
    if (!tbuf) {
        return 0;
    }
    if (!sm2_kdf(xy, klen_bits, tbuf)) {
        free(tbuf);
        return 0;
    }

    size_t i;
    for (i = 0; i < mlen; i++) {
        out[i] = (uint8_t)(c2[i] ^ tbuf[i]);
    }
    free(tbuf);

    {
        size_t c3_inlen = 32u + mlen + 32u;
        uint8_t u[32];
        uint8_t *c3_in = (uint8_t *)malloc(c3_inlen ? c3_inlen : 1u);
        if (!c3_in) {
            return 0;
        }
        memcpy(c3_in, xy, 32);
        if (mlen) {
            memcpy(c3_in + 32, out, mlen);
        }
        memcpy(c3_in + 32 + mlen, xy + 32, 32);
        sm3_digest(c3_in, c3_inlen, u);
        free(c3_in);
        if (memcmp(u, c3, 32) != 0) {
            memset(out, 0, mlen);
            return 0;
        }
    }

    return mlen;
}

int sm2_ecdh_shared_key(const uint8_t priv[32], const uint8_t peer_pub[64], uint8_t out[32])
{
    sm2_z256_t d;
    SM2_Z256_POINT PB, S;
    uint8_t xy[64];

    sm2_z256_from_bytes(d, priv);
    if (sm2_z256_is_zero(d) || sm2_z256_cmp(d, sm2_z256_order()) >= 0) {
        return 0;
    }
    if (sm2_z256_point_from_bytes(&PB, peer_pub) != 1 || !sm2_z256_point_is_on_curve(&PB)) {
        return 0;
    }
    sm2_z256_point_mul(&S, d, &PB);
    if (sm2_z256_point_to_bytes(&S, xy) != 1) {
        return 0;
    }
    if (!sm2_kdf(xy, 256u, out)) {
        return 0;
    }
    return 1;
}

/* 曲线参数 a、b、基点 G（大端 32 字节） */
static const uint8_t SM2_PARAM_A[32] = {
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc
};

static const uint8_t SM2_PARAM_B[32] = {
    0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34, 0x4d, 0x5a, 0x9e, 0x4b,
    0xce, 0xf6, 0x50, 0x9a, 0x7f, 0x39, 0x78, 0x9f, 0x51, 0x5a, 0xb8, 0xf1,
    0x2d, 0xdb, 0xcb, 0xd4, 0x14, 0xd9, 0x40, 0x0e
};

static const uint8_t SM2_GX[32] = {
    0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x04, 0x46,
    0x6a, 0x39, 0xc9, 0x94, 0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1,
    0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7
};

static const uint8_t SM2_GY[32] = {
    0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c, 0x59, 0xbd, 0xce, 0xe3,
    0x6b, 0x69, 0x21, 0x53, 0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40,
    0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0
};

static const uint8_t DEFAULT_USER_ID[] = "1234567812345678";

static void reduce_mod_n(sm2_z256_t v)
{
    const uint64_t *n = sm2_z256_order();
    while (sm2_z256_cmp(v, n) >= 0) {
        sm2_z256_sub(v, v, n);
    }
}

static void sm2_compute_za(const uint8_t *id, size_t id_len, const uint8_t pub[64], uint8_t za[32])
{
    uint8_t buf[256];
    size_t pos = 0;
    uint16_t entla = (uint16_t)(id_len * 8u);
    buf[pos++] = (uint8_t)(entla >> 8);
    buf[pos++] = (uint8_t)(entla & 0xffu);
    memcpy(buf + pos, id, id_len);
    pos += id_len;
    memcpy(buf + pos, SM2_PARAM_A, 32);
    pos += 32;
    memcpy(buf + pos, SM2_PARAM_B, 32);
    pos += 32;
    memcpy(buf + pos, SM2_GX, 32);
    pos += 32;
    memcpy(buf + pos, SM2_GY, 32);
    pos += 32;
    memcpy(buf + pos, pub, 32);
    pos += 32;
    memcpy(buf + pos, pub + 32, 32);
    pos += 32;
    sm3_digest(buf, pos, za);
}

static void hash_to_modn(const uint8_t h[32], sm2_z256_t out)
{
    sm2_z256_from_bytes(out, h);
    reduce_mod_n(out);
}

static void x_coord_to_modn(const uint8_t x[32], sm2_z256_t out)
{
    sm2_z256_from_bytes(out, x);
    reduce_mod_n(out);
}

int sm2_generate_keypair(const uint8_t entropy[SM2_KEY_BYTES], uint8_t priv[SM2_KEY_BYTES],
                         uint8_t pub[SM2_PUBKEY_BYTES])
{
    sm2_z256_t d;
    sm2_z256_from_bytes(d, entropy);
    reduce_mod_n(d);
    if (sm2_z256_is_zero(d)) {
        return 0;
    }
    if (sm2_z256_cmp(d, sm2_z256_order()) >= 0) {
        return 0;
    }
    sm2_z256_to_bytes(d, priv);
    return sm2_keypair_from_private(priv, pub);
}

int sm2_keypair_from_private(const uint8_t priv[SM2_KEY_BYTES], uint8_t pub[SM2_PUBKEY_BYTES])
{
    sm2_z256_t d;
    SM2_Z256_POINT R;
    sm2_z256_from_bytes(d, priv);
    if (sm2_z256_is_zero(d)) {
        return 0;
    }
    if (sm2_z256_cmp(d, sm2_z256_order()) >= 0) {
        return 0;
    }
    sm2_z256_point_mul_generator(&R, d);
    return sm2_z256_point_to_bytes(&R, pub);
}

int sm2_sign(const uint8_t priv[SM2_KEY_BYTES], const uint8_t *msg, size_t msg_len,
             const uint8_t pub[SM2_PUBKEY_BYTES], const uint8_t *id, size_t id_len,
             const uint8_t rand_k[SM2_KEY_BYTES], uint8_t r_out[SM2_KEY_BYTES], uint8_t s_out[SM2_KEY_BYTES])
{
    const uint8_t *use_id = id ? id : DEFAULT_USER_ID;
    size_t use_id_len = id ? id_len : (sizeof(DEFAULT_USER_ID) - 1u);
    sm2_z256_t d, k, e, x1, r, s, t, one, tmp, inv, rd;
    SM2_Z256_POINT Rpt;
    uint8_t za[32], em[32], xy[64];

    if (!msg && msg_len > 0) {
        return 0;
    }

    sm2_compute_za(use_id, use_id_len, pub, za);
    {
        size_t elen = 32 + msg_len;
        uint8_t *ebuf = (uint8_t *)malloc(elen ? elen : 1);
        if (!ebuf) {
            return 0;
        }
        memcpy(ebuf, za, 32);
        if (msg_len) {
            memcpy(ebuf + 32, msg, msg_len);
        }
        sm3_digest(ebuf, elen, em);
        free(ebuf);
    }
    hash_to_modn(em, e);

    sm2_z256_from_bytes(d, priv);
    sm2_z256_from_bytes(k, rand_k);
    if (sm2_z256_is_zero(k) || sm2_z256_cmp(k, sm2_z256_order()) >= 0) {
        return 0;
    }

    sm2_z256_point_mul_generator(&Rpt, k);
    if (sm2_z256_point_to_bytes(&Rpt, xy) != 1) {
        return 0;
    }
    x_coord_to_modn(xy, x1);

    sm2_z256_modn_add(r, e, x1);
    if (sm2_z256_is_zero(r)) {
        return 0;
    }
    sm2_z256_modn_add(t, r, k);
    if (sm2_z256_is_zero(t)) {
        return 0;
    }

    sm2_z256_set_one(one);
    sm2_z256_modn_add(tmp, one, d);
    sm2_z256_modn_inv(inv, tmp);
    sm2_z256_modn_mul(rd, r, d);
    sm2_z256_modn_sub(tmp, k, rd);
    sm2_z256_modn_mul(s, inv, tmp);

    sm2_z256_to_bytes(r, r_out);
    sm2_z256_to_bytes(s, s_out);
    return 1;
}

int sm2_verify(const uint8_t pub[SM2_PUBKEY_BYTES], const uint8_t *msg, size_t msg_len,
               const uint8_t *id, size_t id_len, const uint8_t r_b[SM2_KEY_BYTES],
               const uint8_t s_b[SM2_KEY_BYTES])
{
    const uint8_t *use_id = id ? id : DEFAULT_USER_ID;
    size_t use_id_len = id ? id_len : (sizeof(DEFAULT_USER_ID) - 1u);
    sm2_z256_t e, x1, r, s, t, rp;
    SM2_Z256_POINT PA, Rsum;
    uint8_t za[32], em[32], xy[64];

    sm2_compute_za(use_id, use_id_len, pub, za);
    {
        size_t elen = 32 + msg_len;
        uint8_t *ebuf = (uint8_t *)malloc(elen ? elen : 1);
        if (!ebuf) {
            return 0;
        }
        memcpy(ebuf, za, 32);
        if (msg_len) {
            memcpy(ebuf + 32, msg, msg_len);
        }
        sm3_digest(ebuf, elen, em);
        free(ebuf);
    }
    hash_to_modn(em, e);

    sm2_z256_from_bytes(r, r_b);
    sm2_z256_from_bytes(s, s_b);
    if (sm2_z256_is_zero(r) || sm2_z256_is_zero(s)) {
        return 0;
    }
    if (sm2_z256_cmp(r, sm2_z256_order()) >= 0 || sm2_z256_cmp(s, sm2_z256_order()) >= 0) {
        return 0;
    }

    sm2_z256_modn_add(t, r, s);

    if (sm2_z256_point_from_bytes(&PA, pub) != 1) {
        return 0;
    }
    sm2_z256_point_mul_sum(&Rsum, t, &PA, s);
    if (sm2_z256_point_to_bytes(&Rsum, xy) != 1) {
        return 0;
    }
    x_coord_to_modn(xy, x1);

    sm2_z256_modn_add(rp, e, x1);
    return sm2_z256_equ(r, rp) ? 1 : 0;
}
