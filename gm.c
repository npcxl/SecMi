/**
 * Emscripten / 本地共用入口：对外导出密码学算法 C API（SECMI）。
 */
#include "gm_types.h"
#include "sm3.h"
#include "sm4.h"
#include "sm2.h"
#include <stdlib.h>
#include <string.h>

GM_KEEPALIVE void *gm_malloc(size_t n)
{
    return malloc(n);
}

GM_KEEPALIVE void gm_free(void *p)
{
    free(p);
}

GM_KEEPALIVE void gm_sm3_hash(const uint8_t *msg, size_t len, uint8_t out[32])
{
    sm3_digest(msg, len, out);
}

GM_KEEPALIVE void gm_sm3_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                              uint8_t out[32])
{
    sm3_hmac(key, key_len, msg, msg_len, out);
}

GM_KEEPALIVE void gm_sm4_set_sbox_version(int ver)
{
    sm4_set_sbox_version(ver == 1 ? SM4_SBOX_VER_LEGACY_PRINT : SM4_SBOX_VER_MODERN);
}

GM_KEEPALIVE size_t gm_sm4_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in,
                                      size_t in_len, uint8_t *out)
{
    return sm4_cbc_encrypt_pkcs7(key, iv, in, in_len, out);
}

GM_KEEPALIVE size_t gm_sm4_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in,
                                       size_t in_len, uint8_t *out, size_t out_cap)
{
    return sm4_cbc_decrypt_pkcs7(key, iv, in, in_len, out, out_cap);
}

GM_KEEPALIVE size_t gm_sm4_ecb_encrypt(const uint8_t key[16], const uint8_t *in, size_t in_len, uint8_t *out)
{
    return sm4_ecb_encrypt_pkcs7(key, in, in_len, out);
}

GM_KEEPALIVE size_t gm_sm4_ecb_decrypt(const uint8_t key[16], const uint8_t *in, size_t in_len,
                                       uint8_t *out, size_t out_cap)
{
    return sm4_ecb_decrypt_pkcs7(key, in, in_len, out, out_cap);
}

GM_KEEPALIVE void gm_sm4_ctr_crypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, size_t in_len,
                                   uint8_t *out)
{
    sm4_ctr_crypt(key, iv, in, in_len, out);
}

GM_KEEPALIVE void gm_sm4_ofb_crypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, size_t in_len,
                                   uint8_t *out)
{
    sm4_ofb128_crypt(key, iv, in, in_len, out);
}

GM_KEEPALIVE size_t gm_sm4_cfb128_crypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in,
                                        size_t in_len, uint8_t *out)
{
    return sm4_cfb128_crypt(key, iv, in, in_len, out);
}

GM_KEEPALIVE int gm_sm2_generate_keypair(const uint8_t entropy[32], uint8_t priv[32], uint8_t pub[64])
{
    return sm2_generate_keypair(entropy, priv, pub);
}

GM_KEEPALIVE int gm_sm2_sign(const uint8_t priv[32], const uint8_t *msg, size_t msg_len,
                             const uint8_t pub[64], const uint8_t *id, size_t id_len,
                             const uint8_t rand_k[32], uint8_t r[32], uint8_t s[32])
{
    return sm2_sign(priv, msg, msg_len, pub, id, id_len, rand_k, r, s);
}

GM_KEEPALIVE int gm_sm2_verify(const uint8_t pub[64], const uint8_t *msg, size_t msg_len,
                               const uint8_t *id, size_t id_len, const uint8_t r[32], const uint8_t s[32])
{
    return sm2_verify(pub, msg, msg_len, id, id_len, r, s);
}

GM_KEEPALIVE size_t gm_sm2_encrypt(const uint8_t pub[64], const uint8_t *msg, size_t msg_len,
                                   const uint8_t rand_k[32], uint8_t *out, size_t out_cap, int order_c1c3c2)
{
    return sm2_encrypt(pub, msg, msg_len, rand_k, out, out_cap, order_c1c3c2);
}

GM_KEEPALIVE size_t gm_sm2_decrypt(const uint8_t priv[32], const uint8_t *cipher, size_t cipher_len,
                                   uint8_t *out, size_t out_cap, int order_c1c3c2)
{
    return sm2_decrypt(priv, cipher, cipher_len, out, out_cap, order_c1c3c2);
}

GM_KEEPALIVE int gm_sm2_ecdh_shared_key(const uint8_t priv[32], const uint8_t peer_pub[64], uint8_t out[32])
{
    return sm2_ecdh_shared_key(priv, peer_pub, out);
}
