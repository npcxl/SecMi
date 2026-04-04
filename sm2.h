/**
 * SM2：数字签名（GB/T 32918.2）、公钥加解密与 ECDH（GB/T 32918.4 等），依赖 sm3.c 与 sm2_z256.c。
 */
#ifndef SM2_H
#define SM2_H

#include <stddef.h>
#include <stdint.h>

#define SM2_KEY_BYTES 32
#define SM2_PUBKEY_BYTES 64

/**
 * 由 32 字节私钥 d（大端）生成公钥点（未压缩：X||Y，各 32 字节大端）。
 */
int sm2_keypair_from_private(const uint8_t priv[SM2_KEY_BYTES], uint8_t pub[SM2_PUBKEY_BYTES]);

/**
 * 用 32 字节熵生成合法私钥并导出公钥（熵经 mod n 归约，需保证熵质量）。
 */
int sm2_generate_keypair(const uint8_t entropy[SM2_KEY_BYTES], uint8_t priv[SM2_KEY_BYTES],
                         uint8_t pub[SM2_PUBKEY_BYTES]);

/**
 * 使用随机数 k（32 字节）对消息签名，输出 r,s（大端 32 字节）。
 * pub 用于计算 ZA（与用户 ID 绑定）；id 可为 NULL 表示默认 "1234567812345678"。
 */
int sm2_sign(const uint8_t priv[SM2_KEY_BYTES], const uint8_t *msg, size_t msg_len,
             const uint8_t pub[SM2_PUBKEY_BYTES], const uint8_t *id, size_t id_len,
             const uint8_t rand_k[SM2_KEY_BYTES], uint8_t r[SM2_KEY_BYTES], uint8_t s[SM2_KEY_BYTES]);

/**
 * 验签：默认用户 ID 与签名时一致。
 */
int sm2_verify(const uint8_t pub[SM2_PUBKEY_BYTES], const uint8_t *msg, size_t msg_len,
               const uint8_t *id, size_t id_len, const uint8_t r[SM2_KEY_BYTES],
               const uint8_t s[SM2_KEY_BYTES]);

/** 公钥加密（GB/T 32918.4-2016）：order_c1c3c2=0 为 C1||C2||C3，=1 为 C1||C3||C2。成功返回密文总长度（96+msg_len），失败返回 0。 */
size_t sm2_encrypt(const uint8_t pub[SM2_PUBKEY_BYTES], const uint8_t *msg, size_t msg_len,
                   const uint8_t rand_k[SM2_KEY_BYTES], uint8_t *out, size_t out_cap, int order_c1c3c2);

/** 私钥解密。成功返回明文长度，失败返回 0。 */
size_t sm2_decrypt(const uint8_t priv[SM2_KEY_BYTES], const uint8_t *cipher, size_t cipher_len,
                   uint8_t *out, size_t out_cap, int order_c1c3c2);

/** ECDH：共享点 d·P_peer 上 KDF(x||y, 256) 得 32 字节。成功返回 1。 */
int sm2_ecdh_shared_key(const uint8_t priv[SM2_KEY_BYTES], const uint8_t peer_pub[SM2_PUBKEY_BYTES],
                        uint8_t out[32]);

#endif /* SM2_H */
