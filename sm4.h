/**
 * SM4 分组密码（GM/T 0002-2012），分组与密钥长度均为 128 bit。
 */
#ifndef SM4_H
#define SM4_H

#include <stddef.h>
#include <stdint.h>

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16

/** S 盒版本：现行勘误表（GmSSL/OpenSSL 256 字节）与早期印刷版（末两行分列为 0x18…81 与 0xb2…0e） */
typedef enum {
    SM4_SBOX_VER_MODERN = 0,
    SM4_SBOX_VER_LEGACY_PRINT = 1
} sm4_sbox_version_t;

/**
 * 选择当前线程/进程内 SM4 使用的 S 盒（影响密钥扩展与加解密）。默认 SM4_SBOX_VER_MODERN。
 */
void sm4_set_sbox_version(sm4_sbox_version_t ver);

/**
 * 密钥扩展，生成 32 个轮密钥 rk[32]（每元素 32 位，大端存于 uint32_t）。
 */
void sm4_set_key(const uint8_t key[SM4_KEY_SIZE], uint32_t rk[32]);

/**
 * 单分组 ECB 加密：plain[16] -> cipher[16]。
 */
void sm4_encrypt_block(const uint32_t rk[32], const uint8_t plain[SM4_BLOCK_SIZE],
                       uint8_t cipher[SM4_BLOCK_SIZE]);

/**
 * 单分组 ECB 解密。
 */
void sm4_decrypt_block(const uint32_t rk[32], const uint8_t cipher[SM4_BLOCK_SIZE],
                       uint8_t plain[SM4_BLOCK_SIZE]);

/**
 * CBC + PKCS#7 加密。
 * 输出缓冲区 out 长度至少为 in_len + 16（向上取整到块边界 + 整一块填充）。
 * 返回 out 中密文字节数，失败返回 0。
 */
size_t sm4_cbc_encrypt_pkcs7(const uint8_t key[SM4_KEY_SIZE],
                             const uint8_t iv[SM4_BLOCK_SIZE],
                             const uint8_t *in, size_t in_len,
                             uint8_t *out);

/**
 * CBC + PKCS#7 解密。
 * 成功返回明文长度，失败返回 0。
 */
size_t sm4_cbc_decrypt_pkcs7(const uint8_t key[SM4_KEY_SIZE],
                             const uint8_t iv[SM4_BLOCK_SIZE],
                             const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t out_cap);

/** ECB + PKCS#7（无 IV）。 */
size_t sm4_ecb_encrypt_pkcs7(const uint8_t key[SM4_KEY_SIZE], const uint8_t *in, size_t in_len,
                             uint8_t *out);

size_t sm4_ecb_decrypt_pkcs7(const uint8_t key[SM4_KEY_SIZE], const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t out_cap);

/**
 * CTR：iv 为初始计数器（16 字节大端），按块递增低字节在末字节向高位进位。
 * 加解密同一函数（异或流）。
 */
void sm4_ctr_crypt(const uint8_t key[SM4_KEY_SIZE], const uint8_t iv[SM4_BLOCK_SIZE],
                   const uint8_t *in, size_t in_len, uint8_t *out);

/** OFB-128：iv 为初始移位寄存器；任意长度。 */
void sm4_ofb128_crypt(const uint8_t key[SM4_KEY_SIZE], const uint8_t iv[SM4_BLOCK_SIZE],
                      const uint8_t *in, size_t in_len, uint8_t *out);

/**
 * CFB-128：仅当 in_len 为 16 的倍数时成功；否则返回 0。
 * 加解密同一变换。
 */
size_t sm4_cfb128_crypt(const uint8_t key[SM4_KEY_SIZE], const uint8_t iv[SM4_BLOCK_SIZE],
                        const uint8_t *in, size_t in_len, uint8_t *out);

#endif /* SM4_H */
