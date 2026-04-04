/**
 * SM3 密码杂凑算法（GB/T 32905-2016）
 */
#ifndef SM3_H
#define SM3_H

#include <stddef.h>
#include <stdint.h>

#define SM3_DIGEST_SIZE 32

/**
 * 计算消息 msg 的 SM3 摘要，写入 out[32]（大端字节序与国标示例一致）。
 */
void sm3_digest(const uint8_t *msg, size_t len, uint8_t out[SM3_DIGEST_SIZE]);

/** HMAC-SM3（密钥可为任意长度；内部块长 64 字节）。 */
void sm3_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
              uint8_t out[SM3_DIGEST_SIZE]);

#endif /* SM3_H */
