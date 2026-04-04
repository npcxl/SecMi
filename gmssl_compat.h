/**
 * 本地兼容层：替代 GmSSL 头文件中的 GETU64/PUTU64 与少量工具函数。
 */
#ifndef GMSSL_COMPAT_H
#define GMSSL_COMPAT_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

static inline uint64_t GETU64(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static inline void PUTU64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)v;
}

#define error_print() ((void)0)

int hex_to_bytes(const char *hex, size_t hexlen, uint8_t *out, size_t *outlen);
int format_print(FILE *fp, int ind, int fmt, const char *fmtstr, ...);
int format_bytes(FILE *fp, int fmt, int ind, const char *label, const uint8_t *b, size_t n);

#endif
