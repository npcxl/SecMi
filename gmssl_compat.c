#include "gmssl_compat.h"
#include <ctype.h>

int hex_to_bytes(const char *hex, size_t hexlen, uint8_t *out, size_t *outlen) {
    size_t i;
    if (hexlen % 2 != 0) {
        return -1;
    }
    *outlen = hexlen / 2;
    for (i = 0; i < *outlen; i++) {
        unsigned int hi, lo;
        char c;
        c = hex[i * 2];
        hi = (unsigned char)(isdigit((unsigned char)c) ? c - '0' : (tolower((unsigned char)c) - 'a' + 10));
        c = hex[i * 2 + 1];
        lo = (unsigned char)(isdigit((unsigned char)c) ? c - '0' : (tolower((unsigned char)c) - 'a' + 10));
        if (hi > 15 || lo > 15) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

int format_print(FILE *fp, int ind, int fmt, const char *fmtstr, ...) {
    va_list ap;
    (void)ind;
    (void)fmt;
    va_start(ap, fmtstr);
    vfprintf(fp, fmtstr, ap);
    va_end(ap);
    return 1;
}

int format_bytes(FILE *fp, int fmt, int ind, const char *label, const uint8_t *b, size_t n) {
    size_t i;
    (void)fmt;
    (void)ind;
    fprintf(fp, "%s: ", label);
    for (i = 0; i < n; i++) {
        fprintf(fp, "%02x", b[i]);
    }
    fprintf(fp, "\n");
    return 1;
}
