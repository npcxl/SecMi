/**
 * SECMI：公共类型与宏
 * 纯 C、无第三方依赖；供 SM2/SM3/SM4 模块使用。
 */
#ifndef GM_TYPES_H
#define GM_TYPES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#define GM_KEEPALIVE EMSCRIPTEN_KEEPALIVE
#else
#define GM_KEEPALIVE
#endif

#endif /* GM_TYPES_H */
