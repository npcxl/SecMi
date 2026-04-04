#!/usr/bin/env bash
# SECMI / gm.js — Emscripten 编译脚本（需已安装 emcc 并在 PATH 中）
set -euo pipefail
cd "$(dirname "$0")"

SOURCES=(
  gm.c
  sm3.c
  sm4.c
  sm2.c
  sm2_z256.c
  gmssl_compat.c
)

emcc -O3 -std=c99 -Wall \
  "${SOURCES[@]}" \
  -o gm.js \
  -s WASM=0 \
  -s ENVIRONMENT=web \
  -s EXPORTED_FUNCTIONS='["_malloc","_free","_gm_sm3_hash","_gm_sm3_hmac","_gm_sm4_set_sbox_version","_gm_sm4_cbc_encrypt","_gm_sm4_cbc_decrypt","_gm_sm4_ecb_encrypt","_gm_sm4_ecb_decrypt","_gm_sm4_ctr_crypt","_gm_sm4_ofb_crypt","_gm_sm4_cfb128_crypt","_gm_sm2_generate_keypair","_gm_sm2_sign","_gm_sm2_verify","_gm_sm2_encrypt","_gm_sm2_decrypt","_gm_sm2_ecdh_shared_key"]' \
  -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","UTF8ToString","stringToUTF8","HEAPU8"]' \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s MODULARIZE=0 \
  -s SINGLE_FILE=1 \
  --no-entry

echo ""
echo "========================================"
echo "[OK] Build succeeded"
OUT="$(pwd)/gm.js"
if [[ -f gm.js ]]; then
  echo "File: $OUT"
  echo "Size: $(wc -c < gm.js | tr -d ' ') bytes"
else
  echo "WARNING: gm.js not found"
fi
echo "========================================"
echo "Open test.html in this folder to run the demo."
