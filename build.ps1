# Emscripten build (Windows PowerShell) - same as build.sh / build.bat
# Run: .\build.ps1
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Try-EmsdkEnv {
    $roots = @(
        $env:EMSDK
        (Join-Path $env:USERPROFILE 'emsdk')
        (Join-Path $env:USERPROFILE 'Desktop\emsdk')
        'D:\emsdk-main'
        'D:\emsdk'
        'C:\emsdk'
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($root in $roots) {
        $ps1 = Join-Path $root 'emsdk_env.ps1'
        if (Test-Path $ps1) {
            Write-Host "Loading: $ps1"
            . $ps1
            return
        }
    }
}

$emcc = Get-Command emcc -ErrorAction SilentlyContinue
if (-not $emcc) {
    Try-EmsdkEnv
    $emcc = Get-Command emcc -ErrorAction SilentlyContinue
}
if (-not $emcc) {
    Write-Host '[ERROR] emcc not in PATH. Run D:\emsdk-main\emsdk_env.bat in this window, or set EMSDK, then retry.' -ForegroundColor Red
    exit 1
}

Write-Host "[OK] emcc: $($emcc.Source)"
Write-Host 'Running emcc ...'

$sources = @(
    'gm.c', 'sm3.c', 'sm4.c', 'sm2.c', 'sm2_z256.c', 'gmssl_compat.c'
)

$exportedFuncs = '["_malloc","_free","_gm_sm3_hash","_gm_sm3_hmac","_gm_sm4_set_sbox_version","_gm_sm4_cbc_encrypt","_gm_sm4_cbc_decrypt","_gm_sm4_ecb_encrypt","_gm_sm4_ecb_decrypt","_gm_sm4_ctr_crypt","_gm_sm4_ofb_crypt","_gm_sm4_cfb128_crypt","_gm_sm2_generate_keypair","_gm_sm2_sign","_gm_sm2_verify","_gm_sm2_encrypt","_gm_sm2_decrypt","_gm_sm2_ecdh_shared_key"]'
$exportedRuntime = '["ccall","cwrap","UTF8ToString","stringToUTF8","HEAPU8"]'

$args = @(
    '-O3', '-std=c99', '-Wall'
) + $sources + @(
    '-o', 'gm.js',
    '-s', 'WASM=0',
    '-s', 'ENVIRONMENT=web',
    '-s', "EXPORTED_FUNCTIONS=$exportedFuncs",
    '-s', "EXPORTED_RUNTIME_METHODS=$exportedRuntime",
    '-s', 'ALLOW_MEMORY_GROWTH=1',
    '-s', 'MODULARIZE=0',
    '-s', 'SINGLE_FILE=1',
    '--no-entry'
)

& emcc @args
if ($LASTEXITCODE -ne 0) {
    Write-Host '[ERROR] emcc build failed.' -ForegroundColor Red
    exit $LASTEXITCODE
}

$out = Join-Path $PSScriptRoot 'gm.js'
Write-Host ''
Write-Host '========================================'
Write-Host '[OK] Build succeeded' -ForegroundColor Green
if (Test-Path $out) {
    $len = (Get-Item $out).Length
    Write-Host "File: $out"
    Write-Host "Size: $len bytes"
} else {
    Write-Host "WARNING: gm.js not found at $out"
}
Write-Host '========================================'
Write-Host 'Open test.html in this folder to run the demo.'
