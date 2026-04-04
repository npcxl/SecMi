@echo off
setlocal EnableExtensions
rem Double-click uses cmd /c and closes the window as soon as the script ends.
rem Re-launch with cmd /k so the console stays open after the build (you can type exit to close).
if /i not "%~1"=="__inner" (
    cmd.exe /k "%~f0" __inner
    exit /b 0
)

cd /d "%~dp0"
title Build gm.js (Emscripten)

echo Current directory: %CD%
echo.

rem Try PATH without "call emsdk_env.bat" (some emsdk scripts use "exit" and close this window)
call :try_prepend_emscripten_path

where emcc >nul 2>&1
if not errorlevel 1 goto :do_build

echo emcc not in PATH, trying emsdk_env.bat in common locations...
if defined EMSDK if exist "%EMSDK%\emsdk_env.bat" (
    echo   call "%EMSDK%\emsdk_env.bat"
    call "%EMSDK%\emsdk_env.bat"
)
where emcc >nul 2>&1
if not errorlevel 1 goto :do_build

if exist "%USERPROFILE%\emsdk\emsdk_env.bat" (
    echo   call "%USERPROFILE%\emsdk\emsdk_env.bat"
    call "%USERPROFILE%\emsdk\emsdk_env.bat"
)
where emcc >nul 2>&1
if not errorlevel 1 goto :do_build

if exist "%USERPROFILE%\Desktop\emsdk\emsdk_env.bat" (
    echo   call "%USERPROFILE%\Desktop\emsdk\emsdk_env.bat"
    call "%USERPROFILE%\Desktop\emsdk\emsdk_env.bat"
)
where emcc >nul 2>&1
if not errorlevel 1 goto :do_build

if exist "D:\emsdk\emsdk_env.bat" (
    echo   call D:\emsdk\emsdk_env.bat
    call "D:\emsdk\emsdk_env.bat"
)
where emcc >nul 2>&1
if not errorlevel 1 goto :do_build

if exist "D:\emsdk-main\emsdk_env.bat" (
    echo   call D:\emsdk-main\emsdk_env.bat
    call "D:\emsdk-main\emsdk_env.bat"
)
where emcc >nul 2>&1
if not errorlevel 1 goto :do_build

if exist "C:\emsdk\emsdk_env.bat" (
    echo   call C:\emsdk\emsdk_env.bat
    call "C:\emsdk\emsdk_env.bat"
)
where emcc >nul 2>&1
if not errorlevel 1 goto :do_build

echo.
echo [ERROR] Still no emcc. Install Emscripten first:
echo   https://emscripten.org/docs/getting_started/downloads.html
echo.
echo In D:\emsdk-main run: emsdk install latest  and  emsdk activate latest
echo Then set user env EMSDK=D:\emsdk-main  or run this script again.
echo.
goto :finish_fail

:do_build
echo [OK] emcc found:
where emcc
echo.
echo Running emcc ...
rem 必须 call emcc：emcc 是 .bat，不用 call 时子脚本结束后不会回到本脚本，成功日志永远不会执行
rem Same flags as build.sh (single line avoids CMD quoting issues with -s EXPORTED_*)
call emcc -O3 -std=c99 -Wall gm.c sm3.c sm4.c sm2.c sm2_z256.c gmssl_compat.c -o gm.js -s WASM=0 -s ENVIRONMENT=web -s EXPORTED_FUNCTIONS=[_malloc,_free,_gm_sm3_hash,_gm_sm3_hmac,_gm_sm4_set_sbox_version,_gm_sm4_cbc_encrypt,_gm_sm4_cbc_decrypt,_gm_sm4_ecb_encrypt,_gm_sm4_ecb_decrypt,_gm_sm4_ctr_crypt,_gm_sm4_ofb_crypt,_gm_sm4_cfb128_crypt,_gm_sm2_generate_keypair,_gm_sm2_sign,_gm_sm2_verify,_gm_sm2_encrypt,_gm_sm2_decrypt,_gm_sm2_ecdh_shared_key] -s EXPORTED_RUNTIME_METHODS=[ccall,cwrap,UTF8ToString,stringToUTF8,HEAPU8] -s ALLOW_MEMORY_GROWTH=1 -s MODULARIZE=0 -s SINGLE_FILE=1 --no-entry

if errorlevel 1 (
    echo.
    echo [ERROR] emcc build failed. See messages above.
    echo.
    goto :finish_fail
)

echo.
echo ========================================
echo [OK] Build succeeded
if exist gm.js (
  for %%F in ("gm.js") do (
    echo File:    %%~fF
    echo Size:    %%~zF bytes
  )
) else (
  echo WARNING: gm.js not found under %CD%
)
echo ========================================
echo Open test.html in this folder to run the demo.
echo.
goto :finish_ok

:finish_fail
pause
exit /b 1

:finish_ok
pause
exit /b 0

:try_prepend_emscripten_path
rem Typical layout after "emsdk install": upstream\emscripten contains emcc.bat
if defined EMSDK if exist "%EMSDK%\upstream\emscripten\emcc.bat" (
    echo Prepending PATH: %EMSDK%\upstream\emscripten
    set "PATH=%EMSDK%\upstream\emscripten;%EMSDK%;%PATH%"
    goto :eof
)
if exist "%USERPROFILE%\emsdk\upstream\emscripten\emcc.bat" (
    echo Prepending PATH: %USERPROFILE%\emsdk\upstream\emscripten
    set "PATH=%USERPROFILE%\emsdk\upstream\emscripten;%USERPROFILE%\emsdk;%PATH%"
    set "EMSDK=%USERPROFILE%\emsdk"
    goto :eof
)
if exist "%USERPROFILE%\Desktop\emsdk\upstream\emscripten\emcc.bat" (
    echo Prepending PATH: %USERPROFILE%\Desktop\emsdk\upstream\emscripten
    set "PATH=%USERPROFILE%\Desktop\emsdk\upstream\emscripten;%USERPROFILE%\Desktop\emsdk;%PATH%"
    set "EMSDK=%USERPROFILE%\Desktop\emsdk"
    goto :eof
)
if exist "D:\emsdk-main\upstream\emscripten\emcc.bat" (
    echo Prepending PATH: D:\emsdk-main\upstream\emscripten
    set "PATH=D:\emsdk-main\upstream\emscripten;D:\emsdk-main;%PATH%"
    set "EMSDK=D:\emsdk-main"
    goto :eof
)
if exist "D:\emsdk\upstream\emscripten\emcc.bat" (
    echo Prepending PATH: D:\emsdk\upstream\emscripten
    set "PATH=D:\emsdk\upstream\emscripten;D:\emsdk;%PATH%"
    set "EMSDK=D:\emsdk"
    goto :eof
)
if exist "C:\emsdk\upstream\emscripten\emcc.bat" (
    echo Prepending PATH: C:\emsdk\upstream\emscripten
    set "PATH=C:\emsdk\upstream\emscripten;C:\emsdk;%PATH%"
    set "EMSDK=C:\emsdk"
    goto :eof
)
goto :eof
