@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

:: ============================================================================
:: TBH_build.bat — Build script para TBH (ZERO DLL, monolitico)
::
:: Compila um EXE standalone que:
::   1. Espera o jogo abrir e encontra o processo
::   2. Suspende o processo (NtSuspendProcess — todas threads congeladas)
::   3. Patcheia 0xC3 nos 212 entry points do ACTk via WPM (BYOVD resolving CR3)
::   4. Resume o processo (ACTk nunca executou)
::   5. Instala trampolines via LazyHook + CaveFinder (ZERO VirtualAllocEx)
::
:: Arquivos especificos do TBH:
::   TBH\tbh_loader.cpp  — entry point (wWinMain) + fluxo principal (ZERO DLL)
::   TBH\actk_disable.c  — neutralizador ACTk (212 patches 0xC3)
::   TBH\actk_disable.h  — header
::   TBH\tbh_features.cpp — features via BYOVD/LazyHook/CaveFinder (ZERO DLL)
::   TBH\tbh_menu.cpp    — menu D2D overlay
::   TBH\tbh_common.h    — forward declarations + NT_SUCCESS (force-include)
::
:: Infraestrutura reutilizada do Seraph:
::   Loader\byovd.c          — engine de memoria fisica
::   Loader\byovd_lock.c     — spinlock
::   Loader\lazyhook.c       — motor de trampolines via caves fisicas
::   Loader\cave_finder.c    — descobridor de code caves no .text
::   Loader\syscalls.c       — syscalls diretas
::   Loader\syscalls_asm.asm — assembly das syscalls
::   Loader\debug_buffer.c   — ring buffer de log
::   Loader\keyauth.c        — autenticacao KeyAuth
::   Loader\themida_stubs.c  — stubs do Themida SDK
::
:: USO:
::   b.bat              — build debug (com logs, sem otimizacao)
::   b.bat release      — build release (NDEBUG, otimizado)
:: ============================================================================

echo [TBH] =============================================
echo [TBH]  TBH Build Script
echo [TBH] =============================================

:: --- MSVC environment ---
echo [1/6] Configurando ambiente MSVC...
set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
if not exist %VCVARS% (
    echo [ERRO] vcvarsall.bat nao encontrado em %VCVARS%
    exit /b 1
)
call %VCVARS% x64 >nul

:: --- SDK paths ---
set SDK_VER=10.0.26100.0
set SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\%SDK_VER%
set SDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%

:: --- Build mode ---
set BUILD_MODE=debug
if /i "%1"=="release" set BUILD_MODE=release

if /i "%BUILD_MODE%"=="release" (
    echo [TBH] Modo: RELEASE
    set DIAGFLAGS=/D "NDEBUG" /O2
    if not exist build_rel_ver.txt echo 1 > build_rel_ver.txt
    set /p BUILD_VER=<build_rel_ver.txt
    set /a BUILD_VER+=1
    echo !BUILD_VER!> build_rel_ver.txt
    set OUT_NAME=TBH!BUILD_VER!.exe
) else (
    echo [TBH] Modo: DEBUG
    set DIAGFLAGS=/Od /Zi
    if not exist build_dbg_ver.txt echo 1 > build_dbg_ver.txt
    set /p BUILD_VER=<build_dbg_ver.txt
    set /a BUILD_VER+=1
    echo !BUILD_VER!> build_dbg_ver.txt
    set OUT_NAME=TBH_DBG!BUILD_VER!.exe
)
echo [TBH] Versao: !BUILD_VER! saida: !OUT_NAME!

:: --- XOR key (mesmo mecanismo do Seraph) ---
echo [2/6] Gerando chave XOR...
python tools\gen_xor_strings_dynamic.py random Loader\xor_strings.h
if !ERRORLEVEL! neq 0 (
    echo [WARN] gen_xor_strings falhou, usando fallback 0x55
    echo #define XOR_KEY 0x55 > Loader\xor_strings.h
)
for /f "tokens=3 delims= " %%i in ('findstr /C:"#define XOR_KEY" Loader\xor_strings.h') do set XOR_KEY=%%i
echo [TBH] XOR_KEY = !XOR_KEY!

set OWNER_ID=5uQFO11cIm


:: --- Prep build dir ---
if exist tbh_build rd /s /q tbh_build
mkdir tbh_build

:: --- ntdll.lib (syscalls) ---
echo [3/6] Preparando ntdll.lib...
if not exist ntdll.lib (
    lib /nologo /def:Loader\ntdll.def /out:ntdll.lib /machine:x64 >nul
)

:: --- Embed CtiIo64.sys as resource ---
echo [3/6] Embedding CtiIo64.sys como resource...
if not exist "Loader\CtiIo64.sys" (
    echo [ERRO] CtiIo64.sys nao encontrado em Loader\
    exit /b 1
)
copy /Y "Loader\CtiIo64.sys" "CtiIo64_tmp.sys" >nul
echo 302 RCDATA "CtiIo64_tmp.sys" > tbh_resource.rc
rc /nologo /fo tbh_build\tbh_resource.res tbh_resource.rc
if !ERRORLEVEL! neq 0 (
    echo [ERRO] Falha ao compilar resources
    del CtiIo64_tmp.sys 2>nul
    exit /b 1
)
del CtiIo64_tmp.sys 2>nul

:: --- COMPILE ---
:: /FI tbh_common.h — force-include as forward declarations (WriteLogFile, etc.)
:: para que byovd.c e outros TUs do Seraph enxerguem os stubs do TBH.
echo [5/6] Compilando TBH...
cl /nologo /W3 !DIAGFLAGS! /MT /EHsc /std:c++17 ^
   /D "_UNICODE" /D "UNICODE" ^
   /D "_AMD64_" /D "AMD64" /D "_CONSOLE" ^
   /D "SERAPH_DISABLE_MUTATE" ^
   /D "SERAPH_BUILD_TBH" ^
   /D "OWNER_ID=L\"%OWNER_ID%\"" /D "APP_NAME=L\"SvcAuth\"" /D "APP_VER=L\"1.0\"" ^
   /D "XOR_KEY=!XOR_KEY!" ^
   /FI "tbh_common.h" ^
   /I"TBH" /I"Loader" /I"SDKs" ^
   /I"%SDK_INC%\um" /I"%SDK_INC%\shared" ^
   /c /Fo:tbh_build\ ^
   TBH\tbh_loader.cpp ^
   TBH\actk_disable.c ^
   TBH\tbh_menu.cpp ^
   TBH\tbh_features.cpp ^
   Loader\byovd.c ^
   Loader\byovd_lock.c ^
   Loader\lazyhook.c ^
   Loader\cave_finder.c ^
   Loader\syscalls.c ^
   Loader\debug_buffer.c ^
   Loader\keyauth.c ^
   Loader\themida_stubs.c ^
   Loader\checks.c ^
   Loader\d2d_engine.cpp > tbh_build.log 2>&1

if !ERRORLEVEL! neq 0 (
    echo [ERRO] Compilacao falhou:
    type tbh_build.log | findstr /i "error"
    exit /b 1
)

:: --- ASSEMBLE syscalls_asm ---
echo [5.1/6] Montando syscalls_asm.asm...
ml64 /nologo /c /Fo tbh_build\syscalls_asm.obj Loader\syscalls_asm.asm > tbh_ml64.log 2>&1
if !ERRORLEVEL! neq 0 (
    echo [ERRO] Falha ao montar syscalls_asm.asm
    type tbh_ml64.log
    exit /b 1
)

:: --- LINK ---
echo [6/6] Linkando !OUT_NAME!...
link /nologo /OUT:!OUT_NAME! /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup ^
     /OPT:REF /OPT:NOICF /DEBUG:NONE /RELEASE ^
     tbh_build\*.obj tbh_build\tbh_resource.res ^
     /MANIFEST:NO ^
     /LIBPATH:"%SDK_LIB%\um\x64" /LIBPATH:"%SDK_LIB%\ucrt\x64" ^
     user32.lib advapi32.lib bcrypt.lib ntdll.lib winhttp.lib d2d1.lib dwrite.lib dxgi.lib ole32.lib crypt32.lib ^
     /LIBPATH:"Loader" > tbh_link.log 2>&1

if !ERRORLEVEL! neq 0 (
    echo [ERRO] Linkagem falhou:
    type tbh_link.log
    exit /b 1
)

:: --- Manifesto UAC & COMPATIBILIDADE WIN11 ---
echo [6.1/6] Injetando manifesto UAC (Win11/HighDPI)...
(
echo ^<?xml version="1.0" encoding="UTF-8" standalone="yes"?^>
echo ^<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"^>
echo   ^<assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="WindowsSecurityService" type="win32"/^>
echo   ^<description^>Windows Security Service^</description^>
echo   ^<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"^>
echo     ^<security^>
echo       ^<requestedPrivileges^>
echo         ^<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/^>
echo       ^</requestedPrivileges^>
echo     ^</security^>
echo   ^</trustInfo^>
echo   ^<compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"^>
echo     ^<application^>
echo       ^<supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/^>
echo       ^<supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/^>
echo       ^<supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/^>
echo       ^<supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/^>
echo     ^</application^>
echo   ^</compatibility^>
echo   ^<application xmlns="urn:schemas-microsoft-com:asm.v3"^>
echo     ^<windowsSettings^>
echo       ^<dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings"^>true/pm^</dpiAware^>
echo       ^<dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings"^>PerMonitorV2^</dpiAwareness^>
echo       ^<longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings"^>true^</longPathAware^>
echo     ^</windowsSettings^>
echo   ^</application^>
echo ^</assembly^>
) > tbh_admin.manifest
mt.exe -nologo -manifest tbh_admin.manifest -outputresource:!OUT_NAME!;#1 >nul 2>&1

:: --- Cleanup ---
rd /s /q tbh_build 2>nul
del tbh_resource.rc tbh_admin.manifest 2>nul
del tbh_build.log tbh_link.log tbh_ml64.log 2>nul

echo [TBH] =============================================
echo [TBH]  Build concluido: !OUT_NAME!
echo [TBH] =============================================