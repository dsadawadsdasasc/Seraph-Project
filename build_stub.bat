@echo off
setlocal enabledelayedexpansion

:: ============================================================================
:: build_stub.bat -- Compiles Stub.exe (the small front-end binary).
::
:: Stub.exe responsibilities (in order):
::   1. Apply mitigation policies (DEP/ASLR/CFG/image-load).
::   2. Single-instance mutex.
::   3. HVCI/SecureBoot gate.
::   4. PEB spoof.
::   5. KeyAuth login (D2D UI).
::   6. Download/decrypt/manual-map svc.dll  (Phase 3+).
::   7. Call PayloadMain.
::
:: For Phase 2 (current), step 6 is replaced by LoadLibraryExW("svc.dll")
:: on a local plaintext file produced by build_payload.bat.
::
:: This script is INDEPENDENT of b.bat (legacy monolithic build).  Both
:: can be run in parallel; they share Loader/ source headers but produce
:: separate artefacts.
:: ============================================================================

echo [stub 1/6] Configuring build environment...
set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
if not exist %VCVARS% (
    echo [ERROR] vcvarsall.bat not found at %VCVARS%
    exit /b 1
)
call %VCVARS% x64 >nul

set DIAGFLAGS=/D "NDEBUG" /D "SERAPH_THEMIDA_PROTECT" /D "ANTIRE_WEBHOOK_ID=L\"1500087717902422116\"" /D "ANTIRE_WEBHOOK_TOKEN=L\"ST1yfJFsoxYEGOi6nGsMz-FVV64NCaqWwLC4J6pPEM0EDkU-ZVx9KBTTVsxYog7NzTiO\""

:: --- XOR KEY ---
:: Phase 1: shared with payload via Loader/xor_strings.h.  Phase 5 will
:: split into Stub/stub_xor_strings.h with an independent key.
echo [stub 1.1/6] Regenerating XOR strings...
python tools\gen_xor_strings_dynamic.py random Loader\xor_strings.h
if !ERRORLEVEL! neq 0 (
    echo [WARN] gen_xor_strings failed; using fallback 0x55
    echo #define XOR_KEY 0x55 > Loader\xor_strings.h
)
for /f "tokens=3 delims= " %%i in ('findstr /C:"#define XOR_KEY" Loader\xor_strings.h') do set XOR_KEY=%%i
echo [INFO] XOR_KEY = !XOR_KEY!

:: --- BUILD VERSION ---
if not exist build_stub_ver.txt echo 1 > build_stub_ver.txt
set /p STUB_VER=<build_stub_ver.txt
set /a STUB_VER+=1
echo !STUB_VER!> build_stub_ver.txt
echo [BUILD] Stub version: !STUB_VER!

set OWNER_ID=5uQFO11cIm
set SDK_VER=10.0.26100.0
set SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\%SDK_VER%
set SDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%

if exist stub_build rd /s /q stub_build
mkdir stub_build

:: --- IMPORT LIBRARY (ntdll) ---
echo [stub 2/6] Preparing ntdll import library...
if not exist ntdll.lib (
    lib /nologo /def:Loader\ntdll.def /out:ntdll.lib /machine:x64 >nul
)

:: --- ADMIN MANIFEST ---
echo [stub 3/6] Generating admin manifest...
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
echo ^</assembly^>
) > stub.manifest

:: --- COMPILE STUB ---
:: Sources:
::   Stub/stub_entry.c   - wWinMain, mitigation, mutex, payload load
::   Stub/stub_login.c   - login UI loop, KeyAuth call
::   Stub/stub_log.c     - WriteLog/WriteLogFile no-op stubs (gui.c absent)
::   Loader/checks.c     - HVCI/SecureBoot gate
::   Loader/command.c    - RelaunchAsAdmin (if needed)
::   Loader/keyauth.c    - KeyAuthValidate + ban + (P3.3) GetPayloadKeys
::   Loader/syscalls.c   - direct syscalls (manual mapper Phase 4 needs them)
::   Loader/debug_buffer.c - ring buffer for diagnostics
::   Loader/evasion_user.c - anti-debug checks
::   Loader/antire.c     - process scanner, runs early in stub
::   Loader/d2d_engine.cpp - D2D login UI framework (extracted from gui_core.cpp)
echo [stub 4/6] Compiling sources...
cl /nologo /W3 /O2 /Ob1 /MT /EHsc /D "_UNICODE" /D "UNICODE" ^
   /D "_AMD64_" /D "AMD64" /D "_CONSOLE" /D "NDEBUG" ^
   /D "SERAPH_BUILD_STUB" /D "SERAPH_STUB_LOG_IMPL" ^
   /D "OWNER_ID=L\"%OWNER_ID%\"" /D "APP_NAME=L\"SvcAuth\"" /D "APP_VER=L\"1.0\"" ^
   /D "XOR_KEY=!XOR_KEY!" /D "STUB_VER=!STUB_VER!" !DIAGFLAGS! ^
   /I"Loader" /I"Stub" /I"SDKs" ^
   /I"%SDK_INC%\um" /I"%SDK_INC%\shared" ^
   /c /Fo:stub_build\ ^
   Stub\stub_entry.c Stub\stub_login.c Stub\stub_log.c ^
   Stub\stub_crypto.c Stub\stub_transport.c ^
   Stub\stub_pe_parser.c Stub\stub_victim.c Stub\stub_stomp.c Stub\stub_evasion.c ^
   Loader\self_hash.c ^
   Loader\checks.c Loader\command.c Loader\keyauth.c ^
   Loader\syscalls.c Loader\debug_buffer.c Loader\evasion_user.c ^
   Loader\antire.c Loader\antire_handles.c Loader\d2d_engine.cpp ^
   Loader\seraph_ban_marker.c Loader\seraph_ptr_crypt.c Loader\seraph_secure_val.c Loader\themida_stubs.c > build_stub_compile.log 2>&1
if !ERRORLEVEL! neq 0 (
    echo [ERROR] Stub compilation failed:
    type build_stub_compile.log | findstr /i "error"
    exit /b 1
)

:: --- ASSEMBLE syscalls_asm.asm ---
echo [stub 4.1/6] Assembling syscalls_asm...
ml64 /nologo /c /Fo stub_build\syscalls_asm.obj Loader\syscalls_asm.asm > build_stub_ml64.log 2>&1
if !ERRORLEVEL! neq 0 (
    echo [ERROR] ml64 failed:
    type build_stub_ml64.log
    exit /b 1
)

:: --- LINK Stub.exe ---
echo [stub 5/6] Linking Stub.exe...
link /nologo /OUT:Stub.exe /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup ^
     /OPT:REF /OPT:NOICF /DEBUG:NONE /RELEASE ^
     stub_build\*.obj ^
     /MANIFEST:NO ^
     /LIBPATH:"%SDK_LIB%\um\x64" /LIBPATH:"%SDK_LIB%\ucrt\x64" /LIBPATH:"Loader" /LIBPATH:"." ^
     user32.lib advapi32.lib bcrypt.lib ntdll.lib winhttp.lib ^
     d2d1.lib dwrite.lib ole32.lib crypt32.lib shell32.lib dwmapi.lib ^
     kernel32.lib > build_stub_link.log 2>&1
if !ERRORLEVEL! neq 0 (
    echo [ERROR] Stub link failed:
    type build_stub_link.log
    exit /b 1
)

:: --- INJECT MANIFEST ---
mt.exe -nologo -manifest stub.manifest -outputresource:Stub.exe;#1 > build_stub_mt.log 2>&1

:: --- P6.1 EMBED SELF-HASH ---
echo [stub 5.1/6] Embedding .text SHA256...
python tools\embed_hash.py Stub.exe
if !ERRORLEVEL! neq 0 (
    echo [ERROR] embed_hash failed
    exit /b 1
)

:: --- CLEANUP ---
echo [stub 6/6] Cleaning up...
rd /s /q stub_build 2>nul
del stub.manifest 2>nul
del build_stub_compile.log build_stub_ml64.log build_stub_link.log build_stub_mt.log 2>nul

echo Stub.exe build complete (v!STUB_VER!).
endlocal
