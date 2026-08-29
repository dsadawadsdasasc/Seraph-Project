@echo off
setlocal enabledelayedexpansion

:: ============================================================================
:: build_payload.bat -- Compiles svc.dll (the cheat payload).
::
:: svc.dll is the renamed DLL form of the legacy LOADERxxx.exe MINUS the
:: stub-only files.  It exports a single entry point: PayloadMain.
::
:: Sources are essentially the legacy b.bat list MINUS Loader/loader.c
:: PLUS Loader/payload_entry.c (which provides PayloadMain).
::
:: The CtiIo64.sys driver blob is embedded as resource 302 RCDATA, same
:: as the legacy build.  byovd.c was patched to use &__ImageBase so the
:: lookup correctly targets svc.dll (not the host Stub.exe).
::
:: This script is INDEPENDENT of b.bat.  Both produce different artefacts
:: and can coexist for testing.
:: ============================================================================

echo [pld 1/6] Configuring build environment...
set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
if not exist %VCVARS% (
    echo [ERROR] vcvarsall.bat not found at %VCVARS%
    exit /b 1
)
call %VCVARS% x64 >nul

set DIAGFLAGS=/D "NDEBUG" /D "ANTIRE_WEBHOOK_ID=L\"1500087717902422116\"" /D "ANTIRE_WEBHOOK_TOKEN=L\"ST1yfJFsoxYEGOi6nGsMz-FVV64NCaqWwLC4J6pPEM0EDkU-ZVx9KBTTVsxYog7NzTiO\""

:: --- XOR KEY ---
:: NOTE: build_stub.bat regenerates this file.  If both scripts are run
:: back-to-back, the latter run determines the final key.  When build_split.bat
:: orchestrates both, payload runs LAST so payload's key is the active one.
:: Phase 5 will isolate keys by giving each binary its own header.
echo [pld 1.1/6] Regenerating XOR strings...
python tools\gen_xor_strings_dynamic.py random Loader\xor_strings.h
if !ERRORLEVEL! neq 0 (
    echo [WARN] gen_xor_strings failed; using fallback 0x55
    echo #define XOR_KEY 0x55 > Loader\xor_strings.h
)
for /f "tokens=3 delims= " %%i in ('findstr /C:"#define XOR_KEY" Loader\xor_strings.h') do set XOR_KEY=%%i
echo [INFO] XOR_KEY = !XOR_KEY!

:: --- BUILD VERSION ---
if not exist build_payload_ver.txt echo 1 > build_payload_ver.txt
set /p PLD_VER=<build_payload_ver.txt
set /a PLD_VER+=1
echo !PLD_VER!> build_payload_ver.txt
echo [BUILD] Payload version: !PLD_VER!

set OWNER_ID=5uQFO11cIm
set SDK_VER=10.0.26100.0
set SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\%SDK_VER%
set SDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%

if exist payload_build rd /s /q payload_build
mkdir payload_build

:: --- IMPORT LIBRARY ---
echo [pld 2/6] Preparing ntdll import library...
if not exist ntdll.lib (
    lib /nologo /def:Loader\ntdll.def /out:ntdll.lib /machine:x64 >nul
)

:: --- EMBED CtiIo64.sys AS RESOURCE 302 ---
echo [pld 3/6] Embedding CtiIo64.sys as resource 302...
if not exist "Loader\CtiIo64.sys" (
    echo [ERROR] CtiIo64.sys not found at Loader\
    exit /b 1
)
copy /Y "Loader\CtiIo64.sys" "CtiIo64_tmp.sys" >nul
echo 302 RCDATA "CtiIo64_tmp.sys" > ctiio64_payload.rc
rc /nologo /fo payload_build\ctiio64.res ctiio64_payload.rc
if !ERRORLEVEL! neq 0 (
    echo [ERROR] Failed to compile ctiio64.res
    del CtiIo64_tmp.sys 2>nul
    exit /b 1
)
del CtiIo64_tmp.sys 2>nul
del ctiio64_payload.rc 2>nul

:: --- COMPILE PAYLOAD ---
:: NOTE: Identical source list to legacy b.bat MINUS Loader\loader.c
:: PLUS Loader\payload_entry.c.  Every new .c added to the project must
:: be added here too (same rule as b.bat).
echo [pld 4/6] Compiling payload sources...
cl /nologo /W3 /O2 /Ob1 /MT /EHsc /std:c++17 /LD /D "_UNICODE" /D "UNICODE" ^
   /D "_AMD64_" /D "AMD64" /D "_USRDLL" /D "NDEBUG" ^
   /D "SERAPH_BUILD_PAYLOAD" ^
   /D "OWNER_ID=L\"%OWNER_ID%\"" /D "APP_NAME=L\"SvcAuth\"" /D "APP_VER=L\"1.0\"" ^
   /D "XOR_KEY=!XOR_KEY!" !DIAGFLAGS! ^
   /I"Loader" /I"SDKs" ^
   /I"%SDK_INC%\um" /I"%SDK_INC%\shared" ^
   /c /Fo:payload_build\ ^
    Loader\payload_entry.c ^
    Loader\evasion_user.c Loader\keyauth.c ^
    Loader\gui.c Loader\gui_core.cpp Loader\d2d_engine.cpp Loader\byovd.c ^
    Loader\syscalls.c Loader\config_crypto.c Loader\attach.c ^
    Loader\patch.c Loader\d2_patches.c ^
    Loader\cave_finder.c Loader\lazyhook.c Loader\gamespeed.c Loader\damage.c ^
    Loader\guardian.c Loader\byovd_lock.c Loader\health_regen.c ^
    Loader\immune_boss.c Loader\instakill.c Loader\silent_aim.c Loader\chams.c ^
    Loader\rapid_fire.c Loader\fly.c Loader\lists.c ^
    Loader\esp.c Loader\aimbot.c Loader\skeleton.c Loader\tigerlist.c Loader\sobject_list.c ^
    Loader\suicide.c Loader\namechanger.c Loader\debug_buffer.c Loader\revive.c Loader\no_recoil.c ^
    Loader\shadow_patch.c Loader\noturnback.c Loader\nojoinallies.c ^
    Loader\noinactivity.c Loader\instant_abilities.c Loader\esp_overlay.cpp ^
    Loader\antire.c Loader\antire_handles.c Loader\themida_stubs.c ^
    Loader\interact_aura.c Loader\aura.c Loader\infinite_ammo.c Loader\ammo_brick.c Loader\handling_speed.c Loader\local_player.c Loader\player_cloner.c Loader\bunnyhop.c Loader\movespeed.c Loader\teleports.c Loader\matchmaking.c > build_payload_compile.log 2>&1
if !ERRORLEVEL! neq 0 (
    echo [ERROR] Payload compilation failed:
    type build_payload_compile.log | findstr /i "error"
    exit /b 1
)

:: NOTE: checks.c and command.c are STUB-ONLY (HVCI/SecureBoot gate and
:: RelaunchAsAdmin live in the stub).  No payload TU references their
:: symbols, so excluding them keeps svc.dll smaller and avoids drag-in
:: of unrelated globals.

:: --- ASSEMBLE syscalls_asm.asm ---
echo [pld 4.1/6] Assembling syscalls_asm...
ml64 /nologo /c /Fo payload_build\syscalls_asm.obj Loader\syscalls_asm.asm > build_payload_ml64.log 2>&1
if !ERRORLEVEL! neq 0 (
    echo [ERROR] ml64 failed:
    type build_payload_ml64.log
    exit /b 1
)

:: --- LINK svc.dll ---
:: /DLL                — output is a DLL
:: No /ENTRY            — uses _DllMainCRTStartup default
:: /EXPORT:PayloadMain  — guarantees export even if the linker decides to omit
::                        it (we also have __declspec(dllexport) but belt and
::                        braces is appropriate for a manually-loaded DLL).
::
:: NOTE: /DYNAMICBASE stays default-on so .reloc is emitted.  The Phase 4
:: manual mapper relies on .reloc to relocate when mapped at non-preferred
:: base.  Do NOT add /FIXED here.
echo [pld 5/6] Linking svc.dll...
link /nologo /DLL /OUT:svc.dll ^
     /EXPORT:PayloadMain ^
     /OPT:REF /OPT:NOICF /DEBUG:NONE /RELEASE ^
     payload_build\*.obj payload_build\ctiio64.res ^
     /MANIFEST:NO ^
     /LIBPATH:"%SDK_LIB%\um\x64" /LIBPATH:"%SDK_LIB%\ucrt\x64" /LIBPATH:"." ^
     user32.lib advapi32.lib bcrypt.lib ntdll.lib winhttp.lib ^
     d3d12.lib dxgi.lib d3dcompiler.lib dwmapi.lib shell32.lib ^
     d2d1.lib dwrite.lib ole32.lib crypt32.lib > build_payload_link.log 2>&1
if !ERRORLEVEL! neq 0 (
    echo [ERROR] svc.dll link failed:
    type build_payload_link.log
    exit /b 1
)

:: --- CLEANUP ---
echo [pld 6/6] Cleaning up...
rd /s /q payload_build 2>nul
del build_payload_compile.log build_payload_ml64.log build_payload_link.log 2>nul
del svc.exp svc.lib 2>nul

echo svc.dll build complete (v!PLD_VER!).
endlocal
