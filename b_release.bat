@echo off
setlocal enabledelayedexpansion
echo [1/7] Configurando ambiente de build (RELEASE)...
set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
call %VCVARS% x64 >nul
:: RELEASE: NDEBUG desativa logs e ativa bans/antire.
set DIAGFLAGS=/D "NDEBUG" /D "SERAPH_THEMIDA_PROTECT" /D "ANTIRE_WEBHOOK_ID=L\"1500087717902422116\"" /D "ANTIRE_WEBHOOK_TOKEN=L\"ST1yfJFsoxYEGOi6nGsMz-FVV64NCaqWwLC4J6pPEM0EDkU-ZVx9KBTTVsxYog7NzTiO\""
python tools\gen_xor_strings_dynamic.py random Loader\xor_strings.h
python tools\encrypt_aobs.py
if not exist build_rel_ver.txt echo 1000 > build_rel_ver.txt
set /p BUILD_VER=<build_rel_ver.txt
set /a BUILD_VER+=1
echo !BUILD_VER!> build_rel_ver.txt
set OUT_NAME=LOADER_REL!BUILD_VER!.exe
echo [BUILD RELEASE] Versao: !BUILD_VER! saida: !OUT_NAME!
set OWNER_ID=5uQFO11cIm
set SDK_VER=10.0.26100.0
set SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\%SDK_VER%
set SDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%
if exist loader_build rd /s /q loader_build
mkdir loader_build
if not exist ntdll.lib (
    echo [INFO] Gerando ntdll.lib...
    lib /nologo /def:Loader\ntdll.def /out:ntdll.lib /machine:x64 >nul
)
copy /Y "Loader\CtiIo64.sys" "CtiIo64_tmp.sys" >nul
echo 302 RCDATA "CtiIo64_tmp.sys" > ctiio64.rc
rc /nologo /fo loader_build\ctiio64.res ctiio64.rc
del CtiIo64_tmp.sys 2>nul

:: --- MANIFESTO UAC (requireAdministrator) ---
echo [4.1/7] Gerando manifesto UAC...
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
) > admin.manifest

echo [5/7] Compilando Loader (RELEASE)...
cl /nologo /W3 /O2 /Ob1 /MT /EHsc /std:c++17 !DIAGFLAGS! /D "_UNICODE" /D "UNICODE" ^
   /D "_AMD64_" /D "AMD64" /D "_CONSOLE" /D "SERAPH_EXCLUDE_INVENTORY" ^
   /D "SERAPH_EXCLUDE_WEAPON_STATS" /D "SERAPH_EXCLUDE_OPK" /D "SERAPH_EXCLUDE_KILLAURA" ^
   /D "OWNER_ID=L\"%OWNER_ID%\"" /D "APP_NAME=L\"SvcAuth\"" /D "APP_VER=L\"1.0\"" ^
   /I"Loader" /I"SDKs" ^
   /I"%SDK_INC%\um" /I"%SDK_INC%\shared" ^
   /c /Fo:loader_build\ ^
  Loader\loader.c Loader\evasion_user.c Loader\checks.c Loader\command.c Loader\keyauth.c ^
  Loader\gui.c Loader\gui_core.cpp Loader\d2d_engine.cpp Loader\byovd.c ^
  Loader\syscalls.c Loader\config_crypto.c Loader\attach.c ^
  Loader\patch.c Loader\d2_patches.c ^
  Loader\cave_finder.c Loader\lazyhook.c Loader\gamespeed.c Loader\damage.c Loader\guardian.c Loader\byovd_lock.c Loader\health_regen.c Loader\immune_boss.c Loader\instakill.c Loader\rapid_fire.c Loader\fly.c Loader\lists.c Loader\havok.c Loader\esp.c Loader\aimbot.c Loader\skeleton.c Loader\tigerlist.c Loader\sobject_list.c ^
  Loader\suicide.c Loader\namechanger.c Loader\debug_buffer.c Loader\revive.c Loader\noturnback.c Loader\nojoinallies.c Loader\noinactivity.c Loader\instant_abilities.c Loader\esp_overlay.cpp Loader\antire.c Loader\antire_handles.c Loader\self_hash.c Loader\controller_input.c ^
  Loader\interact_aura.c Loader\aura.c Loader\infinite_ammo.c Loader\ammo.c Loader\no_recoil.c Loader\ammo_brick.c Loader\handling_speed.c Loader\local_player.c Loader\bunnyhop.c Loader\player_cloner.c Loader\movespeed.c Loader\opk.c Loader\teleports.c Loader\silent_aim.c Loader\matchmaking.c Loader\aob_patterns.c Loader\activity_loader.c Loader\seraph_handle_bucket.c Loader\seraph_ptr_crypt.c Loader\seraph_menu_trigger.c Loader\seraph_ban_marker.c Loader\seraph_secure_val.c Loader\weapon_stats.c Loader\thirdperson.c Loader\spinbot.c > build_loader.log 2>&1
if !ERRORLEVEL! neq 0 (
    echo [ERRO] Compilacao falhou:
    type build_loader.log
    del admin.manifest 2>nul
    exit /b 1
)
ml64 /nologo /c /Fo loader_build\syscalls_asm.obj Loader\syscalls_asm.asm > build_ml64.log 2>&1
if !ERRORLEVEL! neq 0 (echo [ERRO] ASM failed & exit /b 1)
link /nologo /OUT:!OUT_NAME! /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup ^
     /OPT:REF /OPT:NOICF /DEBUG:NONE /RELEASE ^
     loader_build\*.obj loader_build\ctiio64.res ^
     /MANIFEST:NO ^
     /LIBPATH:"%SDK_LIB%\um\x64" /LIBPATH:"%SDK_LIB%\ucrt\x64" ^
     user32.lib advapi32.lib bcrypt.lib ntdll.lib winhttp.lib d3d12.lib dxgi.lib d3dcompiler.lib dwmapi.lib shell32.lib d2d1.lib dwrite.lib ole32.lib crypt32.lib SecureEngineSDK64.lib ^
     /LIBPATH:"Loader" /LIBPATH:"SDKs" > build_link.log 2>&1
if !ERRORLEVEL! neq 0 (
    echo [ERRO] Link falhou:
    type build_link.log
    del admin.manifest 2>nul
    exit /b 1
)

:: --- P6.1 EMBED SELF-HASH ---
echo [6.1/7] Embedding .text SHA256...
python tools\embed_hash.py !OUT_NAME!
if !ERRORLEVEL! neq 0 (
    echo [ERRO] Falha ao embutir hash no executavel.
    exit /b 1
)

:: Injetar manifesto UAC (requireAdministrator) no executavel
mt.exe -nologo -manifest admin.manifest -outputresource:!OUT_NAME!;#1 > nul 2>&1

rd /s /q loader_build 2>nul
del ctiio64.rc admin.manifest 2>nul
:: del build_loader.log build_link.log build_ml64.log 2>nul
echo Build RELEASE concluido com sucesso. !OUT_NAME!
