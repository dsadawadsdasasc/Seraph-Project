@echo off
setlocal enabledelayedexpansion
echo [DIAG] Build Marathon SEM CtiIo64 embutido (teste de deteccao)...
set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
call %VCVARS% x64 >nul

set DIAGFLAGS=
python tools\gen_xor_strings_dynamic.py random Loader\xor_strings.h

set OUT_NAME=MARATHON_DIAG_NODRIVER.exe
echo [DIAG] Saida: %OUT_NAME%
set OWNER_ID=5uQFO11cIm
set SDK_VER=10.0.26100.0
set SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\%SDK_VER%
set SDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%

if exist loader_build rd /s /q loader_build
mkdir loader_build

if not exist ntdll.lib (
    lib /nologo /def:Loader\ntdll.def /out:ntdll.lib /machine:x64 >nul
)

:: DIAG: Sem recurso RCDATA (CtiIo64.sys nao embutido)
:: Cria um .res vazio para satisfazer o linker
echo // empty > marathon_diag.rc
rc /nologo /fo loader_build\marathon.res marathon_diag.rc
del marathon_diag.rc 2>nul

echo [4.1] Gerando manifesto UAC...
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

echo [5] Compilando...
cl /nologo /W3 /Ob1 /MT /EHsc /std:c++17 /D "_UNICODE" /D "UNICODE" ^
   /D "_AMD64_" /D "AMD64" /D "_CONSOLE" /D "SERAPH_MARATHON" ^
   /D "OWNER_ID=L\"%OWNER_ID%\"" /D "APP_NAME=L\"SvcAuth\"" /D "APP_VER=L\"1.0\"" ^
   /I"Loader" /I"Marathon" /I"SDKs" ^
   /I"%SDK_INC%\um" /I"%SDK_INC%\shared" ^
   /c /Fo:loader_build\ ^
   Marathon\loader.cpp Marathon\attach.cpp Marathon\esp_overlay.cpp Marathon\gui_core.cpp ^
   Marathon\marathon_game.cpp Marathon\marathon_esp.cpp Marathon\marathon_stubs.cpp ^
   Marathon\marathon_menu_trigger.cpp Marathon\marathon_tigerlist.cpp Marathon\marathon_skeleton.cpp Marathon\marathon_sobject.cpp ^
   Loader\evasion_user.c Loader\checks.c Loader\command.c Loader\keyauth.c ^
   Loader\gui.c Loader\d2d_engine.cpp Loader\byovd.c ^
   Loader\syscalls.c Loader\config_crypto.c ^
   Loader\lazyhook.c Loader\debug_buffer.c Loader\antire.c Loader\antire_handles.c ^
   Loader\themida_stubs.c Loader\controller_input.c Loader\seraph_handle_bucket.c ^
   Loader\seraph_ptr_crypt.c Loader\seraph_ban_marker.c Loader\seraph_secure_val.c > build_loader_m.log 2>&1

if !ERRORLEVEL! neq 0 (
    echo [ERRO] Compilacao falhou:
    type build_loader_m.log
    del admin.manifest 2>nul
    exit /b 1
)

ml64 /nologo /c /Fo loader_build\syscalls_asm.obj Loader\syscalls_asm.asm > build_ml64_m.log 2>&1
if !ERRORLEVEL! neq 0 (echo [ERRO] ASM failed & exit /b 1)

echo [6] Linking...
link /nologo /OUT:%OUT_NAME% /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup ^
     /OPT:REF /OPT:NOICF /DEBUG:NONE /RELEASE ^
     loader_build\*.obj loader_build\marathon.res ^
     /MANIFEST:NO ^
     /LIBPATH:"%SDK_LIB%\um\x64" /LIBPATH:"%SDK_LIB%\ucrt\x64" ^
     user32.lib advapi32.lib bcrypt.lib ntdll.lib winhttp.lib d3d12.lib dxgi.lib d3dcompiler.lib dwmapi.lib shell32.lib d2d1.lib dwrite.lib ole32.lib crypt32.lib ^
     /LIBPATH:"Loader" > build_link_m.log 2>&1

if !ERRORLEVEL! neq 0 (
    echo [ERRO] Link falhou:
    type build_link_m.log
    del admin.manifest 2>nul
    exit /b 1
)

mt.exe -nologo -manifest admin.manifest -outputresource:%OUT_NAME%;#1 > nul 2>&1

rd /s /q loader_build 2>nul
del admin.manifest 2>nul
echo [DIAG] Build concluida: %OUT_NAME%
echo [DIAG] TESTE: abra com o Marathon rodando. Se NAO crashar = CtiIo64 embutido e o problema.
