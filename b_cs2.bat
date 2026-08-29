@echo off
setlocal enabledelayedexpansion
echo [1/7] Configurando ambiente de build para CS2 (DEBUG)...
set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
call %VCVARS% x64 >nul

set DIAGFLAGS=
python tools\gen_xor_strings_dynamic.py random Loader\xor_strings.h

if not exist build_cs2_ver.txt echo 0 > build_cs2_ver.txt
set /p BUILD_VER=<build_cs2_ver.txt
set /a BUILD_VER+=1
echo !BUILD_VER!> build_cs2_ver.txt
set OUT_NAME=CS2_DBG!BUILD_VER!.exe
echo [BUILD CS2] Versao: !BUILD_VER! saida: !OUT_NAME!
set OWNER_ID=5uQFO11cIm
set SDK_VER=10.0.26100.0
set SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\%SDK_VER%
set SDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%

if not exist loader_build mkdir loader_build
del /f /q /s loader_build\* >nul 2>&1

if not exist ntdll.lib (
    echo [INFO] Gerando ntdll.lib...
    lib /nologo /def:Loader\ntdll.def /out:ntdll.lib /machine:x64 >nul
)

copy /Y "Loader\CtiIo64.sys" "CtiIo64_tmp.sys" >nul
(
echo 302 RCDATA "CtiIo64_tmp.sys"
) > cs2.rc
rc /nologo /fo loader_build\cs2.res cs2.rc
del CtiIo64_tmp.sys cs2.rc 2>nul

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

echo [5/7] Compilando Loader do CS2...
cl /nologo /W3 /Ob1 /MT /EHsc /std:c++17 /D "_UNICODE" /D "UNICODE" ^
   /D "_AMD64_" /D "AMD64" /D "_CONSOLE" /D "SERAPH_CS2" ^
   /D "OWNER_ID=L\"%OWNER_ID%\"" /D "APP_NAME=L\"SvcAuth\"" /D "APP_VER=L\"1.0\"" ^
   /I"Loader" /I"CS2" /I"SDKs" ^
   /I"%SDK_INC%\um" /I"%SDK_INC%\shared" ^
   /c /Fo:loader_build\ ^
   CS2\cs2_game.cpp CS2\cs2_esp.cpp CS2\cs2_tigerlist.cpp CS2\cs2_stubs.cpp ^
   Loader\loader.c Loader\evasion_user.c Loader\checks.c Loader\command.c Loader\keyauth.c ^
   Loader\gui.c Loader\gui_core.cpp Loader\d2d_engine.cpp Loader\byovd.c ^
   Loader\syscalls.c Loader\config_crypto.c Loader\attach.c ^
   Loader\lazyhook.c Loader\debug_buffer.c Loader\antire.c Loader\antire_handles.c ^
   Loader\themida_stubs.c Loader\controller_input.c Loader\seraph_handle_bucket.c ^
   Loader\seraph_ptr_crypt.c Loader\seraph_ban_marker.c Loader\seraph_secure_val.c Loader\byovd_lock.c > build_loader_cs2.log 2>&1

if !ERRORLEVEL! neq 0 (
    echo [ERRO] Compilacao falhou:
    type build_loader_cs2.log
    del admin.manifest 2>nul
    exit /b 1
)

ml64 /nologo /c /Fo loader_build\syscalls_asm.obj Loader\syscalls_asm.asm > build_ml64_cs2.log 2>&1
if !ERRORLEVEL! neq 0 (echo [ERRO] ASM failed & exit /b 1)

echo [6/7] Linking CS2 Overlay...
link /nologo /OUT:!OUT_NAME! /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup ^
     /OPT:REF /OPT:NOICF /DEBUG:NONE /RELEASE ^
     loader_build\*.obj loader_build\cs2.res ^
     /MANIFEST:NO ^
     /LIBPATH:"%SDK_LIB%\um\x64" /LIBPATH:"%SDK_LIB%\ucrt\x64" ^
     user32.lib advapi32.lib bcrypt.lib ntdll.lib winhttp.lib d3d12.lib dxgi.lib d3dcompiler.lib dwmapi.lib shell32.lib d2d1.lib dwrite.lib ole32.lib crypt32.lib ^
     /LIBPATH:"Loader" > build_link_cs2.log 2>&1

if !ERRORLEVEL! neq 0 (
    echo [ERRO] Link falhou:
    type build_link_cs2.log
    del admin.manifest 2>nul
    exit /b 1
)

:: Injetar manifesto UAC (requireAdministrator) no executavel
mt.exe -nologo -manifest admin.manifest -outputresource:!OUT_NAME!;#1 > nul 2>&1

rd /s /q loader_build 2>nul
del cs2.rc admin.manifest 2>nul
echo Build CS2 concluido com sucesso. !OUT_NAME!
