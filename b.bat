@echo off
setlocal enabledelayedexpansion

:: --- CONFIGURAÇÃO DO AMBIENTE ---
echo [1/7] Configurando ambiente de build (RELEASE)...
set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
if not exist %VCVARS% (
    echo [ERRO] vcvarsall.bat nao encontrado em %VCVARS%
    exit /b 1
)
call %VCVARS% x64 >nul

:: FULL RELEASE MODE CONFIGURATION
:: NDEBUG - Desativa todos os macros DEBUG_* (debug.h gate) e logs em disco
:: SERAPH_THEMIDA_PROTECT - Ativa macros do Themida (necessário para o Themida reconhecer)
:: SERAPH_EXCLUDE_ESP - Remove tab/toggle ESP da UI para builds públicas
:: SERAPH_EXCLUDE_INVENTORY - Remove funcionalidades de inventory (já definido no comando cl)
set DIAGFLAGS=/D "NDEBUG" /D "SERAPH_THEMIDA_PROTECT" /D "ANTIRE_WEBHOOK_ID=L\"1500087717902422116\"" /D "ANTIRE_WEBHOOK_TOKEN=L\"ST1yfJFsoxYEGOi6nGsMz-FVV64NCaqWwLC4J6pPEM0EDkU-ZVx9KBTTVsxYog7NzTiO\""

:: --- XOR KEY RANDOMIZATION ---
echo [1.1/7] Gerando chave XOR aleatoria por build...
python tools\gen_xor_strings_dynamic.py random Loader\xor_strings.h
if !ERRORLEVEL! neq 0 (
    echo [ERRO] Falha ao gerar strings XOR. Usando chave padrao 0x55.
    echo #define XOR_KEY 0x55 > Loader\xor_strings.h
)
for /f "tokens=3 delims= " %%i in ('findstr /C:"#define XOR_KEY" Loader\xor_strings.h') do set XOR_KEY=%%i
echo [INFO] XOR_KEY = !XOR_KEY!

:: --- BUILD VERSION ---
if not exist build_ver.txt echo 1 > build_ver.txt
set /p BUILD_VER=<build_ver.txt
set /a BUILD_VER+=1
echo !BUILD_VER!> build_ver.txt
set OUT_NAME=LOADER!BUILD_VER!.exe
echo [BUILD] Versao: !BUILD_VER! -^> !OUT_NAME!
set OWNER_ID=5uQFO11cIm
set SDK_VER=10.0.26100.0
set SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\%SDK_VER%
set SDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%

:: --- PREPARAÇÃO DE DIRETÓRIOS ---
if exist loader_build rd /s /q loader_build
mkdir loader_build

:: --- PREPARAÇÃO DE BIBLIOTECAS ---
echo [2/7] Preparando bibliotecas de importacao...
if not exist ntdll.lib (
    echo [INFO] Gerando ntdll.lib a partir de ntdll.def...
    lib /nologo /def:Loader\ntdll.def /out:ntdll.lib /machine:x64 >nul
)

echo [3/7] Gerando recurso CtiIo64...
if not exist "Loader\CtiIo64.sys" (
    echo [ERRO] CtiIo64.sys nao encontrado em Loader\
    exit /b 1
)
copy /Y "Loader\CtiIo64.sys" "CtiIo64_tmp.sys" >nul
echo 302 RCDATA "CtiIo64_tmp.sys" > ctiio64.rc
rc /nologo /fo loader_build\ctiio64.res ctiio64.rc
if !ERRORLEVEL! neq 0 (
    echo [ERRO] Falha ao compilar ctiio64.res
    del CtiIo64_tmp.sys 2>nul
    exit /b 1
)
del CtiIo64_tmp.sys 2>nul

:: --- MANIFESTO (ADMIN) ---
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

:: --- COMPILAÇÃO DO LOADER ---
:: IMPORTANTE: Todo novo arquivo .c/.cpp criado no projeto DEVE ser adicionado
:: explicitamente na lista abaixo. Se esquecer, o linker vai falhar com
:: LNK2019 "símbolo externo não resolvido" mesmo que o código compile sem erros.
echo [5/7] Compilando Loader v19 (RELEASE)...
cl /nologo /W3 /O2 /Ob1 /MT /EHsc /std:c++17 /D "_UNICODE" /D "UNICODE" ^
   /D "_AMD64_" /D "AMD64" /D "_CONSOLE" /D "SERAPH_EXCLUDE_INVENTORY" ^
   /D "OWNER_ID=L\"%OWNER_ID%\"" /D "APP_NAME=L\"SvcAuth\"" /D "APP_VER=L\"1.0\"" ^
   /D "XOR_KEY=!XOR_KEY!" !DIAGFLAGS! ^
   /I"Loader" /I"SDKs" ^
   /I"%SDK_INC%\um" /I"%SDK_INC%\shared" ^
   /c /Fo:loader_build\ ^
  Loader\loader.c Loader\evasion_user.c Loader\checks.c Loader\command.c Loader\keyauth.c ^
  Loader\gui.c Loader\gui_core.cpp Loader\d2d_engine.cpp Loader\byovd.c ^
  Loader\syscalls.c Loader\config_crypto.c Loader\attach.c ^
  Loader\patch.c Loader\d2_patches.c ^
  Loader\cave_finder.c Loader\lazyhook.c Loader\gamespeed.c Loader\damage.c Loader\guardian.c Loader\byovd_lock.c Loader\health_regen.c Loader\immune_boss.c Loader\instakill.c Loader\rapid_fire.c Loader\fly.c Loader\lists.c Loader\havok.c Loader\esp.c Loader\aimbot.c Loader\skeleton.c Loader\tigerlist.c Loader\sobject_list.c ^
  Loader\suicide.c Loader\namechanger.c Loader\debug_buffer.c Loader\revive.c Loader\noturnback.c Loader\nojoinallies.c  Loader\noinactivity.c Loader\instant_abilities.c Loader\esp_overlay.cpp Loader\antire.c Loader\antire_handles.c Loader\self_hash.c Loader\controller_input.c ^
  Loader\interact_aura.c Loader\aura.c Loader\infinite_ammo.c Loader\ammo.c Loader\no_recoil.c Loader\ammo_brick.c Loader\handling_speed.c Loader\local_player.c Loader\player_cloner.c Loader\bunnyhop.c Loader\movespeed.c Loader\opk.c Loader\teleports.c Loader\silent_aim.c Loader\matchmaking.c Loader\aob_patterns.c Loader\weapon_stats.c Loader\thirdperson.c
if !ERRORLEVEL! neq 0 (
    echo [ERRO] Compilacao falhou.
    exit /b 1
)

:: --- ASSEMBLY DAS SYSCALLS REAIS ---
echo [5.1/7] Montando syscalls_asm.asm (ml64)...
ml64 /nologo /c /Fo loader_build\syscalls_asm.obj Loader\syscalls_asm.asm > build_ml64.log 2>&1
if !ERRORLEVEL! neq 0 (
    echo [ERRO] Falha ao montar syscalls_asm.asm
    exit /b 1
)

:: --- LINKAGEM DO LOADER ---
echo [6/7] Linkando Loader v30 com MT...
link /nologo /OUT:!OUT_NAME! /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup ^
     /OPT:REF /OPT:NOICF /DEBUG:NONE /RELEASE ^
     loader_build\*.obj loader_build\ctiio64.res ^
     /MANIFEST:NO ^
     /LIBPATH:"%SDK_LIB%\um\x64" /LIBPATH:"%SDK_LIB%\ucrt\x64" ^
     user32.lib advapi32.lib bcrypt.lib ntdll.lib winhttp.lib d3d12.lib dxgi.lib d3dcompiler.lib dwmapi.lib shell32.lib d2d1.lib dwrite.lib ole32.lib crypt32.lib SecureEngineSDK64.lib ^
     /LIBPATH:"Loader" /LIBPATH:"SDKs"
if !ERRORLEVEL! neq 0 (
    echo [ERRO] Linkagem falhou.
    exit /b 1
)

:: --- P6.1 EMBED SELF-HASH ---
echo [6.1/7] Embedding .text SHA256...
python tools\embed_hash.py !OUT_NAME!
if !ERRORLEVEL! neq 0 (
    echo [ERRO] Falha ao embutir hash no executavel.
    exit /b 1
)

:: Injeção de Manifesto via MT.EXE
mt.exe -nologo -manifest admin.manifest -outputresource:!OUT_NAME!;#1 > build_mt.log 2>&1

:: --- LIMPEZA ---
echo [7/7] Finalizando...
rd /s /q loader_build 2>nul
del ctiio64.rc admin.manifest 2>nul
del build_loader.log build_link.log build_ml64.log build_mt.log 2>nul
for /r Loader %%f in (*.ik) do del "%%f" 2>nul
del *.ik 2>nul
del *.pdb 2>nul
echo Build concluido com sucesso. !OUT_NAME!


