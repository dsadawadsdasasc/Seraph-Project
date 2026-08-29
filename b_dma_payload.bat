@echo off
:: ============================================================
:: b_dma_payload.bat - Build script for Seraph DMA Payload DLL
:: Usage: b_dma_payload.bat
:: ============================================================
setlocal enabledelayedexpansion

echo [PAYLOAD] =============================================
echo [PAYLOAD]  Seraph DMA Payload DLL Build
echo [PAYLOAD] =============================================

:: --- MSVC environment ---
echo [1/5] Configurando ambiente MSVC...
set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
if not exist %VCVARS% (
    echo [ERRO] vcvarsall.bat nao encontrado.
    exit /b 1
)
call %VCVARS% x64 >nul

:: --- Paths ---
set SDK_VER=10.0.26100.0
set SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\%SDK_VER%
set SDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%

:: DMA-Lib relative paths
set DMA_LIB_ROOT=..\DMA-Lib-main\Teeko-DMA-Lib-main\Teeko-DMA-Lib\Teeko-DMA-Lib\Teeko-DMA
set DMA_LIB_INC=%DMA_LIB_ROOT%
set DMA_LIB_DEPS=%DMA_LIB_ROOT%\deps
set DMA_LIB_LIBS=%DMA_LIB_ROOT%\libs
set DMA_LIB_CPP=%DMA_LIB_ROOT%\DMA.cpp

:: --- Prep build dir ---
if exist payload_build rd /s /q payload_build
mkdir payload_build

:: --- XOR key and definitions ---
set XOR_KEY=0x55
set OWNER_ID=5uQFO11cIm

:: --- Compiling Payload DLL ---
echo [2/5] Compilando Payload sources...

set DIAGFLAGS=/D "ANTIRE_WEBHOOK_ID=L\"1500087717902422116\"" /D "ANTIRE_WEBHOOK_TOKEN=L\"ST1yfJFsoxYEGOi6nGsMz-FVV64NCaqWwLC4J6pPEM0EDkU-ZVx9KBTTVsxYog7NzTiO\""

cl /nologo /W3 /O2 /Ob1 /MT /EHsc /std:c++17 ^
   /D "_UNICODE" /D "UNICODE" /D "_AMD64_" /D "AMD64" ^
   /D "NDEBUG" /D "SERAPH_DMA_BUILD" /D "SERAPH_EXCLUDE_INVENTORY" ^
   /D "SERAPH_EXCLUDE_WEAPON_STATS" /D "SERAPH_EXCLUDE_KILLAURA" ^
   /D "SERAPH_THEMIDA_PROTECT" ^
   /D "OWNER_ID=L\"%OWNER_ID%\"" /D "APP_NAME=L\"SvcAuth\"" /D "APP_VER=L\"1.0\"" ^
   /D "XOR_KEY=%XOR_KEY%" !DIAGFLAGS! ^
   /I"DMA" /I"Loader" /I"SDKs" ^
   /I"%DMA_LIB_INC%" /I"%DMA_LIB_DEPS%" ^
   /I"%SDK_INC%\um" /I"%SDK_INC%\shared" ^
   /c /Fo:payload_build\ ^
   ^
   Loader\evasion_user.c ^
   Loader\checks.c ^
   Loader\command.c ^
   Loader\keyauth.c ^
   Loader\gui.c ^
   Loader\gui_core.cpp ^
   Loader\d2d_engine.cpp ^
   Loader\config_crypto.c ^
   Loader\debug_buffer.c ^
   Loader\d2_patches.c ^
   Loader\gamespeed.c ^
   Loader\damage.c ^
   Loader\guardian.c ^
   Loader\health_regen.c ^
   Loader\immune_boss.c ^
   Loader\instakill.c ^
   Loader\silent_aim.c ^
   Loader\rapid_fire.c ^
   DMA\dma_fly.cpp ^
   Loader\lists.c ^
   Loader\esp.c ^
   Loader\aimbot.c ^
   Loader\skeleton.c ^
   Loader\bones.c ^
   Loader\suicide.c ^
   Loader\namechanger.c ^
   Loader\shadow_patch.c ^
   Loader\noturnback.c ^
   Loader\nojoinallies.c ^
   Loader\noinactivity.c ^
   Loader\instant_abilities.c ^
   Loader\esp_overlay.cpp ^
   Loader\interact_aura.c ^
   Loader\aura.c ^
   Loader\infinite_ammo.c ^
   Loader\ammo.c ^
   Loader\no_recoil.c ^
   Loader\ammo_brick.c ^
   Loader\handling_speed.c ^
   Loader\movespeed.c ^
   Loader\bunnyhop.c ^
   Loader\player_cloner.c ^
   Loader\tigerlist.c ^
   Loader\local_player.c ^
   Loader\sobject_list.c ^
   Loader\teleports.c ^
   Loader\revive.c ^
   Loader\thirdperson.c ^
   Loader\matchmaking.c ^
   Loader\seraph_handle_bucket.c ^
   Loader\seraph_ptr_crypt.c ^
   Loader\themida_stubs.c ^
   Loader\controller_input.c ^
   Loader\opk.c ^
   Loader\self_hash.c ^
   Loader\seraph_menu_trigger.c ^
   Loader\aob_patterns.c ^
   Loader\seraph_secure_val.c ^
   Loader\havok.c ^
   Loader\vischeck_mesh.c ^
   Loader\monster_skeleton.c ^
   Loader\instant_size.c ^
   Loader\monster_scale.c ^
   Loader\spinbot.c ^
   Loader\seraph_ban_marker.c ^
   Loader\activity_loader.c ^
   Loader\thirdperson.c ^
   ^
   DMA\dma_mem.cpp ^
   DMA\dma_attach.cpp ^
   DMA\dma_cave_finder.cpp ^
   DMA\dma_lazyhook.cpp ^
   DMA\dma_patch.cpp ^
   DMA\dma_payload_exports.cpp ^
   DMA\dma_antire_stub.cpp ^
   DMA\dma_scatter_tick.cpp ^
   DMA\dma_dll_loader.cpp ^
   DMA\dma_fixup.cpp ^
   DMA\seraph_kmbox.cpp ^
   DMA\seraph_fuser.cpp ^
   DMA\kmbox\kmboxNet_wrapper.cpp ^
   ^
   %DMA_LIB_CPP% ^
   > payload_build\compile.log 2>&1

if !ERRORLEVEL! neq 0 (
    echo [ERRO] Compilacao do Payload falhou:
    type payload_build\compile.log | findstr /i "error"
    echo [INFO] Log completo: payload_build\compile.log
    exit /b 1
)
echo [PAYLOAD] Compilacao OK.

:: --- Link DLL ---
echo [3/5] Linkando payload.dll...

link /nologo /DLL /OUT:payload.dll ^
     /OPT:REF /OPT:NOICF /DEBUG:NONE /RELEASE ^
     payload_build\*.obj ^
     /LIBPATH:"%SDK_LIB%\um\x64" /LIBPATH:"%SDK_LIB%\ucrt\x64" ^
     /LIBPATH:"%DMA_LIB_LIBS%" ^
     user32.lib advapi32.lib bcrypt.lib winhttp.lib ^
     d3d12.lib dxgi.lib d3dcompiler.lib dwmapi.lib ^
     shell32.lib d2d1.lib dwrite.lib ole32.lib crypt32.lib ^
     vmm.lib leechcore.lib delayimp.lib Ws2_32.lib ^
     /DELAYLOAD:vmm.dll /DELAYLOAD:leechcore.dll ^
     > payload_build\link.log 2>&1

if !ERRORLEVEL! neq 0 (
    echo [ERRO] Linkagem do Payload falhou:
    type payload_build\link.log
    exit /b 1
)
echo [PAYLOAD] Link OK.

:: --- Encriptar DLL para payload.bin para distribuição ---
echo [4/5] Gerando payload.bin encriptado...
python tools\encrypt_payload.py
if !ERRORLEVEL! neq 0 (
    echo [ERRO] Falha ao criptografar payload.
    exit /b 1
)

:: --- Cleanup ---
rd /s /q payload_build 2>nul

echo [PAYLOAD] =============================================
echo [PAYLOAD]  Build concluido com sucesso.
echo [PAYLOAD] =============================================
