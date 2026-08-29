@echo off
:: ============================================================
:: b_dma_release.bat - Release build script for Seraph DMA
:: Usage: b_dma_release.bat
:: ============================================================
setlocal enabledelayedexpansion

echo [DMA RELEASE] =====================================
echo [DMA RELEASE]  Seraph DMA Release Build
echo [DMA RELEASE] =====================================

:: --- MSVC environment ---
echo [1/6] Configurando ambiente MSVC...
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

:: --- Build version ---
if not exist build_dma_rel_ver.txt echo 1000 > build_dma_rel_ver.txt
set /p BUILD_VER=<build_dma_rel_ver.txt
set /a BUILD_VER+=1
echo !BUILD_VER!> build_dma_rel_ver.txt
set OUT_NAME=LOADER_DMA_REL!BUILD_VER!.exe
echo [DMA RELEASE] Version: !BUILD_VER! -^> !OUT_NAME!

:: --- XOR key randomization ---
echo [1.1/6] Gerando chave XOR...
python tools\gen_xor_strings_dynamic.py random Loader\xor_strings.h
if !ERRORLEVEL! neq 0 (
    echo [WARN] Falha ao gerar XOR key. Usando chave padrao 0x55.
    echo #define XOR_KEY 0x55 > Loader\xor_strings.h
)
for /f "tokens=3 delims= " %%i in ('findstr /C:"#define XOR_KEY" Loader\xor_strings.h') do set XOR_KEY=%%i
echo [DMA RELEASE] XOR_KEY = !XOR_KEY!

:: --- Owner ID ---
set OWNER_ID=5uQFO11cIm

:: --- Prep build dir ---
if exist dma_rel_build rd /s /q dma_rel_build
mkdir dma_rel_build

:: --- Verify DLLs MemProcFS ---
echo [1.5/6] Verificando DLLs MemProcFS em DMA\...
if not exist DMA\vmm.dll (
    echo [ERRO] DMA\vmm.dll nao encontrada!
    exit /b 1
)
if not exist DMA\leechcore.dll (
    echo [ERRO] DMA\leechcore.dll nao encontrada!
    exit /b 1
)
if not exist DMA\FTD3XX.dll (
    echo [ERRO] DMA\FTD3XX.dll nao encontrada!
    exit /b 1
)
powershell -ExecutionPolicy Bypass -NoProfile -File "_memprocfs_dl\verify_dlls.ps1"
if errorlevel 1 exit /b 1

:: --- Admin manifest (DMA requires elevation) ---
echo [2/6] Gerando manifesto UAC (requireAdministrator)...
(
echo ^<?xml version="1.0" encoding="UTF-8" standalone="yes"?^>
echo ^<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"^>
echo   ^<assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="SeraphDMARelease" type="win32"/^>
echo   ^<description^>Seraph DMA Release^</description^>
echo   ^<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"^>
echo     ^<security^>
echo       ^<requestedPrivileges^>
echo         ^<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/^>
echo       ^</requestedPrivileges^>
echo     ^</security^>
echo   ^</trustInfo^>
echo ^</assembly^>
) > dma_rel_admin.manifest

:: --- Compiling Release ---
echo [3/6] Compilando DMA sources (RELEASE)...

set DIAGFLAGS=/D "NDEBUG" /D "SERAPH_THEMIDA_PROTECT" /D "ANTIRE_WEBHOOK_ID=L\"1500087717902422116\"" /D "ANTIRE_WEBHOOK_TOKEN=L\"ST1yfJFsoxYEGOi6nGsMz-FVV64NCaqWwLC4J6pPEM0EDkU-ZVx9KBTTVsxYog7NzTiO\""

cl /nologo /W3 /O2 /Ob1 /MT /EHsc /std:c++17 ^
   /D "_UNICODE" /D "UNICODE" /D "_AMD64_" /D "AMD64" ^
   /D "NDEBUG" /D "SERAPH_DMA_BUILD" /D "SERAPH_EXCLUDE_INVENTORY" ^
   /D "SERAPH_EXCLUDE_WEAPON_STATS" /D "SERAPH_EXCLUDE_KILLAURA" ^
   /D "SERAPH_THEMIDA_PROTECT" ^
   /D "OWNER_ID=L\"%OWNER_ID%\"" /D "APP_NAME=L\"SvcAuth\"" /D "APP_VER=L\"1.0\"" ^
   /D "XOR_KEY=!XOR_KEY!" !DIAGFLAGS! ^
   /I"DMA" /I"Loader" /I"SDKs" ^
   /I"%DMA_LIB_INC%" /I"%DMA_LIB_DEPS%" ^
   /I"%SDK_INC%\um" /I"%SDK_INC%\shared" ^
   /c /Fo:dma_rel_build\ ^
     Loader\keyauth.c ^
     Loader\config_crypto.c ^
     Loader\seraph_handle_bucket.c ^
     Loader\seraph_ptr_crypt.c ^
     DMA\dma_entry.cpp ^
     DMA\dma_dll_loader.cpp ^
     DMA\dma_pe_loader.cpp ^
     DMA\dma_fixup.cpp ^
   > dma_rel_build\compile.log 2>&1

if !ERRORLEVEL! neq 0 (
    echo [ERRO] Compilacao falhou:
    type dma_rel_build\compile.log | findstr /i "error"
    exit /b 1
)
echo [DMA RELEASE] Compilacao OK.

:: --- Compile resource file ---
echo [3.5/6] Compilando recursos (vmm.dll + leechcore.dll embutidos)...
rc /nologo /fo dma_rel_build\dma_res.res DMA\dma_res.rc > dma_rel_build\rc.log 2>&1
if !ERRORLEVEL! neq 0 (
    echo [ERRO] Falha ao compilar dma_res.rc:
    type dma_rel_build\rc.log
    exit /b 1
)
echo [DMA RELEASE] Recursos compilados OK.

:: --- LINK ---
echo [4/6] Linkando Release DMA.exe...
link /nologo /OUT:!OUT_NAME! ^
     /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup ^
     /OPT:REF /OPT:NOICF /DEBUG:NONE /RELEASE ^
     /MANIFEST:NO ^
     dma_rel_build\*.obj dma_rel_build\dma_res.res ^
     /LIBPATH:"%SDK_LIB%\um\x64" /LIBPATH:"%SDK_LIB%\ucrt\x64" ^
     /LIBPATH:"%DMA_LIB_LIBS%" /LIBPATH:"SDKs" /LIBPATH:"Loader" ^
     user32.lib advapi32.lib bcrypt.lib winhttp.lib ^
     d3d12.lib dxgi.lib d3dcompiler.lib dwmapi.lib ^
     shell32.lib d2d1.lib dwrite.lib ole32.lib crypt32.lib ^
     vmm.lib leechcore.lib delayimp.lib Ws2_32.lib SecureEngineSDK64.lib ^
     /DELAYLOAD:vmm.dll /DELAYLOAD:leechcore.dll ^
     > dma_rel_build\link.log 2>&1

if !ERRORLEVEL! neq 0 (
    echo [ERRO] Linkagem falhou:
    type dma_rel_build\link.log
    exit /b 1
)
echo [DMA RELEASE] Link OK.

:: --- Inject UAC manifest ---
echo [5/6] Injetando manifesto UAC...
mt.exe -nologo -manifest dma_rel_admin.manifest -outputresource:!OUT_NAME!;#1 > dma_rel_build\mt.log 2>&1

:: [6/6] Verify output size
echo [6/6] Verificando tamanho do executavel...
for %%A in (!OUT_NAME!) do set EXE_SIZE=%%~zA
if !EXE_SIZE! LSS 4500000 (
    echo [WARN] !OUT_NAME! parece pequeno demais ^(!EXE_SIZE! bytes^).
)

:: --- Cleanup ---
rd /s /q dma_rel_build 2>nul
del dma_rel_admin.manifest 2>nul
for /r DMA %%f in (*.ik) do del "%%f" 2>nul
del *.ik 2>nul
del *.pdb 2>nul

echo.
echo [DMA RELEASE] =====================================
echo [DMA RELEASE]  Build RELEASE concluido: !OUT_NAME!
echo [DMA RELEASE] =====================================
