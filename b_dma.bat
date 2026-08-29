@echo off
:: ============================================================
:: b_dma.bat - Build script for Seraph DMA
:: Usage: b_dma.bat [release]
:: ============================================================
setlocal enabledelayedexpansion

:: =============================================================================
:: b_dma.bat  --  Build script for the Seraph DMA EXE.
::
:: Architecture:
::   DMA.exe (standalone, operator machine) → FPGA (MemProcFS/VMMDLL)
::     → PCIe → victim machine RAM (Destiny 2)
::
:: No driver loading, no BYOVD, no Themida, no syscall stubs needed.
:: All BYOVD_xxx → DMA_xxx via macros in DMA/byovd.h → dma_mem.hpp.
:: All Themida macros empty via DMA/ThemidaSDK.h.
:: All AntiRE stubs via DMA/antire.h + antire_handles.h.
::
:: DEPENDENCIES (embedded as RCDATA resources inside DMA.exe):
::   vmm.dll + leechcore.dll must be placed in DMA\ before building.
::   They are extracted to %TEMP% at runtime by dma_dll_loader.cpp.
::   Download from:
::     https://github.com/ufrisk/MemProcFS/releases  (vmm.dll)
::     https://github.com/ufrisk/LeechCore/releases  (leechcore.dll)
::
:: =============================================================================

echo [DMA] =============================================
echo [DMA]  Seraph DMA Build
echo [DMA] =============================================

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

:: DMA-Lib relative paths (from Seraph/ directory)
set DMA_LIB_ROOT=..\DMA-Lib-main\Teeko-DMA-Lib-main\Teeko-DMA-Lib\Teeko-DMA-Lib\Teeko-DMA
set DMA_LIB_INC=%DMA_LIB_ROOT%
set DMA_LIB_DEPS=%DMA_LIB_ROOT%\deps
set DMA_LIB_LIBS=%DMA_LIB_ROOT%\libs
set DMA_LIB_CPP=%DMA_LIB_ROOT%\DMA.cpp

:: --- Build version ---
if not exist build_ver.txt echo 1 > build_ver.txt
set /p BUILD_VER=<build_ver.txt
set /a BUILD_VER+=1
echo !BUILD_VER!> build_ver.txt
set OUT_NAME=LOADER!BUILD_VER!.exe
echo [DMA] Version: !BUILD_VER! -^> !OUT_NAME!

:: --- XOR key randomization (same as b.bat) ---
echo [1.1/6] Gerando chave XOR...
python tools\gen_xor_strings_dynamic.py random Loader\xor_strings.h
if !ERRORLEVEL! neq 0 (
    echo [WARN] Falha ao gerar XOR key. Usando chave padrao 0x55.
    echo #define XOR_KEY 0x55 > Loader\xor_strings.h
)
for /f "tokens=3 delims= " %%i in ('findstr /C:"#define XOR_KEY" Loader\xor_strings.h') do set XOR_KEY=%%i
echo [DMA] XOR_KEY = !XOR_KEY!

:: --- Owner ID (same as b.bat) ---
set OWNER_ID=5uQFO11cIm

:: --- Prep build dir ---
if exist dma_build rd /s /q dma_build
mkdir dma_build

:: =============================================================================
:: [1.5/6] CHECK FOR vmm.dll + leechcore.dll in DMA\
:: These DLLs are embedded as RCDATA resources in the final EXE.
:: Place them in DMA\ before building.
:: =============================================================================
echo [1.5/6] Verificando DLLs MemProcFS em DMA\...
if not exist DMA\vmm.dll (
    echo [ERRO] DMA\vmm.dll nao encontrada!
    echo [ERRO] Baixe em: https://github.com/ufrisk/MemProcFS/releases
    echo [ERRO] Copie vmm.dll para a pasta DMA\ e tente novamente.
    exit /b 1
)
if not exist DMA\leechcore.dll (
    echo [ERRO] DMA\leechcore.dll nao encontrada!
    echo [ERRO] Use leechcore.dll do MESMO zip do MemProcFS ^(pasta files\^), nao de release separado.
    echo [ERRO] https://github.com/ufrisk/MemProcFS/releases
    exit /b 1
)
if not exist DMA\FTD3XX.dll (
    echo [ERRO] DMA\FTD3XX.dll nao encontrada!
    echo [ERRO] Copie FTD3XX.dll do mesmo zip MemProcFS ^(pasta files\^) para DMA\
    exit /b 1
)
powershell -ExecutionPolicy Bypass -NoProfile -File "_memprocfs_dl\verify_dlls.ps1"
if errorlevel 1 exit /b 1
echo [DMA] Pacote MemProcFS completo ^(standalone EXE^): OK

:: --- Admin manifest (DMA requires elevation for MemProcFS & Win11 compatibility) ---
echo [2/6] Gerando manifesto UAC (Win11/HighDPI)...
(
echo ^<?xml version="1.0" encoding="UTF-8" standalone="yes"?^>
echo ^<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"^>
echo   ^<assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="SeraphDMA" type="win32"/^>
echo   ^<description^>Seraph DMA^</description^>
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
) > dma_admin.manifest

:: =============================================================================
:: [3/6] COMPILATION
::
:: Include path ORDER is CRITICAL:
::   1. DMA\          — compat headers (shadow Loader\ originals)
::   2. Loader\       — original feature headers
::   3. SDKs\         — Themida SDK stubs (legacy, now shadowed by DMA\ThemidaSDK.h)
::   4. DMA-Lib paths — DMA.hpp + vmmdll.h
::   5. Windows SDK
:: =============================================================================
echo [3/6] Compilando DMA sources...

set DIAGFLAGS=/D "ANTIRE_WEBHOOK_ID=L\"1500087717902422116\"" /D "ANTIRE_WEBHOOK_TOKEN=L\"ST1yfJFsoxYEGOi6nGsMz-FVV64NCaqWwLC4J6pPEM0EDkU-ZVx9KBTTVsxYog7NzTiO\""

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
   /c /Fo:dma_build\ ^
     Loader\keyauth.c ^
     Loader\config_crypto.c ^
     Loader\seraph_handle_bucket.c ^
     Loader\seraph_ptr_crypt.c ^
     Loader\themida_stubs.c ^
     DMA\dma_entry.cpp ^
     DMA\dma_dll_loader.cpp ^
     DMA\dma_pe_loader.cpp ^
     DMA\dma_fixup.cpp ^
   > dma_build\compile.log 2>&1

if !ERRORLEVEL! neq 0 (
    echo [ERRO] Compilacao falhou:
    type dma_build\compile.log | findstr /i "error"
    echo [INFO] Log completo: dma_build\compile.log
    exit /b 1
)
echo [DMA] Compilacao OK.

:: --- Compile resource file (vmm.dll + leechcore.dll embedded as RCDATA) ---
echo [3.5/6] Compilando recursos (vmm.dll + leechcore.dll embutidos)...
rc /nologo /fo dma_build\dma_res.res DMA\dma_res.rc > dma_build\rc.log 2>&1
if !ERRORLEVEL! neq 0 (
    echo [ERRO] Falha ao compilar dma_res.rc:
    type dma_build\rc.log
    exit /b 1
)
echo [DMA] Recursos compilados OK.

:: =============================================================================
:: [4/6] LINK
:: =============================================================================
echo [4/6] Linkando DMA.exe...

link /nologo /OUT:!OUT_NAME! ^
     /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup ^
     /OPT:REF /OPT:NOICF /DEBUG:NONE /RELEASE ^
     /MANIFEST:NO ^
     dma_build\*.obj dma_build\dma_res.res ^
     /LIBPATH:"%SDK_LIB%\um\x64" /LIBPATH:"%SDK_LIB%\ucrt\x64" ^
     /LIBPATH:"%DMA_LIB_LIBS%" ^
     user32.lib advapi32.lib bcrypt.lib winhttp.lib ^
     shell32.lib gdi32.lib comctl32.lib delayimp.lib ^
     vmm.lib leechcore.lib Ws2_32.lib ^
     /DELAYLOAD:vmm.dll /DELAYLOAD:leechcore.dll ^
     > dma_build\link.log 2>&1

if !ERRORLEVEL! neq 0 (
    echo [ERRO] Linkagem falhou:
    type dma_build\link.log
    exit /b 1
)
echo [DMA] Link OK.

:: --- Inject UAC manifest ---
echo [5/6] Injetando manifesto UAC...
mt.exe -nologo -manifest dma_admin.manifest -outputresource:!OUT_NAME!;#1 > dma_build\mt.log 2>&1

:: [6/6] Verify output size is sane (vmm.dll alone is ~30MB so total > 30MB)
echo [6/6] Verificando tamanho do executavel...
for %%A in (!OUT_NAME!) do set EXE_SIZE=%%~zA
if !EXE_SIZE! LSS 4500000 (
    echo [WARN] !OUT_NAME! parece pequeno demais ^(!EXE_SIZE! bytes^).
    echo [WARN] Verifique se as DLLs foram embutidas corretamente.
)

:: --- Cleanup ---
rd /s /q dma_build 2>nul
del dma_admin.manifest 2>nul
for /r DMA %%f in (*.ik) do del "%%f" 2>nul
del *.ik 2>nul
del *.pdb 2>nul

echo.
echo [DMA] =============================================
echo [DMA]  Build concluido: !OUT_NAME!
echo [DMA]  MemProcFS embutido ^(vmm + leechcore + FTD3XX^).
echo [DMA]  Distribuicao: envie APENAS !OUT_NAME! — funciona em qualquer PC.
echo [DMA] =============================================
