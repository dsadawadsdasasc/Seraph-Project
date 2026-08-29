@echo off
setlocal enabledelayedexpansion

echo [1/4] Configurando ambiente de build...
set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
if not exist %VCVARS% (
    echo [ERRO] vcvarsall.bat nao encontrado em %VCVARS%
    exit /b 1
)
call %VCVARS% x64 >nul

set SDK_VER=10.0.26100.0
set SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\%SDK_VER%
set SDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%

if exist dumper_build rd /s /q dumper_build
mkdir dumper_build

echo [2/4] Preparando recursos e assemblies...
if not exist ntdll.lib (
    lib /nologo /def:Loader\ntdll.def /out:ntdll.lib /machine:x64 >nul
)
copy /Y "Loader\CtiIo64.sys" "CtiIo64_tmp.sys" >nul
echo 302 RCDATA "CtiIo64_tmp.sys" > ctiio64_dumper.rc
rc /nologo /fo dumper_build\ctiio64.res ctiio64_dumper.rc
del CtiIo64_tmp.sys 2>nul

ml64 /nologo /c /Fo dumper_build\syscalls_asm.obj Loader\syscalls_asm.asm > build_dumper_ml64.log 2>&1

echo [3/4] Compilando Dumper...
cl /nologo /W3 /O2 /Ob1 /MT /EHsc /D "_UNICODE" /D "UNICODE" ^
   /D "_AMD64_" /D "AMD64" /D "_CONSOLE" /D "NDEBUG" /D "SERAPH_EXCLUDE_INVENTORY" ^
   /I"Loader" /I"SDKs" ^
   /I"%SDK_INC%\um" /I"%SDK_INC%\shared" ^
   /c /Fo:dumper_build\ ^
   Dumper\dumper.cpp ^
   Loader\byovd.c Loader\syscalls.c Loader\attach.c Loader\byovd_lock.c Loader\lazyhook.c Loader\debug_buffer.c > build_dumper.log 2>&1

if !ERRORLEVEL! neq 0 (
    echo [ERRO] Compilacao falhou:
    type build_dumper.log | findstr /i "error"
    exit /b 1
)

echo [4/4] Linkando Dumper...
link /nologo /OUT:Dumper.exe /SUBSYSTEM:CONSOLE ^
     /OPT:REF /OPT:NOICF /DEBUG:NONE /RELEASE ^
     dumper_build\*.obj dumper_build\ctiio64.res ^
     /MANIFEST:NO ^
     /LIBPATH:"%SDK_LIB%\um\x64" /LIBPATH:"%SDK_LIB%\ucrt\x64" ^
     user32.lib advapi32.lib bcrypt.lib ntdll.lib d3d12.lib dxgi.lib d3dcompiler.lib dwmapi.lib shell32.lib d2d1.lib dwrite.lib ole32.lib crypt32.lib ^
     /LIBPATH:"Loader" > build_dumper_link.log 2>&1

if !ERRORLEVEL! neq 0 (
    echo [ERRO] Linkagem falhou. Veja build_dumper_link.log:
    type build_dumper_link.log
    exit /b 1
)

echo [OK] Finalizando...
rd /s /q dumper_build 2>nul
del ctiio64_dumper.rc 2>nul
del build_dumper*.log 2>nul
echo Build concluido com sucesso. Dumper.exe
