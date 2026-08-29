@echo off
setlocal enabledelayedexpansion
echo [DIAG-MINIMAL] Build minima -- apenas MessageBox, sem nenhum codigo do cheat
set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
call %VCVARS% x64 >nul

set SDK_VER=10.0.26100.0
set SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\%SDK_VER%
set SDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%

if exist loader_build_min rd /s /q loader_build_min
mkdir loader_build_min

:: Build 1: Manifesto requireAdministrator + MESMAS DLLs do loader real
echo.
echo === TESTE 1: Mesmo manifesto (requireAdministrator) + Mesmas DLLs ===
(
echo #include ^<windows.h^>
echo int WINAPI wWinMain(HINSTANCE h,HINSTANCE p,LPWSTR c,int n^){
echo     MessageBoxW(NULL,L"DIAG1: ainda vivo",L"DIAG",0^);
echo     return 0;
echo }
) > diag_minimal.cpp

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
) > diag.manifest

cl /nologo /MT /c /Fo:loader_build_min\ /I"%SDK_INC%\um" /I"%SDK_INC%\shared" diag_minimal.cpp >nul 2>&1
link /nologo /OUT:DIAG1_admin_samedlls.exe /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup /MANIFEST:NO ^
     /LIBPATH:"%SDK_LIB%\um\x64" /LIBPATH:"%SDK_LIB%\ucrt\x64" ^
     loader_build_min\diag_minimal.obj ^
     user32.lib advapi32.lib bcrypt.lib winhttp.lib d3d12.lib dxgi.lib d3dcompiler.lib dwmapi.lib shell32.lib d2d1.lib dwrite.lib ole32.lib crypt32.lib >nul 2>&1
mt.exe -nologo -manifest diag.manifest -outputresource:DIAG1_admin_samedlls.exe;#1 >nul 2>&1
echo Gerado: DIAG1_admin_samedlls.exe  [requireAdministrator + mesmas DLLs do loader]

:: Build 2: SEM manifesto admin (asInvoker), mesmas DLLs
(
echo ^<?xml version="1.0" encoding="UTF-8" standalone="yes"?^>
echo ^<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"^>
echo   ^<assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="DiagApp" type="win32"/^>
echo   ^<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"^>
echo     ^<security^>
echo       ^<requestedPrivileges^>
echo         ^<requestedExecutionLevel level="asInvoker" uiAccess="false"/^>
echo       ^</requestedPrivileges^>
echo     ^</security^>
echo   ^</trustInfo^>
echo ^</assembly^>
) > diag_noadmin.manifest
copy /Y DIAG1_admin_samedlls.exe DIAG2_noadmin_samedlls.exe >nul
mt.exe -nologo -manifest diag_noadmin.manifest -outputresource:DIAG2_noadmin_samedlls.exe;#1 >nul 2>&1
echo Gerado: DIAG2_noadmin_samedlls.exe  [asInvoker (sem admin) + mesmas DLLs]

:: Build 3: requireAdministrator + SEM DLLs suspeitas (apenas user32)
link /nologo /OUT:DIAG3_admin_nodlls.exe /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup /MANIFEST:NO ^
     /LIBPATH:"%SDK_LIB%\um\x64" /LIBPATH:"%SDK_LIB%\ucrt\x64" ^
     loader_build_min\diag_minimal.obj ^
     user32.lib >nul 2>&1
mt.exe -nologo -manifest diag.manifest -outputresource:DIAG3_admin_nodlls.exe;#1 >nul 2>&1
echo Gerado: DIAG3_admin_nodlls.exe  [requireAdministrator + SEM DLLs suspeitas]

:: Build 4: SEM admin + SEM DLLs suspeitas (totalmente limpo)
copy /Y DIAG3_admin_nodlls.exe DIAG4_clean.exe >nul
mt.exe -nologo -manifest diag_noadmin.manifest -outputresource:DIAG4_clean.exe;#1 >nul 2>&1
echo Gerado: DIAG4_clean.exe  [asInvoker + SEM DLLs suspeitas - totalmente limpo]

rd /s /q loader_build_min 2>nul
del diag_minimal.cpp diag.manifest diag_noadmin.manifest 2>nul

echo.
echo ============================================================
echo INSTRUCOES DE TESTE (executar com Marathon rodando):
echo   DIAG1: mesmo manifesto + mesmas DLLs   -^> crasha? = PE detectado
echo   DIAG2: sem admin + mesmas DLLs          -^> crasha? = DLLs sao o problema
echo   DIAG3: admin + sem DLLs suspeitas       -^> crasha? = manifesto e o problema  
echo   DIAG4: totalmente limpo                 -^> crasha? = nenhum destes e o problema
echo ============================================================
