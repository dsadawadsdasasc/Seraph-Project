@echo off
setlocal enabledelayedexpansion
:: ============================================================================
:: build_split.bat -- Orchestrates Stub.exe + svc.dll build.
::
:: Usage: just run from the repo root.
::
:: Order matters:
::   1. build_stub.bat   - regenerates Loader/xor_strings.h, then compiles Stub.
::   2. build_payload.bat - regenerates Loader/xor_strings.h again, compiles svc.dll.
::
:: After this script: Stub.exe + svc.dll sit next to each other in the repo
:: root.  Run Stub.exe; it LoadLibrary'es svc.dll from the same directory
:: (Phase 2 checkpoint behaviour).  In Phase 3+ Stub.exe downloads svc.dll
:: from GitHub instead.
::
:: For the LEGACY monolithic build (single LOADERxxx.exe), use b.bat.
:: ============================================================================

echo ============================================================
echo Building Stub.exe + svc.dll (split architecture)
echo ============================================================
echo.

call build_stub.bat
if errorlevel 1 (
    echo.
    echo *** Stub build FAILED ***
    pause
    exit /b 1
)
echo.

call build_payload.bat
if errorlevel 1 (
    echo.
    echo *** Payload build FAILED ***
    pause
    exit /b 1
)
echo.

echo ============================================================
echo Split build complete.
echo   Stub.exe   = front-end (login, mitigation, payload load)
echo   svc.dll    = cheat payload (BYOVD, features, menu)
echo ============================================================
endlocal
pause
