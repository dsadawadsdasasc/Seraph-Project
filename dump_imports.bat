@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
echo === MARATHON LOADER_DBG4.exe ===
dumpbin /imports LOADER_DBG4.exe | findstr /i ".dll"
echo.
echo === D2 LOADER_DBG1087.exe ===
dumpbin /imports LOADER_DBG1087.exe | findstr /i ".dll"
