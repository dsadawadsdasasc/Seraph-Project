@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
echo === MARATHON ===
dumpbin /imports LOADER_DBG4.exe > imports_marathon.txt
echo === D2 ===
dumpbin /imports LOADER_DBG1087.exe > imports_d2.txt
echo Done.
