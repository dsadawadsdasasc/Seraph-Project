@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
set SDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0
cl /nologo /W3 /Od /MTd /EHsc /D _UNICODE /D UNICODE /D _AMD64_ /D AMD64 /D _CONSOLE /D SERAPH_EXCLUDE_INVENTORY /D XOR_KEY=0x55 /D OWNER_ID=L"" /D APP_NAME=L"X" /D APP_VER=L"1" /I Loader /I SDKs /I "%SDK_INC%\um" /I "%SDK_INC%\shared" /c /Fo:skeleton_test.obj Loader\skeleton.c 2>&1
echo ERRORLEVEL=%ERRORLEVEL%
del skeleton_test.obj 2>nul
