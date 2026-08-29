@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
cd /d "C:\Users\leona\Downloads\Seraph folder\Seraph"
mkdir loader_build_test 2>nul
cl /nologo /W3 /Ob1 /MT /D "_AMD64_" /D "AMD64" /D "_CONSOLE" /D "XOR_KEY=1" /D "SERAPH_EXCLUDE_INVENTORY" /I"Loader" /I"SDKs" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared" /c /Fo:loader_build_test\ Loader\skeleton.c
echo EXIT: %ERRORLEVEL%
