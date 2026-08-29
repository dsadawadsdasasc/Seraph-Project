@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
set SDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0
if not exist loader_build mkdir loader_build
cl /nologo /W3 /c /I"Loader" /I"SDKs" /I"%SDK_INC%\um" /I"%SDK_INC%\shared" /D"NDEBUG" /D"XOR_KEY=0x55" Loader\local_player.c /Fo:loader_build\
echo Exit: %ERRORLEVEL%
