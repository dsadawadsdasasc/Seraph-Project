@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
cl /nologo /W3 /EHsc /I. /I"Loader" fly_reacquire_test.cpp /Fe:fly_reacquire_test.exe
exit /b %ERRORLEVEL%
