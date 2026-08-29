@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
cd /d "C:\Users\leona\Downloads\Seraph folder\Seraph"
mkdir loader_build_test 2>nul
cl /nologo /W3 /Ob1 /MT /EHsc ^
   /D "_AMD64_" /D "AMD64" /D "_CONSOLE" /D "NDEBUG" /D "XOR_KEY=1" ^
   /D "OWNER_ID=L\"test\"" /D "APP_NAME=L\"test\"" /D "APP_VER=L\"1.0\"" ^
   /D "SERAPH_EXCLUDE_INVENTORY" ^
   /I"Loader" /I"SDKs" ^
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um" ^
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared" ^
   /c /Fo:loader_build_test\ ^
   Loader\esp_overlay.cpp
echo EXIT: %ERRORLEVEL%
