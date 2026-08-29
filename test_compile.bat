@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
mkdir "C:\Users\leona\Downloads\Seraph folder\Seraph\loader_build_test" 2>nul
cd /d "C:\Users\leona\Downloads\Seraph folder\Seraph"
cl /nologo /W3 /Ob1 /MT /EHsc /D _AMD64_ /D AMD64 /D _CONSOLE /D NDEBUG /D XOR_KEY=1 /I Loader /I SDKs /c /Fo:loader_build_test\ Loader\aimbot.c Loader\skeleton.c Loader\esp_overlay.cpp
