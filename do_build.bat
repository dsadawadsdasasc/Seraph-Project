@echo off
call build_all.bat > build_out.log 2>&1
echo EXIT:%ERRORLEVEL% >> build_out.log
