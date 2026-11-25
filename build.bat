@echo off
gcc -O2 -municode -o "%~dp0..\noah_ssl_unpack.exe" "%~dp0noah_ssl_unpack.c"
if %errorlevel% equ 0 (
    echo Build succeeded: ..\noah_ssl_unpack.exe
) else (
    echo Build failed!
)
pause
