@echo off
setlocal
if not exist "%~dp0stack\runtime\tmp" mkdir "%~dp0stack\runtime\tmp"
set "TEMP=%~dp0stack\runtime\tmp"
set "TMP=%~dp0stack\runtime\tmp"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_secure.ps1"
set "SERVER_EXIT=%ERRORLEVEL%"
echo.
echo Server beendet. Rueckgabewert: %SERVER_EXIT%
pause
exit /b %SERVER_EXIT%
