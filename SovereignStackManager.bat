@echo off
setlocal
set "TEMP=%~dp0stack\runtime\tmp"
set "TMP=%~dp0stack\runtime\tmp"
if not exist "%TEMP%" mkdir "%TEMP%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0SovereignStackManager.ps1"
exit /b %ERRORLEVEL%
