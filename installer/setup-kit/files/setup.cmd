@echo off
rem Started by OfficeSecurity-Setup.exe after it unpacks itself. Uses 64-bit Windows PowerShell
rem (the setup program may be 32-bit, which would otherwise install into the wrong folders).
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
exit /b %ERRORLEVEL%
