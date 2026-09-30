@echo off
setlocal EnableExtensions
rem ======================================================================
rem  Office Computer Security System - makes OfficeSecurity-Setup.exe
rem
rem  Double-click this file in the extracted folder. It packs the program
rem  files in "files\" into ONE setup program, using the C# compiler that
rem  is part of Windows (.NET Framework 4.8). Nothing is downloaded and
rem  nothing is installed.
rem ======================================================================

set "KIT=%~dp0"
set "FILES=%KIT%files"
set "OUT=%KIT%OfficeSecurity-Setup.exe"
set "WORK=%TEMP%\OCSS-MakeSetup-%RANDOM%%RANDOM%"
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"

echo.
echo  Office Computer Security - making the setup program
echo  ---------------------------------------------------
echo.

for %%F in ("App\OfficeSecurity.exe" "Server\OfficeSecurity.Server.exe" "Agent\OfficeSecurity.Agent.exe" "install.ps1" "setup-program\Setup.cs" "setup-program\setup.manifest") do (
  if not exist "%FILES%\%%~F" (
    echo  ERROR: "files\%%~F" is missing.
    echo  Extract the WHOLE zip file first ^(right-click the zip, "Extract All..."^),
    echo  then run MAKE-SETUP.bat from the extracted folder.
    goto :failed
  )
)

if not exist "%CSC%" (
  echo  ERROR: the C# compiler of .NET Framework 4 was not found on this computer.
  echo  It is part of Windows 10 and 11. Turn on ".NET Framework 4.8 Advanced Services"
  echo  in "Turn Windows features on or off", then try again.
  goto :failed
)

mkdir "%WORK%" || goto :failed

echo  [1/2] Packing the program files ^(about a minute^)...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.IO.Compression.FileSystem; $root=$env:FILES+'\'; $zip=[IO.Compression.ZipFile]::Open($env:WORK+'\payload.zip','Create'); try { foreach ($d in 'App','Server','Agent') { Get-ChildItem -LiteralPath ($root+$d) -Recurse -File | ForEach-Object { [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $_.FullName, $_.FullName.Substring($root.Length), 'Optimal') } }; [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $root+'install.ps1', 'install.ps1', 'Optimal') } finally { $zip.Dispose() }"
if errorlevel 1 goto :failed

echo  [2/2] Building OfficeSecurity-Setup.exe...
if exist "%OUT%" del /f /q "%OUT%"
"%CSC%" /nologo /target:winexe /platform:x64 /optimize+ /out:"%OUT%" ^
  /win32manifest:"%FILES%\setup-program\setup.manifest" ^
  /resource:"%WORK%\payload.zip",payload.zip ^
  /reference:System.IO.Compression.dll /reference:System.IO.Compression.FileSystem.dll /reference:System.Windows.Forms.dll ^
  "%FILES%\setup-program\Setup.cs"
if errorlevel 1 goto :failed
if not exist "%OUT%" goto :failed

rmdir /s /q "%WORK%" 2>nul
echo.
echo  DONE: %OUT%
echo.
echo  Copy OfficeSecurity-Setup.exe to each office computer and double-click it.
echo  It asks whether the computer is the MAIN OFFICE COMPUTER or a STAFF COMPUTER.
echo.
if not defined OCSS_NO_PAUSE pause
exit /b 0

:failed
if exist "%WORK%" rmdir /s /q "%WORK%" 2>nul
echo.
echo  The setup program was NOT made.
if not defined OCSS_NO_PAUSE pause
exit /b 1
