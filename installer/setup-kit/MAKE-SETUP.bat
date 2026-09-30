@echo off
setlocal EnableExtensions
rem ======================================================================
rem  Office Computer Security System - makes OfficeSecurity-Setup.exe
rem
rem  Double-click this file in the extracted folder. It packs the program
rem  files in "files\" into ONE setup program using IExpress, which is
rem  built into Windows. Nothing is downloaded and nothing is installed.
rem ======================================================================

set "KIT=%~dp0"
set "FILES=%KIT%files"
set "OUT=%KIT%OfficeSecurity-Setup.exe"
rem IExpress is happiest with a work folder without spaces: use the short form of the TEMP path.
for %%I in ("%TEMP%") do set "SHORTTEMP=%%~sI"
if not defined SHORTTEMP set "SHORTTEMP=%TEMP%"
set "WORK=%SHORTTEMP%\OCSS-MakeSetup-%RANDOM%%RANDOM%"

echo.
echo  Office Computer Security - making the setup program
echo  ---------------------------------------------------
echo.

for %%F in ("App\OfficeSecurity.exe" "Server\OfficeSecurity.Server.exe" "Agent\OfficeSecurity.Agent.exe" "install.ps1" "setup.cmd") do (
  if not exist "%FILES%\%%~F" (
    echo  ERROR: "files\%%~F" is missing.
    echo  Extract the WHOLE zip file first ^(right-click the zip, "Extract All..."^),
    echo  then run MAKE-SETUP.bat from the extracted folder.
    goto :failed
  )
)

if not exist "%SystemRoot%\System32\iexpress.exe" (
  echo  ERROR: IExpress ^(part of Windows^) was not found on this computer.
  goto :failed
)

mkdir "%WORK%" || goto :failed

echo  [1/3] Packing the program files ^(about a minute^)...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.IO.Compression.FileSystem; $zip=[IO.Compression.ZipFile]::Open('%WORK%\payload.zip','Create'); try { foreach ($d in 'App','Server','Agent') { $root='%FILES%\'; Get-ChildItem -Path ($root+$d) -Recurse -File | ForEach-Object { [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $_.FullName, $_.FullName.Substring($root.Length), 'Optimal') } } } finally { $zip.Dispose() }"
if errorlevel 1 goto :failed
copy /y "%FILES%\install.ps1" "%WORK%\install.ps1" >nul || goto :failed
copy /y "%FILES%\setup.cmd" "%WORK%\setup.cmd" >nul || goto :failed

echo  [2/3] Writing the IExpress instructions...
set "SED=%WORK%\setup.sed"
>>"%SED%" echo [Version]
>>"%SED%" echo Class=IEXPRESS
>>"%SED%" echo SEDVersion=3
>>"%SED%" echo [Options]
>>"%SED%" echo PackagePurpose=InstallApp
>>"%SED%" echo ShowInstallProgramWindow=0
>>"%SED%" echo HideExtractAnimation=0
>>"%SED%" echo UseLongFileName=1
>>"%SED%" echo InsideCompressed=0
>>"%SED%" echo CAB_FixedSize=0
>>"%SED%" echo CAB_ResvCodeSigning=0
>>"%SED%" echo RebootMode=N
>>"%SED%" echo InstallPrompt=%%InstallPrompt%%
>>"%SED%" echo DisplayLicense=%%DisplayLicense%%
>>"%SED%" echo FinishMessage=%%FinishMessage%%
>>"%SED%" echo TargetName=%%TargetName%%
>>"%SED%" echo FriendlyName=%%FriendlyName%%
>>"%SED%" echo AppLaunched=%%AppLaunched%%
>>"%SED%" echo PostInstallCmd=%%PostInstallCmd%%
>>"%SED%" echo AdminQuietInstCmd=%%AdminQuietInstCmd%%
>>"%SED%" echo UserQuietInstCmd=%%UserQuietInstCmd%%
>>"%SED%" echo SourceFiles=SourceFiles
>>"%SED%" echo [Strings]
>>"%SED%" echo InstallPrompt=
>>"%SED%" echo DisplayLicense=
>>"%SED%" echo FinishMessage=
>>"%SED%" echo TargetName=%OUT%
>>"%SED%" echo FriendlyName=Office Computer Security Setup
>>"%SED%" echo AppLaunched=cmd.exe /c setup.cmd
>>"%SED%" echo PostInstallCmd=^<None^>
>>"%SED%" echo AdminQuietInstCmd=cmd.exe /c setup.cmd
>>"%SED%" echo UserQuietInstCmd=cmd.exe /c setup.cmd
>>"%SED%" echo FILE0="payload.zip"
>>"%SED%" echo FILE1="install.ps1"
>>"%SED%" echo FILE2="setup.cmd"
>>"%SED%" echo [SourceFiles]
>>"%SED%" echo SourceFiles0=%WORK%\
>>"%SED%" echo [SourceFiles0]
>>"%SED%" echo %%FILE0%%=
>>"%SED%" echo %%FILE1%%=
>>"%SED%" echo %%FILE2%%=

echo  [3/3] Building OfficeSecurity-Setup.exe ^(1-3 minutes^)...
if exist "%OUT%" del /f /q "%OUT%"
"%SystemRoot%\System32\iexpress.exe" /N /Q "%WORK%\setup.sed"
if not exist "%OUT%" (
  echo  ERROR: IExpress did not create the setup program.
  goto :failed
)

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
