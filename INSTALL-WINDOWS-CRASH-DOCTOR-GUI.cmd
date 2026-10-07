@echo off
setlocal
set "WCD_INSTALLER=%TEMP%\Install-WindowsCrashDoctorGui.ps1"
set "WCD_CHECKSUM=%TEMP%\Install-WindowsCrashDoctorGui.ps1.sha256"
set "WCD_RELEASE=https://github.com/Parris-Tech-Services/hprobooktroubleshoot/releases/download/windows-crash-doctor-desktop-latest"

echo Downloading the tested Windows Doctor installer and checksum...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; Invoke-WebRequest -UseBasicParsing '%WCD_RELEASE%/Install-WindowsCrashDoctorGui.ps1' -OutFile '%WCD_INSTALLER%'; Invoke-WebRequest -UseBasicParsing '%WCD_RELEASE%/Install-WindowsCrashDoctorGui.ps1.sha256' -OutFile '%WCD_CHECKSUM%'; $text=Get-Content -LiteralPath '%WCD_CHECKSUM%' -Raw; $m=[regex]::Match($text,'(?i)\b([0-9a-f]{64})\b'); if(-not $m.Success){throw 'Published installer checksum is invalid.'}; $expected=$m.Groups[1].Value.ToLowerInvariant(); $actual=(Get-FileHash -LiteralPath '%WCD_INSTALLER%' -Algorithm SHA256).Hash.ToLowerInvariant(); if($actual -ne $expected){throw ('Installer SHA-256 verification failed. Expected '+$expected+' but downloaded '+$actual)}; Write-Host ('Installer SHA-256 verified: '+$actual) -ForegroundColor Green"
if errorlevel 1 goto :fail

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%WCD_INSTALLER%"
if errorlevel 1 goto :fail

del /q "%WCD_INSTALLER%" "%WCD_CHECKSUM%" >nul 2>nul
exit /b 0

:fail
echo.
echo Windows Doctor installation did not complete. No unverified installer was executed.
pause
exit /b 1
