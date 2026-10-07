@echo off
setlocal
set "INSTALLER=%TEMP%\Install-WindowsCrashDoctor.ps1"

echo Windows Crash Doctor
echo ====================
echo Downloading the installer from the official project repository...

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/Parris-Tech-Services/hprobooktroubleshoot/main/scripts/Install-WindowsCrashDoctor.ps1' -OutFile '%INSTALLER%'; exit 0 } catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }"
if errorlevel 1 (
    echo.
    echo Download failed.
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%INSTALLER%"
set "EXITCODE=%ERRORLEVEL%"
del /q "%INSTALLER%" >nul 2>&1

echo.
if "%EXITCODE%"=="0" (
    echo Windows Crash Doctor installation/test completed.
) else (
    echo Windows Crash Doctor exited with code %EXITCODE%.
)
echo Press any key to close this window.
pause >nul
exit /b %EXITCODE%
