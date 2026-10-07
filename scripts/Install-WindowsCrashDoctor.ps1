[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'WindowsCrashDoctor\App'),
    [switch]$InstallOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$tag = 'windows-crash-doctor-desktop-latest'
$repo = 'Parris-Tech-Services/hprobooktroubleshoot'
$apiUrl = "https://api.github.com/repos/$repo/releases/tags/$tag"
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WindowsCrashDoctorInstall-' + [guid]::NewGuid().ToString('N'))
$zipPath = Join-Path $tempRoot 'WindowsCrashDoctor-Engine.zip'
$hashPath = Join-Path $tempRoot 'WindowsCrashDoctor-Engine.zip.sha256'
$extractRoot = Join-Path $tempRoot 'extract'
$headers = @{
    Accept = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
    'User-Agent' = 'WindowsCrashDoctorCliInstaller/0.2'
}

function Get-ReleaseAsset {
    param([Parameter(Mandatory=$true)]$Release,[Parameter(Mandatory=$true)][string]$Name)
    $asset = @($Release.assets | Where-Object { $_.name -eq $Name } | Select-Object -First 1)
    if (-not $asset.Count) { throw "Release $tag does not contain required asset: $Name" }
    $asset[0]
}

function Get-ExpectedSha256 {
    param([Parameter(Mandatory=$true)]$Asset,[Parameter(Mandatory=$true)][string]$ChecksumPath)
    if ($Asset.PSObject.Properties.Name -contains 'digest' -and [string]$Asset.digest -match '^sha256:([0-9a-fA-F]{64})$') {
        return $Matches[1].ToLowerInvariant()
    }
    $text = Get-Content -LiteralPath $ChecksumPath -Raw
    $match = [regex]::Match($text, '(?i)\b([0-9a-f]{64})\b')
    if (-not $match.Success) { throw 'Published checksum asset did not contain a SHA-256 digest.' }
    $match.Groups[1].Value.ToLowerInvariant()
}

Write-Host ''
Write-Host 'Windows Doctor verified CLI installer' -ForegroundColor Cyan
Write-Host '=====================================' -ForegroundColor Cyan
Write-Host "Install location: $InstallRoot"
Write-Host 'The installer itself stays in standard-user mode; the diagnostic runner requests UAC only when collection actually needs it.'
Write-Host ''

New-Item -ItemType Directory -Path $tempRoot, $extractRoot -Force | Out-Null

try {
    Write-Host '1/6 Resolving the tested canary release...'
    $release = Invoke-RestMethod -Headers $headers -Uri $apiUrl -Method Get
    $zipAsset = Get-ReleaseAsset -Release $release -Name 'WindowsCrashDoctor-Engine.zip'
    $hashAsset = Get-ReleaseAsset -Release $release -Name 'WindowsCrashDoctor-Engine.zip.sha256'

    Write-Host '2/6 Downloading engine package and checksum...'
    Invoke-WebRequest -Uri $zipAsset.browser_download_url -Headers $headers -OutFile $zipPath -UseBasicParsing
    Invoke-WebRequest -Uri $hashAsset.browser_download_url -Headers $headers -OutFile $hashPath -UseBasicParsing
    $expected = Get-ExpectedSha256 -Asset $zipAsset -ChecksumPath $hashPath
    $actual = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "SHA-256 verification failed. Expected $expected but downloaded $actual. Nothing was installed." }
    Write-Host "SHA-256 verified: $actual" -ForegroundColor Green

    Write-Host '3/6 Extracting verified package...'
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractRoot -Force
    foreach ($requiredDirectory in @('scripts','windows-crash-doctor')) {
        if (-not (Test-Path -LiteralPath (Join-Path $extractRoot $requiredDirectory) -PathType Container)) {
            throw "Verified package is incomplete; missing directory: $requiredDirectory"
        }
    }

    Write-Host '4/6 Installing/updating Windows Doctor...'
    $installParent = Split-Path -Parent $InstallRoot
    New-Item -ItemType Directory -Path $installParent -Force | Out-Null
    $staging = Join-Path $installParent ('App.new-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    Copy-Item -Path (Join-Path $extractRoot '*') -Destination $staging -Recurse -Force

    $runner = Join-Path $staging 'windows-crash-doctor\Run-WindowsCrashDoctor.ps1'
    $selfTest = Join-Path $staging 'windows-crash-doctor\tests\self-test.ps1'
    $telemetryTest = Join-Path $staging 'windows-crash-doctor\tests\telemetry-self-test.ps1'
    $integrationSelfTest = Join-Path $staging 'windows-crash-doctor\tests\integration-self-test.ps1'
    $versionFile = Join-Path $staging 'windows-crash-doctor\version.json'
    foreach ($required in @($runner, $selfTest, $telemetryTest, $integrationSelfTest, $versionFile)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Installation package is incomplete; missing: $required" }
    }

    Write-Host '5/6 Running package self-tests before activation...'
    & $selfTest -RepositoryMode
    & $telemetryTest
    & $integrationSelfTest -RepositoryMode

    if (Test-Path -LiteralPath $InstallRoot) { Remove-Item -LiteralPath $InstallRoot -Recurse -Force }
    Move-Item -LiteralPath $staging -Destination $InstallRoot
    $runner = Join-Path $InstallRoot 'windows-crash-doctor\Run-WindowsCrashDoctor.ps1'

    [ordered]@{
        releaseTag = [string]$release.tag_name
        releaseId = [long]$release.id
        targetCommit = [string]$release.target_commitish
        sha256 = $actual
        verified = $true
        installedAtUtc = [datetimeoffset]::UtcNow.ToString('o')
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $InstallRoot 'installed-build.json') -Encoding utf8

    Write-Host '6/6 Creating launchers...'
    $desktop = [Environment]::GetFolderPath('Desktop')
    $cmdPath = Join-Path $desktop 'Windows Doctor.cmd'
    $cmd = @"
@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$runner"
set EXITCODE=%ERRORLEVEL%
echo.
if not "%EXITCODE%"=="0" echo Windows Doctor exited with code %EXITCODE%.
echo Press any key to close this window.
pause >nul
exit /b %EXITCODE%
"@
    Set-Content -LiteralPath $cmdPath -Value $cmd -Encoding ASCII

    $startMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
    $shortcutPath = Join-Path $startMenu 'Windows Doctor.lnk'
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $shortcut.Arguments = ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $runner)
        $shortcut.WorkingDirectory = $InstallRoot
        $shortcut.IconLocation = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe,0"
        $shortcut.Description = 'Collect and analyse Windows crash/hang diagnostics'
        $shortcut.Save()
    }
    catch { Write-Warning "Start Menu shortcut could not be created: $($_.Exception.Message)" }

    Write-Host ''
    Write-Host 'INSTALL PASS — release package verified before installation.' -ForegroundColor Green
    Write-Host "Desktop launcher: $cmdPath" -ForegroundColor Green
    Write-Host "Installed app: $InstallRoot" -ForegroundColor Green

    if (-not $InstallOnly) {
        Write-Host ''
        Write-Host 'Starting Windows Doctor. UAC will be requested by the runner for the diagnostic collection.' -ForegroundColor Cyan
        & $runner
    }
}
finally {
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
}
