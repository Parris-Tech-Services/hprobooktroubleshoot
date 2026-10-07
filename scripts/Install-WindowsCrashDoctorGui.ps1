[CmdletBinding()]
param(
    [switch]$NoLaunch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tag = 'windows-crash-doctor-desktop-latest'
$repo = 'Parris-Tech-Services/hprobooktroubleshoot'
$apiUrl = "https://api.github.com/repos/$repo/releases/tags/$tag"
$installRoot = Join-Path $env:LOCALAPPDATA 'WindowsCrashDoctor\app'
$exePath = Join-Path $installRoot 'WindowsCrashDoctor.exe'
$desktop = [Environment]::GetFolderPath('Desktop')
$shortcutPath = Join-Path $desktop 'Windows Doctor.lnk'
$tempRoot = Join-Path $env:TEMP ('WindowsCrashDoctorInstall-' + [guid]::NewGuid().ToString('N'))
$tempExe = Join-Path $tempRoot 'WindowsCrashDoctor.exe'
$tempHash = Join-Path $tempRoot 'WindowsCrashDoctor.exe.sha256'
$headers = @{
    Accept = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
    'User-Agent' = 'WindowsCrashDoctorInstaller/0.2'
}

function Get-ReleaseAsset {
    param([Parameter(Mandatory=$true)]$Release,[Parameter(Mandatory=$true)][string]$Name)
    $asset = @($Release.assets | Where-Object { $_.name -eq $Name } | Select-Object -First 1)
    if (-not $asset.Count) { throw "Release $tag does not contain required asset: $Name" }
    $asset[0]
}

function Get-ExpectedSha256 {
    param([Parameter(Mandatory=$true)]$ExeAsset,[Parameter(Mandatory=$true)][string]$ChecksumPath)
    if ($ExeAsset.PSObject.Properties.Name -contains 'digest' -and [string]$ExeAsset.digest -match '^sha256:([0-9a-fA-F]{64})$') {
        return $Matches[1].ToLowerInvariant()
    }
    $text = Get-Content -LiteralPath $ChecksumPath -Raw
    $match = [regex]::Match($text, '(?i)\b([0-9a-f]{64})\b')
    if (-not $match.Success) { throw 'Published checksum asset did not contain a SHA-256 digest.' }
    $match.Groups[1].Value.ToLowerInvariant()
}

New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
try {
    Write-Host 'Resolving the tested Windows Crash Doctor canary release…' -ForegroundColor Cyan
    $release = Invoke-RestMethod -Headers $headers -Uri $apiUrl -Method Get
    if (-not $release.prerelease) { Write-Warning 'Expected a prerelease/canary release but GitHub returned a non-prerelease release.' }

    $exeAsset = Get-ReleaseAsset -Release $release -Name 'WindowsCrashDoctor.exe'
    $hashAsset = Get-ReleaseAsset -Release $release -Name 'WindowsCrashDoctor.exe.sha256'

    Write-Host "Downloading WindowsCrashDoctor.exe from release id $($release.id)…"
    Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $exeAsset.browser_download_url -OutFile $tempExe
    Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $hashAsset.browser_download_url -OutFile $tempHash

    if ((Get-Item $tempExe).Length -lt 1000000) { throw 'Downloaded executable is unexpectedly small.' }

    $expected = Get-ExpectedSha256 -ExeAsset $exeAsset -ChecksumPath $tempHash
    $actual = (Get-FileHash -LiteralPath $tempExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "SHA-256 verification failed. Expected $expected but downloaded $actual. Nothing was installed."
    }
    Write-Host "SHA-256 verified: $actual" -ForegroundColor Green

    New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
    Copy-Item -LiteralPath $tempExe -Destination $exePath -Force
    Unblock-File -LiteralPath $exePath -ErrorAction SilentlyContinue

    $installed = [ordered]@{
        releaseTag = [string]$release.tag_name
        releaseId = [long]$release.id
        targetCommit = [string]$release.target_commitish
        sha256 = $actual
        verified = $true
        installedAtUtc = [datetimeoffset]::UtcNow.ToString('o')
    }
    $installed | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $installRoot 'installed-build.json') -Encoding utf8

    $wsh = New-Object -ComObject WScript.Shell
    $shortcut = $wsh.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $exePath
    $shortcut.WorkingDirectory = $installRoot
    $shortcut.Description = 'Windows Doctor'
    $shortcut.Save()

    Write-Host "Installed verified build: $exePath" -ForegroundColor Green
    Write-Host "Desktop shortcut: $shortcutPath" -ForegroundColor Green

    if (-not $NoLaunch) { Start-Process -FilePath $exePath }
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
