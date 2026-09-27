[CmdletBinding()]
param(
    [switch]$NoLaunch,
    [switch]$NoShortcut,
    [switch]$VerifyOnly,
    [string]$LocalReleaseDirectory,
    [string]$InstallRootOverride,
    [string]$ExpectedSourceCommit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$tag = 'windows-crash-doctor-desktop-latest'
$repo = 'joshualparris/hprobooktroubleshoot'
$apiBase = "https://api.github.com/repos/$repo"
$releaseApiUrl = "$apiBase/releases/tags/$tag"
$defaultInstallRoot = Join-Path $env:LOCALAPPDATA 'WindowsCrashDoctor\app'
$installRoot = if ([string]::IsNullOrWhiteSpace($InstallRootOverride)) { $defaultInstallRoot } else { [System.IO.Path]::GetFullPath($InstallRootOverride) }
$exePath = Join-Path $installRoot 'WindowsCrashDoctor.exe'
$desktop = [Environment]::GetFolderPath('Desktop')
$shortcutPath = Join-Path $desktop 'Windows Crash Doctor.lnk'
$tempRoot = Join-Path $env:TEMP ('WindowsCrashDoctorInstall-' + [guid]::NewGuid().ToString('N'))

$apiHeaders = @{
    Accept = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
    'User-Agent' = 'WindowsCrashDoctorInstaller/0.3'
}

function Get-WcdRequiredReleaseAsset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Release,
        [Parameter(Mandatory = $true)] [string]$Name
    )

    $matches = @($Release.assets | Where-Object { [string]$_.name -eq $Name })
    if ($matches.Count -ne 1) {
        throw "Release '$($Release.tag_name)' must contain exactly one '$Name' asset; found $($matches.Count)."
    }
    return $matches[0]
}

function Read-WcdChecksumFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [string]$ExpectedFileName
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required checksum file is missing: $Path"
    }

    $text = (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop).Trim()
    $escapedName = [regex]::Escape($ExpectedFileName)
    $match = [regex]::Match($text, "(?i)^([0-9a-f]{64})\s+\*?$escapedName$")
    if (-not $match.Success) {
        throw "Checksum file '$Path' must contain exactly one SHA-256 entry for '$ExpectedFileName'."
    }
    return $match.Groups[1].Value.ToLowerInvariant()
}

function Get-WcdApiAssetSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] $Asset)

    if ($Asset.PSObject.Properties.Name -contains 'digest' -and
        [string]$Asset.digest -match '^sha256:([0-9a-fA-F]{64})$') {
        return $Matches[1].ToLowerInvariant()
    }
    return $null
}

function Assert-WcdDownloadedAssetDigest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Asset,
        [Parameter(Mandatory = $true)] [string]$Path
    )

    $apiHash = Get-WcdApiAssetSha256 -Asset $Asset
    if ([string]::IsNullOrWhiteSpace($apiHash)) { return }

    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $apiHash) {
        throw "GitHub release asset digest mismatch for '$($Asset.name)'. Expected $apiHash but got $actual."
    }
}

function Invoke-WcdDownloadExactReleaseAsset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Asset,
        [Parameter(Mandatory = $true)] [string]$Destination
    )

    if ([string]::IsNullOrWhiteSpace([string]$Asset.url) -or [long]$Asset.id -le 0) {
        throw "Release asset '$($Asset.name)' does not have a stable GitHub asset identity."
    }

    $downloadHeaders = @{
        Accept = 'application/octet-stream'
        'X-GitHub-Api-Version' = '2022-11-28'
        'User-Agent' = 'WindowsCrashDoctorInstaller/0.3'
    }
    Invoke-WebRequest -UseBasicParsing -Headers $downloadHeaders -Uri ([string]$Asset.url) -OutFile $Destination -ErrorAction Stop
    Assert-WcdDownloadedAssetDigest -Asset $Asset -Path $Destination
}

function Test-WcdInstallerPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Directory,
        [string]$RequiredSourceCommit,
        [AllowNull()] $ExecutableReleaseAsset,
        [AllowNull()] $ManifestReleaseAsset
    )

    $root = (Resolve-Path -LiteralPath $Directory -ErrorAction Stop).Path
    $manifestPath = Join-Path $root 'release-manifest.json'
    $manifestChecksumPath = Join-Path $root 'release-manifest.json.sha256'
    $payloadExe = Join-Path $root 'WindowsCrashDoctor.exe'
    $payloadExeChecksum = Join-Path $root 'WindowsCrashDoctor.exe.sha256'

    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'release-manifest.json is missing.' }
    if (-not (Test-Path -LiteralPath $payloadExe -PathType Leaf)) { throw 'WindowsCrashDoctor.exe is missing.' }

    $expectedManifestHash = Read-WcdChecksumFile -Path $manifestChecksumPath -ExpectedFileName 'release-manifest.json'
    $actualManifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualManifestHash -ne $expectedManifestHash) {
        throw "Release manifest SHA-256 mismatch. Expected $expectedManifestHash but got $actualManifestHash."
    }
    if ($null -ne $ManifestReleaseAsset) {
        $apiManifestHash = Get-WcdApiAssetSha256 -Asset $ManifestReleaseAsset
        if (-not [string]::IsNullOrWhiteSpace($apiManifestHash) -and $apiManifestHash -ne $actualManifestHash) {
            throw "GitHub digest disagrees with release-manifest.json.sha256. API=$apiManifestHash checksum=$actualManifestHash."
        }
    }

    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "release-manifest.json is invalid JSON: $($_.Exception.Message)"
    }

    if ([int]$manifest.schemaVersion -ne 1) { throw "Unsupported release manifest schema version: $($manifest.schemaVersion)" }
    if ([string]$manifest.repository -ne $repo) { throw "Release manifest repository mismatch: '$($manifest.repository)'." }
    if ([string]$manifest.channel -ne 'canary') { throw "Release manifest channel is not 'canary': '$($manifest.channel)'." }

    $sourceCommit = ([string]$manifest.sourceCommit).ToLowerInvariant()
    if ($sourceCommit -notmatch '^[0-9a-f]{40}$') {
        throw "Release manifest sourceCommit is not a full Git commit SHA: '$sourceCommit'."
    }
    if (-not [string]::IsNullOrWhiteSpace($RequiredSourceCommit) -and
        $sourceCommit -ne $RequiredSourceCommit.ToLowerInvariant()) {
        throw "Release manifest sourceCommit mismatch. Expected '$RequiredSourceCommit' but got '$sourceCommit'."
    }

    $exeRecords = @($manifest.assets | Where-Object { [string]$_.name -eq 'WindowsCrashDoctor.exe' })
    if ($exeRecords.Count -ne 1) {
        throw "Release manifest must contain exactly one WindowsCrashDoctor.exe record; found $($exeRecords.Count)."
    }
    $exeRecord = $exeRecords[0]
    $manifestExeHash = ([string]$exeRecord.sha256).ToLowerInvariant()
    if ($manifestExeHash -notmatch '^[0-9a-f]{64}$') { throw 'Release manifest contains an invalid WindowsCrashDoctor.exe SHA-256.' }

    $checksumExeHash = Read-WcdChecksumFile -Path $payloadExeChecksum -ExpectedFileName 'WindowsCrashDoctor.exe'
    if ($checksumExeHash -ne $manifestExeHash) {
        throw "Manifest/checksum disagreement for WindowsCrashDoctor.exe. Manifest=$manifestExeHash checksum=$checksumExeHash."
    }

    $actualExeHash = (Get-FileHash -LiteralPath $payloadExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualExeHash -ne $manifestExeHash) {
        throw "WindowsCrashDoctor.exe SHA-256 mismatch. Expected $manifestExeHash but got $actualExeHash."
    }

    $actualSize = [long](Get-Item -LiteralPath $payloadExe).Length
    if ([long]$exeRecord.sizeBytes -ne $actualSize) {
        throw "WindowsCrashDoctor.exe size does not match the signed release metadata. Manifest=$($exeRecord.sizeBytes) actual=$actualSize."
    }

    if ($null -ne $ExecutableReleaseAsset) {
        $apiExeHash = Get-WcdApiAssetSha256 -Asset $ExecutableReleaseAsset
        if (-not [string]::IsNullOrWhiteSpace($apiExeHash) -and $apiExeHash -ne $actualExeHash) {
            throw "GitHub digest disagrees with the manifest/checksum for WindowsCrashDoctor.exe. API=$apiExeHash manifest=$actualExeHash."
        }
    }

    return [pscustomobject][ordered]@{
        Verified = $true
        SourceCommit = $sourceCommit
        ExecutableSHA256 = $actualExeHash
        ManifestSHA256 = $actualManifestHash
        ProductVersion = [string]$manifest.productVersion
        EngineVersion = [string]$manifest.engineVersion
        RuleSetVersion = [string]$manifest.ruleSetVersion
        ExecutablePath = $payloadExe
    }
}

function Install-WcdVerifiedExecutable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$VerifiedExecutablePath,
        [Parameter(Mandatory = $true)] [string]$ExpectedHash,
        [Parameter(Mandatory = $true)] [string]$DestinationPath
    )

    $destinationDirectory = Split-Path -Parent $DestinationPath
    New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null

    $token = [guid]::NewGuid().ToString('N')
    $candidate = Join-Path $destinationDirectory ("WindowsCrashDoctor.exe.new-$token")
    $backup = Join-Path $destinationDirectory ("WindowsCrashDoctor.exe.rollback-$token")
    $hadExisting = Test-Path -LiteralPath $DestinationPath -PathType Leaf

    Copy-Item -LiteralPath $VerifiedExecutablePath -Destination $candidate -Force
    $candidateHash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($candidateHash -ne $ExpectedHash) {
        Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
        throw 'Staged executable changed before installation. Existing installation was left untouched.'
    }

    try {
        if ($hadExisting) {
            # Same-volume replacement keeps the old working binary as a rollback copy.
            [System.IO.File]::Replace($candidate, $DestinationPath, $backup, $true)
        }
        else {
            [System.IO.File]::Move($candidate, $DestinationPath)
        }

        $installedHash = (Get-FileHash -LiteralPath $DestinationPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($installedHash -ne $ExpectedHash) {
            throw "Installed executable failed post-replacement verification. Expected $ExpectedHash but got $installedHash."
        }

        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            Remove-Item -LiteralPath $backup -Force
        }
        return $installedHash
    }
    catch {
        $installError = $_
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            try {
                if (Test-Path -LiteralPath $DestinationPath -PathType Leaf) {
                    Remove-Item -LiteralPath $DestinationPath -Force
                }
                Move-Item -LiteralPath $backup -Destination $DestinationPath -Force
            }
            catch {
                throw "Installation failed and automatic rollback also failed. Rollback copy remains at '$backup'. Original error: $($installError.Exception.Message). Rollback error: $($_.Exception.Message)"
            }
        }
        elseif (-not $hadExisting) {
            Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
        }

        throw $installError
    }
    finally {
        Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
    }
}

New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
try {
    $payloadRoot = $tempRoot
    $release = $null
    $exeAsset = $null
    $manifestAsset = $null
    $requiredCommit = $ExpectedSourceCommit

    if (-not [string]::IsNullOrWhiteSpace($LocalReleaseDirectory)) {
        $payloadRoot = (Resolve-Path -LiteralPath $LocalReleaseDirectory -ErrorAction Stop).Path
        Write-Host "Verifying local release payload: $payloadRoot" -ForegroundColor Cyan
    }
    else {
        Write-Host 'Resolving the tested Windows Crash Doctor canary release...' -ForegroundColor Cyan
        $release = Invoke-RestMethod -Headers $apiHeaders -Uri $releaseApiUrl -Method Get -ErrorAction Stop
        if ([string]$release.tag_name -ne $tag) { throw "Resolved release tag mismatch: '$($release.tag_name)'." }
        if ([bool]$release.draft) { throw 'Refusing to install from a draft release.' }
        if (-not [bool]$release.prerelease) { throw 'Expected the rolling canary to be marked as a prerelease.' }

        $targetCommit = ([string]$release.target_commitish).ToLowerInvariant()
        if ($targetCommit -notmatch '^[0-9a-f]{40}$') {
            throw "Canary release target_commitish is not an immutable 40-character commit SHA: '$targetCommit'."
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedSourceCommit) -and $targetCommit -ne $ExpectedSourceCommit.ToLowerInvariant()) {
            throw "Resolved canary commit '$targetCommit' does not match requested commit '$ExpectedSourceCommit'."
        }
        $requiredCommit = $targetCommit

        $requiredNames = @(
            'WindowsCrashDoctor.exe',
            'WindowsCrashDoctor.exe.sha256',
            'release-manifest.json',
            'release-manifest.json.sha256'
        )
        $assetsByName = @{}
        foreach ($name in $requiredNames) {
            $assetsByName[$name] = Get-WcdRequiredReleaseAsset -Release $release -Name $name
        }
        $exeAsset = $assetsByName['WindowsCrashDoctor.exe']
        $manifestAsset = $assetsByName['release-manifest.json']

        foreach ($name in $requiredNames) {
            $asset = $assetsByName[$name]
            $destination = Join-Path $payloadRoot $name
            Write-Host "Downloading exact release asset id $($asset.id): $name"
            Invoke-WcdDownloadExactReleaseAsset -Asset $asset -Destination $destination
        }

        # Re-read this exact release id. If the rolling canary was replaced during the download,
        # the install fails rather than silently switching to assets from a new release.
        $confirmed = Invoke-RestMethod -Headers $apiHeaders -Uri "$apiBase/releases/$($release.id)" -Method Get -ErrorAction Stop
        if ([long]$confirmed.id -ne [long]$release.id -or
            [string]$confirmed.tag_name -ne $tag -or
            ([string]$confirmed.target_commitish).ToLowerInvariant() -ne $targetCommit) {
            throw 'The canary release changed while it was being downloaded. Nothing was installed; run the installer again.'
        }
    }

    $verification = Test-WcdInstallerPayload `
        -Directory $payloadRoot `
        -RequiredSourceCommit $requiredCommit `
        -ExecutableReleaseAsset $exeAsset `
        -ManifestReleaseAsset $manifestAsset

    Write-Host "Verified executable SHA-256: $($verification.ExecutableSHA256)" -ForegroundColor Green
    Write-Host "Verified manifest SHA-256:   $($verification.ManifestSHA256)" -ForegroundColor Green
    Write-Host "Verified source commit:      $($verification.SourceCommit)" -ForegroundColor Green

    if ($VerifyOnly) {
        Write-Host 'Verification-only mode complete. No installation changes were made.' -ForegroundColor Green
        return
    }

    $installedHash = Install-WcdVerifiedExecutable `
        -VerifiedExecutablePath $verification.ExecutablePath `
        -ExpectedHash $verification.ExecutableSHA256 `
        -DestinationPath $exePath

    $releaseId = if ($null -ne $release) { [long]$release.id } else { $null }
    $metadata = [ordered]@{
        releaseTag = if ($null -ne $release) { [string]$release.tag_name } else { 'local-verified-payload' }
        releaseId = $releaseId
        sourceCommit = $verification.SourceCommit
        executableSHA256 = $installedHash
        manifestSHA256 = $verification.ManifestSHA256
        productVersion = $verification.ProductVersion
        engineVersion = $verification.EngineVersion
        ruleSetVersion = $verification.RuleSetVersion
        verified = $true
        installedAtUtc = [datetimeoffset]::UtcNow.ToString('o')
    }

    try {
        $metadataTemp = Join-Path $installRoot ('installed-build.json.new-' + [guid]::NewGuid().ToString('N'))
        $metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $metadataTemp -Encoding utf8
        Move-Item -LiteralPath $metadataTemp -Destination (Join-Path $installRoot 'installed-build.json') -Force
    }
    catch {
        Write-Warning "The verified executable was installed, but build metadata could not be written: $($_.Exception.Message)"
    }

    if (-not $NoShortcut) {
        try {
            $wsh = New-Object -ComObject WScript.Shell
            $shortcut = $wsh.CreateShortcut($shortcutPath)
            $shortcut.TargetPath = $exePath
            $shortcut.WorkingDirectory = $installRoot
            $shortcut.Description = 'Windows Crash Doctor'
            $shortcut.Save()
            Write-Host "Desktop shortcut: $shortcutPath" -ForegroundColor Green
        }
        catch {
            Write-Warning "Windows Crash Doctor was installed, but the desktop shortcut could not be created: $($_.Exception.Message)"
        }
    }

    Write-Host "Installed verified build: $exePath" -ForegroundColor Green
    if (-not $NoLaunch) {
        Start-Process -FilePath $exePath
    }
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
