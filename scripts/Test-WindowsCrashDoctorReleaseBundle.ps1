[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ReleaseDirectory,

    [string]$ExpectedSourceCommit,

    [string]$ExpectedRepository = 'joshualparris/hprobooktroubleshoot',

    [string]$ExpectedChannel = 'canary',

    [string[]]$RequiredAssetNames = @(
        'WindowsCrashDoctor.exe',
        'WindowsCrashDoctor-Engine.zip',
        'Install-WindowsCrashDoctorGui.ps1',
        'Install-WindowsCrashDoctor.ps1',
        'INSTALL-WINDOWS-CRASH-DOCTOR-GUI.cmd'
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Assert-WcdSafeAssetName {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        throw 'Release manifest contains an empty asset name.'
    }

    if ([System.IO.Path]::GetFileName($Name) -ne $Name -or
        $Name.Contains('/') -or $Name.Contains('\') -or $Name -in @('.', '..')) {
        throw "Release manifest asset name is not a safe leaf file name: $Name"
    }
}

$resolvedDirectory = (Resolve-Path -LiteralPath $ReleaseDirectory -ErrorAction Stop).Path
$manifestPath = Join-Path $resolvedDirectory 'release-manifest.json'
$manifestChecksumPath = Join-Path $resolvedDirectory 'release-manifest.json.sha256'

if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Release manifest is missing: $manifestPath"
}

$expectedManifestHash = Read-WcdChecksumFile -Path $manifestChecksumPath -ExpectedFileName 'release-manifest.json'
$actualManifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualManifestHash -ne $expectedManifestHash) {
    throw "Release manifest SHA-256 mismatch. Expected $expectedManifestHash but got $actualManifestHash."
}

try {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}
catch {
    throw "Release manifest is not valid JSON: $($_.Exception.Message)"
}

if ([int]$manifest.schemaVersion -ne 1) {
    throw "Unsupported release manifest schema version: $($manifest.schemaVersion)"
}
if ([string]$manifest.repository -ne $ExpectedRepository) {
    throw "Release manifest repository mismatch. Expected '$ExpectedRepository' but got '$($manifest.repository)'."
}
if ([string]$manifest.channel -ne $ExpectedChannel) {
    throw "Release manifest channel mismatch. Expected '$ExpectedChannel' but got '$($manifest.channel)'."
}

$sourceCommit = ([string]$manifest.sourceCommit).ToLowerInvariant()
if ($sourceCommit -notmatch '^[0-9a-f]{40}$') {
    throw "Release manifest sourceCommit is not a full 40-character Git commit SHA: '$sourceCommit'."
}
if (-not [string]::IsNullOrWhiteSpace($ExpectedSourceCommit) -and
    $sourceCommit -ne $ExpectedSourceCommit.ToLowerInvariant()) {
    throw "Release manifest sourceCommit mismatch. Expected '$ExpectedSourceCommit' but got '$sourceCommit'."
}

$assets = @($manifest.assets)
if ($assets.Count -eq 0) {
    throw 'Release manifest contains no assets.'
}

$manifestNames = New-Object System.Collections.Generic.List[string]
$seenNames = @{}
foreach ($asset in $assets) {
    $name = [string]$asset.name
    Assert-WcdSafeAssetName -Name $name

    if ($seenNames.ContainsKey($name)) {
        throw "Release manifest contains duplicate asset name: $name"
    }
    $seenNames[$name] = $true
    $manifestNames.Add($name)

    $manifestHash = ([string]$asset.sha256).ToLowerInvariant()
    if ($manifestHash -notmatch '^[0-9a-f]{64}$') {
        throw "Release manifest contains an invalid SHA-256 for '$name'."
    }

    $assetPath = Join-Path $resolvedDirectory $name
    if (-not (Test-Path -LiteralPath $assetPath -PathType Leaf)) {
        throw "Manifested release asset is missing: $name"
    }

    $checksumPath = "$assetPath.sha256"
    $checksumHash = Read-WcdChecksumFile -Path $checksumPath -ExpectedFileName $name
    if ($checksumHash -ne $manifestHash) {
        throw "Manifest/checksum disagreement for '$name'. Manifest=$manifestHash checksum=$checksumHash."
    }

    $actualHash = (Get-FileHash -LiteralPath $assetPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $manifestHash) {
        throw "Release asset SHA-256 mismatch for '$name'. Expected $manifestHash but got $actualHash."
    }

    $actualSize = [long](Get-Item -LiteralPath $assetPath).Length
    $manifestSize = [long]$asset.sizeBytes
    if ($manifestSize -lt 0 -or $actualSize -ne $manifestSize) {
        throw "Release asset size mismatch for '$name'. Manifest=$manifestSize actual=$actualSize."
    }
}

foreach ($required in @($RequiredAssetNames)) {
    if (-not [string]::IsNullOrWhiteSpace($required) -and -not $seenNames.ContainsKey($required)) {
        throw "Release manifest is missing required asset: $required"
    }
}

$primaryFiles = @(
    Get-ChildItem -LiteralPath $resolvedDirectory -File -ErrorAction Stop |
        Where-Object { $_.Name -ne 'release-manifest.json' -and $_.Name -notlike '*.sha256' } |
        ForEach-Object { $_.Name }
)
foreach ($name in $primaryFiles) {
    if (-not $seenNames.ContainsKey($name)) {
        throw "Release directory contains an unmanifested primary asset: $name"
    }
}
foreach ($name in $manifestNames) {
    if ($primaryFiles -notcontains $name) {
        throw "Release manifest references an asset that is not present as a primary file: $name"
    }
}

$checksumFiles = @(Get-ChildItem -LiteralPath $resolvedDirectory -File -Filter '*.sha256' -ErrorAction Stop)
$expectedChecksumNames = New-Object System.Collections.Generic.List[string]
$expectedChecksumNames.Add('release-manifest.json.sha256')
foreach ($name in $manifestNames) { $expectedChecksumNames.Add("$name.sha256") }
foreach ($checksum in $checksumFiles) {
    if ($expectedChecksumNames -notcontains $checksum.Name) {
        throw "Release directory contains an unexpected checksum file: $($checksum.Name)"
    }
}
foreach ($expectedChecksumName in $expectedChecksumNames) {
    if (-not (Test-Path -LiteralPath (Join-Path $resolvedDirectory $expectedChecksumName) -PathType Leaf)) {
        throw "Release directory is missing expected checksum file: $expectedChecksumName"
    }
}

[pscustomobject][ordered]@{
    Verified = $true
    SourceCommit = $sourceCommit
    Repository = [string]$manifest.repository
    Channel = [string]$manifest.channel
    ProductVersion = [string]$manifest.productVersion
    EngineVersion = [string]$manifest.engineVersion
    RuleSetVersion = [string]$manifest.ruleSetVersion
    AssetCount = $assets.Count
    ManifestSHA256 = $actualManifestHash
}
