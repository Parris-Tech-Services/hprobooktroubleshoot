# SymbolServer.psm1 - Microsoft Symbol Server Support and Local Symbol Cache
# Implements WCD-002: Microsoft symbol-server support with configurable local symbol cache

Set-StrictMode -Version Latest

$script:DefaultSymbolServer = 'https://msdl.microsoft.com/download/symbols'
$script:DefaultCachePath = if ($env:LOCALAPPDATA) {
    Join-Path $env:LOCALAPPDATA 'WindowsDoctor\Symbols'
} else {
    Join-Path ([System.IO.Path]::GetTempPath()) 'WindowsDoctorSymbols'
}

$script:CurrentConfig = [ordered]@{
    SymbolServerUrl = $script:DefaultSymbolServer
    CachePath       = $script:DefaultCachePath
    Offline         = $false
    TimeoutSeconds  = 15
}

# Inspect environment for _NT_SYMBOL_PATH if present
if ($env:_NT_SYMBOL_PATH) {
    # Typical format: srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
    $parts = $env:_NT_SYMBOL_PATH -split '\*'
    foreach ($p in $parts) {
        if ($p -match '^https?://') {
            $script:CurrentConfig.SymbolServerUrl = $p.Trim()
        }
        elseif (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue) {
            $script:CurrentConfig.CachePath = $p.Trim()
        }
    }
}

function Get-CrashDoctorSymbolConfig {
    [CmdletBinding()]
    param()

    return [pscustomobject][ordered]@{
        SymbolServerUrl = [string]$script:CurrentConfig.SymbolServerUrl
        CachePath       = [string]$script:CurrentConfig.CachePath
        Offline         = [bool]$script:CurrentConfig.Offline
        TimeoutSeconds  = [int]$script:CurrentConfig.TimeoutSeconds
        CacheExists     = [bool](Test-Path -LiteralPath $script:CurrentConfig.CachePath -PathType Container)
    }
}

function Set-CrashDoctorSymbolConfig {
    [CmdletBinding()]
    param(
        [string]$SymbolServerUrl,
        [string]$CachePath,
        [switch]$Offline,
        [switch]$Online,
        [int]$TimeoutSeconds
    )

    if (-not [string]::IsNullOrWhiteSpace($SymbolServerUrl)) {
        $cleanUrl = $SymbolServerUrl.Trim().TrimEnd('/')
        $script:CurrentConfig.SymbolServerUrl = $cleanUrl
    }

    if (-not [string]::IsNullOrWhiteSpace($CachePath)) {
        $resolved = [Environment]::ExpandEnvironmentVariables($CachePath.Trim())
        $script:CurrentConfig.CachePath = $resolved
        if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
            New-Item -ItemType Directory -Path $resolved -Force | Out-Null
        }
    }

    if ($Offline) { $script:CurrentConfig.Offline = $true }
    if ($Online) { $script:CurrentConfig.Offline = $false }

    if ($TimeoutSeconds -gt 0) {
        $script:CurrentConfig.TimeoutSeconds = $TimeoutSeconds
    }

    return Get-CrashDoctorSymbolConfig
}

function Get-CrashDoctorModulePdbInfo {
    [CmdletBinding()]
    param(
        [byte[]]$CvBytes
    )

    if ($null -eq $CvBytes -or $CvBytes.Length -lt 24) { return $null }

    # Signature: 0x53445352 ('RSDS' in little-endian ASCII)
    $sig = [BitConverter]::ToUInt32($CvBytes, 0)
    if ($sig -ne 0x53445352) { return $null }

    $d1 = [BitConverter]::ToUInt32($CvBytes, 4)
    $d2 = [BitConverter]::ToUInt16($CvBytes, 8)
    $d3 = [BitConverter]::ToUInt16($CvBytes, 10)
    $d4 = [BitConverter]::ToString($CvBytes, 12, 8) -replace '-'
    $guid = ('{0:X8}{1:X4}{2:X4}{3}' -f $d1, $d2, $d3, $d4).ToUpperInvariant()
    $age = [BitConverter]::ToUInt32($CvBytes, 20)

    $pdbRaw = [System.Text.Encoding]::UTF8.GetString($CvBytes, 24, $CvBytes.Length - 24)
    $nullIdx = $pdbRaw.IndexOf([char]0)
    $pdbPath = if ($nullIdx -ge 0) { $pdbRaw.Substring(0, $nullIdx) } else { $pdbRaw }
    $pdbFileName = [System.IO.Path]::GetFileName($pdbPath)

    if ([string]::IsNullOrWhiteSpace($pdbFileName)) { return $null }

    $ageHex = ('{0:X}' -f $age).ToUpperInvariant()
    $symbolKey = "{0}/{1}{2}/{0}" -f $pdbFileName, $guid, $ageHex

    return [pscustomobject][ordered]@{
        PdbFileName = $pdbFileName
        PdbFullPath = $pdbPath
        Guid        = $guid
        Age         = $age
        AgeHex      = $ageHex
        SymbolKey   = $symbolKey
    }
}

function Find-CrashDoctorSymbol {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$SymbolKey,
        [string]$CachePath,
        [switch]$Download,
        [switch]$Offline
    )

    $cleanKey = $SymbolKey.Trim().Replace('/', '\')
    $keyParts = $SymbolKey.Trim().Split('/')
    if ($keyParts.Length -ne 3) {
        throw "Invalid SymbolKey format '$SymbolKey'. Expected format: 'name.pdb/GUIDAGE/name.pdb'."
    }

    $pdbName = $keyParts[0]
    $guidAge = $keyParts[1]

    $activeCache = if (-not [string]::IsNullOrWhiteSpace($CachePath)) { $CachePath } else { [string]$script:CurrentConfig.CachePath }
    $localTarget = Join-Path $activeCache $cleanKey

    if (Test-Path -LiteralPath $localTarget -PathType Leaf) {
        $fi = Get-Item -LiteralPath $localTarget
        return [pscustomobject][ordered]@{
            Found        = $true
            LocalPath    = $localTarget
            Source       = 'LocalCache'
            FileSize     = $fi.Length
            SymbolKey    = $SymbolKey
            DownloadUrl  = $null
            Status       = 'Available'
        }
    }

    $serverUrl = [string]$script:CurrentConfig.SymbolServerUrl
    $downloadUrl = "$serverUrl/$SymbolKey"
    $isOffline = if ($Offline) { $true } else { [bool]$script:CurrentConfig.Offline }

    if (-not $Download -or $isOffline) {
        return [pscustomobject][ordered]@{
            Found        = $false
            LocalPath    = $localTarget
            Source       = 'None'
            FileSize     = 0
            SymbolKey    = $SymbolKey
            DownloadUrl  = $downloadUrl
            Status       = if ($isOffline) { 'Offline' } else { 'NotCached' }
        }
    }

    # Online download attempt with timeout and bounds validation
    try {
        $parentDir = Split-Path -Parent $localTarget
        if (-not (Test-Path -LiteralPath $parentDir -PathType Container)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $timeout = [int]$script:CurrentConfig.TimeoutSeconds
        $req = [System.Net.HttpWebRequest]::Create($downloadUrl)
        $req.Timeout = $timeout * 1000
        $req.UserAgent = 'Microsoft-Symbol-Check/10.0.0.0 (WindowsDoctor)'

        $resp = $req.GetResponse()
        try {
            $stream = $resp.GetResponseStream()
            $fs = [System.IO.File]::Create($localTarget)
            try {
                $stream.CopyTo($fs)
            } finally {
                $fs.Dispose()
                $stream.Dispose()
            }
        } finally {
            $resp.Dispose()
        }

        $fi = Get-Item -LiteralPath $localTarget
        return [pscustomobject][ordered]@{
            Found        = $true
            LocalPath    = $localTarget
            Source       = 'SymbolServer'
            FileSize     = $fi.Length
            SymbolKey    = $SymbolKey
            DownloadUrl  = $downloadUrl
            Status       = 'Downloaded'
        }
    }
    catch {
        if (Test-Path -LiteralPath $localTarget) {
            Remove-Item -LiteralPath $localTarget -Force -ErrorAction SilentlyContinue
        }
        return [pscustomobject][ordered]@{
            Found        = $false
            LocalPath    = $localTarget
            Source       = 'SymbolServer'
            FileSize     = 0
            SymbolKey    = $SymbolKey
            DownloadUrl  = $downloadUrl
            Status       = "Unavailable: $($_.Exception.Message)"
        }
    }
}

Export-ModuleMember -Function Get-CrashDoctorSymbolConfig, Set-CrashDoctorSymbolConfig, Get-CrashDoctorModulePdbInfo, Find-CrashDoctorSymbol
