[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'SymbolServer.psm1') -Force

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    if ($Actual -ne $Expected) {
        throw "ASSERTION FAILED: $Message. Expected '$Expected', got '$Actual'."
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

$tempDir = Join-Path ([IO.Path]::GetTempPath()) ('WcdSymbolTest-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
    # 1. Config defaults
    $cfg = Get-CrashDoctorSymbolConfig
    Assert-Equal $cfg.SymbolServerUrl 'https://msdl.microsoft.com/download/symbols' 'Default symbol server URL'
    Assert-Equal $cfg.Offline $false 'Default offline status should be false'
    Assert-Equal $cfg.TimeoutSeconds 15 'Default timeout seconds'

    # 2. Set config
    $customCache = Join-Path $tempDir 'CustomCache'
    $updated = Set-CrashDoctorSymbolConfig -CachePath $customCache -Offline -TimeoutSeconds 30
    Assert-Equal $updated.CachePath $customCache 'Custom cache path'
    Assert-Equal $updated.Offline $true 'Offline mode set to true'
    Assert-Equal $updated.TimeoutSeconds 30 'Timeout updated'
    Assert-True (Test-Path -LiteralPath $customCache -PathType Container) 'Custom cache directory should be created'

    # 3. Get-CrashDoctorModulePdbInfo with synthetic RSDS bytes
    # RSDS signature = 0x53445352
    $guidBytes = [guid]::NewGuid().ToByteArray()
    $age = [uint32]2
    $pdbName = 'ntkrnlmp.pdb'
    $pdbBytes = [System.Text.Encoding]::UTF8.GetBytes("$pdbName`0")

    $cvBytes = New-Object byte[] (24 + $pdbBytes.Length)
    [BitConverter]::GetBytes([uint32]0x53445352).CopyTo($cvBytes, 0)
    $guidBytes.CopyTo($cvBytes, 4)
    [BitConverter]::GetBytes($age).CopyTo($cvBytes, 20)
    $pdbBytes.CopyTo($cvBytes, 24)

    $pdbInfo = Get-CrashDoctorModulePdbInfo -CvBytes $cvBytes
    Assert-True ($null -ne $pdbInfo) 'Module PDB info should be parsed'
    Assert-Equal $pdbInfo.PdbFileName $pdbName 'PDB file name'
    Assert-Equal $pdbInfo.Age $age 'PDB age'
    Assert-Equal $pdbInfo.AgeHex '2' 'PDB age in hex'
    Assert-True ($pdbInfo.SymbolKey -like "$pdbName/*2/$pdbName") 'SymbolKey format name/GUIDAGE/name'

    # Non-RSDS signature should return null
    $badBytes = New-Object byte[] 32
    $badInfo = Get-CrashDoctorModulePdbInfo -CvBytes $badBytes
    Assert-True ($null -eq $badInfo) 'Non-RSDS signature should return null'

    # 4. Find-CrashDoctorSymbol: Local Cache hit
    $keyParts = $pdbInfo.SymbolKey.Split('/')
    $cachedSubDir = Join-Path $customCache (Join-Path $keyParts[0] $keyParts[1])
    New-Item -ItemType Directory -Path $cachedSubDir -Force | Out-Null
    $cachedFile = Join-Path $cachedSubDir $keyParts[2]
    [IO.File]::WriteAllBytes($cachedFile, [byte[]]@(0x50, 0x44, 0x42, 0x20))

    $found = Find-CrashDoctorSymbol -SymbolKey $pdbInfo.SymbolKey -CachePath $customCache
    Assert-True $found.Found 'Symbol should be found in local cache'
    Assert-Equal $found.Source 'LocalCache' 'Source should be LocalCache'
    Assert-Equal $found.Status 'Available' 'Status should be Available'
    Assert-Equal $found.FileSize 4 'Cached file size'

    # 5. Find-CrashDoctorSymbol: Offline mode cache miss
    $missKey = 'missing.pdb/12345678123412341234123456789ABC1/missing.pdb'
    $missResult = Find-CrashDoctorSymbol -SymbolKey $missKey -CachePath $customCache -Offline
    Assert-Equal $missResult.Found $false 'Missing symbol should not be found'
    Assert-Equal $missResult.Status 'Offline' 'Status should be Offline'
    Assert-True ($missResult.DownloadUrl -like '*missing.pdb*') 'DownloadUrl should be formatted'

    # 6. Invalid key format handling
    $invalidFormatFailed = $false
    try {
        Find-CrashDoctorSymbol -SymbolKey 'invalid_key' -CachePath $customCache
    } catch {
        $invalidFormatFailed = $true
    }
    Assert-True $invalidFormatFailed 'Invalid symbol key format should throw'

    Write-Host 'SymbolServer test: ALL 6 TESTS PASSED.'
}
finally {
    # Restore default config
    Set-CrashDoctorSymbolConfig -CachePath (Join-Path $env:LOCALAPPDATA 'WindowsDoctor\Symbols') -Online -TimeoutSeconds 15 | Out-Null
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
