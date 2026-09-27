[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptsRoot = Split-Path -Parent $PSScriptRoot
$installer = Join-Path $scriptsRoot 'Install-WindowsCrashDoctorGui.ps1'
$bundleVerifier = Join-Path $scriptsRoot 'Test-WindowsCrashDoctorReleaseBundle.ps1'
$powershellExe = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellExe -PathType Leaf)) { $powershellExe = 'powershell.exe' }

function Assert-True {
    param(
        [Parameter(Mandatory = $true)] [bool]$Condition,
        [Parameter(Mandatory = $true)] [string]$Message
    )
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

function New-TestRelease {
    param(
        [Parameter(Mandatory = $true)] [string]$Directory,
        [Parameter(Mandatory = $true)] [string]$Commit,
        [string]$ExecutableText = 'verified-new-build'
    )

    if (Test-Path -LiteralPath $Directory) { Remove-Item -LiteralPath $Directory -Recurse -Force }
    New-Item -ItemType Directory -Path $Directory -Force | Out-Null

    $exe = Join-Path $Directory 'WindowsCrashDoctor.exe'
    [System.IO.File]::WriteAllBytes($exe, [Text.Encoding]::UTF8.GetBytes($ExecutableText))
    $exeHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
    "$exeHash  WindowsCrashDoctor.exe" | Set-Content -LiteralPath "$exe.sha256" -Encoding Ascii

    $manifest = [ordered]@{
        schemaVersion = 1
        channel = 'canary'
        productVersion = '0.2.0-test'
        engineVersion = '0.2.0-test'
        ruleSetVersion = '1-test'
        sourceCommit = $Commit
        repository = 'joshualparris/hprobooktroubleshoot'
        workflowRun = 'https://example.invalid/test'
        generatedAtUtc = [datetimeoffset]::UtcNow.ToString('o')
        verification = [ordered]@{ installerIntegrityTests = 'passed' }
        assets = @(
            [ordered]@{
                name = 'WindowsCrashDoctor.exe'
                sha256 = $exeHash
                sizeBytes = (Get-Item -LiteralPath $exe).Length
            }
        )
    }
    $manifestPath = Join-Path $Directory 'release-manifest.json'
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$manifestHash  release-manifest.json" | Set-Content -LiteralPath "$manifestPath.sha256" -Encoding Ascii

    return [pscustomobject]@{
        ExecutablePath = $exe
        ExecutableHash = $exeHash
        ManifestPath = $manifestPath
        ManifestHash = $manifestHash
    }
}

function Invoke-InstallerChild {
    param([string[]]$Arguments)

    $previousPreference = $ErrorActionPreference
    try {
        # Negative integrity tests intentionally make the child write to stderr. Treat that as
        # captured test output rather than allowing the parent script's Stop preference to abort.
        $ErrorActionPreference = 'Continue'
        $output = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $installer @Arguments 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        # A deliberately failing child must not become this regression script's own process status.
        $global:LASTEXITCODE = 0
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Output = $output
    }
}

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ('WcdInstallerIntegrity-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp -Force | Out-Null

$commit = '1111111111111111111111111111111111111111'
$otherCommit = '2222222222222222222222222222222222222222'
$releaseDir = Join-Path $temp 'release'

try {
    # 1. A coherent local release bundle must verify.
    $fixture = New-TestRelease -Directory $releaseDir -Commit $commit
    $verified = & $bundleVerifier `
        -ReleaseDirectory $releaseDir `
        -ExpectedSourceCommit $commit `
        -RequiredAssetNames @('WindowsCrashDoctor.exe')
    Assert-True ([bool]$verified.Verified) 'Release bundle verifier did not return Verified=true.'
    Assert-True ($verified.SourceCommit -eq $commit) 'Release bundle verifier returned the wrong source commit.'

    $result = Invoke-InstallerChild -Arguments @(
        '-VerifyOnly', '-NoLaunch', '-NoShortcut',
        '-LocalReleaseDirectory', $releaseDir,
        '-ExpectedSourceCommit', $commit
    )
    Assert-True ($result.ExitCode -eq 0) "Installer verification-only mode rejected a valid fixture. Output: $($result.Output)"

    # 2. Tampering with the executable after checksums were produced must fail closed.
    [System.IO.File]::AppendAllText($fixture.ExecutablePath, 'tampered')
    $result = Invoke-InstallerChild -Arguments @(
        '-VerifyOnly', '-NoLaunch', '-NoShortcut',
        '-LocalReleaseDirectory', $releaseDir,
        '-ExpectedSourceCommit', $commit
    )
    Assert-True ($result.ExitCode -ne 0) 'Tampered executable unexpectedly passed installer verification.'

    # 3. Manifest/checksum disagreement must fail even when the executable itself is unchanged.
    $fixture = New-TestRelease -Directory $releaseDir -Commit $commit
    ('0' * 64 + '  WindowsCrashDoctor.exe') | Set-Content -LiteralPath "$($fixture.ExecutablePath).sha256" -Encoding Ascii
    $result = Invoke-InstallerChild -Arguments @(
        '-VerifyOnly', '-NoLaunch', '-NoShortcut',
        '-LocalReleaseDirectory', $releaseDir,
        '-ExpectedSourceCommit', $commit
    )
    Assert-True ($result.ExitCode -ne 0) 'Checksum/manifest disagreement unexpectedly passed installer verification.'

    # 4. A coherent bundle for a different commit must not satisfy a requested commit.
    $fixture = New-TestRelease -Directory $releaseDir -Commit $commit
    $result = Invoke-InstallerChild -Arguments @(
        '-VerifyOnly', '-NoLaunch', '-NoShortcut',
        '-LocalReleaseDirectory', $releaseDir,
        '-ExpectedSourceCommit', $otherCommit
    )
    Assert-True ($result.ExitCode -ne 0) 'Source-commit mismatch unexpectedly passed installer verification.'

    # 5. A malformed manifest checksum must fail before manifest trust.
    $fixture = New-TestRelease -Directory $releaseDir -Commit $commit
    'not-a-valid-checksum' | Set-Content -LiteralPath "$($fixture.ManifestPath).sha256" -Encoding Ascii
    $result = Invoke-InstallerChild -Arguments @(
        '-VerifyOnly', '-NoLaunch', '-NoShortcut',
        '-LocalReleaseDirectory', $releaseDir,
        '-ExpectedSourceCommit', $commit
    )
    Assert-True ($result.ExitCode -ne 0) 'Malformed manifest checksum unexpectedly passed installer verification.'

    # 6. Bundle verification must reject unmanifested primary assets.
    $fixture = New-TestRelease -Directory $releaseDir -Commit $commit
    'unexpected' | Set-Content -LiteralPath (Join-Path $releaseDir 'unexpected.bin') -Encoding Ascii
    $bundleRejected = $false
    try {
        & $bundleVerifier `
            -ReleaseDirectory $releaseDir `
            -ExpectedSourceCommit $commit `
            -RequiredAssetNames @('WindowsCrashDoctor.exe') | Out-Null
    }
    catch { $bundleRejected = $true }
    Assert-True $bundleRejected 'Release bundle verifier accepted an unmanifested primary asset.'

    # 7. Verified replacement must install the new binary and record its provenance.
    $fixture = New-TestRelease -Directory $releaseDir -Commit $commit
    $installRoot = Join-Path $temp 'install-success'
    New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
    $installedExe = Join-Path $installRoot 'WindowsCrashDoctor.exe'
    [System.IO.File]::WriteAllText($installedExe, 'known-good-old-build')

    $result = Invoke-InstallerChild -Arguments @(
        '-NoLaunch', '-NoShortcut',
        '-LocalReleaseDirectory', $releaseDir,
        '-InstallRootOverride', $installRoot,
        '-ExpectedSourceCommit', $commit
    )
    Assert-True ($result.ExitCode -eq 0) "Verified local installation failed. Output: $($result.Output)"
    $installedHash = (Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True ($installedHash -eq $fixture.ExecutableHash) 'Installed executable hash does not match the verified fixture.'
    $installedMetadata = Get-Content -LiteralPath (Join-Path $installRoot 'installed-build.json') -Raw | ConvertFrom-Json
    Assert-True ([string]$installedMetadata.sourceCommit -eq $commit) 'Installed build metadata did not record the verified source commit.'
    Assert-True ([string]$installedMetadata.executableSHA256 -eq $fixture.ExecutableHash) 'Installed build metadata did not record the verified executable hash.'

    # 8. If Windows refuses to replace a locked working executable, the old installation must survive unchanged.
    $lockedRoot = Join-Path $temp 'install-locked'
    New-Item -ItemType Directory -Path $lockedRoot -Force | Out-Null
    $lockedExe = Join-Path $lockedRoot 'WindowsCrashDoctor.exe'
    [System.IO.File]::WriteAllText($lockedExe, 'locked-known-good-old-build')
    $oldHash = (Get-FileHash -LiteralPath $lockedExe -Algorithm SHA256).Hash.ToLowerInvariant()
    $lock = [System.IO.File]::Open($lockedExe, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    try {
        $result = Invoke-InstallerChild -Arguments @(
            '-NoLaunch', '-NoShortcut',
            '-LocalReleaseDirectory', $releaseDir,
            '-InstallRootOverride', $lockedRoot,
            '-ExpectedSourceCommit', $commit
        )
        Assert-True ($result.ExitCode -ne 0) 'Installer unexpectedly replaced an exclusively locked working executable.'
    }
    finally {
        $lock.Dispose()
    }

    $survivingHash = (Get-FileHash -LiteralPath $lockedExe -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True ($survivingHash -eq $oldHash) 'Failed replacement corrupted or removed the previously working executable.'
    $rollbackArtifacts = @(Get-ChildItem -LiteralPath $lockedRoot -File -Filter 'WindowsCrashDoctor.exe.rollback-*' -ErrorAction SilentlyContinue)
    Assert-True ($rollbackArtifacts.Count -eq 0) 'Failed pre-replacement attempt left an unexpected rollback artifact.'

    Write-Host 'Windows Crash Doctor installer/release integrity tests: PASS'
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
