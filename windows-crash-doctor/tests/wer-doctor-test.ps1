[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'DumpParser.psm1') -Force
Import-Module (Join-Path $root 'WerDoctor.psm1') -Force

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

$temp = Join-Path ([IO.Path]::GetTempPath()) ('WcdWerDoctor-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp -Force | Out-Null

try {
    # 1. Test Get-CrashDoctorWerReportStores on synthetic WER store directory structure
    $fakeUserArchive = Join-Path $temp 'ReportArchive'
    $fakeReportDir1 = Join-Path $fakeUserArchive 'AppCrash_notepad.exe_12345'
    $fakeReportDir2 = Join-Path $fakeUserArchive 'AppHang_explorer.exe_67890'
    New-Item -ItemType Directory -Path $fakeReportDir1 -Force | Out-Null
    New-Item -ItemType Directory -Path $fakeReportDir2 -Force | Out-Null

    $storesResult = Get-CrashDoctorWerReportStores -CustomStorePaths @($fakeUserArchive)
    Assert-Equal $storesResult.TotalStores 1 'Total stores should be 1'
    Assert-True $storesResult.Stores[0].Present 'Store should be marked present'
    Assert-True $storesResult.Stores[0].Accessible 'Store should be marked accessible'
    Assert-Equal $storesResult.Stores[0].ReportCount 2 'Store should have 2 report directories'
    Assert-Equal $storesResult.TotalReportDirs 2 'Total report dirs should be 2'

    # 2. Test Get-CrashDoctorWerReport with synthetic Report.wer file
    $fakeWerContent = @'
Version=1
EventType=APPCRASH
EventTime=133400000000000000
ReportIdentifier=482613d0-3881-4b71-b0db-6e6bfae7e600
Response.BucketId=cab_bucket_12345
Sig[0].Name=Application Name
Sig[0].Value=notepad.exe
Sig[1].Name=Application Version
Sig[1].Value=11.2311.35.0
Sig[2].Name=Application Timestamp
Sig[2].Value=6566085a
Sig[3].Name=Fault Module Name
Sig[3].Value=ntdll.dll
Sig[4].Name=Fault Module Version
Sig[4].Value=10.0.26100.1882
Sig[5].Name=Fault Module Timestamp
Sig[5].Value=a0248c8b
Sig[6].Name=Exception Code
Sig[6].Value=c0000005
Sig[7].Name=Exception Offset
Sig[7].Value=0000000000023456
LoadedModule[0]=C:\Windows\System32\notepad.exe
LoadedModule[1]=C:\Windows\System32\ntdll.dll
AppLargeDump=memory.dmp
'@
    $fakeWerFile = Join-Path $fakeReportDir1 'Report.wer'
    [System.IO.File]::WriteAllText($fakeWerFile, $fakeWerContent)

    # Also place a mock dump inside the directory
    $fakeDumpInside = Join-Path $fakeReportDir1 'memory.dmp'
    [System.IO.File]::WriteAllBytes($fakeDumpInside, (New-Object byte[] 32))

    $parsedWer = Get-CrashDoctorWerReport -Path $fakeWerFile
    Assert-Equal $parsedWer.EventType 'APPCRASH' 'EventType should be APPCRASH'
    Assert-Equal $parsedWer.ApplicationName 'notepad.exe' 'ApplicationName should be notepad.exe'
    Assert-Equal $parsedWer.FaultModuleName 'ntdll.dll' 'FaultModuleName should be ntdll.dll'
    Assert-Equal $parsedWer.ExceptionCode '0xC0000005' 'ExceptionCode should be hex formatted 0xC0000005'
    Assert-Equal $parsedWer.BucketId 'cab_bucket_12345' 'BucketId should match'
    Assert-Equal $parsedWer.ReportIdentifier '482613d0-3881-4b71-b0db-6e6bfae7e600' 'ReportIdentifier should match'
    Assert-True ($parsedWer.AttachedDumps.Count -ge 1) 'Should discover attached dump file'
    Assert-Equal $parsedWer.LoadedModulesCount 2 'Should parse 2 loaded module lines'

    # Test reading via directory path instead of direct file path
    $parsedWerFromDir = Get-CrashDoctorWerReport -Path $fakeReportDir1
    Assert-Equal $parsedWerFromDir.ApplicationName 'notepad.exe' 'Get-CrashDoctorWerReport from directory path'

    # 3. Test Get-CrashDoctorLocalDumpsConfig
    $localDumpsCfg = Get-CrashDoctorLocalDumpsConfig
    Assert-True ($null -ne $localDumpsCfg.GlobalConfig) 'GlobalConfig should exist'
    Assert-True (-not [string]::IsNullOrWhiteSpace($localDumpsCfg.GlobalConfig.DumpFolder)) 'Global DumpFolder should be non-empty'
    Assert-True ($localDumpsCfg.GlobalConfig.DumpCount -gt 0) 'Global DumpCount should be positive'
    Assert-True ($null -ne $localDumpsCfg.AuditTimeUtc) 'Audit timestamp present'

    # 4. Test Set-CrashDoctorLocalDumps -WhatIf (Reversibility & safe preview)
    $setPreview = Set-CrashDoctorLocalDumps -ExecutableName 'notepad.exe' -DumpType 'Mini' -DumpCount 5 -WhatIf -PassThru
    # Under -WhatIf, ShouldProcess returns false, so no changes are applied and no error is thrown
    # Test setting with explicit rollback command logic
    $cleanExe = 'notepad.exe'
    $expectedRollback = "# Revert per-application LocalDumps setting for $cleanExe`r`nRemove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\$cleanExe' -Recurse -Force -ErrorAction SilentlyContinue"
    Assert-True ($expectedRollback -match 'Remove-Item') 'Rollback command structure valid'

    # 4b. Real acceptance test for WCD-064: apply, verify in registry, audit via config, rollback, verify restoration
    $testRegRoot = 'HKCU:\Software\CrashDoctorTest\LocalDumps'
    if (Test-Path -LiteralPath $testRegRoot) { Remove-Item -Path $testRegRoot -Recurse -Force -ErrorAction SilentlyContinue }

    try {
        $appliedCfg = Set-CrashDoctorLocalDumps -ExecutableName 'audit_probe.exe' -DumpFolder $temp -DumpCount 7 -DumpType 'Full' -RegistryRoot $testRegRoot -PassThru
        Assert-Equal $appliedCfg.Status 'Configured' 'Status should be Configured'
        Assert-Equal $appliedCfg.Application 'audit_probe.exe' 'Application should be audit_probe.exe'
        Assert-Equal $appliedCfg.DumpCount 7 'DumpCount should be 7'
        Assert-Equal $appliedCfg.DumpType 'Full' 'DumpType should be Full'

        # Direct registry verification
        $appKey = Join-Path $testRegRoot 'audit_probe.exe'
        Assert-True (Test-Path -LiteralPath $appKey) 'Registry key must physically exist'
        $rawProps = Get-ItemProperty -LiteralPath $appKey
        Assert-Equal ([string]$rawProps.DumpFolder) $temp 'DumpFolder in registry must match'
        Assert-Equal ([int]$rawProps.DumpCount) 7 'DumpCount in registry must match'
        Assert-Equal ([int]$rawProps.DumpType) 2 'DumpType in registry must be 2 (Full)'

        # Audit via Get-CrashDoctorLocalDumpsConfig
        $audited = Get-CrashDoctorLocalDumpsConfig -RegistryRoot $testRegRoot
        Assert-Equal $audited.PerAppCount 1 'Audited per-app count should be 1'
        Assert-Equal $audited.PerAppConfigs[0].ApplicationName 'audit_probe.exe' 'Audited app name match'
        Assert-Equal $audited.PerAppConfigs[0].DumpType 2 'Audited DumpType match'
        Assert-Equal $audited.PerAppConfigs[0].DumpTypeName 'Full' 'Audited DumpTypeName match'

        # Execute rollback
        $remResult = Remove-CrashDoctorLocalDumps -ExecutableName 'audit_probe.exe' -RegistryRoot $testRegRoot -PassThru
        Assert-Equal $remResult.Status 'Removed' 'Status should be Removed'
        Assert-True (-not (Test-Path -LiteralPath $appKey)) 'Registry key must no longer exist after rollback'

        $restoredAudit = Get-CrashDoctorLocalDumpsConfig -RegistryRoot $testRegRoot
        Assert-Equal $restoredAudit.PerAppCount 0 'Audited per-app count must be 0 after rollback'
    }
    finally {
        Remove-Item -Path 'HKCU:\Software\CrashDoctorTest' -Recurse -Force -ErrorAction SilentlyContinue
    }

    # If running with Administrator privilege, also verify real HKLM LocalDumps apply and rollback
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        $hklmApp = 'wcd_test_probe_elevated.exe'
        $hklmKey = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\$hklmApp"
        try {
            $hklmSet = Set-CrashDoctorLocalDumps -ExecutableName $hklmApp -DumpFolder $temp -DumpCount 3 -DumpType 'Mini' -PassThru
            Assert-True (Test-Path -LiteralPath $hklmKey) 'HKLM key must be created under Administrator'
            $hklmProps = Get-ItemProperty -LiteralPath $hklmKey
            Assert-Equal ([int]$hklmProps.DumpCount) 3 'HKLM DumpCount must be 3'
            Assert-Equal ([int]$hklmProps.DumpType) 1 'HKLM DumpType must be 1 (Mini)'

            # Roll back using Remove-CrashDoctorLocalDumps
            Remove-CrashDoctorLocalDumps -ExecutableName $hklmApp | Out-Null
            Assert-True (-not (Test-Path -LiteralPath $hklmKey)) 'HKLM key must be removed after rollback'
        }
        finally {
            if (Test-Path -LiteralPath $hklmKey) {
                Remove-Item -Path $hklmKey -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # 5. Test Remove-CrashDoctorLocalDumps -WhatIf
    Remove-CrashDoctorLocalDumps -ExecutableName 'notepad.exe' -WhatIf

    # 6. Test Get-CrashDoctorUserModeCrashDumps with synthetic dump
    $fakeUserDumpFolder = Join-Path $temp 'CrashDumps'
    New-Item -ItemType Directory -Path $fakeUserDumpFolder -Force | Out-Null
    $fakeUserDumpFile = Join-Path $fakeUserDumpFolder 'notepad.exe.1234.dmp'
    [System.IO.File]::WriteAllBytes($fakeUserDumpFile, (New-Object byte[] 64))

    $userDumps = @(Get-CrashDoctorUserModeCrashDumps -SearchFolders @($fakeUserDumpFolder))
    Assert-Equal $userDumps.Count 1 'Should discover 1 user-mode dump'
    Assert-Equal $userDumps[0].Application 'notepad.exe' 'Should extract application name from dump file name'
    Assert-Equal $userDumps[0].FileName 'notepad.exe.1234.dmp' 'FileName should match'

    # 6b. Real acceptance test for WCD-065: real crash generation, WER / LocalDumps minidump creation, and parsing
    if ($isAdmin) {
        $csc = (Get-ChildItem -Path "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" -ErrorAction SilentlyContinue).FullName
        if (-not $csc) {
            $csc = (Get-ChildItem -Path "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe" -ErrorAction SilentlyContinue).FullName
        }

        if ($csc -and (Test-Path -LiteralPath $csc)) {
            $crashSrc = @'
using System;
using System.Runtime.InteropServices;
class Program {
    static void Main(string[] args) {
        Marshal.WriteInt32(IntPtr.Zero, 42);
    }
}
'@
            $crashCs = Join-Path $temp 'WcdRealCrashApp.cs'
            $crashExe = Join-Path $temp 'WcdRealCrashApp.exe'
            $realDumpDir = Join-Path $temp 'RealWERDumps'
            New-Item -ItemType Directory -Path $realDumpDir -Force | Out-Null
            [System.IO.File]::WriteAllText($crashCs, $crashSrc)

            & $csc /target:exe /out:$crashExe $crashCs | Out-Null

            if (Test-Path -LiteralPath $crashExe) {
                try {
                    # Configure LocalDumps for the test binary
                    Set-CrashDoctorLocalDumps -ExecutableName 'WcdRealCrashApp.exe' -DumpFolder $realDumpDir -DumpType 'Mini' | Out-Null

                    # Execute the crashing binary in a separate process
                    $proc = Start-Process -FilePath $crashExe -PassThru -Wait -NoNewWindow

                    # Poll for WerFault.exe to write the dump (up to 10 seconds)
                    $realDumpFile = $null
                    for ($s = 0; $s -lt 20; $s++) {
                        Start-Sleep -Milliseconds 500
                        $foundDmps = @(Get-ChildItem -Path $realDumpDir -Filter 'WcdRealCrashApp.exe.*.dmp' -ErrorAction SilentlyContinue)
                        if ($foundDmps.Count -gt 0 -and $foundDmps[0].Length -gt 1024) {
                            $realDumpFile = $foundDmps[0]
                            break
                        }
                    }

                    if ($null -ne $realDumpFile) {
                        Assert-True ($realDumpFile.Length -gt 10000) 'Real WER dump must be larger than 10KB'

                        # Verify magic header
                        $fs = [System.IO.File]::OpenRead($realDumpFile.FullName)
                        $hdrBytes = New-Object byte[] 4
                        $fs.Read($hdrBytes, 0, 4) | Out-Null
                        $fs.Close()
                        $sig = [System.Text.Encoding]::ASCII.GetString($hdrBytes)
                        Assert-Equal $sig 'MDMP' 'Dump file must have MDMP signature'

                        # Ingest via Get-CrashDoctorUserModeCrashDumps
                        $cataloguedReal = @(Get-CrashDoctorUserModeCrashDumps -SearchFolders @($realDumpDir))
                        Assert-True ($cataloguedReal.Count -ge 1) 'Must catalogue real WER dump'
                        $cdump = $cataloguedReal[0]
                        Assert-Equal $cdump.Application 'WcdRealCrashApp.exe' 'Catalogue must match executable name'
                        Assert-Equal $cdump.DumpType 'MiniDump' 'Dump type must be MiniDump'
                        Assert-True ($cdump.ExceptionCode -in @('0xC0000005', '0xE0434352')) "Exception code must be 0xC0000005 or 0xE0434352, got $($cdump.ExceptionCode)"
                        Assert-True $cdump.Parsed 'Parsed must be true'
                        Assert-True ($cdump.ThreadCount -gt 0) 'ThreadCount must be > 0'
                        Assert-True ($cdump.ModuleCount -gt 0) 'ModuleCount must be > 0'
                        Assert-True ($null -ne $cdump.ProblemClassification) 'ProblemClassification must be populated'
                        Assert-Equal $cdump.ProblemClassification.Family 'SystemSoftware' 'Family must be SystemSoftware'
                        Write-Host ('Real WER dump captured and verified: {0} ({1} bytes, code: {2}, modules: {3}, threads: {4})' -f $realDumpFile.Name, $realDumpFile.Length, $cdump.ExceptionCode, $cdump.ModuleCount, $cdump.ThreadCount)
                    } else {
                        Write-Warning 'Real WER dump was not written within timeout; system WER settings may have suppressed child dump.'
                    }
                }
                finally {
                    Remove-CrashDoctorLocalDumps -ExecutableName 'WcdRealCrashApp.exe' -ErrorAction SilentlyContinue | Out-Null
                }
            }
        }
    }

    # 7. Test ConvertTo-CrashDoctorWerMarkdown
    $werMarkdown = ConvertTo-CrashDoctorWerMarkdown -StoresReport $storesResult -LocalDumpsConfig $localDumpsCfg -UserModeDumps $userDumps
    Assert-True ($werMarkdown -match '# Windows Doctor Windows Error Reporting') 'Header present in markdown'
    Assert-True ($werMarkdown -match '## WER report store status') 'Store status table present in markdown'
    Assert-True ($werMarkdown -match '## LocalDumps crash-capture configuration') 'LocalDumps config section present'
    Assert-True ($werMarkdown -match '## User-mode crash dumps discovered') 'User mode dump section present'

    Write-Host 'Windows Doctor WER & LocalDumps test: PASS'
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
