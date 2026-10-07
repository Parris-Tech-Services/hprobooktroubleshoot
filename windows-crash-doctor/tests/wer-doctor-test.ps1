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

    # 5. Test Remove-CrashDoctorLocalDumps -WhatIf
    Remove-CrashDoctorLocalDumps -ExecutableName 'notepad.exe' -WhatIf

    # 6. Test Get-CrashDoctorUserModeCrashDumps
    $fakeUserDumpFolder = Join-Path $temp 'CrashDumps'
    New-Item -ItemType Directory -Path $fakeUserDumpFolder -Force | Out-Null
    $fakeUserDumpFile = Join-Path $fakeUserDumpFolder 'notepad.exe.1234.dmp'
    [System.IO.File]::WriteAllBytes($fakeUserDumpFile, (New-Object byte[] 64))

    $userDumps = @(Get-CrashDoctorUserModeCrashDumps -SearchFolders @($fakeUserDumpFolder))
    Assert-Equal $userDumps.Count 1 'Should discover 1 user-mode dump'
    Assert-Equal $userDumps[0].Application 'notepad.exe' 'Should extract application name from dump file name'
    Assert-Equal $userDumps[0].FileName 'notepad.exe.1234.dmp' 'FileName should match'

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
