[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'DumpParser.psm1') -Force

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

function Convert-HexU32 {
    param([string]$Hex)
    return [Convert]::ToUInt32($Hex, 16)
}

function Convert-HexU64 {
    param([string]$Hex)
    return [Convert]::ToUInt64($Hex, 16)
}

function Set-U16 {
    param([byte[]]$Bytes, [int]$Offset, [uint16]$Value)
    [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset)
}

function Set-U32 {
    param([byte[]]$Bytes, [int]$Offset, [uint32]$Value)
    [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset)
}

function Set-U64 {
    param([byte[]]$Bytes, [int]$Offset, [uint64]$Value)
    [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset)
}

function Set-I64 {
    param([byte[]]$Bytes, [int]$Offset, [int64]$Value)
    [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset)
}

$temp = Join-Path ([IO.Path]::GetTempPath()) ('WcdDumpParser-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp -Force | Out-Null

try {
    # Synthetic user-mode minidump containing SystemInfo, Exception, ModuleList and ThreadList streams.
    $miniPath = Join-Path $temp 'synthetic-mini.dmp'
    $mini = New-Object byte[] 440
    [Text.Encoding]::ASCII.GetBytes('MDMP').CopyTo($mini, 0)
    Set-U32 $mini 4 0x0000A793
    Set-U32 $mini 8 4
    Set-U32 $mini 12 32
    Set-U32 $mini 20 0x5F3759DF

    # Directory: SystemInfo, Exception, ModuleList, ThreadList.
    Set-U32 $mini 32 7; Set-U32 $mini 36 56; Set-U32 $mini 40 80
    Set-U32 $mini 44 6; Set-U32 $mini 48 168; Set-U32 $mini 52 136
    Set-U32 $mini 56 4; Set-U32 $mini 60 112; Set-U32 $mini 64 304
    Set-U32 $mini 68 3; Set-U32 $mini 72 4; Set-U32 $mini 76 416

    # MINIDUMP_SYSTEM_INFO.
    Set-U16 $mini 80 9
    Set-U16 $mini 82 6
    Set-U16 $mini 84 0x3c03
    $mini[86] = 4
    $mini[87] = 1
    Set-U32 $mini 88 10
    Set-U32 $mini 92 0
    Set-U32 $mini 96 26100
    Set-U32 $mini 100 2

    # MINIDUMP_EXCEPTION_STREAM.
    Set-U32 $mini 136 42
    Set-U32 $mini 144 (Convert-HexU32 'C0000005')
    Set-U64 $mini 160 0x1234567812345678
    Set-U32 $mini 168 2
    Set-U64 $mini 176 1
    Set-U64 $mini 184 2

    # MINIDUMP_MODULE_LIST with one 108-byte module entry.
    Set-U32 $mini 304 1
    Set-U64 $mini 308 0x00007ff600000000
    Set-U32 $mini 316 0x12000
    Set-U32 $mini 320 (Convert-HexU32 'AABBCCDD')
    Set-U32 $mini 324 0x5F3759DF
    Set-U32 $mini 328 420

    # Thread list count only.
    Set-U32 $mini 416 3

    # MINIDUMP_STRING at RVA 420.
    $moduleName = [Text.Encoding]::Unicode.GetBytes('test.dll')
    Set-U32 $mini 420 ([uint32]$moduleName.Length)
    $moduleName.CopyTo($mini, 424)
    [IO.File]::WriteAllBytes($miniPath, $mini)

    $miniInfo = Get-CrashDoctorDumpInfo -Path $miniPath
    Assert-Equal $miniInfo.Format 'MiniDump' 'minidump format detection'
    Assert-Equal $miniInfo.Architecture 'x64' 'minidump architecture'
    Assert-Equal $miniInfo.Header.NumberOfStreams 4 'stream count'
    Assert-Equal $miniInfo.SystemInfo.BuildNumber 26100 'Windows build parsing'
    Assert-Equal $miniInfo.Exception.ThreadId 42 'exception thread ID'
    Assert-Equal $miniInfo.Exception.ExceptionCode (Convert-HexU32 'C0000005') 'exception code'
    Assert-Equal $miniInfo.Exception.ExceptionAddress ([uint64]0x1234567812345678) 'exception address'
    Assert-Equal $miniInfo.ModuleCount 1 'module count'
    Assert-Equal $miniInfo.Modules[0].Name 'test.dll' 'module-name string parsing'
    Assert-Equal $miniInfo.ThreadCount 3 'thread count'

    # Exercise the app's public CLI surface, not just the parser module.
    $output = Join-Path $temp 'output'
    New-Item -ItemType Directory -Path $output -Force | Out-Null
    & (Join-Path $root 'Invoke-CrashDoctor.ps1') -DumpPath $miniPath -OutputDirectory $output | Out-Null
    $dumpJsonPath = Join-Path $output 'crash-doctor-dump-report.json'
    $dumpMarkdownPath = Join-Path $output 'crash-doctor-dump-report.md'
    Assert-True (Test-Path -LiteralPath $dumpJsonPath) 'dump CLI JSON report must be created'
    Assert-True (Test-Path -LiteralPath $dumpMarkdownPath) 'dump CLI Markdown report must be created'
    $cliReport = Get-Content -LiteralPath $dumpJsonPath -Raw | ConvertFrom-Json
    Assert-Equal $cliReport.Format 'MiniDump' 'dump CLI JSON format'

    # Synthetic x64 kernel crash dump header.
    $kernel64Path = Join-Path $temp 'synthetic-kernel64.dmp'
    $kernel64 = New-Object byte[] 8192
    [Text.Encoding]::ASCII.GetBytes('PAGEDU64').CopyTo($kernel64, 0)
    Set-U32 $kernel64 8 15
    Set-U32 $kernel64 12 26100
    Set-U64 $kernel64 16 0x1111222233334444
    Set-U64 $kernel64 24 0x5555666677778888
    Set-U64 $kernel64 32 (Convert-HexU64 'FFFFF80000001000')
    Set-U64 $kernel64 40 (Convert-HexU64 'FFFFF80000002000')
    Set-U32 $kernel64 48 0x8664
    Set-U32 $kernel64 52 4
    Set-U32 $kernel64 56 0x139
    Set-U64 $kernel64 64 3
    Set-U64 $kernel64 72 0x1111
    Set-U64 $kernel64 80 0x2222
    Set-U64 $kernel64 88 0
    Set-U64 $kernel64 128 (Convert-HexU64 'FFFFF80000003000')
    Set-U32 $kernel64 3992 2
    Set-I64 $kernel64 4000 123456789
    Set-I64 $kernel64 4008 133000000000000000
    Set-I64 $kernel64 4144 987654321
    Set-U32 $kernel64 4152 0xCFF
    Set-U32 $kernel64 4160 1
    Set-U32 $kernel64 4164 0x110
    Set-U32 $kernel64 4168 0
    [IO.File]::WriteAllBytes($kernel64Path, $kernel64)

    $kernel64Info = Get-CrashDoctorDumpInfo -Path $kernel64Path
    Assert-Equal $kernel64Info.Format 'KernelCrashDump' 'x64 kernel format detection'
    Assert-Equal $kernel64Info.Architecture 'x64' 'x64 kernel architecture'
    Assert-Equal $kernel64Info.Header.BugCheckCode 0x139 'x64 bugcheck code'
    Assert-Equal $kernel64Info.Header.BugCheckParameter1 ([uint64]3) 'x64 bugcheck parameter'
    Assert-Equal $kernel64Info.Header.DumpTypeName 'Summary' 'x64 dump type'
    Assert-Equal $kernel64Info.Header.RequiredDumpSpace ([int64]123456789) 'required dump space'

    # Synthetic x86 kernel crash dump header.
    $kernel32Path = Join-Path $temp 'synthetic-kernel32.dmp'
    $kernel32 = New-Object byte[] 4096
    [Text.Encoding]::ASCII.GetBytes('PAGEDUMP').CopyTo($kernel32, 0)
    Set-U32 $kernel32 8 15
    Set-U32 $kernel32 12 7601
    Set-U32 $kernel32 16 0x00123000
    Set-U32 $kernel32 20 0x00456000
    Set-U32 $kernel32 24 0x00800000
    Set-U32 $kernel32 28 0x00900000
    Set-U32 $kernel32 32 0x014c
    Set-U32 $kernel32 36 2
    Set-U32 $kernel32 40 0xA
    Set-U32 $kernel32 44 1
    Set-U32 $kernel32 48 2
    Set-U32 $kernel32 52 3
    Set-U32 $kernel32 56 4
    [IO.File]::WriteAllBytes($kernel32Path, $kernel32)

    $kernel32Info = Get-CrashDoctorDumpInfo -Path $kernel32Path
    Assert-Equal $kernel32Info.Architecture 'x86' 'x86 kernel architecture'
    Assert-Equal $kernel32Info.Header.BugCheckCode 0xA 'x86 bugcheck code'
    Assert-Equal $kernel32Info.Header.BugCheckParameter4 4 'x86 bugcheck parameter 4'

    # Corruption and format guards.
    $badPath = Join-Path $temp 'not-a-dump.bin'
    [IO.File]::WriteAllBytes($badPath, [Text.Encoding]::ASCII.GetBytes('NOTADUMP'))
    $rejected = $false
    try { Get-CrashDoctorDumpInfo -Path $badPath | Out-Null } catch { $rejected = $true }
    Assert-True $rejected 'unknown format must be rejected'

    $truncatedPath = Join-Path $temp 'truncated.dmp'
    [IO.File]::WriteAllBytes($truncatedPath, [Text.Encoding]::ASCII.GetBytes('MDMP1234'))
    $truncatedRejected = $false
    try { Get-CrashDoctorDumpInfo -Path $truncatedPath | Out-Null } catch { $truncatedRejected = $true }
    Assert-True $truncatedRejected 'truncated minidump must be rejected'

    # Bugcheck name resolver tests.
    Assert-Equal (Get-CrashDoctorBugCheckName -Code 0x9F) 'DRIVER_POWER_STATE_FAILURE' 'Bugcheck 0x9F name lookup'
    Assert-Equal (Get-CrashDoctorBugCheckName -Code 0x133) 'DPC_WATCHDOG_VIOLATION' 'Bugcheck 0x133 name lookup'
    Assert-Equal (Get-CrashDoctorBugCheckName -Code 0x3B) 'SYSTEM_SERVICE_EXCEPTION' 'Bugcheck 0x3B name lookup'
    Assert-Equal (Get-CrashDoctorBugCheckName -Code 0xDEADBEEF) '0xDEADBEEF' 'Unknown bugcheck preserves hex format'

    # Crash history discovery test across the synthetic dumps created in $temp.
    $history = Get-CrashDoctorSystemCrashHistory -SearchPaths @($temp)
    Assert-True ($history.Count -ge 4) 'Crash history should discover all dumps including truncated'
    $validHistory = @($history | Where-Object { $_.Valid })
    Assert-True ($validHistory.Count -eq 3) 'Exactly 3 synthetic dumps should be marked valid'
    $invalidHistory = @($history | Where-Object { -not $_.Valid })
    Assert-True ($invalidHistory.Count -ge 1) 'Corrupted/truncated dump must be recorded as invalid'
    # Problem classification tests (WCD-018).
    $classWhea = Get-CrashDoctorProblemClassification -BugCheckCode 0x124
    Assert-Equal $classWhea.Family 'Hardware' '0x124 classified as Hardware'
    Assert-Equal $classWhea.Confidence 'High' '0x124 confidence is High'

    $classMem = Get-CrashDoctorProblemClassification -BugCheckCode 0x1A
    Assert-Equal $classMem.Family 'MemoryCorruption' '0x1A classified as MemoryCorruption'

    $classStorage = Get-CrashDoctorProblemClassification -BugCheckCode 0x7A
    Assert-Equal $classStorage.Family 'StorageFileSystem' '0x7A classified as StorageFileSystem'

    $classPower = Get-CrashDoctorProblemClassification -BugCheckCode 0x164
    Assert-Equal $classPower.Family 'PowerThermal' '0x164 classified as PowerThermal'

    $classDriver = Get-CrashDoctorProblemClassification -BugCheckCode 0xD1 -FaultingModule 'mybadnet.sys'
    Assert-Equal $classDriver.Family 'Driver' '0xD1 classified as Driver'
    Assert-True ([bool]($classDriver.ContributingFactors -match 'mybadnet\.sys')) 'Contributing factors include faulting driver'

    $classSys = Get-CrashDoctorProblemClassification -BugCheckCode 0x3B
    Assert-Equal $classSys.Family 'SystemSoftware' '0x3B without third-party driver classified as SystemSoftware'

    # Stack candidate driver unwinding test (WCD-023).
    $fakeStackPath = Join-Path $temp 'stack-test.bin'
    $fakeStackBytes = New-Object byte[] 64
    # Place a return address pointing inside third-party driver (0x00007ff810002040)
    Set-U64 $fakeStackBytes 16 0x00007ff810002040
    # Place a return address pointing inside ntoskrnl.exe (0x00007ff800005000)
    Set-U64 $fakeStackBytes 32 0x00007ff800005000
    [IO.File]::WriteAllBytes($fakeStackPath, $fakeStackBytes)

    $stackStream = [System.IO.File]::OpenRead($fakeStackPath)
    try {
        $mockThreads = @(
            [pscustomobject]@{
                ThreadId = 100
                StackRva = 0
                StackDataSize = 64
            }
        )
        $mockModules = @(
            [pscustomobject]@{ Name = 'thirdparty.sys'; BaseOfImage = [uint64]0x00007ff810000000; SizeOfImage = [uint32]0x10000 },
            [pscustomobject]@{ Name = 'ntoskrnl.exe'; BaseOfImage = [uint64]0x00007ff800000000; SizeOfImage = [uint32]0x50000 }
        )
        $stackDrivers = @(Get-CrashDoctorStackCandidateDrivers -Stream $stackStream -Threads $mockThreads -Modules $mockModules -FaultingThreadId 100)
        Assert-True ($stackDrivers.Count -ge 2) 'Should discover both candidate drivers on stack'
        $tpDriver = @($stackDrivers | Where-Object { $_.Name -eq 'thirdparty.sys' })
        Assert-True ($tpDriver.Count -eq 1) 'Discovered thirdparty.sys driver on stack'
        Assert-True (-not $tpDriver[0].IsCoreComponent) 'thirdparty.sys is correctly flagged non-core'
        $coreDriver = @($stackDrivers | Where-Object { $_.Name -eq 'ntoskrnl.exe' })
        Assert-True ($coreDriver[0].IsCoreComponent) 'ntoskrnl.exe is correctly flagged as Windows core'
    }
    finally {
        $stackStream.Dispose()
    }

    # Crash history properties verification.
    Assert-True ($validHistory[0].PSObject.Properties.Name -contains 'ProblemClassification') 'Crash history record has ProblemClassification'
    Assert-True ($validHistory[0].PSObject.Properties.Name -contains 'StackDrivers') 'Crash history record has StackDrivers'
    Assert-True ($validHistory[0].PSObject.Properties.Name -contains 'BugCheckAnalysis') 'Crash history record has BugCheckAnalysis'
    Assert-True ($validHistory[0].PSObject.Properties.Name -contains 'FaultingCallStack') 'Crash history record has FaultingCallStack'
    Assert-True ($validHistory[0].PSObject.Properties.Name -contains 'CallStacks') 'Crash history record has CallStacks'

    # WCD-003: BugCheck and Exception decoding tests (!analyze -v style)
    $bcaIrql = Get-CrashDoctorBugCheckAnalysis -BugCheckCode 0x0A -Parameters @(0x1000L, 2L, 0L, 0xFFFFF80012345678L) -FaultingModule 'badnet.sys'
    Assert-Equal $bcaIrql.BugCheckName 'IRQL_NOT_LESS_OR_EQUAL' '0x0A bugcheck name'
    Assert-Equal $bcaIrql.ProblemFamily 'Driver' '0x0A family is Driver'
    Assert-Equal $bcaIrql.FailureBucket 'AV_IRQL_badnet.sys' '0x0A failure bucket'
    Assert-Equal $bcaIrql.Parameters.Count 4 '0x0A has 4 decoded parameters'
    Assert-Equal $bcaIrql.Parameters[1].Name 'IRQL Level' '0x0A P2 name is IRQL Level'

    $bcaMem = Get-CrashDoctorBugCheckAnalysis -BugCheckCode 0x1A -Parameters @(0x403L, 0x1000L, 0x2000L, 0x3000L)
    Assert-Equal $bcaMem.ProblemFamily 'MemoryCorruption' '0x1A family is MemoryCorruption'
    Assert-True ($bcaMem.Explanation -like '*Page table page corruption*') '0x1A P1=0x403 subtype explanation'

    $bcaTdr = Get-CrashDoctorBugCheckAnalysis -BugCheckCode 0x116 -FaultingModule 'nvlddmkm.sys'
    Assert-Equal $bcaTdr.ProblemFamily 'Driver' '0x116 family is Driver'
    Assert-True ($bcaTdr.RecommendedAction -like '*nvlddmkm.sys*') '0x116 recommendation references faulting module'

    $bcaAv = Get-CrashDoctorBugCheckAnalysis -BugCheckCode 0xC0000005L -Parameters @(0L, 0x00007FF712340000L) -FaultingModule 'app.exe'
    Assert-Equal $bcaAv.ProblemFamily 'SystemSoftware' 'User-mode AV family'
    Assert-Equal $bcaAv.Parameters.Count 2 'AV has 2 parameters'
    Assert-Equal $bcaAv.Parameters[0].Name 'Access Type' 'AV P1 is Access Type'

    # Heuristic fallback regression: raw stack address candidates are NOT true call-stack unwinding
    $fakeDumpPath = Join-Path $temp 'callstack-test.bin'
    $fakeDumpBytes = New-Object byte[] 512

    # Context structure: at offset 0 (size 0x100): Rip at offset 0xF8, Rsp at 0x98, Rbp at 0xA0
    Set-U64 $fakeDumpBytes 0xF8 0x00007FF800001020 # Rip -> ntoskrnl.exe+0x1020
    Set-U64 $fakeDumpBytes 0x98 0x0000008000002000 # Rsp
    Set-U64 $fakeDumpBytes 0xA0 0x0000008000002040 # Rbp

    # Stack memory: at offset 256 (size 128): StackMemoryBase = 0x0000008000002000
    # Stack offset 0 (0x0000008000002000): caller return address into myfilter.sys
    Set-U64 $fakeDumpBytes (256 + 0) 0x00007FF810003050 # myfilter.sys+0x3050
    # Stack offset 16 (0x0000008000002010): caller return address into ntoskrnl.exe
    Set-U64 $fakeDumpBytes (256 + 16) 0x00007FF800006080 # ntoskrnl.exe+0x6080

    [IO.File]::WriteAllBytes($fakeDumpPath, $fakeDumpBytes)
    $csStream = [System.IO.File]::OpenRead($fakeDumpPath)
    try {
        $testThread = [pscustomobject]@{
            ThreadId        = 555
            ContextRva      = 0
            ContextDataSize = 256
            StackRva        = 256
            StackDataSize   = 128
            StackMemoryBase = [uint64]0x0000008000002000
        }
        $testModules = @(
            [pscustomobject]@{ Name = 'ntoskrnl.exe'; BaseOfImage = [uint64]0x00007FF800000000; SizeOfImage = [uint32]0x50000 },
            [pscustomobject]@{ Name = 'myfilter.sys'; BaseOfImage = [uint64]0x00007FF810000000; SizeOfImage = [uint32]0x20000 }
        )

        $unwoundFrames = @(Read-CrashDoctorHeuristicThreadFrames -Stream $csStream -Thread $testThread -Modules $testModules)
        Assert-True ($unwoundFrames.Count -ge 3) 'Should return at least 3 heuristic stack-frame candidates (RIP + 2 module-address hits)'
        Assert-Equal $unwoundFrames[0].FrameNumber 0 'Frame 0 is top frame'
        Assert-Equal $unwoundFrames[0].ModuleName 'ntoskrnl.exe' 'Frame 0 module is ntoskrnl.exe'
        Assert-Equal $unwoundFrames[0].Offset '0x1020' 'Frame 0 offset is 0x1020'

        Assert-Equal $unwoundFrames[1].FrameNumber 1 'Frame 1'
        Assert-Equal $unwoundFrames[1].ModuleName 'myfilter.sys' 'Frame 1 module is myfilter.sys'
        Assert-Equal $unwoundFrames[1].Offset '0x3050' 'Frame 1 offset is 0x3050'

        # Thread ranking test
        $allThreadStacks = @(Get-CrashDoctorHeuristicThreadStacks -Stream $csStream -Threads @($testThread) -Modules $testModules -FaultingThreadId 555)
        Assert-Equal $allThreadStacks.Count 1 '1 heuristic thread stack produced'
        Assert-Equal $allThreadStacks[0].Rank 1 'Faulting thread is ranked 1'
        Assert-Equal $allThreadStacks[0].Tag 'FAULTING_THREAD' 'Tag is FAULTING_THREAD'
    }
    finally {
        $csStream.Dispose()
    }

    # Markdown format verification: Ensure call stack and candidate drivers are clearly distinct
    $mockReport = [pscustomobject][ordered]@{
        Path                  = 'C:\CrashDumps\sample.dmp'
        FileName              = 'sample.dmp'
        FileSize              = 102400
        CrashTimeUtc          = '2026-10-07T00:00:00Z'
        CrashTimeLocal        = '2026-10-07 10:00:00'
        Format                = 'MiniDump'
        Architecture          = 'x64'
        BugCheckCode          = '0x0000000A'
        BugCheckName          = 'IRQL_NOT_LESS_OR_EQUAL'
        BugCheckParameters    = @('0x1000', '0x2', '0x0', '0xFFFFF80012345678')
        FaultingModule        = 'myfilter.sys'
        ExceptionAddress      = '0xFFFFF80012345678'
        ProblemClassification = $classDriver
        BugCheckAnalysis      = $bcaIrql
        FaultingCallStack     = [pscustomobject]@{
            ThreadId   = 555
            FrameCount = 2
            Frames     = @(
                [pscustomobject]@{ FrameNumber = 0; ModuleName = 'ntoskrnl.exe'; Symbol = 'ntoskrnl.exe+0x1020'; ReturnAddress = $null },
                [pscustomobject]@{ FrameNumber = 1; ModuleName = 'myfilter.sys'; Symbol = 'myfilter.sys+0x3050'; ReturnAddress = '0x00007FF810003050' }
            )
        }
        CallStacks            = @()
        StackDrivers          = @([pscustomobject]@{ Name = 'myfilter.sys'; IsCoreComponent = $false })
        Valid                 = $true
        Error                 = $null
    }

    $md = ConvertTo-CrashDoctorCrashHistoryMarkdown -Crashes @($mockReport)
    Assert-True ($md -like '*Failure bucket ID*AV_IRQL_badnet.sys*') 'Markdown includes failure bucket ID'
    Assert-True ($md -like '*Faulting call stack (unwound activation frames)*') 'Markdown includes unwound call stack header'
    Assert-True ($md -like '*ntoskrnl.exe+0x1020*') 'Markdown contains unwound symbol'
    Assert-True ($md -like '*Candidate stack-involved drivers (raw memory scan)*') 'Markdown keeps candidate stack drivers clearly separate'

    Write-Host 'Windows Crash Doctor dump parser test: PASS'
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
