Set-StrictMode -Version Latest

$symbolModule = Join-Path $PSScriptRoot 'SymbolServer.psm1'
if (Test-Path -LiteralPath $symbolModule -PathType Leaf) {
    Import-Module $symbolModule -Force
}

$debuggerModule = Join-Path $PSScriptRoot 'DebuggerBackend.psm1'
if (Test-Path -LiteralPath $debuggerModule -PathType Leaf) {
    Import-Module $debuggerModule -Force
}

$script:MiniDumpSignature = 0x504d444d # 'MDMP'
$script:KernelDumpSignature = 0x45474150 # 'PAGE'
$script:KernelDumpValid32 = 0x504d5544 # 'DUMP'
$script:KernelDumpValid64 = 0x34365544 # 'DU64'

$script:MiniDumpStreamNames = @{
    0  = 'UnusedStream'
    1  = 'ReservedStream0'
    2  = 'ReservedStream1'
    3  = 'ThreadListStream'
    4  = 'ModuleListStream'
    5  = 'MemoryListStream'
    6  = 'ExceptionStream'
    7  = 'SystemInfoStream'
    8  = 'ThreadExListStream'
    9  = 'Memory64ListStream'
    10 = 'CommentStreamA'
    11 = 'CommentStreamW'
    12 = 'HandleDataStream'
    13 = 'FunctionTableStream'
    14 = 'UnloadedModuleListStream'
    15 = 'MiscInfoStream'
    16 = 'MemoryInfoListStream'
    17 = 'ThreadInfoListStream'
    18 = 'HandleOperationListStream'
    19 = 'TokenStream'
    20 = 'JavaScriptDataStream'
    21 = 'SystemMemoryInfoStream'
    22 = 'ProcessVmCountersStream'
    23 = 'IptTraceStream'
    24 = 'ThreadNamesStream'
}

$script:KnownBugCheckNames = @{
    '0xA'        = 'IRQL_NOT_LESS_OR_EQUAL'
    '0x1A'       = 'MEMORY_MANAGEMENT'
    '0x1E'       = 'KMODE_EXCEPTION_NOT_HANDLED'
    '0x24'       = 'NTFS_FILE_SYSTEM'
    '0x3B'       = 'SYSTEM_SERVICE_EXCEPTION'
    '0x4E'       = 'PFN_LIST_CORRUPT'
    '0x50'       = 'PAGE_FAULT_IN_NONPAGED_AREA'
    '0x77'       = 'KERNEL_STACK_INPAGE_ERROR'
    '0x7A'       = 'KERNEL_DATA_INPAGE_ERROR'
    '0x7E'       = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED'
    '0x7F'       = 'UNEXPECTED_KERNEL_MODE_TRAP'
    '0x9C'       = 'MACHINE_CHECK_EXCEPTION'
    '0x9F'       = 'DRIVER_POWER_STATE_FAILURE'
    '0xBE'       = 'ATTEMPTED_WRITE_TO_READONLY_MEMORY'
    '0xC2'       = 'BAD_POOL_CALLER'
    '0xC4'       = 'DRIVER_VERIFIER_DETECTED_VIOLATION'
    '0xC5'       = 'DRIVER_CORRUPTED_EXPOOL'
    '0xCE'       = 'DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS'
    '0xD1'       = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL'
    '0xED'       = 'UNMOUNTABLE_BOOT_VOLUME'
    '0xEF'       = 'CRITICAL_PROCESS_DIED'
    '0xF7'       = 'DRIVER_OVERRAN_STACK_BUFFER'
    '0x101'      = 'CLOCK_WATCHDOG_TIMEOUT'
    '0x109'      = 'CRITICAL_STRUCTURE_CORRUPTION'
    '0x116'      = 'VIDEO_TDR_FAILURE'
    '0x117'      = 'VIDEO_TDR_TIMEOUT_DETECTED'
    '0x119'      = 'VIDEO_SCHEDULER_INTERNAL_ERROR'
    '0x124'      = 'WHEA_UNCORRECTABLE_ERROR'
    '0x12B'      = 'FAULTY_HARDWARE_CORRUPTED_PAGE'
    '0x133'      = 'DPC_WATCHDOG_VIOLATION'
    '0x139'      = 'KERNEL_SECURITY_CHECK_FAILURE'
    '0x13A'      = 'KERNEL_MODE_HEAP_CORRUPTION'
    '0x144'      = 'BUGCODE_USB3_DRIVER'
    '0x154'      = 'UNEXPECTED_STORE_EXCEPTION'
    '0x164'      = 'INTERNAL_POWER_ERROR'
    '0x192'      = 'KERNEL_AUTO_BOOST_LOCK_ACQUISITION_WITH_RAISED_IRQL'
    '0x1A1'      = 'WIN32K_CALLOUT_WATCHDOG_BUGCHECK'
    '0x1C6'      = 'FAST_ERESOURCE_PRECONDITION_VIOLATION'
    '0x1CA'      = 'SYNTHETIC_WATCHDOG_TIMEOUT'
    '0x1D5'      = 'DRIVER_PNP_WATCHDOG'
    '0xC0000005' = 'STATUS_ACCESS_VIOLATION'
    '0xC00000FD' = 'STATUS_STACK_OVERFLOW'
    '0xE0434352' = 'CLR_EXCEPTION'
}

function Get-CrashDoctorBugCheckName {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Code)

    $u = [uint32]0
    if ($Code -is [string]) {
        $clean = $Code.Trim()
        if ($clean.StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) {
            $clean = $clean.Substring(2)
        }
        $parsed = [uint32]0
        if ([uint32]::TryParse($clean, [Globalization.NumberStyles]::HexNumber, [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
            $u = $parsed
        }
    }
    elseif ($Code -is [uint32]) {
        $u = $Code
    }
    else {
        $bytes = [BitConverter]::GetBytes([int64]$Code)
        $u = [BitConverter]::ToUInt32($bytes, 0)
    }

    $key = ('0x{0:X}' -f $u).ToUpperInvariant()
    if ($script:KnownBugCheckNames.ContainsKey($key)) {
        return $script:KnownBugCheckNames[$key]
    }
    return ('0x{0:X8}' -f $u)
}

function Find-CrashDoctorFaultingModule {
    param($DumpInfo)
    if ($null -eq $DumpInfo) { return $null }
    if (-not ($DumpInfo.PSObject.Properties.Name -contains 'Exception') -or $null -eq $DumpInfo.Exception) { return $null }
    if (-not ($DumpInfo.Exception.PSObject.Properties.Name -contains 'ExceptionAddress') -or $null -eq $DumpInfo.Exception.ExceptionAddress) { return $null }
    $addr = [uint64]$DumpInfo.Exception.ExceptionAddress
    if ($addr -eq 0) { return $null }
    if (-not ($DumpInfo.PSObject.Properties.Name -contains 'Modules') -or $null -eq $DumpInfo.Modules) { return $null }
    foreach ($m in @($DumpInfo.Modules)) {
        $base = [uint64]$m.BaseOfImage
        $size = [uint64]$m.SizeOfImage
        if ($addr -ge $base -and $addr -lt ($base + $size)) {
            return $m.Name
        }
    }
    return $null
}

function Read-CrashDoctorBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [System.IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)] [Int64]$Offset,
        [Parameter(Mandatory = $true)] [int]$Count
    )

    if ($Offset -lt 0 -or $Count -lt 0 -or ($Offset + $Count) -gt $Stream.Length) {
        throw "Requested dump range is outside the file: offset=$Offset count=$Count length=$($Stream.Length)"
    }

    $buffer = New-Object byte[] $Count
    $null = $Stream.Seek($Offset, [System.IO.SeekOrigin]::Begin)
    $read = 0
    while ($read -lt $Count) {
        $n = $Stream.Read($buffer, $read, $Count - $read)
        if ($n -le 0) { throw "Unexpected end of dump file at offset $($Offset + $read)." }
        $read += $n
    }
    return $buffer
}

function Get-CrashDoctorUInt16 {
    param([byte[]]$Bytes, [int]$Offset)
    if ($Offset -lt 0 -or ($Offset + 2) -gt $Bytes.Length) { throw 'Truncated dump structure while reading UInt16.' }
    return [BitConverter]::ToUInt16($Bytes, $Offset)
}

function Get-CrashDoctorUInt32 {
    param([byte[]]$Bytes, [int]$Offset)
    if ($Offset -lt 0 -or ($Offset + 4) -gt $Bytes.Length) { throw 'Truncated dump structure while reading UInt32.' }
    return [BitConverter]::ToUInt32($Bytes, $Offset)
}

function Get-CrashDoctorUInt64 {
    param([byte[]]$Bytes, [int]$Offset)
    if ($Offset -lt 0 -or ($Offset + 8) -gt $Bytes.Length) { throw 'Truncated dump structure while reading UInt64.' }
    return [BitConverter]::ToUInt64($Bytes, $Offset)
}

function Get-CrashDoctorInt64 {
    param([byte[]]$Bytes, [int]$Offset)
    if ($Offset -lt 0 -or ($Offset + 8) -gt $Bytes.Length) { throw 'Truncated dump structure while reading Int64.' }
    return [BitConverter]::ToInt64($Bytes, $Offset)
}

function ConvertTo-CrashDoctorUInt64 {
    param($Value)
    if ($null -eq $Value) { return [uint64]0 }
    if ($Value -is [uint64]) { return $Value }
    if ($Value -is [int64]) {
        $b = [BitConverter]::GetBytes([int64]$Value)
        return [BitConverter]::ToUInt64($b, 0)
    }
    if ($Value -is [uint32]) { return [uint64]$Value }
    if ($Value -is [int32]) {
        $b = [BitConverter]::GetBytes([int32]$Value)
        return [uint64][BitConverter]::ToUInt32($b, 0)
    }
    if ($Value -is [string]) {
        $s = $Value.Trim()
        if ($s.StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) {
            $s = $s.Substring(2)
        }
        $parsed = [uint64]0
        if ([uint64]::TryParse($s, [Globalization.NumberStyles]::HexNumber, [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
            return $parsed
        }
    }
    try {
        return [uint64]$Value
    } catch {
        return [uint64]0
    }
}

function ConvertTo-CrashDoctorUInt32 {
    param($Value)
    if ($null -eq $Value) { return [uint32]0 }
    if ($Value -is [uint32]) { return $Value }
    if ($Value -is [int32]) {
        $b = [BitConverter]::GetBytes([int32]$Value)
        return [BitConverter]::ToUInt32($b, 0)
    }
    if ($Value -is [uint64]) {
        $b = [BitConverter]::GetBytes([uint64]$Value)
        return [BitConverter]::ToUInt32($b, 0)
    }
    if ($Value -is [int64]) {
        $b = [BitConverter]::GetBytes([int64]$Value)
        return [BitConverter]::ToUInt32($b, 0)
    }
    if ($Value -is [string]) {
        $s = $Value.Trim()
        if ($s.StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) {
            $s = $s.Substring(2)
        }
        $parsed = [uint32]0
        if ([uint32]::TryParse($s, [Globalization.NumberStyles]::HexNumber, [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
            return $parsed
        }
        $parsed64 = [uint64]0
        if ([uint64]::TryParse($s, [Globalization.NumberStyles]::HexNumber, [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed64)) {
            $b = [BitConverter]::GetBytes([uint64]$parsed64)
            return [BitConverter]::ToUInt32($b, 0)
        }
    }
    try {
        return [uint32]$Value
    } catch {
        return [uint32]0
    }
}

function Get-CrashDoctorMachineName {
    param([uint32]$MachineType)
    switch ($MachineType) {
        0x014c { 'x86' }
        0x0200 { 'IA64' }
        0x8664 { 'x64' }
        0x01c0 { 'ARM' }
        0xaa64 { 'ARM64' }
        default { ('0x{0:X4}' -f $MachineType) }
    }
}

function Get-CrashDoctorProcessorArchitectureName {
    param([uint16]$Architecture)
    switch ($Architecture) {
        0 { 'x86' }
        5 { 'ARM' }
        6 { 'IA64' }
        9 { 'x64' }
        12 { 'ARM64' }
        0xffff { 'Unknown' }
        default { $Architecture.ToString() }
    }
}

function Read-CrashDoctorMiniDumpString {
    param(
        [System.IO.FileStream]$Stream,
        [uint32]$Rva,
        [int]$MaximumBytes = 65536
    )

    if ($Rva -eq 0) { return $null }
    $lengthBytes = Read-CrashDoctorBytes -Stream $Stream -Offset $Rva -Count 4
    $byteLength = [int](Get-CrashDoctorUInt32 -Bytes $lengthBytes -Offset 0)
    if ($byteLength -gt $MaximumBytes -or ($byteLength % 2) -ne 0) {
        throw "Invalid MINIDUMP_STRING length $byteLength at RVA $Rva."
    }
    if ($byteLength -eq 0) { return '' }
    $bytes = Read-CrashDoctorBytes -Stream $Stream -Offset ($Rva + 4) -Count $byteLength
    return [Text.Encoding]::Unicode.GetString($bytes)
}

function Get-CrashDoctorMiniDumpStreamName {
    param([uint32]$StreamType)
    if ($script:MiniDumpStreamNames.ContainsKey([int]$StreamType)) {
        return $script:MiniDumpStreamNames[[int]$StreamType]
    }
    return "StreamType$StreamType"
}

function Read-CrashDoctorMiniDumpSystemInfo {
    param([System.IO.FileStream]$Stream, $Directory)
    if ($Directory.DataSize -lt 24) { return $null }
    $bytes = Read-CrashDoctorBytes -Stream $Stream -Offset $Directory.Rva -Count ([Math]::Min([int]$Directory.DataSize, 64))
    $arch = Get-CrashDoctorUInt16 -Bytes $bytes -Offset 0
    $csdRva = if ($bytes.Length -ge 28) { Get-CrashDoctorUInt32 -Bytes $bytes -Offset 24 } else { 0 }
    $csd = $null
    if ($csdRva -ne 0) {
        try { $csd = Read-CrashDoctorMiniDumpString -Stream $Stream -Rva $csdRva } catch { $csd = $null }
    }

    return [pscustomobject][ordered]@{
        ProcessorArchitecture = Get-CrashDoctorProcessorArchitectureName -Architecture $arch
        ProcessorArchitectureValue = $arch
        ProcessorLevel = Get-CrashDoctorUInt16 -Bytes $bytes -Offset 2
        ProcessorRevision = Get-CrashDoctorUInt16 -Bytes $bytes -Offset 4
        NumberOfProcessors = [int]$bytes[6]
        ProductType = [int]$bytes[7]
        MajorVersion = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 8
        MinorVersion = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 12
        BuildNumber = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 16
        PlatformId = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 20
        ServicePack = $csd
    }
}

function Read-CrashDoctorMiniDumpException {
    param([System.IO.FileStream]$Stream, $Directory)
    if ($Directory.DataSize -lt 40) { return $null }
    $bytes = Read-CrashDoctorBytes -Stream $Stream -Offset $Directory.Rva -Count ([Math]::Min([int]$Directory.DataSize, 168))
    $parameterCount = [Math]::Min([int](Get-CrashDoctorUInt32 -Bytes $bytes -Offset 32), 15)
    $parameters = @()
    for ($i = 0; $i -lt $parameterCount; $i++) {
        $offset = 40 + ($i * 8)
        if (($offset + 8) -le $bytes.Length) {
            $parameters += Get-CrashDoctorUInt64 -Bytes $bytes -Offset $offset
        }
    }

    return [pscustomobject][ordered]@{
        ThreadId = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 0
        ExceptionCode = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 8
        ExceptionFlags = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 12
        ExceptionAddress = Get-CrashDoctorUInt64 -Bytes $bytes -Offset 24
        NumberParameters = $parameterCount
        Parameters = $parameters
    }
}

function Read-CrashDoctorMiniDumpModules {
    param([System.IO.FileStream]$Stream, $Directory)
    if ($Directory.DataSize -lt 4) { return @() }
    $countBytes = Read-CrashDoctorBytes -Stream $Stream -Offset $Directory.Rva -Count 4
    $count = [int](Get-CrashDoctorUInt32 -Bytes $countBytes -Offset 0)
    if ($count -gt 4096) { throw "Unreasonable MINIDUMP_MODULE count: $count" }
    $entrySize = 108
    $available = [Math]::Floor(([int64]$Directory.DataSize - 4) / $entrySize)
    if ($count -gt $available) { throw "Truncated MINIDUMP_MODULE_LIST: expected $count entries, only $available fit." }

    $modules = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $count; $i++) {
        $offset = [int64]$Directory.Rva + 4 + ($i * $entrySize)
        $bytes = Read-CrashDoctorBytes -Stream $Stream -Offset $offset -Count $entrySize
        $nameRva = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 20
        $name = $null
        if ($nameRva -ne 0) {
            try { $name = Read-CrashDoctorMiniDumpString -Stream $Stream -Rva $nameRva } catch { $name = $null }
        }

        # CodeView Record (PDB RSDS info) at offset 76
        $cvDataSize = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 76
        $cvRva = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 80
        $pdbInfo = $null
        if ($cvDataSize -ge 24 -and $cvRva -ne 0 -and ($cvRva + $cvDataSize) -le $Stream.Length) {
            try {
                $cvBytes = Read-CrashDoctorBytes -Stream $Stream -Offset $cvRva -Count $cvDataSize
                if (Get-Command Get-CrashDoctorModulePdbInfo -ErrorAction SilentlyContinue) {
                    $pdbInfo = Get-CrashDoctorModulePdbInfo -CvBytes $cvBytes
                }
            } catch { }
        }

        $modules.Add([pscustomobject][ordered]@{
            BaseOfImage   = Get-CrashDoctorUInt64 -Bytes $bytes -Offset 0
            SizeOfImage   = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 8
            Checksum      = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 12
            TimeDateStamp = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 16
            Name          = $name
            PdbInfo       = $pdbInfo
        })
    }
    return $modules.ToArray()
}

function Read-CrashDoctorMiniDumpCountStream {
    param([System.IO.FileStream]$Stream, $Directory)
    if ($Directory.DataSize -lt 4) { return $null }
    $bytes = Read-CrashDoctorBytes -Stream $Stream -Offset $Directory.Rva -Count 4
    return [int](Get-CrashDoctorUInt32 -Bytes $bytes -Offset 0)
}

function Read-CrashDoctorMiniDumpMemory64Summary {
    param([System.IO.FileStream]$Stream, $Directory)
    if ($Directory.DataSize -lt 16) { return $null }
    $header = Read-CrashDoctorBytes -Stream $Stream -Offset $Directory.Rva -Count 16
    $count = Get-CrashDoctorUInt64 -Bytes $header -Offset 0
    if ($count -gt 10000000) { throw "Unreasonable MINIDUMP_MEMORY64_LIST range count: $count" }
    $available = [Math]::Floor(([int64]$Directory.DataSize - 16) / 16)
    if ($count -gt $available) { throw "Truncated MINIDUMP_MEMORY64_LIST: expected $count ranges, only $available fit." }
    $total = [uint64]0
    for ($i = 0; $i -lt [int]$count; $i++) {
        $entry = Read-CrashDoctorBytes -Stream $Stream -Offset ([int64]$Directory.Rva + 16 + ($i * 16)) -Count 16
        $total += Get-CrashDoctorUInt64 -Bytes $entry -Offset 8
    }
    return [pscustomobject][ordered]@{
        RangeCount = $count
        BaseRva = Get-CrashDoctorUInt64 -Bytes $header -Offset 8
        TotalMemoryBytes = $total
    }
}

function Read-CrashDoctorMiniDumpMemoryInfoSummary {
    param([System.IO.FileStream]$Stream, $Directory)
    if ($Directory.DataSize -lt 16) { return $null }
    $bytes = Read-CrashDoctorBytes -Stream $Stream -Offset $Directory.Rva -Count 16
    return [pscustomobject][ordered]@{
        HeaderSize = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 0
        EntrySize = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 4
        EntryCount = Get-CrashDoctorUInt64 -Bytes $bytes -Offset 8
    }
}

function Read-CrashDoctorMiniDumpThreads {
    param([System.IO.FileStream]$Stream, $Directory)
    if ($Directory.DataSize -lt 4) { return ,@() }
    $countBytes = Read-CrashDoctorBytes -Stream $Stream -Offset $Directory.Rva -Count 4
    $count = [int](Get-CrashDoctorUInt32 -Bytes $countBytes -Offset 0)
    if ($count -gt 2048) { throw "Unreasonable MINIDUMP_THREAD count: $count" }
    $entrySize = 48
    $available = [Math]::Floor(([int64]$Directory.DataSize - 4) / $entrySize)
    if ($available -lt 1) { return ,@() }
    $readCount = [Math]::Min($count, [int]$available)

    $threads = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $readCount; $i++) {
        $offset = [int64]$Directory.Rva + 4 + ($i * $entrySize)
        $bytes = Read-CrashDoctorBytes -Stream $Stream -Offset $offset -Count $entrySize
        $threads.Add([pscustomobject][ordered]@{
            ThreadId        = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 0
            SuspendCount    = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 4
            PriorityClass   = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 8
            Priority        = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 12
            Teb             = Get-CrashDoctorUInt64 -Bytes $bytes -Offset 16
            StackMemoryBase = Get-CrashDoctorUInt64 -Bytes $bytes -Offset 24
            StackDataSize   = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 32
            StackRva        = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 36
            ContextDataSize = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 40
            ContextRva      = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 44
        })
    }
    return $threads.ToArray()
}

<#
.SYNOPSIS
    Scans raw thread stack memory for pointer-sized values that fall within the address space of loaded modules.
.DESCRIPTION
    Implements WCD-023 (BlueScreenView-style candidate stack-address-to-module mapping).
    Note: This is candidate address-to-module scanning, NOT true call-stack unwinding.
    True call-stack unwinding with frame pointer / DWARF / PDB traversal is tracked in WCD-004 and WCD-005.
#>
function Get-CrashDoctorStackCandidateDrivers {
    [CmdletBinding()]
    param(
        [System.IO.FileStream]$Stream,
        [object[]]$Threads,
        [object[]]$Modules,
        [uint32]$FaultingThreadId = 0,
        [string]$Architecture = 'x64'
    )

    if ($null -eq $Stream -or $null -eq $Modules -or $Modules.Count -eq 0) { return @() }

    $targetThreads = @()
    if ($Threads -and $Threads.Count -gt 0) {
        if ($FaultingThreadId -ne 0) {
            $matching = @($Threads | Where-Object { $_.ThreadId -eq $FaultingThreadId })
            if ($matching.Count -gt 0) { $targetThreads = $matching }
            else { $targetThreads = $Threads }
        } else {
            $targetThreads = $Threads
        }
    }

    $ptrSize = if ($Architecture -eq 'x86') { 4 } else { 8 }
    $foundDrivers = New-Object System.Collections.Generic.List[object]
    $seenModules = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($thread in $targetThreads) {
        $rva = [int64]$thread.StackRva
        $size = [int]$thread.StackDataSize
        if ($rva -lt 0 -or $size -le 0 -or ($rva + $size) -gt $Stream.Length) { continue }
        if ($size -gt 2097152) { $size = 2097152 }

        $stackBytes = Read-CrashDoctorBytes -Stream $Stream -Offset $rva -Count $size
        $maxOffset = $size - $ptrSize
        for ($pos = 0; $pos -le $maxOffset; $pos += $ptrSize) {
            $addr = if ($ptrSize -eq 8) {
                Get-CrashDoctorUInt64 -Bytes $stackBytes -Offset $pos
            } else {
                [uint64](Get-CrashDoctorUInt32 -Bytes $stackBytes -Offset $pos)
            }

            if ($addr -eq 0) { continue }

            foreach ($m in $Modules) {
                $base = [uint64]$m.BaseOfImage
                $modSize = [uint64]$m.SizeOfImage
                if ($addr -ge $base -and $addr -lt ($base + $modSize)) {
                    $modName = [System.IO.Path]::GetFileName([string]$m.Name)
                    if ([string]::IsNullOrWhiteSpace($modName)) { $modName = [string]$m.Name }
                    if ($seenModules.Add($modName)) {
                        $offsetHex = '0x{0:X}' -f ($addr - $base)
                        $isCore = [bool]($modName -match '(?i)^(ntoskrnl\.exe|hal\.dll|(fltmgr|ntfs|ndis|tcpip|ci|win32k|win32kbase|win32kfull|storport|dump_storport)\.(sys|dll)|(ntdll|kernel32|kernelbase|user32|gdi32|msvcrt|clr|mscoree|ucrtbase|combase|rpcrt4)\.dll)$')
                        $foundDrivers.Add([pscustomobject][ordered]@{
                            Name            = $modName
                            FullPath        = $m.Name
                            BaseAddress     = ('0x{0:X16}' -f $base)
                            StackAddress    = ('0x{0:X16}' -f $addr)
                            Offset          = $offsetHex
                            ThreadId        = $thread.ThreadId
                            IsCoreComponent = $isCore
                        })
                    }
                    break
                }
            }
        }
    }

    return $foundDrivers.ToArray()
}

function Get-CrashDoctorProblemClassification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $BugCheckCode,
        [uint64[]] $Parameters = @(),
        [string] $FaultingModule = $null,
        [object[]] $CandidateDrivers = @()
    )

    $u = [uint32]0
    if ($BugCheckCode -is [string]) {
        $clean = $BugCheckCode.Trim()
        if ($clean.StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) {
            $clean = $clean.Substring(2)
        }
        $parsed = [uint32]0
        if ([uint32]::TryParse($clean, [Globalization.NumberStyles]::HexNumber, [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
            $u = $parsed
        }
    }
    elseif ($BugCheckCode -is [uint32]) {
        $u = $BugCheckCode
    }
    else {
        $bytes = [BitConverter]::GetBytes([int64]$BugCheckCode)
        $u = [BitConverter]::ToUInt32($bytes, 0)
    }

    $bugCheckHex = ('0x{0:X}' -f $u).ToUpperInvariant()
    $bugCheckName = Get-CrashDoctorBugCheckName -Code $u
    $contributing = New-Object System.Collections.Generic.List[string]
    $contributing.Add("BugCheck: $bugCheckName ($bugCheckHex)")

    if (-not [string]::IsNullOrWhiteSpace($FaultingModule)) {
        $contributing.Add("Faulting module: $FaultingModule")
    }

    $thirdPartyDrivers = New-Object System.Collections.Generic.List[object]
    if ($CandidateDrivers) {
        foreach ($d in @($CandidateDrivers)) {
            if ($null -eq $d) { continue }
            $name = if ($d -is [System.Management.Automation.PSObject] -and $null -ne $d.PSObject.Properties['Name']) { [string]$d.Name } else { [string]$d }
            if ($name -match '(?i)\.sys$') {
                $isCore = [bool]($name -match '(?i)^(ntoskrnl|hal|fltmgr|ntfs|ndis|tcpip|ci|win32k|win32kbase|win32kfull|storport|dump_storport)\.(sys|exe|dll)$')
                if ($d -is [System.Management.Automation.PSObject] -and $null -ne $d.PSObject.Properties['IsCoreComponent']) {
                    $isCore = [bool]$d.IsCoreComponent
                }
                if (-not $isCore) {
                    $thirdPartyDrivers.Add($d)
                }
            }
        }
    }

    if ($thirdPartyDrivers.Count -gt 0) {
        $driverNames = ($thirdPartyDrivers | Select-Object -ExpandProperty Name -Unique) -join ', '
        $contributing.Add("Third-party stack drivers: $driverNames")
    }

    switch ($u) {
        # Hardware / Platform
        { $_ -in @(0x124, 0x9C, 0x101, 0x1CA) } {
            $summary = switch ($u) {
                0x124 { 'Hardware uncorrectable error (WHEA); processor, PCIe or memory bus error detected by hardware architecture.' }
                0x9C  { 'Machine Check Exception (MCE); unrecoverable hardware exception reported by the CPU.' }
                0x101 { 'Clock watchdog timeout; secondary processor core failed to service clock interrupts.' }
                0x1CA { 'Synthetic watchdog timeout; operating system freeze detected by hypervisor or platform watchdog.' }
            }
            return [pscustomobject][ordered]@{
                Family              = 'Hardware'
                Confidence          = 'High'
                Summary             = "Hardware / CPU / Platform defect ($bugCheckName)"
                Explanation         = $summary
                RecommendedAction   = 'Inspect system temperatures and voltages, update motherboard UEFI/BIOS firmware, check CPU cooler mounting, and inspect PCIe devices.'
                ContributingFactors = $contributing.ToArray()
            }
        }

        # Memory Corruption
        { $_ -in @(0x1A, 0x4E, 0x12B, 0x109, 0x13A, 0xC2) } {
            $summary = switch ($u) {
                0x1A  { 'Memory Management corruption; corrupt page table entries or physical memory inconsistency.' }
                0x4E  { 'Page Frame Number (PFN) list corrupt; physical memory tracking list corrupted.' }
                0x12B { 'Faulty hardware corrupted page; hardware memory architecture detected single- or multi-bit physical memory error.' }
                0x109 { 'Critical structure corruption; kernel code or critical structures corrupted by bad memory or malicious driver.' }
                0x13A { 'Kernel mode heap corruption; memory pool corruption by kernel component.' }
                0xC2  { 'Bad pool caller; invalid memory allocation or free requested by kernel caller.' }
            }
            $conf = if ($u -in @(0x1A, 0x4E, 0x12B)) { 'High' } else { 'Medium' }
            return [pscustomobject][ordered]@{
                Family              = 'MemoryCorruption'
                Confidence          = $conf
                Summary             = "Memory / Physical RAM corruption ($bugCheckName)"
                Explanation         = $summary
                RecommendedAction   = 'Run Windows Memory Diagnostic (mdsched.exe) or MemTest86, verify RAM XMP/EXPO timings, and test individual memory modules.'
                ContributingFactors = $contributing.ToArray()
            }
        }

        # Storage / File System
        { $_ -in @(0x24, 0x77, 0x7A, 0xED, 0x154) } {
            $summary = switch ($u) {
                0x24  { 'NTFS file system driver failure or disk metadata corruption.' }
                0x77  { 'Kernel stack inpage error; requested kernel stack data could not be read from disk paging file.' }
                0x7A  { 'Kernel data inpage error; paging file data read failure, frequently caused by bad sectors or storage controller timeout.' }
                0xED  { 'Unmountable boot volume; file system or storage failure during boot volume initialization.' }
                0x154 { 'Unexpected store exception; memory store manager failed to read from storage volume.' }
            }
            return [pscustomobject][ordered]@{
                Family              = 'StorageFileSystem'
                Confidence          = 'High'
                Summary             = "Storage / File system / Pagefile failure ($bugCheckName)"
                Explanation         = $summary
                RecommendedAction   = 'Run chkdsk /f /r, inspect NVMe/SATA SMART health indicators, verify cable/drive connections, and update storage controller firmware.'
                ContributingFactors = $contributing.ToArray()
            }
        }

        # Power / Thermal
        { $_ -in @(0x164) } {
            return [pscustomobject][ordered]@{
                Family              = 'PowerThermal'
                Confidence          = 'High'
                Summary             = "Power / Thermal management failure ($bugCheckName)"
                Explanation         = 'Internal power transition failure; power management driver failed to execute state transition.'
                RecommendedAction   = 'Update chipset and ACPI drivers, check battery/power supply health, and disable Fast Startup to test stability.'
                ContributingFactors = $contributing.ToArray()
            }
        }

        # Driver / Third-Party Kernel Module
        { $_ -in @(0x9F, 0xC4, 0xC5, 0xCE, 0xD1, 0xF7, 0x116, 0x117, 0x119, 0x133, 0x139, 0x144, 0x192, 0x1D5) } {
            $driverNote = if ($FaultingModule) { "Faulting driver candidate: $FaultingModule." } else { 'Kernel driver faulted during execution.' }
            $summary = switch ($u) {
                0x9F  { "Driver power state failure; driver failed to complete power IRP in required timeframe. $driverNote" }
                0xD1  { "Driver IRQL not less or equal; driver accessed pageable memory at raised interrupt request level (IRQL). $driverNote" }
                0x116 { "Video TDR failure; graphics driver failed to respond to display scheduler timeout. $driverNote" }
                0x117 { "Video TDR timeout detected; display driver timeout. $driverNote" }
                0x133 { "DPC watchdog violation; driver spent excessive cumulative time in Deferred Procedure Call (DPC) routine. $driverNote" }
                0x139 { "Kernel security check failure; buffer overrun or list corruption detected by compiler guard. $driverNote" }
                0x144 { "USB 3.0 controller driver bugcheck. $driverNote" }
                0x1D5 { "Driver PnP watchdog timeout; driver stalled in Plug and Play handler. $driverNote" }
                default { "Driver defect violation ($bugCheckName). $driverNote" }
            }
            return [pscustomobject][ordered]@{
                Family              = 'Driver'
                Confidence          = 'High'
                Summary             = "Kernel driver fault ($bugCheckName)"
                Explanation         = $summary
                RecommendedAction   = if ($FaultingModule) { "Update, roll back, or reinstall the driver associated with $FaultingModule." } else { 'Update third-party device drivers and review recently installed drivers.' }
                ContributingFactors = $contributing.ToArray()
            }
        }

        # System Software / Subsystem
        { $_ -in @(0x3BL, 0x7EL, 0x1EL, 0x7FL, 0xEFL, 0xC0000005L, 0xC00000FDL, 0xE0434352L) } {
            $fam = if ($thirdPartyDrivers.Count -gt 0) { 'Driver' } else { 'SystemSoftware' }
            $conf = if ($thirdPartyDrivers.Count -gt 0) { 'Medium' } else { 'Medium' }
            $summary = switch ($u) {
                0x3B  { 'System service exception; unhandled exception in kernel-mode system service.' }
                0x7E  { 'System thread exception not handled; kernel worker thread encountered unhandled exception.' }
                0x1E  { 'Kmode exception not handled; kernel code executed illegal or unhandled instruction.' }
                0x7F  { 'Unexpected kernel mode trap; processor trap such as divide-by-zero or double fault.' }
                0xEF  { 'Critical process died; essential Windows system process (csrss.exe, wininit.exe, etc.) was terminated.' }
                0xC0000005L { 'Access violation exception; invalid pointer dereference or memory access.' }
                0xC00000FDL { 'Stack overflow exception; call recursion exhausted available thread stack.' }
                0xE0434352L { 'CLR / .NET runtime exception; unhandled managed exception in runtime process.' }
                default { "Kernel or application exception ($bugCheckName)." }
            }
            if ($thirdPartyDrivers.Count -gt 0) {
                $summary += " Third-party driver(s) present on faulting stack: $(($thirdPartyDrivers | Select-Object -ExpandProperty Name -Unique) -join ', ')."
            }
            return [pscustomobject][ordered]@{
                Family              = $fam
                Confidence          = $conf
                Summary             = if ($fam -eq 'Driver') { "Driver-involved exception ($bugCheckName)" } else { "System software exception ($bugCheckName)" }
                Explanation         = $summary
                RecommendedAction   = if ($fam -eq 'Driver') { 'Review and update third-party drivers identified on the crash stack; run DISM and SFC to verify system file integrity.' } else { 'Run sfc /scannow and DISM /Online /Cleanup-Image /RestoreHealth to verify operating system binaries.' }
                ContributingFactors = $contributing.ToArray()
            }
        }

        # Page fault in nonpaged area (0x50): can be memory or driver
        0x50 {
            $fam = if ($thirdPartyDrivers.Count -gt 0 -or ($FaultingModule -and $FaultingModule -match '(?i)\.sys$' -and $FaultingModule -notmatch '(?i)^(ntoskrnl|hal)\.sys$')) { 'Driver' } else { 'MemoryCorruption' }
            return [pscustomobject][ordered]@{
                Family              = $fam
                Confidence          = 'Medium'
                Summary             = if ($fam -eq 'Driver') { 'Driver invalid memory access (PAGE_FAULT_IN_NONPAGED_AREA)' } else { 'Memory fault (PAGE_FAULT_IN_NONPAGED_AREA)' }
                Explanation         = 'Invalid system memory was referenced by the processor. This can be caused by a driver accessing unmapped or paged-out memory, or by physical RAM defects.'
                RecommendedAction   = if ($fam -eq 'Driver') { 'Update or uninstall the faulting device driver, or run Windows Memory Diagnostic to eliminate RAM faults.' } else { 'Test physical RAM with Windows Memory Diagnostic or MemTest86.' }
                ContributingFactors = $contributing.ToArray()
            }
        }

        default {
            $fam = if ($thirdPartyDrivers.Count -gt 0) { 'Driver' } elseif ($FaultingModule -and $FaultingModule -match '(?i)\.sys$') { 'Driver' } elseif ($FaultingModule) { 'SystemSoftware' } else { 'Unknown' }
            return [pscustomobject][ordered]@{
                Family              = $fam
                Confidence          = 'Low'
                Summary             = if ($fam -eq 'Driver') { "Probable driver fault ($bugCheckName)" } else { "Unclassified crash ($bugCheckName)" }
                Explanation         = "Bugcheck code $bugCheckHex ($bugCheckName) is not mapped to a specific automated heuristic."
                RecommendedAction   = 'Inspect system event logs around the crash timestamp and cross-reference with device manager problem states.'
                ContributingFactors = $contributing.ToArray()
            }
        }
    }
}

function Get-CrashDoctorBugCheckAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $BugCheckCode,
        [object[]] $Parameters = @(),
        [string] $FaultingModule = $null,
        $ExceptionAddress = $null,
        [string] $Architecture = 'x64'
    )

    $u = [uint32]0
    if ($BugCheckCode -is [string]) {
        $clean = $BugCheckCode.Trim()
        if ($clean.StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) {
            $clean = $clean.Substring(2)
        }
        $parsed = [uint32]0
        if ([uint32]::TryParse($clean, [Globalization.NumberStyles]::HexNumber, [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
            $u = $parsed
        }
    }
    elseif ($BugCheckCode -is [uint32]) {
        $u = $BugCheckCode
    }
    else {
        $bytes = [BitConverter]::GetBytes([int64]$BugCheckCode)
        $u = [BitConverter]::ToUInt32($bytes, 0)
    }

    $bugCheckHex = ('0x{0:X}' -f $u).ToUpperInvariant()
    $bugCheckName = Get-CrashDoctorBugCheckName -Code $u

    $paramList = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Parameters) {
        foreach ($p in $Parameters) {
            if ($null -ne $p) { $paramList.Add($p) }
        }
    }

    $p1 = if ($paramList.Count -gt 0) { ConvertTo-CrashDoctorUInt64 $paramList[0] } else { [uint64]0 }
    $p2 = if ($paramList.Count -gt 1) { ConvertTo-CrashDoctorUInt64 $paramList[1] } else { [uint64]0 }
    $p3 = if ($paramList.Count -gt 2) { ConvertTo-CrashDoctorUInt64 $paramList[2] } else { [uint64]0 }
    $p4 = if ($paramList.Count -gt 3) { ConvertTo-CrashDoctorUInt64 $paramList[3] } else { [uint64]0 }

    $pDetails = New-Object System.Collections.Generic.List[object]
    $failureBucket = $null
    $summary = ''
    $explanation = ''
    $recommended = ''
    $problemFamily = 'Unknown'

    switch ($u) {
        # 0x0A: IRQL_NOT_LESS_OR_EQUAL
        0x0A {
            $problemFamily = 'Driver'
            $accessType = switch ($p3) { 0 { 'Read' } 1 { 'Write' } 8 { 'Execute' } default { "Access($p3)" } }
            $irqlName = switch ($p2) { 2 { 'DISPATCH_LEVEL (2)' } 12 { 'SYNCH_LEVEL (12)' } 15 { 'HIGH_LEVEL (15)' } default { "IRQL $p2" } }
            $failureBucket = if ($FaultingModule) { "AV_IRQL_$FaultingModule" } else { 'AV_IRQL_NOT_LESS_OR_EQUAL' }
            $summary = "Kernel memory referenced at an invalid IRQL level ($irqlName)."
            $explanation = "An operating system thread referenced pageable or invalid virtual memory at an interrupt request level (IRQL) that does not permit page faults. The operation was a $accessType of address 0x{0:X16} by instruction at 0x{1:X16}." -f $p1, $p4
            $recommended = if ($FaultingModule) { "Update, roll back or reinstall $FaultingModule." } else { 'Update device drivers; inspect driver verifier logs.' }

            $pDetails.Add([pscustomobject]@{ Index = 1; RawHex = ('0x{0:X16}' -f $p1); Name = 'Memory Referenced'; Description = ('Virtual address referenced: 0x{0:X16}' -f $p1) })
            $pDetails.Add([pscustomobject]@{ Index = 2; RawHex = ('0x{0:X16}' -f $p2); Name = 'IRQL Level'; Description = $irqlName })
            $pDetails.Add([pscustomobject]@{ Index = 3; RawHex = ('0x{0:X16}' -f $p3); Name = 'Access Type'; Description = "$accessType operation (0=Read, 1=Write, 8=Execute)" })
            $pDetails.Add([pscustomobject]@{ Index = 4; RawHex = ('0x{0:X16}' -f $p4); Name = 'Instruction Address'; Description = ('Address of instruction referencing memory: 0x{0:X16}' -f $p4) })
        }

        # 0x1A: MEMORY_MANAGEMENT
        0x1A {
            $problemFamily = 'MemoryCorruption'
            $subtype = switch ($p1) {
                0x403   { 'Page table page corruption detected during trim or unmap.' }
                0x411   { 'PTE or PFN list entry corrupted.' }
                0x41284 { 'Working set list corruption detected by memory manager.' }
                0x41792 { 'Page corruption detected during file mapping or transition.' }
                0x41790 { 'Page table page allocation failure; system exhausted nonpaged resources.' }
                0x61941 { 'Corrupt paging hierarchy or page table entry (PTE).' }
                default { ('Memory management corruption subtype 0x{0:X}.' -f $p1) }
            }
            $failureBucket = ('MEMORY_MANAGEMENT_0x{0:X}' -f $p1)
            $summary = "Internal memory manager detected corruption ($subtype)."
            $explanation = "Windows Memory Manager encountered severe inconsistency in page table entries, physical frame number (PFN) metadata, or working set structures. Subtype: $subtype."
            $recommended = 'Run Windows Memory Diagnostic (mdsched.exe) or MemTest86, verify RAM XMP/EXPO settings, and test individual DIMMs.'

            $pDetails.Add([pscustomobject]@{ Index = 1; RawHex = ('0x{0:X16}' -f $p1); Name = 'Subtype Code'; Description = $subtype })
            $pDetails.Add([pscustomobject]@{ Index = 2; RawHex = ('0x{0:X16}' -f $p2); Name = 'Target Address'; Description = ('Virtual address or PFN: 0x{0:X16}' -f $p2) })
            $pDetails.Add([pscustomobject]@{ Index = 3; RawHex = ('0x{0:X16}' -f $p3); Name = 'PTE / Data Value'; Description = ('PTE contents or original value: 0x{0:X16}' -f $p3) })
            $pDetails.Add([pscustomobject]@{ Index = 4; RawHex = ('0x{0:X16}' -f $p4); Name = 'Fault Context'; Description = ('Internal context / secondary address: 0x{0:X16}' -f $p4) })
        }

        # 0x3B: SYSTEM_SERVICE_EXCEPTION
        0x3B {
            $problemFamily = 'SystemSoftware'
            $uP1 = ConvertTo-CrashDoctorUInt32 $p1
            $excHex = ('0x{0:X8}' -f $uP1)
            $excName = Get-CrashDoctorBugCheckName -Code $uP1
            $failureBucket = if ($FaultingModule) { "SYSTEM_SERVICE_EXCEPTION_$FaultingModule" } else { "SYSTEM_SERVICE_EXCEPTION_$excName" }
            $summary = "Unhandled exception in kernel-mode system service code ($excName)."
            $explanation = "A system routine executed by the operating system kernel or a subsystem component generated an unhandled exception ($excHex - $excName) at instruction 0x{0:X16}." -f $p2
            $recommended = 'Run sfc /scannow and DISM /Online /Cleanup-Image /RestoreHealth to verify system components.'

            $pDetails.Add([pscustomobject]@{ Index = 1; RawHex = ('0x{0:X16}' -f $p1); Name = 'Exception Code'; Description = ("Exception that caused the bugcheck: {0} ({1})" -f $excHex, $excName) })
            $pDetails.Add([pscustomobject]@{ Index = 2; RawHex = ('0x{0:X16}' -f $p2); Name = 'Instruction Address'; Description = ('Address of instruction causing exception: 0x{0:X16}' -f $p2) })
            $pDetails.Add([pscustomobject]@{ Index = 3; RawHex = ('0x{0:X16}' -f $p3); Name = 'Context Record'; Description = ('Pointer to CONTEXT record: 0x{0:X16}' -f $p3) })
            $pDetails.Add([pscustomobject]@{ Index = 4; RawHex = ('0x{0:X16}' -f $p4); Name = 'Reserved'; Description = ('Reserved / secondary parameter: 0x{0:X16}' -f $p4) })
        }

        # 0x50: PAGE_FAULT_IN_NONPAGED_AREA
        0x50 {
            $problemFamily = if ($FaultingModule -and $FaultingModule -match '(?i)\.sys$') { 'Driver' } else { 'MemoryCorruption' }
            $accessType = switch ($p2) { 0 { 'Read' } 1 { 'Write' } 8 { 'Execute' } default { "Access($p2)" } }
            $failureBucket = if ($FaultingModule) { "PAGE_FAULT_$FaultingModule" } else { "PAGE_FAULT_IN_NONPAGED_AREA_$accessType" }
            $summary = "Invalid system memory referenced ($accessType access to 0x{0:X16})." -f $p1
            $explanation = "The operating system referenced unmapped memory or invalid non-paged memory during a $accessType operation at instruction 0x{0:X16}." -f $p3
            $recommended = if ($problemFamily -eq 'Driver') { "Update or rollback driver $FaultingModule." } else { 'Test system memory with Windows Memory Diagnostic (mdsched.exe).' }

            $pDetails.Add([pscustomobject]@{ Index = 1; RawHex = ('0x{0:X16}' -f $p1); Name = 'Invalid Address'; Description = ('Memory address referenced: 0x{0:X16}' -f $p1) })
            $pDetails.Add([pscustomobject]@{ Index = 2; RawHex = ('0x{0:X16}' -f $p2); Name = 'Access Type'; Description = "$accessType operation (0=Read, 1=Write, 8=Execute)" })
            $pDetails.Add([pscustomobject]@{ Index = 3; RawHex = ('0x{0:X16}' -f $p3); Name = 'Instruction Address'; Description = ('Instruction referencing invalid address: 0x{0:X16}' -f $p3) })
            $pDetails.Add([pscustomobject]@{ Index = 4; RawHex = ('0x{0:X16}' -f $p4); Name = 'Fault Type'; Description = ('Fault type / non-paged pool status: 0x{0:X16}' -f $p4) })
        }

        # 0x7E: SYSTEM_THREAD_EXCEPTION_NOT_HANDLED
        0x7E {
            $problemFamily = if ($FaultingModule -and $FaultingModule -match '(?i)\.sys$') { 'Driver' } else { 'SystemSoftware' }
            $uP1 = ConvertTo-CrashDoctorUInt32 $p1
            $excHex = ('0x{0:X8}' -f $uP1)
            $excName = Get-CrashDoctorBugCheckName -Code $uP1
            $failureBucket = if ($FaultingModule) { "THREAD_EXCEPTION_$FaultingModule" } else { "THREAD_EXCEPTION_$excName" }
            $summary = "System thread generated an unhandled exception ($excName)."
            $explanation = "A system worker thread encountered an unhandled exception ($excHex - $excName) at instruction 0x{0:X16}." -f $p2
            $recommended = if ($FaultingModule) { "Update or reinstall $FaultingModule." } else { 'Inspect recent driver and system updates.' }

            $pDetails.Add([pscustomobject]@{ Index = 1; RawHex = ('0x{0:X16}' -f $p1); Name = 'Exception Code'; Description = ("Exception code: {0} ({1})" -f $excHex, $excName) })
            $pDetails.Add([pscustomobject]@{ Index = 2; RawHex = ('0x{0:X16}' -f $p2); Name = 'Instruction Address'; Description = ('Address where exception occurred: 0x{0:X16}' -f $p2) })
            $pDetails.Add([pscustomobject]@{ Index = 3; RawHex = ('0x{0:X16}' -f $p3); Name = 'Exception Record'; Description = ('Pointer to EXCEPTION_RECORD: 0x{0:X16}' -f $p3) })
            $pDetails.Add([pscustomobject]@{ Index = 4; RawHex = ('0x{0:X16}' -f $p4); Name = 'Context Record'; Description = ('Pointer to CONTEXT record: 0x{0:X16}' -f $p4) })
        }

        # 0x116: VIDEO_TDR_FAILURE
        0x116 {
            $problemFamily = 'Driver'
            $failureBucket = if ($FaultingModule) { "VIDEO_TDR_FAILURE_$FaultingModule" } else { 'VIDEO_TDR_FAILURE' }
            $summary = "Display driver failed to respond to timeout detection and recovery (TDR)."
            $explanation = "The graphics driver failed to respond to a display scheduler interrupt within the allotted timeout period. Windows attempted a GPU reset (TDR) which failed or was not acknowledged by the display miniport driver."
            $recommended = if ($FaultingModule) { "Clean install or update graphics driver $FaultingModule using DDU or official GPU vendor drivers." } else { 'Update or reinstall the display graphics driver.' }

            $pDetails.Add([pscustomobject]@{ Index = 1; RawHex = ('0x{0:X16}' -f $p1); Name = 'TDR Context'; Description = ('Pointer to TDR recovery context: 0x{0:X16}' -f $p1) })
            $pDetails.Add([pscustomobject]@{ Index = 2; RawHex = ('0x{0:X16}' -f $p2); Name = 'Miniport Device Extension'; Description = ('Pointer to miniport device context: 0x{0:X16}' -f $p2) })
            $pDetails.Add([pscustomobject]@{ Index = 3; RawHex = ('0x{0:X16}' -f $p3); Name = 'Driver Error Code'; Description = ('Driver subsystem error code: 0x{0:X16}' -f $p3) })
            $pDetails.Add([pscustomobject]@{ Index = 4; RawHex = ('0x{0:X16}' -f $p4); Name = 'Internal State / Subcode'; Description = ('Subsystem internal state: 0x{0:X16}' -f $p4) })
        }

        # 0x133: DPC_WATCHDOG_VIOLATION
        0x133 {
            $problemFamily = 'Driver'
            $failureBucket = if ($FaultingModule) { "DPC_WATCHDOG_VIOLATION_$FaultingModule" } else { 'DPC_WATCHDOG_VIOLATION' }
            $subtype = switch ($p1) {
                0 { 'Single DPC routine exceeded execution time limit.' }
                1 { 'Cumulative time spent at DISPATCH_LEVEL exceeded watchdog limit.' }
                default { "DPC watchdog violation subtype $p1" }
            }
            $summary = "Deferred Procedure Call (DPC) watchdog timeout ($subtype)."
            $explanation = "The DPC watchdog detected that an operating system driver spent an excessive duration executing at DISPATCH_LEVEL or a single DPC routine ran too long without yielding CPU."
            $recommended = if ($FaultingModule) { "Update or rollback driver $FaultingModule, or inspect driver trace logs for high DPC latency." } else { 'Update device drivers; inspect DPC/ISR latency with LatencyMon or Windows Performance Analyzer.' }

            $pDetails.Add([pscustomobject]@{ Index = 1; RawHex = ('0x{0:X16}' -f $p1); Name = 'Violation Subtype'; Description = $subtype })
            $pDetails.Add([pscustomobject]@{ Index = 2; RawHex = ('0x{0:X16}' -f $p2); Name = 'DPC Time Limit (Ticks)'; Description = ('Watchdog time limit: 0x{0:X16}' -f $p2) })
            $pDetails.Add([pscustomobject]@{ Index = 3; RawHex = ('0x{0:X16}' -f $p3); Name = 'DPC Time Spent (Ticks)'; Description = ('Time spent in DPC: 0x{0:X16}' -f $p3) })
            $pDetails.Add([pscustomobject]@{ Index = 4; RawHex = ('0x{0:X16}' -f $p4); Name = 'Reserved / Parameter 4'; Description = ('Context pointer or parameter: 0x{0:X16}' -f $p4) })
        }

        # 0x124: WHEA_UNCORRECTABLE_ERROR
        0x124 {
            $problemFamily = 'Hardware'
            $source = switch ($p1) {
                0 { 'Machine Check Exception (MCA)' }
                4 { 'PCI Express Error (PCIe AER)' }
                11 { 'Non-Maskable Interrupt (NMI)' }
                default { "Hardware Error Source ($p1)" }
            }
            $failureBucket = "WHEA_UNCORRECTABLE_ERROR_$($source -replace '\s+', '_')"
            $summary = "Fatal hardware error reported by platform architecture ($source)."
            $explanation = "Windows Hardware Error Architecture (WHEA) captured an uncorrectable hardware fault from processor cores, caches, memory controllers, or PCIe buses. Source: $source."
            $recommended = 'Check CPU temperatures/voltages, update BIOS/UEFI firmware, reseat PCIe devices, and inspect PSU power stability.'

            $pDetails.Add([pscustomobject]@{ Index = 1; RawHex = ('0x{0:X16}' -f $p1); Name = 'Error Source'; Description = $source })
            $pDetails.Add([pscustomobject]@{ Index = 2; RawHex = ('0x{0:X16}' -f $p2); Name = 'Error Record'; Description = ('Pointer to WHEA_ERROR_RECORD: 0x{0:X16}' -f $p2) })
            $pDetails.Add([pscustomobject]@{ Index = 3; RawHex = ('0x{0:X16}' -f $p3); Name = 'MCi_STATUS High'; Description = ('Processor MCi_STATUS high 32 bits: 0x{0:X16}' -f $p3) })
            $pDetails.Add([pscustomobject]@{ Index = 4; RawHex = ('0x{0:X16}' -f $p4); Name = 'MCi_STATUS Low'; Description = ('Processor MCi_STATUS low 32 bits: 0x{0:X16}' -f $p4) })
        }

        # 0xC0000005: STATUS_ACCESS_VIOLATION
        0xC0000005L {
            $problemFamily = 'SystemSoftware'
            $accessType = switch ($p1) { 0 { 'Read' } 1 { 'Write' } 8 { 'Execute (DEP)' } default { "Access($p1)" } }
            $failureBucket = if ($FaultingModule) { "AV_$FaultingModule" } else { "AV_$accessType" }
            $targetHex = ('0x{0:X16}' -f $p2)
            $summary = "Access violation ($accessType violation accessing $targetHex)."
            $explanation = "A thread attempted to perform an invalid $accessType operation on virtual memory address $targetHex without proper memory access permissions or into unallocated address space."
            $recommended = if ($FaultingModule) { "Review $FaultingModule for null pointer dereferences or buffer corruption." } else { 'Inspect application crash logs and faulting modules.' }

            $pDetails.Add([pscustomobject]@{ Index = 1; RawHex = ('0x{0:X16}' -f $p1); Name = 'Access Type'; Description = "$accessType violation (0=Read, 1=Write, 8=Execute/DEP)" })
            $pDetails.Add([pscustomobject]@{ Index = 2; RawHex = ('0x{0:X16}' -f $p2); Name = 'Target Memory Address'; Description = ("Memory address accessed: {0}" -f $targetHex) })
            if ($paramList.Count -ge 3) {
                $pDetails.Add([pscustomobject]@{ Index = 3; RawHex = ('0x{0:X16}' -f $p3); Name = 'Reserved / Instruction'; Description = ('Secondary address / context: 0x{0:X16}' -f $p3) })
            }
            if ($paramList.Count -ge 4) {
                $pDetails.Add([pscustomobject]@{ Index = 4; RawHex = ('0x{0:X16}' -f $p4); Name = 'Reserved'; Description = ('Reserved: 0x{0:X16}' -f $p4) })
            }
        }

        # 0xE0434352: CLR_EXCEPTION
        0xE0434352L {
            $problemFamily = 'SystemSoftware'
            $failureBucket = if ($FaultingModule) { "CLR_EXCEPTION_$FaultingModule" } else { 'CLR_EXCEPTION' }
            $uP1 = ConvertTo-CrashDoctorUInt32 $p1
            $hresultHex = ('0x{0:X8}' -f $uP1)
            $summary = "Unhandled Common Language Runtime (.NET) exception ($hresultHex)."
            $explanation = "A managed .NET application terminated due to an unhandled exception. The runtime raised Win32 exception code 0xE0434352 (ASCII: CCR / CLR) with HRESULT $hresultHex."
            $recommended = 'Inspect Application event logs and .NET Runtime event source for the managed stack trace and inner exception details.'

            $pDetails.Add([pscustomobject]@{ Index = 1; RawHex = ('0x{0:X16}' -f $p1); Name = 'HRESULT / Subcode'; Description = ("Managed exception HRESULT: {0}" -f $hresultHex) })
            $pDetails.Add([pscustomobject]@{ Index = 2; RawHex = ('0x{0:X16}' -f $p2); Name = 'Exception Object'; Description = ('Managed exception object address: 0x{0:X16}' -f $p2) })
            $pDetails.Add([pscustomobject]@{ Index = 3; RawHex = ('0x{0:X16}' -f $p3); Name = 'Reserved'; Description = ('Reserved: 0x{0:X16}' -f $p3) })
            $pDetails.Add([pscustomobject]@{ Index = 4; RawHex = ('0x{0:X16}' -f $p4); Name = 'Reserved'; Description = ('Reserved: 0x{0:X16}' -f $p4) })
        }

        default {
            $problemFamily = if ($FaultingModule -and $FaultingModule -match '(?i)\.sys$') { 'Driver' } elseif ($FaultingModule) { 'SystemSoftware' } else { 'Unknown' }
            $failureBucket = if ($FaultingModule) { "${bugCheckName}_$FaultingModule" } else { $bugCheckName }
            $summary = "$bugCheckName ($bugCheckHex)"
            $explanation = "Bugcheck code $bugCheckHex ($bugCheckName) with parameters: 0x{0:X}, 0x{1:X}, 0x{2:X}, 0x{3:X}." -f $p1, $p2, $p3, $p4
            $recommended = 'Inspect system event logs around the crash timestamp and cross-reference with device driver status.'

            $count = [Math]::Max(4, $paramList.Count)
            for ($i = 0; $i -lt $count; $i++) {
                $v = if ($i -lt $paramList.Count) { ConvertTo-CrashDoctorUInt64 $paramList[$i] } else { [uint64]0 }
                $pDetails.Add([pscustomobject]@{
                    Index       = $i + 1
                    RawHex      = ('0x{0:X16}' -f $v)
                    Name        = "Parameter $($i + 1)"
                    Description = ('Raw parameter value: 0x{0:X16}' -f $v)
                })
            }
        }
    }

    return [pscustomobject][ordered]@{
        FailureBucket     = $failureBucket
        BugCheckCode      = $u
        BugCheckHex       = $bugCheckHex
        BugCheckName      = $bugCheckName
        ProblemFamily     = $problemFamily
        Summary           = $summary
        Explanation       = $explanation
        RecommendedAction = $recommended
        FaultingModule    = $FaultingModule
        ExceptionAddress  = if ($ExceptionAddress) { ('0x{0:X16}' -f [uint64]$ExceptionAddress) } else { $null }
        Parameters        = $pDetails.ToArray()
    }
}

function Read-CrashDoctorHeuristicThreadFrames {
    [CmdletBinding()]
    param(
        [System.IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)] $Thread,
        [object[]]$Modules = @(),
        [string]$Architecture = 'x64',
        $ExceptionContext = $null,
        [int]$MaxFrames = 32
    )

    $ptrSize = if ($Architecture -eq 'x86') { 4 } else { 8 }
    $frames = New-Object System.Collections.Generic.List[object]

    if ($null -eq $Stream -or $null -eq $Thread) { return @() }
    $ctxSize = if ($Thread.PSObject.Properties.Name -contains 'ContextDataSize') { [int]$Thread.ContextDataSize } else { 0 }
    $ctxRva = if ($Thread.PSObject.Properties.Name -contains 'ContextRva') { [int64]$Thread.ContextRva } else { [int64]0 }
    if ($ctxSize -lt 40 -or $ctxRva -lt 0 -or ($ctxRva + $ctxSize) -gt $Stream.Length) {
        return @()
    }

    # Extract thread registers from Context
    $rip = [uint64]0
    $rsp = [uint64]0
    $rbp = [uint64]0

    try {
        $ctxBytes = Read-CrashDoctorBytes -Stream $Stream -Offset $ctxRva -Count $ctxSize
        if ($Architecture -eq 'x86') {
            if ($ctxBytes.Length -ge 0xCC) {
                $rip = [uint64](Get-CrashDoctorUInt32 -Bytes $ctxBytes -Offset 0xB8) # Eip
                $rsp = [uint64](Get-CrashDoctorUInt32 -Bytes $ctxBytes -Offset 0xC4) # Esp
                $rbp = [uint64](Get-CrashDoctorUInt32 -Bytes $ctxBytes -Offset 0xB4) # Ebp
            }
        } else {
            if ($ctxBytes.Length -ge 0x100) {
                $rip = Get-CrashDoctorUInt64 -Bytes $ctxBytes -Offset 0xF8 # Rip
                $rsp = Get-CrashDoctorUInt64 -Bytes $ctxBytes -Offset 0x98 # Rsp
                $rbp = Get-CrashDoctorUInt64 -Bytes $ctxBytes -Offset 0xA0 # Rbp
            }
        }
    } catch { }

    # Helper to find module containing an instruction pointer
    $findModule = {
        param([uint64]$addr)
        foreach ($m in $Modules) {
            $base = [uint64]$m.BaseOfImage
            $size = [uint64]$m.SizeOfImage
            if ($addr -ge $base -and $addr -lt ($base + $size)) {
                $leaf = [System.IO.Path]::GetFileName([string]$m.Name)
                if ([string]::IsNullOrWhiteSpace($leaf)) { $leaf = [string]$m.Name }
                return [pscustomobject]@{
                    ModuleName  = $leaf
                    FullPath    = $m.Name
                    BaseAddress = $base
                    Offset      = ($addr - $base)
                }
            }
        }
        return $null
    }

    # Frame 0: Current Instruction Pointer (RIP/EIP)
    if ($rip -ne 0) {
        $f0Mod = & $findModule $rip
        $f0Name = if ($f0Mod) { $f0Mod.ModuleName } else { 'Unknown' }
        $f0OffsetHex = if ($f0Mod) { ('0x{0:X}' -f $f0Mod.Offset) } else { $null }
        $f0Symbol = if ($f0Mod) { "{0}+{1}" -f $f0Name, $f0OffsetHex } else { ('0x{0:X16}' -f $rip) }

        $frames.Add([pscustomobject][ordered]@{
            FrameNumber        = 0
            InstructionPointer = ('0x{0:X16}' -f $rip)
            StackPointer       = ('0x{0:X16}' -f $rsp)
            FramePointer       = ('0x{0:X16}' -f $rbp)
            ModuleName         = $f0Name
            Offset             = $f0OffsetHex
            Symbol             = $f0Symbol
            ReturnAddress      = $null
        })
    }

    # Walk subsequent frames through stack memory
    $stackRva = if ($Thread.PSObject.Properties.Name -contains 'StackRva') { [int64]$Thread.StackRva } else { [int64]0 }
    $stackSize = if ($Thread.PSObject.Properties.Name -contains 'StackDataSize') { [int]$Thread.StackDataSize } else { 0 }
    $stackBase = if ($Thread.PSObject.Properties.Name -contains 'StackMemoryBase') { [uint64]$Thread.StackMemoryBase } else { [uint64]0 }

    if ($stackRva -gt 0 -and $stackSize -ge $ptrSize -and ($stackRva + $stackSize) -le $Stream.Length) {
        try {
            $stackBytes = Read-CrashDoctorBytes -Stream $Stream -Offset $stackRva -Count $stackSize
            $startPos = if ($rsp -ge $stackBase -and ($rsp - $stackBase) -lt [uint64]$stackSize) {
                [int]($rsp - $stackBase)
            } else {
                0
            }

            $frameIndex = $frames.Count
            $lastHitAddr = [uint64]0
            $maxOffset = $stackSize - $ptrSize

            for ($pos = $startPos; $pos -le $maxOffset; $pos += $ptrSize) {
                $val = if ($ptrSize -eq 8) {
                    Get-CrashDoctorUInt64 -Bytes $stackBytes -Offset $pos
                } else {
                    [uint64](Get-CrashDoctorUInt32 -Bytes $stackBytes -Offset $pos)
                }

                if ($val -eq 0 -or $val -eq $lastHitAddr -or $val -eq $rip) { continue }

                $hit = & $findModule $val
                if ($hit -and $hit.Offset -gt 0x10) {
                    $modName = $hit.ModuleName
                    $offsetHex = ('0x{0:X}' -f $hit.Offset)
                    $symbolStr = "{0}+{1}" -f $modName, $offsetHex
                    $curSp = $stackBase + [uint64]$pos

                    $frames.Add([pscustomobject][ordered]@{
                        FrameNumber        = $frameIndex
                        InstructionPointer = ('0x{0:X16}' -f $val)
                        StackPointer       = ('0x{0:X16}' -f $curSp)
                        FramePointer       = $null
                        ModuleName         = $modName
                        Offset             = $offsetHex
                        Symbol             = $symbolStr
                        ReturnAddress      = ('0x{0:X16}' -f $val)
                    })

                    $lastHitAddr = $val
                    $frameIndex++
                    if ($frameIndex -ge $MaxFrames) { break }
                }
            }
        } catch { }
    }

    return $frames.ToArray()
}

function Get-CrashDoctorHeuristicThreadStacks {
    [CmdletBinding()]
    param(
        [System.IO.FileStream]$Stream,
        [object[]]$Threads,
        [object[]]$Modules,
        [uint32]$FaultingThreadId = 0,
        [string]$Architecture = 'x64',
        $ExceptionContext = $null,
        [int]$MaxThreads = 64
    )

    $threadList = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Threads) {
        foreach ($t in $Threads) {
            if ($null -ne $t -and $t -is [System.Management.Automation.PSObject] -and ($t.PSObject.Properties.Name -contains 'ThreadId')) {
                $threadList.Add($t)
            }
        }
    }
    if ($threadList.Count -eq 0) { return @() }

    $callStacks = New-Object System.Collections.Generic.List[object]
    $maxCount = [Math]::Min($threadList.Count, $MaxThreads)
    for ($i = 0; $i -lt $maxCount; $i++) {
        $t = $threadList[$i]
        $isFaulting = ($FaultingThreadId -ne 0 -and $t.ThreadId -eq $FaultingThreadId)
        $frames = @(Read-CrashDoctorHeuristicThreadFrames -Stream $Stream -Thread $t -Modules $Modules -Architecture $Architecture -ExceptionContext $(if ($isFaulting) { $ExceptionContext } else { $null }))

        $topSymbol = if ($frames.Count -gt 0) { $frames[0].Symbol } else { 'NoFrames' }
        $hasThirdParty = $false
        foreach ($f in $frames) {
            if ($f.ModuleName -and $f.ModuleName -match '(?i)\.sys$' -and $f.ModuleName -notmatch '(?i)^(ntoskrnl|hal|fltmgr|ntfs|ndis|tcpip|ci|win32k)\.sys$') {
                $hasThirdParty = $true
                break
            }
        }

        $rank = if ($isFaulting) { 1 } elseif ($hasThirdParty) { 2 } else { 3 }
        $tag = switch ($rank) {
            1 { 'FAULTING_THREAD' }
            2 { 'ACTIVE_WORKER' }
            3 { 'IDLE_THREAD' }
        }

        $callStacks.Add([pscustomobject][ordered]@{
            ThreadId         = $t.ThreadId
            IsFaultingThread = $isFaulting
            Rank             = $rank
            Tag              = $tag
            FrameCount       = $frames.Count
            TopFrame         = $topSymbol
            Frames           = $frames
        })
    }

    # Sort so faulting thread is first, then active workers, then idle
    $sorted = @($callStacks | Sort-Object { $_.Rank })
    return $sorted
}

function Read-CrashDoctorMiniDump {
    param([System.IO.FileStream]$Stream, [string]$ResolvedPath)

    $header = Read-CrashDoctorBytes -Stream $Stream -Offset 0 -Count 32
    $streamCount = [int](Get-CrashDoctorUInt32 -Bytes $header -Offset 8)
    $directoryRva = Get-CrashDoctorUInt32 -Bytes $header -Offset 12
    if ($streamCount -gt 4096) { throw "Unreasonable MINIDUMP stream count: $streamCount" }
    $directoryBytes = [int64]$streamCount * 12
    if (($directoryRva + $directoryBytes) -gt $Stream.Length) { throw 'MINIDUMP stream directory extends beyond the file.' }

    $directories = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $streamCount; $i++) {
        $bytes = Read-CrashDoctorBytes -Stream $Stream -Offset ([int64]$directoryRva + ($i * 12)) -Count 12
        $streamType = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 0
        $dataSize = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 4
        $rva = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 8
        if (($rva + [int64]$dataSize) -gt $Stream.Length) { throw "MINIDUMP stream $streamType extends beyond the file." }
        $directories.Add([pscustomobject][ordered]@{
            StreamType = $streamType
            Name = Get-CrashDoctorMiniDumpStreamName -StreamType $streamType
            DataSize = $dataSize
            Rva = $rva
        })
    }

    $byType = @{}
    foreach ($directory in $directories) {
        if (-not $byType.ContainsKey([int]$directory.StreamType)) { $byType[[int]$directory.StreamType] = $directory }
    }

    $systemInfo = if ($byType.ContainsKey(7)) { Read-CrashDoctorMiniDumpSystemInfo -Stream $Stream -Directory $byType[7] } else { $null }
    $exception = if ($byType.ContainsKey(6)) { Read-CrashDoctorMiniDumpException -Stream $Stream -Directory $byType[6] } else { $null }
    $modules = if ($byType.ContainsKey(4)) { @(Read-CrashDoctorMiniDumpModules -Stream $Stream -Directory $byType[4]) } else { @() }
    $threads = if ($byType.ContainsKey(3)) { @(Read-CrashDoctorMiniDumpThreads -Stream $Stream -Directory $byType[3]) } else { @() }
    $threadCount = if ($null -ne $threads -and @($threads).Count -gt 0) { @($threads).Count } elseif ($byType.ContainsKey(3)) { Read-CrashDoctorMiniDumpCountStream -Stream $Stream -Directory $byType[3] } else { $null }
    $memoryRangeCount = if ($byType.ContainsKey(5)) { Read-CrashDoctorMiniDumpCountStream -Stream $Stream -Directory $byType[5] } else { $null }
    $memory64 = if ($byType.ContainsKey(9)) { Read-CrashDoctorMiniDumpMemory64Summary -Stream $Stream -Directory $byType[9] } else { $null }
    $memoryInfo = if ($byType.ContainsKey(16)) { Read-CrashDoctorMiniDumpMemoryInfoSummary -Stream $Stream -Directory $byType[16] } else { $null }

    $faultingThreadId = if ($exception) { [uint32]$exception.ThreadId } else { [uint32]0 }
    $dumpArch = if ($systemInfo) { $systemInfo.ProcessorArchitecture } else { 'x64' }
    $stackDrivers = Get-CrashDoctorStackCandidateDrivers -Stream $Stream -Threads $threads -Modules $modules -FaultingThreadId $faultingThreadId -Architecture $dumpArch
    $faultingModule = Find-CrashDoctorFaultingModule -DumpInfo ([pscustomobject]@{ Exception = $exception; Modules = $modules })
    $exceptionCode = if ($exception) { [uint32]$exception.ExceptionCode } else { [uint32]0 }
    $exceptionParams = if ($exception -and $exception.Parameters) { @($exception.Parameters) } else { @() }
    $problemClassification = Get-CrashDoctorProblemClassification -BugCheckCode $exceptionCode -Parameters $exceptionParams -FaultingModule $faultingModule -CandidateDrivers $stackDrivers

    $exceptionAddress = if ($exception) { $exception.ExceptionAddress } else { $null }
    $bugCheckAnalysis = Get-CrashDoctorBugCheckAnalysis -BugCheckCode $exceptionCode -Parameters $exceptionParams -FaultingModule $faultingModule -ExceptionAddress $exceptionAddress -Architecture $dumpArch

    # Heuristic raw-stack candidates are useful evidence, but they are not true unwound call stacks.
    $heuristicThreadStacks = @(Get-CrashDoctorHeuristicThreadStacks -Stream $Stream -Threads $threads -Modules $modules -FaultingThreadId $faultingThreadId -Architecture $dumpArch)
    $callStacks = @()
    $faultingCallStack = $null

    return [pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        Path = $ResolvedPath
        FileSize = $Stream.Length
        Format = 'MiniDump'
        Architecture = if ($systemInfo) { $systemInfo.ProcessorArchitecture } else { $null }
        Header = [pscustomobject][ordered]@{
            Signature = 'MDMP'
            Version = Get-CrashDoctorUInt32 -Bytes $header -Offset 4
            NumberOfStreams = $streamCount
            StreamDirectoryRva = $directoryRva
            Checksum = Get-CrashDoctorUInt32 -Bytes $header -Offset 16
            TimeDateStamp = Get-CrashDoctorUInt32 -Bytes $header -Offset 20
            Flags = Get-CrashDoctorUInt64 -Bytes $header -Offset 24
        }
        SystemInfo = $systemInfo
        Exception = $exception
        FaultingModule = $faultingModule
        BugCheckAnalysis = $bugCheckAnalysis
        FaultingCallStack = $faultingCallStack
        CallStacks = @($callStacks)
        HeuristicThreadStacks = @($heuristicThreadStacks)
        CallStackMethod = 'None'
        TrueUnwindAvailable = $false
        DebuggerAnalysis = $null
        ModuleCount = @($modules).Count
        Modules = @($modules)
        ThreadCount = $threadCount
        StackDrivers = @($stackDrivers)
        ProblemClassification = $problemClassification
        MemoryRangeCount = $memoryRangeCount
        Memory64 = $memory64
        MemoryInfo = $memoryInfo
        Streams = $directories.ToArray()
        ParseCoverage = 'Header, stream directory, system info, exception, bugcheck analysis, modules, heuristic thread-stack candidates, thread stack drivers and memory summaries'
    }
}

function Get-CrashDoctorKernelDumpTypeName {
    param([uint32]$DumpType)
    switch ($DumpType) {
        0 { 'Unknown' }
        1 { 'Full' }
        2 { 'Summary' }
        3 { 'Header' }
        4 { 'Triage' }
        5 { 'BitmapFull' }
        6 { 'BitmapKernel' }
        7 { 'Automatic' }
        default { "DumpType$DumpType" }
    }
}

function Read-CrashDoctorKernelDump64 {
    param([System.IO.FileStream]$Stream, [string]$ResolvedPath)
    if ($Stream.Length -lt 8192) { throw '64-bit kernel dump is smaller than the 8192-byte DUMP_HEADER64.' }
    $header = Read-CrashDoctorBytes -Stream $Stream -Offset 0 -Count 8192
    $dumpType = Get-CrashDoctorUInt32 -Bytes $header -Offset 3992
    $bugCheckCode = Get-CrashDoctorUInt32 -Bytes $header -Offset 56
    $p1 = Get-CrashDoctorUInt64 -Bytes $header -Offset 64
    $p2 = Get-CrashDoctorUInt64 -Bytes $header -Offset 72
    $p3 = Get-CrashDoctorUInt64 -Bytes $header -Offset 80
    $p4 = Get-CrashDoctorUInt64 -Bytes $header -Offset 88
    $params = @($p1, $p2, $p3, $p4)
    $arch = Get-CrashDoctorMachineName -MachineType (Get-CrashDoctorUInt32 -Bytes $header -Offset 48)
    $classification = Get-CrashDoctorProblemClassification -BugCheckCode $bugCheckCode -Parameters $params
    $bugCheckAnalysis = Get-CrashDoctorBugCheckAnalysis -BugCheckCode $bugCheckCode -Parameters $params -Architecture $arch

    return [pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        Path = $ResolvedPath
        FileSize = $Stream.Length
        Format = 'KernelCrashDump'
        Architecture = $arch
        ProblemClassification = $classification
        BugCheckAnalysis = $bugCheckAnalysis
        FaultingCallStack = $null
        CallStacks = @()
        StackDrivers = @()
        Header = [pscustomobject][ordered]@{
            Signature = 'PAGE'
            ValidDump = 'DU64'
            MajorVersion = Get-CrashDoctorUInt32 -Bytes $header -Offset 8
            MinorVersion = Get-CrashDoctorUInt32 -Bytes $header -Offset 12
            DirectoryTableBase = Get-CrashDoctorUInt64 -Bytes $header -Offset 16
            PfnDataBase = Get-CrashDoctorUInt64 -Bytes $header -Offset 24
            PsLoadedModuleList = Get-CrashDoctorUInt64 -Bytes $header -Offset 32
            PsActiveProcessHead = Get-CrashDoctorUInt64 -Bytes $header -Offset 40
            MachineImageType = Get-CrashDoctorUInt32 -Bytes $header -Offset 48
            NumberProcessors = Get-CrashDoctorUInt32 -Bytes $header -Offset 52
            BugCheckCode = $bugCheckCode
            BugCheckParameter1 = $p1
            BugCheckParameter2 = $p2
            BugCheckParameter3 = $p3
            BugCheckParameter4 = $p4
            KdDebuggerDataBlock = Get-CrashDoctorUInt64 -Bytes $header -Offset 128
            DumpType = $dumpType
            DumpTypeName = Get-CrashDoctorKernelDumpTypeName -DumpType $dumpType
            RequiredDumpSpace = Get-CrashDoctorInt64 -Bytes $header -Offset 4000
            SystemTimeFileTime = Get-CrashDoctorInt64 -Bytes $header -Offset 4008
            SystemUpTime100ns = Get-CrashDoctorInt64 -Bytes $header -Offset 4144
            MiniDumpFields = Get-CrashDoctorUInt32 -Bytes $header -Offset 4152
            SecondaryDataState = Get-CrashDoctorUInt32 -Bytes $header -Offset 4156
            ProductType = Get-CrashDoctorUInt32 -Bytes $header -Offset 4160
            SuiteMask = Get-CrashDoctorUInt32 -Bytes $header -Offset 4164
            WriterStatus = Get-CrashDoctorUInt32 -Bytes $header -Offset 4168
        }
        ParseCoverage = 'DUMP_HEADER64 metadata and bugcheck analysis; physical memory pages are not yet traversed'
    }
}

function Read-CrashDoctorKernelDump32 {
    param([System.IO.FileStream]$Stream, [string]$ResolvedPath)
    if ($Stream.Length -lt 4096) { throw '32-bit kernel dump is smaller than a crash-dump header page.' }
    $header = Read-CrashDoctorBytes -Stream $Stream -Offset 0 -Count ([Math]::Min(4096, [int]$Stream.Length))
    $bugCheckCode = Get-CrashDoctorUInt32 -Bytes $header -Offset 40
    $p1 = Get-CrashDoctorUInt32 -Bytes $header -Offset 44
    $p2 = Get-CrashDoctorUInt32 -Bytes $header -Offset 48
    $p3 = Get-CrashDoctorUInt32 -Bytes $header -Offset 52
    $p4 = Get-CrashDoctorUInt32 -Bytes $header -Offset 56
    $params = @($p1, $p2, $p3, $p4)
    $arch = Get-CrashDoctorMachineName -MachineType (Get-CrashDoctorUInt32 -Bytes $header -Offset 32)
    $classification = Get-CrashDoctorProblemClassification -BugCheckCode $bugCheckCode -Parameters $params
    $bugCheckAnalysis = Get-CrashDoctorBugCheckAnalysis -BugCheckCode $bugCheckCode -Parameters $params -Architecture $arch

    return [pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        Path = $ResolvedPath
        FileSize = $Stream.Length
        Format = 'KernelCrashDump'
        Architecture = $arch
        ProblemClassification = $classification
        BugCheckAnalysis = $bugCheckAnalysis
        FaultingCallStack = $null
        CallStacks = @()
        StackDrivers = @()
        Header = [pscustomobject][ordered]@{
            Signature = 'PAGE'
            ValidDump = 'DUMP'
            MajorVersion = Get-CrashDoctorUInt32 -Bytes $header -Offset 8
            MinorVersion = Get-CrashDoctorUInt32 -Bytes $header -Offset 12
            DirectoryTableBase = Get-CrashDoctorUInt32 -Bytes $header -Offset 16
            PfnDataBase = Get-CrashDoctorUInt32 -Bytes $header -Offset 20
            PsLoadedModuleList = Get-CrashDoctorUInt32 -Bytes $header -Offset 24
            PsActiveProcessHead = Get-CrashDoctorUInt32 -Bytes $header -Offset 28
            MachineImageType = Get-CrashDoctorUInt32 -Bytes $header -Offset 32
            NumberProcessors = Get-CrashDoctorUInt32 -Bytes $header -Offset 36
            BugCheckCode = $bugCheckCode
            BugCheckParameter1 = $p1
            BugCheckParameter2 = $p2
            BugCheckParameter3 = $p3
            BugCheckParameter4 = $p4
        }
        ParseCoverage = 'DUMP_HEADER32 core metadata and bugcheck analysis; physical memory pages are not yet traversed'
    }
}

function Get-CrashDoctorDumpInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [switch]$UseDebugger,
        [string]$SymbolCachePath,
        [int]$DebuggerTimeoutSeconds = 180
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Dump file does not exist: $Path"
    }

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $stream = [System.IO.File]::Open(
        $resolved,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    )
    try {
        if ($stream.Length -lt 8) { throw 'Dump file is too small to identify.' }
        $prefix = Read-CrashDoctorBytes -Stream $stream -Offset 0 -Count 8
        $signature = Get-CrashDoctorUInt32 -Bytes $prefix -Offset 0
        $validDump = Get-CrashDoctorUInt32 -Bytes $prefix -Offset 4

        if ($signature -eq $script:MiniDumpSignature) {
            $report = Read-CrashDoctorMiniDump -Stream $stream -ResolvedPath $resolved
        }
        elseif ($signature -eq $script:KernelDumpSignature -and $validDump -eq $script:KernelDumpValid64) {
            $report = Read-CrashDoctorKernelDump64 -Stream $stream -ResolvedPath $resolved
        }
        elseif ($signature -eq $script:KernelDumpSignature -and $validDump -eq $script:KernelDumpValid32) {
            $report = Read-CrashDoctorKernelDump32 -Stream $stream -ResolvedPath $resolved
        }
        else {
            $ascii = [Text.Encoding]::ASCII.GetString($prefix)
            throw "Unsupported or unrecognized dump format. First 8 bytes: '$ascii'."
        }
    }
    finally {
        $stream.Dispose()
    }

    if ($UseDebugger) {
        if (-not (Get-Command Invoke-CrashDoctorDebuggerAnalysis -ErrorAction SilentlyContinue)) {
            throw 'Debugger analysis was requested but DebuggerBackend.psm1 is unavailable.'
        }

        $debugger = Invoke-CrashDoctorDebuggerAnalysis -DumpPath $resolved -SymbolCachePath $SymbolCachePath -TimeoutSeconds $DebuggerTimeoutSeconds
        $report.DebuggerAnalysis = $debugger
        if ($debugger.Success -and $debugger.IsTrueUnwind) {
            $report.CallStacks = @($debugger.CallStacks)
            $report.CallStackMethod = 'Cdb/DbgEng'
            $report.TrueUnwindAvailable = $true
            $faulting = @($debugger.CallStacks | Where-Object { $_.IsFaultingThread } | Select-Object -First 1)
            if ($faulting.Count -eq 0 -and $debugger.CallStacks.Count -gt 0) {
                $faulting = @($debugger.CallStacks[0])
            }
            $report.FaultingCallStack = if ($faulting.Count -gt 0) { $faulting[0] } else { $null }

            if ($report.PSObject.Properties.Name -contains 'BugCheckAnalysis' -and $report.BugCheckAnalysis -and $debugger.FailureBucket) {
                $report.BugCheckAnalysis.FailureBucket = $debugger.FailureBucket
            }
        }
    }

    return $report
}

function Get-CrashDoctorSystemCrashHistory {
    [CmdletBinding()]
    param(
        [string[]]$SearchPaths,
        [int]$MaxEntries = 50
    )

    if ($null -eq $SearchPaths -or $SearchPaths.Count -eq 0) {
        $SearchPaths = @(
            (Join-Path $env:SystemRoot 'Minidump'),
            (Join-Path $env:SystemRoot 'MEMORY.DMP'),
            (Join-Path $env:SystemDrive 'CrashDumps'),
            (Join-Path $env:LOCALAPPDATA 'CrashDumps'),
            (Join-Path $env:SystemRoot 'LiveKernelReports')
        )
    }

    $dumpFiles = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    foreach ($target in $SearchPaths) {
        if ([string]::IsNullOrWhiteSpace($target)) { continue }
        if (Test-Path -LiteralPath $target -PathType Leaf) {
            $item = Get-Item -LiteralPath $target -ErrorAction SilentlyContinue
            if ($item -and $item.Extension -match '(?i)^\.(dmp|mdmp)$') {
                $dumpFiles.Add($item)
            }
        }
        elseif (Test-Path -LiteralPath $target -PathType Container) {
            $files = @(Get-ChildItem -LiteralPath $target -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match '(?i)^\.(dmp|mdmp)$' })
            foreach ($f in $files) { $dumpFiles.Add($f) }
        }
    }

    $crashes = New-Object System.Collections.Generic.List[object]
    $seenPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($file in $dumpFiles) {
        if (-not $seenPaths.Add($file.FullName)) { continue }

        try {
            $info = Get-CrashDoctorDumpInfo -Path $file.FullName
            $crashTime = $file.LastWriteTimeUtc
            $hasHeader = ($info.PSObject.Properties.Name -contains 'Header') -and ($null -ne $info.Header)
            $hasException = ($info.PSObject.Properties.Name -contains 'Exception') -and ($null -ne $info.Exception)

            if ($info.Format -eq 'MiniDump' -and $hasHeader -and ($info.Header.PSObject.Properties.Name -contains 'TimeDateStamp') -and $info.Header.TimeDateStamp -and $info.Header.TimeDateStamp -gt 0) {
                try {
                    $crashTime = [DateTimeOffset]::FromUnixTimeSeconds([int64]$info.Header.TimeDateStamp).UtcDateTime
                } catch { }
            }

            $bugCheckCode = [uint32]0
            $params = @()
            if ($info.Format -eq 'KernelCrashDump' -and $hasHeader) {
                $bugCheckCode = [uint32]$info.Header.BugCheckCode
                $params = @(
                    [uint64]$info.Header.BugCheckParameter1,
                    [uint64]$info.Header.BugCheckParameter2,
                    [uint64]$info.Header.BugCheckParameter3,
                    [uint64]$info.Header.BugCheckParameter4
                )
            }
            elseif ($info.Format -eq 'MiniDump' -and $hasException) {
                $bugCheckCode = [uint32]$info.Exception.ExceptionCode
                if (($info.Exception.PSObject.Properties.Name -contains 'Parameters') -and $info.Exception.Parameters) {
                    $params = @($info.Exception.Parameters)
                }
            }

            $bugCheckName = Get-CrashDoctorBugCheckName -Code $bugCheckCode
            $faultingModule = Find-CrashDoctorFaultingModule -DumpInfo $info
            $exceptionAddressHex = if ($hasException -and ($info.Exception.PSObject.Properties.Name -contains 'ExceptionAddress') -and $info.Exception.ExceptionAddress) {
                '0x{0:X16}' -f [uint64]$info.Exception.ExceptionAddress
            } else { $null }

            $stackDrivers = if ($info.PSObject.Properties.Name -contains 'StackDrivers') { @($info.StackDrivers) } else { @() }
            $classification = if ($info.PSObject.Properties.Name -contains 'ProblemClassification' -and $info.ProblemClassification) {
                $info.ProblemClassification
            } else {
                Get-CrashDoctorProblemClassification -BugCheckCode $bugCheckCode -Parameters $params -FaultingModule $faultingModule -CandidateDrivers $stackDrivers
            }

            $bugCheckAnalysis = if ($info.PSObject.Properties.Name -contains 'BugCheckAnalysis' -and $info.BugCheckAnalysis) {
                $info.BugCheckAnalysis
            } else {
                Get-CrashDoctorBugCheckAnalysis -BugCheckCode $bugCheckCode -Parameters $params -FaultingModule $faultingModule -ExceptionAddress $exceptionAddressHex -Architecture $info.Architecture
            }
            $faultingCallStack = if ($info.PSObject.Properties.Name -contains 'FaultingCallStack') { $info.FaultingCallStack } else { $null }
            $callStacks = if ($info.PSObject.Properties.Name -contains 'CallStacks') { @($info.CallStacks) } else { @() }

            $crashes.Add([pscustomobject][ordered]@{
                Path                  = $file.FullName
                FileName              = $file.Name
                FileSize              = $file.Length
                CrashTimeUtc          = $crashTime.ToString('o')
                CrashTimeLocal        = $crashTime.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
                Format                = $info.Format
                Architecture          = $info.Architecture
                BugCheckCode          = ('0x{0:X8}' -f $bugCheckCode)
                BugCheckName          = $bugCheckName
                BugCheckParameters    = @($params | ForEach-Object { '0x{0:X}' -f [uint64]$_ })
                FaultingModule        = $faultingModule
                ExceptionAddress      = $exceptionAddressHex
                ProblemClassification = $classification
                BugCheckAnalysis      = $bugCheckAnalysis
                FaultingCallStack     = $faultingCallStack
                CallStacks            = $callStacks
                StackDrivers          = @($stackDrivers)
                Valid                 = $true
                Error                 = $null
            })
        }
        catch {
            $crashes.Add([pscustomobject][ordered]@{
                Path                  = $file.FullName
                FileName              = $file.Name
                FileSize              = $file.Length
                CrashTimeUtc          = $file.LastWriteTimeUtc.ToString('o')
                CrashTimeLocal        = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                Format                = 'Unknown'
                Architecture          = $null
                BugCheckCode          = $null
                BugCheckName          = $null
                BugCheckParameters    = @()
                FaultingModule        = $null
                ExceptionAddress      = $null
                ProblemClassification = $null
                BugCheckAnalysis      = $null
                FaultingCallStack     = $null
                CallStacks            = @()
                StackDrivers          = @()
                Valid                 = $false
                Error                 = $_.Exception.Message
            })
        }
    }

    $sorted = @($crashes | Sort-Object { [datetime]$_.CrashTimeUtc } -Descending)
    if ($sorted.Count -gt $MaxEntries) {
        $sorted = $sorted[0..($MaxEntries - 1)]
    }
    return $sorted
}

function ConvertTo-CrashDoctorCrashHistoryMarkdown {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Crashes)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# Windows Doctor historical crash summary')
    $lines.Add('')

    $crashList = @($Crashes)
    if ($crashList.Count -eq 0) {
        $lines.Add('No crash dumps or minidumps were discovered in standard crash locations (`C:\Windows\Minidump`, `C:\Windows\MEMORY.DMP`, etc.).')
        $lines.Add('')
        $lines.Add('> A lack of dump files is reassuring but does not guarantee zero crashes if crash dump capture was disabled or failing.')
        return ($lines -join [Environment]::NewLine)
    }

    $lines.Add("- Discovered crash dumps: **$($crashList.Count)**")
    $validCount = @($crashList | Where-Object { $_.Valid }).Count
    $lines.Add("- Valid parsed dumps: **$validCount**")
    $latest = $crashList[0]
    $lines.Add("- Most recent crash: **$($latest.CrashTimeLocal)** ($($latest.BugCheckName))")
    if ($latest.ProblemClassification) {
        $lines.Add("- Probable cause family: **$($latest.ProblemClassification.Family)** (Confidence: $($latest.ProblemClassification.Confidence))")
    }
    $lines.Add('')

    $lines.Add('## Crash index')
    $lines.Add('')
    $lines.Add('| Date / Time (Local) | BugCheck Code | BugCheck Name | Problem Family | Faulting Module | Dump File | Size |')
    $lines.Add('|---|---|---|---|---|---|---:|')
    foreach ($c in $crashList) {
        $name = if ($c.BugCheckName) { $c.BugCheckName.Replace('|', '\|') } else { 'Unknown' }
        $code = if ($c.BugCheckCode) { '`{0}`' -f $c.BugCheckCode } else { '—' }
        $mod = if ($c.FaultingModule) { '`{0}`' -f $c.FaultingModule } else { '—' }
        $fam = if ($c.ProblemClassification) { "$($c.ProblemClassification.Family)" } else { '—' }
        $sizeKb = [math]::Round($c.FileSize / 1024, 0)
        $lines.Add("| $($c.CrashTimeLocal) | $code | $name | $fam | $mod | $($c.FileName) | $sizeKb KB |")
    }

    $lines.Add('')
    $lines.Add('## Detailed crash records')
    $lines.Add('')
    foreach ($c in $crashList) {
        $lines.Add("### $($c.FileName) - $($c.CrashTimeLocal)")
        $lines.Add('')
        $lines.Add(('- **Path:** `{0}`' -f $c.Path))
        $lines.Add("- **Format / Architecture:** $($c.Format) / $($c.Architecture)")
        $lines.Add(('- **BugCheck:** {0} (`{1}`)' -f $c.BugCheckName, $c.BugCheckCode))
        if ($c.BugCheckParameters -and $c.BugCheckParameters.Count -gt 0) {
            $lines.Add("- **Parameters:** $($c.BugCheckParameters -join ', ')")
        }
        if ($c.BugCheckAnalysis) {
            $bca = $c.BugCheckAnalysis
            if ($bca.FailureBucket) {
                $lines.Add(('- **Failure bucket ID:** `{0}`' -f $bca.FailureBucket))
            }
            if ($bca.Summary) {
                $lines.Add("- **Analysis summary:** $($bca.Summary)")
            }
            if ($bca.Explanation) {
                $lines.Add("- **Technical explanation:** $($bca.Explanation)")
            }
            if ($bca.Parameters -and $bca.Parameters.Count -gt 0) {
                $lines.Add('')
                $lines.Add('  | Parameter | Value | Meaning |')
                $lines.Add('  |---|---|---|')
                foreach ($p in $bca.Parameters) {
                    $lines.Add(("  | P{0} ({1}) | `{2}` | {3} |" -f $p.Index, $p.Name, $p.RawHex, $p.Description))
                }
                $lines.Add('')
            }
        }
        if ($c.ProblemClassification) {
            $lines.Add("- **Problem family:** $($c.ProblemClassification.Family) (Confidence: $($c.ProblemClassification.Confidence))")
            $lines.Add("- **Recommended next step:** $($c.ProblemClassification.RecommendedAction)")
        }
        if ($c.FaultingModule) {
            $lines.Add(('- **Candidate faulting module:** `{0}`' -f $c.FaultingModule))
        }
        if ($c.FaultingCallStack -and $c.FaultingCallStack.Frames -and $c.FaultingCallStack.Frames.Count -gt 0) {
            $lines.Add('')
            $lines.Add('- **Faulting call stack (unwound activation frames):**')
            $lines.Add('')
            $lines.Add('  | # | Module | Symbol / Offset | Return Address |')
            $lines.Add('  |---|---|---|---|')
            foreach ($fr in $c.FaultingCallStack.Frames) {
                $ret = if ($fr.ReturnAddress) { ('`{0}`' -f $fr.ReturnAddress) } else { '—' }
                $lines.Add(("  | {0} | `{1}` | `{2}` | {3} |" -f $fr.FrameNumber, $fr.ModuleName, $fr.Symbol, $ret))
            }
            $lines.Add('')
        }
        if ($c.StackDrivers -and $c.StackDrivers.Count -gt 0) {
            $driverNames = ($c.StackDrivers | Select-Object -ExpandProperty Name -Unique) -join ', '
            $lines.Add("- **Candidate stack-involved drivers (raw memory scan):** $driverNames")
        }
        if ($c.ExceptionAddress) {
            $lines.Add(('- **Exception address:** `{0}`' -f $c.ExceptionAddress))
        }
        if (-not $c.Valid -and $c.Error) {
            $lines.Add("- **Parse error:** $($c.Error)")
        }
        $lines.Add('')
    }

    $lines.Add('> Note: Candidate stack-involved drivers reflect raw stack memory references and are kept separate from true unwound call stacks.')
    return ($lines -join [Environment]::NewLine)
}

Export-ModuleMember -Function Get-CrashDoctorDumpInfo, Get-CrashDoctorSystemCrashHistory, Get-CrashDoctorBugCheckName, ConvertTo-CrashDoctorCrashHistoryMarkdown, Find-CrashDoctorFaultingModule, Get-CrashDoctorProblemClassification, Get-CrashDoctorStackCandidateDrivers, Read-CrashDoctorMiniDumpThreads, Get-CrashDoctorBugCheckAnalysis, Read-CrashDoctorHeuristicThreadFrames, Get-CrashDoctorHeuristicThreadStacks, Get-CrashDoctorSymbolConfig, Set-CrashDoctorSymbolConfig, Get-CrashDoctorModulePdbInfo, Find-CrashDoctorSymbol, ConvertTo-CrashDoctorUInt32