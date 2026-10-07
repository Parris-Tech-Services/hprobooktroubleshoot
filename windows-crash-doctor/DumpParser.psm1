Set-StrictMode -Version Latest

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
        $modules.Add([pscustomobject][ordered]@{
            BaseOfImage = Get-CrashDoctorUInt64 -Bytes $bytes -Offset 0
            SizeOfImage = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 8
            Checksum = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 12
            TimeDateStamp = Get-CrashDoctorUInt32 -Bytes $bytes -Offset 16
            Name = $name
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
    $threadCount = if ($byType.ContainsKey(3)) { Read-CrashDoctorMiniDumpCountStream -Stream $Stream -Directory $byType[3] } else { $null }
    $memoryRangeCount = if ($byType.ContainsKey(5)) { Read-CrashDoctorMiniDumpCountStream -Stream $Stream -Directory $byType[5] } else { $null }
    $memory64 = if ($byType.ContainsKey(9)) { Read-CrashDoctorMiniDumpMemory64Summary -Stream $Stream -Directory $byType[9] } else { $null }
    $memoryInfo = if ($byType.ContainsKey(16)) { Read-CrashDoctorMiniDumpMemoryInfoSummary -Stream $Stream -Directory $byType[16] } else { $null }

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
        ModuleCount = @($modules).Count
        Modules = @($modules)
        ThreadCount = $threadCount
        MemoryRangeCount = $memoryRangeCount
        Memory64 = $memory64
        MemoryInfo = $memoryInfo
        Streams = $directories.ToArray()
        ParseCoverage = 'Header, stream directory, system info, exception, modules, thread count and memory summaries'
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
    return [pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        Path = $ResolvedPath
        FileSize = $Stream.Length
        Format = 'KernelCrashDump'
        Architecture = Get-CrashDoctorMachineName -MachineType (Get-CrashDoctorUInt32 -Bytes $header -Offset 48)
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
            BugCheckCode = Get-CrashDoctorUInt32 -Bytes $header -Offset 56
            BugCheckParameter1 = Get-CrashDoctorUInt64 -Bytes $header -Offset 64
            BugCheckParameter2 = Get-CrashDoctorUInt64 -Bytes $header -Offset 72
            BugCheckParameter3 = Get-CrashDoctorUInt64 -Bytes $header -Offset 80
            BugCheckParameter4 = Get-CrashDoctorUInt64 -Bytes $header -Offset 88
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
        ParseCoverage = 'DUMP_HEADER64 metadata only; physical memory pages are not yet traversed'
    }
}

function Read-CrashDoctorKernelDump32 {
    param([System.IO.FileStream]$Stream, [string]$ResolvedPath)
    if ($Stream.Length -lt 4096) { throw '32-bit kernel dump is smaller than a crash-dump header page.' }
    $header = Read-CrashDoctorBytes -Stream $Stream -Offset 0 -Count ([Math]::Min(4096, [int]$Stream.Length))
    return [pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        Path = $ResolvedPath
        FileSize = $Stream.Length
        Format = 'KernelCrashDump'
        Architecture = Get-CrashDoctorMachineName -MachineType (Get-CrashDoctorUInt32 -Bytes $header -Offset 32)
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
            BugCheckCode = Get-CrashDoctorUInt32 -Bytes $header -Offset 40
            BugCheckParameter1 = Get-CrashDoctorUInt32 -Bytes $header -Offset 44
            BugCheckParameter2 = Get-CrashDoctorUInt32 -Bytes $header -Offset 48
            BugCheckParameter3 = Get-CrashDoctorUInt32 -Bytes $header -Offset 52
            BugCheckParameter4 = Get-CrashDoctorUInt32 -Bytes $header -Offset 56
        }
        ParseCoverage = 'DUMP_HEADER32 core metadata only; physical memory pages are not yet traversed'
    }
}

function Get-CrashDoctorDumpInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path
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
            return Read-CrashDoctorMiniDump -Stream $stream -ResolvedPath $resolved
        }
        if ($signature -eq $script:KernelDumpSignature -and $validDump -eq $script:KernelDumpValid64) {
            return Read-CrashDoctorKernelDump64 -Stream $stream -ResolvedPath $resolved
        }
        if ($signature -eq $script:KernelDumpSignature -and $validDump -eq $script:KernelDumpValid32) {
            return Read-CrashDoctorKernelDump32 -Stream $stream -ResolvedPath $resolved
        }

        $ascii = [Text.Encoding]::ASCII.GetString($prefix)
        throw "Unsupported or unrecognized dump format. First 8 bytes: '$ascii'."
    }
    finally {
        $stream.Dispose()
    }
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

            $crashes.Add([pscustomobject][ordered]@{
                Path                = $file.FullName
                FileName            = $file.Name
                FileSize            = $file.Length
                CrashTimeUtc        = $crashTime.ToString('o')
                CrashTimeLocal      = $crashTime.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
                Format              = $info.Format
                Architecture        = $info.Architecture
                BugCheckCode        = ('0x{0:X8}' -f $bugCheckCode)
                BugCheckName        = $bugCheckName
                BugCheckParameters  = @($params | ForEach-Object { '0x{0:X}' -f [uint64]$_ })
                FaultingModule      = $faultingModule
                ExceptionAddress    = $exceptionAddressHex
                Valid               = $true
                Error               = $null
            })
        }
        catch {
            $crashes.Add([pscustomobject][ordered]@{
                Path                = $file.FullName
                FileName            = $file.Name
                FileSize            = $file.Length
                CrashTimeUtc        = $file.LastWriteTimeUtc.ToString('o')
                CrashTimeLocal      = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                Format              = 'Unknown'
                Architecture        = $null
                BugCheckCode        = $null
                BugCheckName        = $null
                BugCheckParameters  = @()
                FaultingModule      = $null
                ExceptionAddress    = $null
                Valid               = $false
                Error               = $_.Exception.Message
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
    $lines.Add('')

    $lines.Add('## Crash index')
    $lines.Add('')
    $lines.Add('| Date / Time (Local) | BugCheck Code | BugCheck Name | Faulting Module | Dump File | Size |')
    $lines.Add('|---|---|---|---|---|---:|')
    foreach ($c in $crashList) {
        $name = if ($c.BugCheckName) { $c.BugCheckName.Replace('|', '\|') } else { 'Unknown' }
        $code = if ($c.BugCheckCode) { '`{0}`' -f $c.BugCheckCode } else { '—' }
        $mod = if ($c.FaultingModule) { '`{0}`' -f $c.FaultingModule } else { '—' }
        $sizeKb = [math]::Round($c.FileSize / 1024, 0)
        $lines.Add("| $($c.CrashTimeLocal) | $code | $name | $mod | $($c.FileName) | $sizeKb KB |")
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
        if ($c.FaultingModule) {
            $lines.Add(('- **Candidate faulting module:** `{0}`' -f $c.FaultingModule))
        }
        if ($c.ExceptionAddress) {
            $lines.Add(('- **Exception address:** `{0}`' -f $c.ExceptionAddress))
        }
        if (-not $c.Valid -and $c.Error) {
            $lines.Add("- **Parse error:** $($c.Error)")
        }
        $lines.Add('')
    }

    $lines.Add('> Note: A driver identified in a crash stack is an active participant or victim at the moment of the crash; it is not automatically the sole root cause. Use bugcheck parameters and system event context for confirmation.')
    return ($lines -join [Environment]::NewLine)
}

Export-ModuleMember -Function Get-CrashDoctorDumpInfo, Get-CrashDoctorSystemCrashHistory, Get-CrashDoctorBugCheckName, ConvertTo-CrashDoctorCrashHistoryMarkdown, Find-CrashDoctorFaultingModule