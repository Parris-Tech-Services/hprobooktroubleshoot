# HP ProBook 11 G2 diagnostic snapshot
# Read-only apart from writing output files. Run elevated for the most complete result.

[CmdletBinding()]
param(
    [string]$OutputRoot = ([Environment]::GetFolderPath('Desktop')),
    [int]$EventHours = 6,
    [string]$SensorCsvPath,
    [string]$SensorJsonlPath
)

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = Join-Path -Path $OutputRoot -ChildPath "HPProBook-$stamp"
New-Item -ItemType Directory -Path $out -Force | Out-Null

function Save-Section {
    param(
        [Parameter(Mandatory = $true)] [string]$Name,
        [Parameter(Mandatory = $true)] [scriptblock]$Action
    )

    $path = Join-Path -Path $out -ChildPath $Name
    try {
        & $Action 2>&1 | Out-File -FilePath $path -Encoding utf8 -Width 300
    }
    catch {
        "ERROR: $($_.Exception.Message)" | Out-File -FilePath $path -Encoding utf8
    }
}

Save-Section 'computer-system.txt' { Get-CimInstance Win32_ComputerSystem | Format-List * }
Save-Section 'os.txt' {
    Get-CimInstance Win32_OperatingSystem |
        Format-List Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, LocalDateTime
}
Save-Section 'baseboard.txt' { Get-CimInstance Win32_BaseBoard | Format-List * }
Save-Section 'bios.txt' { Get-CimInstance Win32_BIOS | Format-List * }
Save-Section 'cpu.txt' { Get-CimInstance Win32_Processor | Format-List * }
Save-Section 'memory.txt' { Get-CimInstance Win32_PhysicalMemory | Format-List * }
Save-Section 'memory-pressure.txt' {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object TotalVisibleMemorySize, FreePhysicalMemory, TotalVirtualMemorySize, FreeVirtualMemory |
        Format-List
    Get-Counter '\Memory\Available MBytes', '\Memory\Committed Bytes', '\Memory\% Committed Bytes In Use' -MaxSamples 3 -SampleInterval 1 |
        Select-Object -ExpandProperty CounterSamples |
        Select-Object Path, CookedValue |
        Format-Table -AutoSize
}

Save-Section 'pagefile-and-dumps.txt' {
    Get-CimInstance Win32_ComputerSystem | Format-List AutomaticManagedPagefile
    Get-CimInstance Win32_PageFileSetting | Format-List Name, InitialSize, MaximumSize
    Get-CimInstance Win32_PageFileUsage | Format-List Name, AllocatedBaseSize, CurrentUsage, PeakUsage
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' |
        Select-Object CrashDumpEnabled, DumpFile, MinidumpDir, AutoReboot, AlwaysKeepMemoryDump |
        Format-List
}

Save-Section 'physical-disks.txt' { Get-PhysicalDisk | Format-List * }
Save-Section 'storage-reliability.txt' {
    Get-PhysicalDisk | Get-StorageReliabilityCounter | Format-List *
}

Save-Section 'powercfg-a.txt' { powercfg /a }
Save-Section 'powercfg-lastwake.txt' { powercfg /lastwake }
Save-Section 'powercfg-waketimers.txt' { powercfg /waketimers }
Save-Section 'bitlocker-status.txt' { manage-bde -status C: }
Save-Section 'problem-devices.txt' { pnputil /enum-devices /problem }
Save-Section 'firmware-devices.txt' {
    Get-PnpDevice -Class Firmware |
        Format-List FriendlyName, Status, Class, InstanceId, Problem, ConfigManagerErrorCode
}
Save-Section 'published-drivers.txt' { pnputil /enum-drivers }

Save-Section 'interesting-services.txt' {
    Get-Service | Where-Object {
        ($_.Name -match 'XTU|Cx|Conex|WirelessButton|HP') -or
        ($_.DisplayName -match 'XTU|Conex|Wireless Button|HP')
    } | Sort-Object Name | Format-Table -AutoSize
}

Save-Section 'interesting-drivers.txt' {
    Get-CimInstance Win32_SystemDriver | Where-Object {
        ($_.Name -match 'XTU|Cx|Conex|HP|Intel') -or
        ($_.DisplayName -match 'XTU|Conex|HP|Intel') -or
        ($_.PathName -match 'XTU|Conex|Cx|HP')
    } | Sort-Object Name |
        Select-Object Name, DisplayName, State, StartMode, PathName |
        Format-Table -AutoSize
}

$start = (Get-Date).AddHours(-1 * $EventHours)
Save-Section 'recent-system-events.txt' {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $start } -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
        Format-List
}
Save-Section 'recent-application-events.txt' {
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $start } -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
        Format-List
}

# Preserve recent binary event logs locally for deeper analysis.
$milliseconds = $EventHours * 60 * 60 * 1000
$eventQuery = "*[System[TimeCreated[timediff(@SystemTime) <= $milliseconds]]]"
$systemEvtx = Join-Path -Path $out -ChildPath 'System.evtx'
$applicationEvtx = Join-Path -Path $out -ChildPath 'Application.evtx'
& wevtutil.exe epl System $systemEvtx "/q:$eventQuery" 2>$null
& wevtutil.exe epl Application $applicationEvtx "/q:$eventQuery" 2>$null

$setupApiTarget = Join-Path -Path $out -ChildPath 'setupapi.dev.log'
Copy-Item -LiteralPath "$env:WINDIR\INF\setupapi.dev.log" -Destination $setupApiTarget -ErrorAction SilentlyContinue

$batteryReport = Join-Path -Path $out -ChildPath 'battery-report.html'
$powerReport = Join-Path -Path $out -ChildPath 'systempower-report.html'
$msinfoReport = Join-Path -Path $out -ChildPath 'msinfo32.nfo'
powercfg /batteryreport /output $batteryReport | Out-Null
powercfg /systempowerreport /output $powerReport | Out-Null
try {
    $msinfoProc = Start-Process -FilePath 'msinfo32.exe' -ArgumentList @('/nfo', $msinfoReport) -PassThru -NoNewWindow -ErrorAction SilentlyContinue
    if ($msinfoProc) {
        if (-not $msinfoProc.WaitForExit(15000)) {
            Write-Warning "msinfo32 export timed out after 15 seconds; continuing without .nfo export."
            try { Stop-Process -Id $msinfoProc.Id -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
}
catch {
    Write-Warning "msinfo32 export could not be started: $($_.Exception.Message)"
}

$sensorCsvAttached = $false
$sensorCsvSourceName = $null
if (-not [string]::IsNullOrWhiteSpace($SensorCsvPath)) {
    if (Test-Path -LiteralPath $SensorCsvPath -PathType Leaf) {
        Copy-Item -LiteralPath $SensorCsvPath -Destination (Join-Path $out 'sensors.csv') -Force
        $sensorCsvAttached = $true
        $sensorCsvSourceName = Split-Path -Leaf $SensorCsvPath
    }
    else {
        Write-Warning "Sensor CSV was requested but not found: $SensorCsvPath"
    }
}
else {
    $recentCsv = @(Get-ChildItem -LiteralPath $OutputRoot -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(?:sensors?|hwinfo).*\.csv$' -and $_.LastWriteTimeUtc -ge (Get-Date).ToUniversalTime().AddHours(-4) } |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1)
    if ($recentCsv.Count -gt 0) {
        Copy-Item -LiteralPath $recentCsv[0].FullName -Destination (Join-Path $out 'sensors.csv') -Force
        $sensorCsvAttached = $true
        $sensorCsvSourceName = $recentCsv[0].Name
        Write-Host "Auto-attached recent sensor CSV: $($recentCsv[0].Name)"
    }
}

$sensorJsonlAttached = $false
$sensorJsonlSourceName = $null
if (-not [string]::IsNullOrWhiteSpace($SensorJsonlPath)) {
    if (Test-Path -LiteralPath $SensorJsonlPath -PathType Leaf) {
        Copy-Item -LiteralPath $SensorJsonlPath -Destination (Join-Path $out 'sensors.jsonl') -Force
        $sensorJsonlAttached = $true
        $sensorJsonlSourceName = Split-Path -Leaf $SensorJsonlPath
    }
    else {
        Write-Warning "Sensor JSONL was requested but not found: $SensorJsonlPath"
    }
}
else {
    $recentJsonl = @(Get-ChildItem -LiteralPath $OutputRoot -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(?:sensor|wcd-sensors).*\.jsonl$' -and $_.LastWriteTimeUtc -ge (Get-Date).ToUniversalTime().AddHours(-4) } |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1)
    if ($recentJsonl.Count -gt 0) {
        Copy-Item -LiteralPath $recentJsonl[0].FullName -Destination (Join-Path $out 'sensors.jsonl') -Force
        $sensorJsonlAttached = $true
        $sensorJsonlSourceName = $recentJsonl[0].Name
        Write-Host "Auto-attached recent sensor log: $($recentJsonl[0].Name)"
    }
}

$metadataPath = Join-Path -Path $out -ChildPath 'collection-metadata.txt'
$metadata = [ordered]@{
    CollectedAtLocal    = (Get-Date).ToString('o')
    EventHours          = $EventHours
    ComputerName        = $env:COMPUTERNAME
    UserName            = $env:USERNAME
    OutputDirectory     = $out
    SensorCsvAttached   = $sensorCsvAttached
    SensorCsvSource     = $sensorCsvSourceName
    SensorJsonlAttached = $sensorJsonlAttached
    SensorJsonlSource   = $sensorJsonlSourceName
}
$metadata.GetEnumerator() | ForEach-Object {
    '{0}={1}' -f $_.Key, $_.Value
} | Out-File -FilePath $metadataPath -Encoding utf8

Write-Host "Saved diagnostic snapshot to $out"
if (-not $sensorCsvAttached -and -not $sensorJsonlAttached) {
    Write-Host 'Optional: rerun with -SensorCsvPath or -SensorJsonlPath to correlate sensor telemetry.'
}
Write-Host 'Review the folder for sensitive information before publishing any file from it.'
