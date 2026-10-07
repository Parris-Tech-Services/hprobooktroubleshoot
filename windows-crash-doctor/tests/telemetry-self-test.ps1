[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$crashDoctorRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $crashDoctorRoot 'TelemetryAnalysis.psm1'
Import-Module $modulePath -Force

function Assert-True {
    param(
        [Parameter(Mandatory = $true)] [bool]$Condition,
        [Parameter(Mandatory = $true)] [string]$Message
    )
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("CrashDoctorTelemetryTest-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp -Force | Out-Null

try {
    # Deliberately includes a duplicate CPU Package header because HWiNFO does this in real exports.
    @'
Date,Time,"Physical Memory Available [MB]","Physical Memory Load [%]","Virtual Memory Load [%]","Page File Total [MB]","Page File Used [MB]","Total CPU Usage [%]","CPU Package [°C]","CPU Package [°C]","Core Thermal Throttling (avg) [Yes/No]","Total Errors []","Drive Remaining Life [%]","Drive Failure [Yes/No]","Drive Warning [Yes/No]","Total Activity [%]","GT Limit Reasons (avg) [Yes/No]","GT: Fuses limit [Yes/No]","Ring Limit Reasons (avg) [Yes/No]","RING: Max VR Voltage  ICCmax  PL4 [Yes/No]"
12.9.2026,15:16:14.000,360,91,82,2636,650,42,48,48,No,0,86,No,No,12,No,No,No,No
12.9.2026,15:16:16.000,300,92,84,2636,724,100,52,52,No,0,86,No,No,60,Yes,Yes,Yes,Yes
12.9.2026,15:16:18.000,340,90,83,2636,700,35,46,46,No,0,86,No,No,18,No,No,No,No
'@ | Set-Content -LiteralPath (Join-Path $temp 'sensors.csv') -Encoding Default

    @'
<html><script>
var LocalSprData = {"ReportInformation":{"ReportVersion":"1.1","ReportDuration":7,"UtcOffset":600,"ScanTime":"2026-09-12T04:56:16Z","ReportStartTime":"2026-09-05T04:56:15Z"},"ScenarioInstances":[{"Type":9,"EntryTimestamp":"2026-09-12T04:15:59Z","EntryTimestampLocal":"2026-09-12T14:15:59Z","OnAc":false,"Metadata":{"Values":[]}},{"Type":10,"EntryTimestamp":"2042-01-28T10:00:00Z","EntryTimestampLocal":"2042-01-28T20:00:00Z","OnAc":true,"Metadata":{"Values":[{"Key":"EventLog.BugcheckCode","Value":'0x1E'}]}}]};
var OtherData = {};
</script></html>
'@ | Set-Content -LiteralPath (Join-Path $temp 'systempower-report.html') -Encoding utf8

    $telemetry = Invoke-CrashDoctorTelemetryAnalysis -EvidencePath $temp
    Assert-True $telemetry.Available 'Telemetry analysis reported unavailable.'
    Assert-True ($telemetry.Sensor.Provider -eq 'HWiNFO-style CSV') 'HWiNFO fixture used the wrong provider adapter.'
    Assert-True ($telemetry.Sensor.Summary.SampleCount -eq 3) 'CSV rows were not enumerated as three samples.'

    $ids = @($telemetry.Findings | ForEach-Object { $_.Id })
    foreach ($expected in @(
        'sensor-sustained-memory-pressure',
        'sensor-no-thermal-throttle-evidence',
        'sensor-whea-counter-clean',
        'sensor-drive-health-reassuring',
        'sensor-capture-continuous',
        'sensor-transient-gpu-ring-limits',
        'sensor-combined-workload-burst',
        'power-report-abnormal-shutdown',
        'power-report-stale-failure-records'
    )) {
        Assert-True ($ids -contains $expected) "Expected finding did not fire: $expected"
    }

    Assert-True (-not ($ids -contains 'power-report-bugcheck')) 'Out-of-window future bugcheck was incorrectly counted as current.'
    Assert-True ($telemetry.Power.Summary.InWindowAbnormalShutdownCount -eq 1) 'Abnormal shutdown count is wrong.'
    Assert-True ($telemetry.Power.Summary.InWindowBugcheckCount -eq 0) 'Future bugcheck contaminated the report window.'
    Assert-True ($telemetry.Power.Summary.OutOfWindowFailureRecordCount -eq 1) 'Out-of-window failure count is wrong.'
    Assert-True ($telemetry.Sensor.Summary.CombinedWorkloadBurstCount -eq 1) 'Combined workload burst was not detected.'
    Assert-True ($telemetry.Sensor.Summary.ThermalThrottleSampleCount -eq 0) 'Quiet thermal fixture reported throttling.'
    Assert-True ($telemetry.Sensor.Summary.WheaTotalErrorsMax -eq 0) 'Quiet WHEA fixture reported an error.'

    $report = [pscustomobject][ordered]@{ Findings = @() }
    $merged = Add-CrashDoctorTelemetryToReport -Report $report -Telemetry $telemetry
    Assert-True (@($merged.Findings).Count -eq @($telemetry.Findings).Count) 'Telemetry findings did not merge into the core report.'
    Assert-True ($null -ne $merged.Telemetry.Sensor) 'Telemetry summary was not attached to the core report.'

    $markdown = ConvertTo-CrashDoctorTelemetryMarkdownSection -Telemetry $telemetry
    Assert-True ($markdown -match 'Telemetry summary') 'Telemetry Markdown section is missing.'
    Assert-True ($markdown -match 'In-window abnormal shutdowns') 'Power-report summary is missing from Markdown.'

    # Native Crash Doctor deep captures use LibreHardwareMonitor JSONL. This fixture proves
    # that the same telemetry findings pipeline now consumes that format without claiming
    # WHEA/drive-health signals the provider does not expose.
    $jsonTemp = Join-Path $temp 'lhm'
    New-Item -ItemType Directory -Path $jsonTemp -Force | Out-Null
    @'
{"Sample":1,"CapturedAt":"2026-09-12T15:16:14+10:00","HardwareType":"Memory","HardwareName":"Memory","SensorType":"Load","SensorName":"Memory","Value":91}
{"Sample":1,"CapturedAt":"2026-09-12T15:16:14+10:00","HardwareType":"Cpu","HardwareName":"Intel CPU","SensorType":"Load","SensorName":"CPU Total","Value":42}
{"Sample":1,"CapturedAt":"2026-09-12T15:16:14+10:00","HardwareType":"Cpu","HardwareName":"Intel CPU","SensorType":"Temperature","SensorName":"CPU Package","Value":48}
{"Sample":1,"CapturedAt":"2026-09-12T15:16:14+10:00","HardwareType":"Storage","HardwareName":"SSD","SensorType":"Load","SensorName":"Total Activity","Value":12}
{"Sample":2,"CapturedAt":"2026-09-12T15:16:16+10:00","HardwareType":"Memory","HardwareName":"Memory","SensorType":"Load","SensorName":"Memory","Value":92}
{"Sample":2,"CapturedAt":"2026-09-12T15:16:16+10:00","HardwareType":"Cpu","HardwareName":"Intel CPU","SensorType":"Load","SensorName":"CPU Total","Value":100}
{"Sample":2,"CapturedAt":"2026-09-12T15:16:16+10:00","HardwareType":"Cpu","HardwareName":"Intel CPU","SensorType":"Temperature","SensorName":"CPU Package","Value":52}
{"Sample":2,"CapturedAt":"2026-09-12T15:16:16+10:00","HardwareType":"Storage","HardwareName":"SSD","SensorType":"Load","SensorName":"Total Activity","Value":60}
not-json-and-must-be-skipped
{"Sample":3,"CapturedAt":"2026-09-12T15:16:18+10:00","HardwareType":"Memory","HardwareName":"Memory","SensorType":"Load","SensorName":"Memory","Value":90}
{"Sample":3,"CapturedAt":"2026-09-12T15:16:18+10:00","HardwareType":"Cpu","HardwareName":"Intel CPU","SensorType":"Load","SensorName":"CPU Total","Value":35}
{"Sample":3,"CapturedAt":"2026-09-12T15:16:18+10:00","HardwareType":"Cpu","HardwareName":"Intel CPU","SensorType":"Temperature","SensorName":"CPU Package","Value":46}
{"Sample":3,"CapturedAt":"2026-09-12T15:16:18+10:00","HardwareType":"Storage","HardwareName":"SSD","SensorType":"Load","SensorName":"Total Activity","Value":18}
'@ | Set-Content -LiteralPath (Join-Path $jsonTemp 'sensor-fixture.jsonl') -Encoding utf8

    $lhm = Invoke-CrashDoctorTelemetryAnalysis -EvidencePath $jsonTemp
    Assert-True $lhm.Available 'LibreHardwareMonitor telemetry analysis reported unavailable.'
    Assert-True ($lhm.Sensor.Provider -eq 'LibreHardwareMonitor') 'JSONL fixture used the wrong provider adapter.'
    Assert-True ($lhm.Sensor.Summary.SampleCount -eq 3) 'JSONL samples were not grouped correctly.'
    Assert-True ($lhm.Sensor.Summary.CombinedWorkloadBurstCount -eq 1) 'JSONL combined workload burst was not detected.'
    $lhmIds = @($lhm.Findings | ForEach-Object { $_.Id })
    foreach ($expected in @('sensor-sustained-memory-pressure','sensor-no-thermal-throttle-evidence','sensor-capture-continuous','sensor-combined-workload-burst')) {
        Assert-True ($lhmIds -contains $expected) "LibreHardwareMonitor expected finding did not fire: $expected"
    }
    Assert-True (-not ($lhmIds -contains 'sensor-whea-counter-clean')) 'LibreHardwareMonitor path invented WHEA negative evidence.'
    Assert-True (-not ($lhmIds -contains 'sensor-drive-health-reassuring')) 'LibreHardwareMonitor path invented drive-health negative evidence.'

    # LHM JSONL fixture with available memory and drive endurance sensors.
    $lhmFullTemp = Join-Path $temp 'lhm-full'
    New-Item -ItemType Directory -Path $lhmFullTemp -Force | Out-Null
    @'
{"Sample":1,"CapturedAt":"2026-09-12T15:16:14+10:00","HardwareType":"Memory","HardwareName":"Memory","SensorType":"Load","SensorName":"Memory","Value":85}
{"Sample":1,"CapturedAt":"2026-09-12T15:16:14+10:00","HardwareType":"Memory","HardwareName":"Memory","SensorType":"Data","SensorName":"Memory Available","Value":1.2}
{"Sample":1,"CapturedAt":"2026-09-12T15:16:14+10:00","HardwareType":"Cpu","HardwareName":"Intel CPU","SensorType":"Load","SensorName":"CPU Total","Value":40}
{"Sample":1,"CapturedAt":"2026-09-12T15:16:14+10:00","HardwareType":"Cpu","HardwareName":"Intel CPU","SensorType":"Temperature","SensorName":"CPU Package","Value":45}
{"Sample":1,"CapturedAt":"2026-09-12T15:16:14+10:00","HardwareType":"Storage","HardwareName":"NVMe SSD","SensorType":"Level","SensorName":"Remaining Life","Value":98}
{"Sample":2,"CapturedAt":"2026-09-12T15:16:16+10:00","HardwareType":"Memory","HardwareName":"Memory","SensorType":"Load","SensorName":"Memory","Value":86}
{"Sample":2,"CapturedAt":"2026-09-12T15:16:16+10:00","HardwareType":"Memory","HardwareName":"Memory","SensorType":"Data","SensorName":"Memory Available","Value":1.1}
{"Sample":2,"CapturedAt":"2026-09-12T15:16:16+10:00","HardwareType":"Cpu","HardwareName":"Intel CPU","SensorType":"Load","SensorName":"CPU Total","Value":42}
{"Sample":2,"CapturedAt":"2026-09-12T15:16:16+10:00","HardwareType":"Cpu","HardwareName":"Intel CPU","SensorType":"Temperature","SensorName":"CPU Package","Value":46}
{"Sample":2,"CapturedAt":"2026-09-12T15:16:16+10:00","HardwareType":"Storage","HardwareName":"NVMe SSD","SensorType":"Level","SensorName":"Remaining Life","Value":98}
'@ | Set-Content -LiteralPath (Join-Path $lhmFullTemp 'sensors.jsonl') -Encoding utf8
    $lhmFull = Invoke-CrashDoctorTelemetryAnalysis -EvidencePath $lhmFullTemp
    Assert-True $lhmFull.Available 'Full LHM telemetry reported unavailable.'
    Assert-True ($null -ne $lhmFull.Sensor.Summary.PhysicalMemoryAvailableMinMB) 'PhysicalMemoryAvailableMinMB was not parsed.'
    Assert-True ($lhmFull.Sensor.Summary.DriveRemainingLifeMinPct -eq 98) 'DriveRemainingLifeMinPct was not parsed.'
    $lhmFullIds = @($lhmFull.Findings | ForEach-Object { $_.Id })
    Assert-True ($lhmFullIds -contains 'sensor-drive-health-reassuring') 'sensor-drive-health-reassuring did not fire when drive health is present.'

    # Windows PowerShell 5.1 unwraps function output aggressively. These fixtures deliberately
    # omit thermal/GPU-limit columns so zero-match helper output is exercised under StrictMode.
    $cardinalityRoot = Join-Path $temp 'cardinality'
    New-Item -ItemType Directory -Path $cardinalityRoot -Force | Out-Null

    $zero = Join-Path $cardinalityRoot 'zero'
    New-Item -ItemType Directory -Path $zero -Force | Out-Null
    "Date,Time,`"Physical Memory Load [%]`",`"Total CPU Usage [%]`"" | Set-Content -LiteralPath (Join-Path $zero 'sensors.csv') -Encoding Default
    $zeroTelemetry = Invoke-CrashDoctorTelemetryAnalysis -EvidencePath $zero
    Assert-True (-not $zeroTelemetry.Sensor.Available) 'Header-only HWiNFO capture should be unavailable.'

    $one = Join-Path $cardinalityRoot 'one'
    New-Item -ItemType Directory -Path $one -Force | Out-Null
    @'
Date,Time,"Physical Memory Load [%]","Total CPU Usage [%]"
12.9.2026,15:16:14.000,50,20
'@ | Set-Content -LiteralPath (Join-Path $one 'sensors.csv') -Encoding Default
    $oneTelemetry = Invoke-CrashDoctorTelemetryAnalysis -EvidencePath $one
    Assert-True $oneTelemetry.Sensor.Available 'One-row HWiNFO capture reported unavailable.'
    Assert-True ($oneTelemetry.Sensor.Summary.SampleCount -eq 1) 'One-row HWiNFO capture did not preserve cardinality.'
    Assert-True ($oneTelemetry.Sensor.Summary.ThermalThrottleSampleCount -eq 0) 'Missing thermal columns should produce zero positive samples, not an exception.'

    $many = Join-Path $cardinalityRoot 'many'
    New-Item -ItemType Directory -Path $many -Force | Out-Null
    @'
Date,Time,"Physical Memory Load [%]","Total CPU Usage [%]"
12.9.2026,15:16:14.000,50,20
12.9.2026,15:16:16.000,60,30
12.9.2026,15:16:18.000,70,40
'@ | Set-Content -LiteralPath (Join-Path $many 'sensors.csv') -Encoding Default
    $manyTelemetry = Invoke-CrashDoctorTelemetryAnalysis -EvidencePath $many
    Assert-True $manyTelemetry.Sensor.Available 'Multi-row HWiNFO capture reported unavailable.'
    Assert-True ($manyTelemetry.Sensor.Summary.SampleCount -eq 3) 'Multi-row HWiNFO capture did not preserve cardinality.'

    Write-Host 'Windows Crash Doctor telemetry self-test: PASS'
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
