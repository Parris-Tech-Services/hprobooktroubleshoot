Set-StrictMode -Version Latest

function New-TelemetryFinding {
    param([string]$Id,[string]$Severity,[string]$Confidence,[string]$Title,[string]$Evidence,[string]$Interpretation,[string]$NextStep)
    [pscustomobject][ordered]@{Id=$Id;Severity=$Severity;Confidence=$Confidence;Title=$Title;Evidence=$Evidence;Interpretation=$Interpretation;NextStep=$NextStep}
}

function ConvertTo-TelemetryNumber {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    $number=0.0
    $styles=[Globalization.NumberStyles]::Float -bor [Globalization.NumberStyles]::AllowThousands
    if ([double]::TryParse([string]$Value,$styles,[Globalization.CultureInfo]::InvariantCulture,[ref]$number)) { return $number }
    if ([double]::TryParse([string]$Value,[ref]$number)) { return $number }
    $null
}

function Get-TelemetryPercentile {
    param([double[]]$Values,[double]$Percentile)
    if ($Values.Count -eq 0) { return $null }
    $sorted=@($Values|Sort-Object)
    if ($sorted.Count -eq 1) { return [double]$sorted[0] }
    $position=($Percentile/100)*($sorted.Count-1)
    $low=[math]::Floor($position);$high=[math]::Ceiling($position)
    if ($low -eq $high) { return [double]$sorted[$low] }
    ([double]$sorted[$low]*(1-($position-$low)))+([double]$sorted[$high]*($position-$low))
}

function Import-WcdSensorCsv {
    param([Parameter(Mandatory=$true)][string]$Path)
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
    $parser=[Microsoft.VisualBasic.FileIO.TextFieldParser]::new($Path,[Text.Encoding]::GetEncoding(28591),$true)
    $parser.TextFieldType=[Microsoft.VisualBasic.FileIO.FieldType]::Delimited
    $parser.SetDelimiters(',');$parser.HasFieldsEnclosedInQuotes=$true
    try {
        if ($parser.EndOfData) { return @() }
        $raw=@($parser.ReadFields());$seen=@{};$headers=@()
        foreach($h0 in $raw){$h=[string]$h0;if([string]::IsNullOrWhiteSpace($h)){$h='Unnamed'};if($seen.ContainsKey($h)){$seen[$h]++;$headers+=('{0} #{1}' -f $h,$seen[$h])}else{$seen[$h]=1;$headers+=$h}}
        $rows=New-Object System.Collections.Generic.List[object]
        while(-not $parser.EndOfData){try{$fields=@($parser.ReadFields())}catch [Microsoft.VisualBasic.FileIO.MalformedLineException]{continue};if($fields.Count -eq 0){continue};$row=[ordered]@{};for($i=0;$i -lt $headers.Count;$i++){$row[$headers[$i]]=if($i -lt $fields.Count){$fields[$i]}else{$null}};$rows.Add([pscustomobject]$row)}
        # Windows PowerShell 5.1 cannot reliably wrap generic List[object] with @(...),
        # while `,$rows` creates the original nested collection regression. Convert once.
        return $rows.ToArray()
    } finally {$parser.Close()}
}

function Find-WcdColumn {param([object[]]$Rows,[string]$Pattern);if($Rows.Count -eq 0){return $null};$m=@($Rows[0].PSObject.Properties.Name|Where-Object{$_ -match $Pattern}|Select-Object -First 1);if($m.Count){[string]$m[0]}else{$null}}
function Find-WcdColumns {param([object[]]$Rows,[string]$Pattern);if($Rows.Count -eq 0){return @()};@($Rows[0].PSObject.Properties.Name|Where-Object{$_ -match $Pattern})}
function Get-WcdSeries {param([object[]]$Rows,[AllowNull()][string]$Column);if([string]::IsNullOrWhiteSpace($Column)){return @()};@(foreach($r in $Rows){$n=ConvertTo-TelemetryNumber $r.$Column;if($null -ne $n){$n}})}

function Get-WcdCsvSensorTime {
    param($Row)
    if($null -eq $Row.PSObject.Properties['Date'] -or $null -eq $Row.PSObject.Properties['Time']){return $null}
    $dt=[datetime]::MinValue;$formats=[string[]]@('d.M.yyyy H:m:s.fff','d.M.yyyy H:m:s','dd.MM.yyyy HH:mm:ss.fff','yyyy-MM-dd HH:mm:ss.fff')
    if([datetime]::TryParseExact(('{0} {1}' -f $Row.Date,$Row.Time),$formats,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AllowWhiteSpaces,[ref]$dt)){$dt}else{$null}
}

function Get-WcdMaxSampleGapSeconds {
    param([datetime[]]$Times)
    if($Times.Count -lt 2){return $null};$gaps=@();for($i=1;$i -lt $Times.Count;$i++){$gap=($Times[$i]-$Times[$i-1]).TotalSeconds;if($gap -ge 0){$gaps+=$gap}};if(-not $gaps.Count){return $null};[math]::Round(($gaps|Measure-Object -Maximum).Maximum,3)
}

function Add-WcdCommonSensorFindings {
    param([Parameter(Mandatory=$true)]$Summary,[Parameter(Mandatory=$true)]$Findings,[bool]$HasMemory,[bool]$HasTemperature,[bool]$HasWhea,[bool]$HasDriveHealth,[bool]$HasGpuLimits)
    if($HasMemory -and (($Summary.PhysicalMemoryLoadMedianPct -ge 80) -or ($null -ne $Summary.PhysicalMemoryAvailableMinMB -and $Summary.PhysicalMemoryAvailableMinMB -lt 512) -or ($Summary.PhysicalMemoryLoadMaxPct -ge 90))){$sev='Medium';if(($null -ne $Summary.PhysicalMemoryLoadP95Pct -and $Summary.PhysicalMemoryLoadP95Pct -ge 90) -or ($null -ne $Summary.PhysicalMemoryAvailableMinMB -and $Summary.PhysicalMemoryAvailableMinMB -lt 256)){$sev='High'};$e="Median RAM load=$($Summary.PhysicalMemoryLoadMedianPct)%; P95=$($Summary.PhysicalMemoryLoadP95Pct)%; max=$($Summary.PhysicalMemoryLoadMaxPct)%.";if($null -ne $Summary.PhysicalMemoryAvailableMinMB){$e+=" Minimum available=$($Summary.PhysicalMemoryAvailableMinMB) MB."};$Findings.Add((New-TelemetryFinding 'sensor-sustained-memory-pressure' $sev 'High' 'Sensor capture shows sustained physical-memory pressure' $e 'This supports paging pressure and user-visible stalls. It does not by itself prove the mechanism of a hard reset or total machine lock.' 'Correlate future hangs with RAM/pagefile pressure and repeat representative workload with more physical RAM if practical.'))}
    if($HasTemperature){if($Summary.ThermalThrottleSampleCount -gt 0 -or ($null -ne $Summary.CpuPackageTempMaxC -and $Summary.CpuPackageTempMaxC -ge 95)){$Findings.Add((New-TelemetryFinding 'sensor-thermal-pressure-present' 'High' 'High' 'Sensor capture contains thermal-limit evidence' "CPU package max=$($Summary.CpuPackageTempMaxC) C; throttle-positive samples=$($Summary.ThermalThrottleSampleCount)." 'Thermal pressure is present in this interval.' 'Inspect cooling and exact throttle timestamps before unrelated changes.'))}elseif($null -ne $Summary.CpuPackageTempMaxC){$Findings.Add((New-TelemetryFinding 'sensor-no-thermal-throttle-evidence' 'Info' 'High' 'No CPU thermal-throttling evidence appears in the sensor capture' "CPU package max=$($Summary.CpuPackageTempMaxC) C; throttle-positive samples=0." 'This weakens overheating for this captured interval only.' 'Keep thermal failure lower unless a future incident capture shows a temperature/throttle excursion.'))}}
    if($HasWhea){if($Summary.WheaTotalErrorsMax -gt 0){$Findings.Add((New-TelemetryFinding 'sensor-whea-errors-present' 'High' 'High' 'Sensor telemetry reports WHEA hardware errors' "Maximum WHEA Total Errors=$($Summary.WheaTotalErrorsMax)." 'This raises CPU, memory, PCIe and motherboard priority.' 'Inspect matching WHEA-Logger events.'))}else{$Findings.Add((New-TelemetryFinding 'sensor-whea-counter-clean' 'Info' 'High' 'Sensor WHEA counter remained at zero' 'WHEA Total Errors stayed at 0 for all numeric sensor samples.' 'This is bounded negative evidence for the capture, not a hardware guarantee.' 'Preserve longer captures if the machine fails again.'))}}
    if($HasDriveHealth){if($Summary.DriveFailureSampleCount -gt 0 -or $Summary.DriveWarningSampleCount -gt 0){$Findings.Add((New-TelemetryFinding 'sensor-drive-health-warning' 'High' 'High' 'Drive health warning appears in the sensor capture' "Drive Failure samples=$($Summary.DriveFailureSampleCount); Drive Warning samples=$($Summary.DriveWarningSampleCount); minimum remaining life=$($Summary.DriveRemainingLifeMinPct)%." 'Storage should move up the suspect order.' 'Run vendor/UEFI storage diagnostics and preserve SMART data.'))}else{$Findings.Add((New-TelemetryFinding 'sensor-drive-health-reassuring' 'Info' 'Medium' 'Sensor drive-health flags are reassuring' "Drive Failure samples=0; Drive Warning samples=0; minimum remaining life=$($Summary.DriveRemainingLifeMinPct)%." 'This weakens a straightforward failing-drive theory but cannot rule out intermittent faults.' 'Keep storage lower unless new timeouts, SMART changes or diagnostic failures appear.'))}}
    if($null -ne $Summary.MaxSampleGapSeconds){if($Summary.MaxSampleGapSeconds -le 5){$Findings.Add((New-TelemetryFinding 'sensor-capture-continuous' 'Info' 'High' 'Sensor sampling remained continuous' "Maximum sample gap=$($Summary.MaxSampleGapSeconds) seconds across $($Summary.SampleCount) samples." 'No long logger pause is visible; a hidden freeze during this exact capture is unlikely.' 'Use the same logging method across the next incident window.'))}elseif($Summary.MaxSampleGapSeconds -gt 10){$Findings.Add((New-TelemetryFinding 'sensor-capture-gap' 'Medium' 'Medium' 'Sensor capture contains a significant sampling gap' "Maximum sample gap=$($Summary.MaxSampleGapSeconds) seconds." 'A gap can reflect a stall, sleep or logger interruption.' 'Correlate the gap with events and user-observed timing.'))}}
    if($HasGpuLimits -and $Summary.GpuRingLimitSampleCount -gt 0 -and $Summary.ThermalThrottleSampleCount -eq 0){$Findings.Add((New-TelemetryFinding 'sensor-transient-gpu-ring-limits' 'Low' 'Medium' 'Transient GPU/ring limit reasons occurred without thermal throttling' "GT/ring limit-positive samples=$($Summary.GpuRingLimitSampleCount); thermal-positive samples=0." 'These can occur during normal power management and are a lead, not a GPU-failure diagnosis.' 'Elevate only if future failures align with the same flags or graphics errors.'))}
    if($Summary.CombinedWorkloadBurstCount -gt 0){$Findings.Add((New-TelemetryFinding 'sensor-combined-workload-burst' 'Low' 'High' 'A combined CPU, memory and disk workload burst was captured' "CPU>=95%, RAM>=90%, disk>=50% samples=$($Summary.CombinedWorkloadBurstCount); first=$($Summary.FirstCombinedWorkloadBurst)." 'This is a real stress point; continuous sampling means it was not a captured hard freeze.' 'Add process-level capture around future bursts.'))}
}

function Get-WcdHWiNFOTelemetry {
    param([Parameter(Mandatory=$true)][System.IO.FileInfo]$File)
    $rows=@(Import-WcdSensorCsv -Path $File.FullName);if(-not $rows.Count){return [pscustomobject]@{Available=$false;SourceFile=$File.Name;Provider='HWiNFO-style CSV';Summary=$null;Findings=@()}}
    $memCol=Find-WcdColumn $rows '^Physical Memory Load \[%\]$';$availCol=Find-WcdColumn $rows '^Physical Memory Available \[MB\]$';$vmCol=Find-WcdColumn $rows '^Virtual Memory Load \[%\]$';$pfTotalCol=Find-WcdColumn $rows '^Page File Total \[MB\]$';$pfUsedCol=Find-WcdColumn $rows '^Page File Used \[MB\]$';$cpuCol=Find-WcdColumn $rows '^Total CPU Usage \[%\]$';$tempCol=Find-WcdColumn $rows '^CPU Package \[';$wheaCol=Find-WcdColumn $rows '^(?:WHEA )?Total Errors \[\]$';$lifeCol=Find-WcdColumn $rows '^Drive Remaining Life \[%\]$';$failCol=Find-WcdColumn $rows '^Drive Failure(?: \[Yes/No\])?$';$warnCol=Find-WcdColumn $rows '^Drive Warning(?: \[Yes/No\])?$';$diskCol=Find-WcdColumn $rows '^Total Activity \[%\]$';$thermalCols=@(Find-WcdColumns $rows '(?i)Thermal Throttling|Critical Temperature|PROCHOT');$limitCols=@(Find-WcdColumns $rows '(?i)^GT Limit Reasons|^GT: Fuses limit|^Ring Limit Reasons|^RING: Max VR Voltage')
    $mem=@(Get-WcdSeries $rows $memCol);$avail=@(Get-WcdSeries $rows $availCol);$vm=@(Get-WcdSeries $rows $vmCol);$pfTotal=@(Get-WcdSeries $rows $pfTotalCol);$pfUsed=@(Get-WcdSeries $rows $pfUsedCol);$cpu=@(Get-WcdSeries $rows $cpuCol);$temp=@(Get-WcdSeries $rows $tempCol);$whea=@(Get-WcdSeries $rows $wheaCol);$life=@(Get-WcdSeries $rows $lifeCol);$disk=@(Get-WcdSeries $rows $diskCol);$times=@(foreach($r in $rows){$t=Get-WcdCsvSensorTime $r;if($null -ne $t){$t}})
    $thermalYes=0;$limitYes=0;$driveFail=0;$driveWarn=0;$burst=0;$firstBurst=$null
    foreach($r in $rows){$hit=$false;foreach($c in $thermalCols){if([string]$r.$c -match '^(?i:Yes|True|1)$'){$hit=$true;break}};if($hit){$thermalYes++};$hit=$false;foreach($c in $limitCols){if([string]$r.$c -match '^(?i:Yes|True|1)$'){$hit=$true;break}};if($hit){$limitYes++};if($failCol -and [string]$r.$failCol -match '^(?i:Yes|True|1)$'){$driveFail++};if($warnCol -and [string]$r.$warnCol -match '^(?i:Yes|True|1)$'){$driveWarn++};if($memCol -and $cpuCol -and $diskCol){$m=ConvertTo-TelemetryNumber $r.$memCol;$c=ConvertTo-TelemetryNumber $r.$cpuCol;$d=ConvertTo-TelemetryNumber $r.$diskCol;if($null -ne $m -and $null -ne $c -and $null -ne $d -and $m -ge 90 -and $c -ge 95 -and $d -ge 50){$burst++;if($null -eq $firstBurst){$firstBurst=Get-WcdCsvSensorTime $r}}}}
    $s=[pscustomobject][ordered]@{Provider='HWiNFO-style CSV';SampleCount=$times.Count;Start=if($times.Count){$times[0].ToString('o')}else{$null};End=if($times.Count){$times[-1].ToString('o')}else{$null};DurationMinutes=if($times.Count -gt 1){[math]::Round(($times[-1]-$times[0]).TotalMinutes,1)}else{$null};MaxSampleGapSeconds=Get-WcdMaxSampleGapSeconds $times;PhysicalMemoryLoadMedianPct=if($mem.Count){[math]::Round((Get-TelemetryPercentile $mem 50),1)}else{$null};PhysicalMemoryLoadP95Pct=if($mem.Count){[math]::Round((Get-TelemetryPercentile $mem 95),1)}else{$null};PhysicalMemoryLoadMaxPct=if($mem.Count){[math]::Round(($mem|Measure-Object -Maximum).Maximum,1)}else{$null};PhysicalMemoryAvailableMinMB=if($avail.Count){[math]::Round(($avail|Measure-Object -Minimum).Minimum,0)}else{$null};VirtualMemoryLoadMaxPct=if($vm.Count){[math]::Round(($vm|Measure-Object -Maximum).Maximum,1)}else{$null};PageFileTotalMaxMB=if($pfTotal.Count){[math]::Round(($pfTotal|Measure-Object -Maximum).Maximum,0)}else{$null};PageFileUsedMaxMB=if($pfUsed.Count){[math]::Round(($pfUsed|Measure-Object -Maximum).Maximum,0)}else{$null};CpuUsageP95Pct=if($cpu.Count){[math]::Round((Get-TelemetryPercentile $cpu 95),1)}else{$null};CpuUsageMaxPct=if($cpu.Count){[math]::Round(($cpu|Measure-Object -Maximum).Maximum,1)}else{$null};CpuPackageTempMaxC=if($temp.Count){[math]::Round(($temp|Measure-Object -Maximum).Maximum,1)}else{$null};ThermalThrottleSampleCount=$thermalYes;WheaTotalErrorsMax=if($whea.Count){[math]::Round(($whea|Measure-Object -Maximum).Maximum,0)}else{$null};DriveRemainingLifeMinPct=if($life.Count){[math]::Round(($life|Measure-Object -Minimum).Minimum,1)}else{$null};DriveFailureSampleCount=$driveFail;DriveWarningSampleCount=$driveWarn;DiskActivityMaxPct=if($disk.Count){[math]::Round(($disk|Measure-Object -Maximum).Maximum,1)}else{$null};GpuRingLimitSampleCount=$limitYes;CombinedWorkloadBurstCount=$burst;FirstCombinedWorkloadBurst=if($null -ne $firstBurst){$firstBurst.ToString('o')}else{$null}}
    $f=New-Object System.Collections.Generic.List[object];Add-WcdCommonSensorFindings -Summary $s -Findings $f -HasMemory ($mem.Count -gt 0) -HasTemperature (($temp.Count -gt 0) -or ($thermalCols.Count -gt 0)) -HasWhea ($whea.Count -gt 0) -HasDriveHealth (($life.Count -gt 0) -or $failCol -or $warnCol) -HasGpuLimits ($limitCols.Count -gt 0)
    [pscustomobject][ordered]@{Available=$true;SourceFile=$File.Name;Provider='HWiNFO-style CSV';Summary=$s;Findings=$f.ToArray()}
}

function Import-WcdSensorJsonl {
    param([Parameter(Mandatory=$true)][string]$Path)
    $items=New-Object System.Collections.Generic.List[object]
    foreach($line in Get-Content -LiteralPath $Path -ErrorAction Stop){if([string]::IsNullOrWhiteSpace($line)){continue};try{$item=$line|ConvertFrom-Json -ErrorAction Stop;if($null -eq $item.PSObject.Properties['Error']){$items.Add($item)}}catch{continue}}
    return $items.ToArray()
}

function Get-WcdLibreHardwareMonitorTelemetry {
    param([Parameter(Mandatory=$true)][System.IO.FileInfo]$File)
    $items=@(Import-WcdSensorJsonl -Path $File.FullName);if(-not $items.Count){return [pscustomobject]@{Available=$false;SourceFile=$File.Name;Provider='LibreHardwareMonitor';Summary=$null;Findings=@()}}
    $groups=@($items|Group-Object Sample|Sort-Object {[int]$_.Name});$memory=@();$availMB=@();$vm=@();$cpu=@();$disk=@();$temp=@();$driveLife=@();$times=@();$burst=0;$firstBurst=$null;$thermalPositive=0
    foreach($group in $groups){
        $sampleItems=@($group.Group);$timestamp=$null
        foreach($item in $sampleItems){if($item.CapturedAt){$dto=[datetimeoffset]::MinValue;if([datetimeoffset]::TryParse([string]$item.CapturedAt,[ref]$dto)){$timestamp=$dto.LocalDateTime;break}}}
        if($null -ne $timestamp){$times+=$timestamp}
        $memoryValue=$null;$cpuValue=$null;$diskValue=$null;$tempValue=$null
        foreach($item in $sampleItems){
            $value=ConvertTo-TelemetryNumber $item.Value;if($null -eq $value){continue}
            $ht=[string]$item.HardwareType;$hn=[string]$item.HardwareName;$st=[string]$item.SensorType;$sn=[string]$item.SensorName
            if($null -eq $memoryValue -and $st -match '^(?i)Load$' -and (($ht -match '(?i)Memory') -or ($hn -match '(?i)Memory')) -and $sn -match '(?i)Memory|Load'){$memoryValue=$value}
            if($st -match '^(?i)Data$' -and (($ht -match '(?i)Memory') -or ($hn -match '(?i)Memory')) -and $sn -match '(?i)Available'){$mb=if($value -lt 128){[math]::Round($value*1024,0)}else{[math]::Round($value,0)};$availMB+=$mb}
            if($st -match '^(?i)Load$' -and $sn -match '(?i)Virtual Memory|Page File|Commit'){$vm+=$value}
            if($null -eq $cpuValue -and $st -match '^(?i)Load$' -and (($ht -match '(?i)Cpu') -or ($hn -match '(?i)CPU|Processor')) -and $sn -match '(?i)CPU Total|Total CPU|CPU.*Total'){$cpuValue=$value}
            if($null -eq $diskValue -and $st -match '^(?i)Load$' -and (($ht -match '(?i)Storage') -or ($hn -match '(?i)SSD|NVMe|Disk|Drive')) -and $sn -match '(?i)Activity'){$diskValue=$value}
            if((($ht -match '(?i)Storage') -or ($hn -match '(?i)SSD|NVMe|Disk|Drive')) -and ($sn -match '(?i)Remaining Life|Wear|Endurance')){$driveLife+=$value}
            if($st -match '^(?i)Temperature$' -and (($ht -match '(?i)Cpu') -or ($hn -match '(?i)CPU|Processor')) -and $sn -match '(?i)Package|Core Max|CPU|Core'){if($null -eq $tempValue -or $value -gt $tempValue){$tempValue=$value}}
            if($sn -match '(?i)Thermal Throttling|PROCHOT|Critical Temperature' -and $value -gt 0){$thermalPositive++}
        }
        if($null -ne $memoryValue){$memory+=$memoryValue}
        if($null -ne $cpuValue){$cpu+=$cpuValue}
        if($null -ne $diskValue){$disk+=$diskValue}
        if($null -ne $tempValue){$temp+=$tempValue}
        if($null -ne $memoryValue -and $null -ne $cpuValue -and $null -ne $diskValue -and $memoryValue -ge 90 -and $cpuValue -ge 95 -and $diskValue -ge 50){$burst++;if($null -eq $firstBurst -and $null -ne $timestamp){$firstBurst=$timestamp}}
    }
    $hasDriveHealth=($driveLife.Count -gt 0)
    $minDriveLife=if($hasDriveHealth){[math]::Round(($driveLife|Measure-Object -Minimum).Minimum,1)}else{$null}
    $driveFailures=if($hasDriveHealth -and $null -ne $minDriveLife -and $minDriveLife -le 0){1}else{0}
    $driveWarnings=if($hasDriveHealth -and $null -ne $minDriveLife -and $minDriveLife -le 10){1}else{0}
    $s=[pscustomobject][ordered]@{
        Provider='LibreHardwareMonitor'
        SampleCount=$groups.Count
        Start=if($times.Count){$times[0].ToString('o')}else{$null}
        End=if($times.Count){$times[-1].ToString('o')}else{$null}
        DurationMinutes=if($times.Count -gt 1){[math]::Round(($times[-1]-$times[0]).TotalMinutes,1)}else{$null}
        MaxSampleGapSeconds=Get-WcdMaxSampleGapSeconds $times
        PhysicalMemoryLoadMedianPct=if($memory.Count){[math]::Round((Get-TelemetryPercentile $memory 50),1)}else{$null}
        PhysicalMemoryLoadP95Pct=if($memory.Count){[math]::Round((Get-TelemetryPercentile $memory 95),1)}else{$null}
        PhysicalMemoryLoadMaxPct=if($memory.Count){[math]::Round(($memory|Measure-Object -Maximum).Maximum,1)}else{$null}
        PhysicalMemoryAvailableMinMB=if($availMB.Count){[math]::Round(($availMB|Measure-Object -Minimum).Minimum,0)}else{$null}
        VirtualMemoryLoadMaxPct=if($vm.Count){[math]::Round(($vm|Measure-Object -Maximum).Maximum,1)}else{$null}
        PageFileTotalMaxMB=$null
        PageFileUsedMaxMB=$null
        CpuUsageP95Pct=if($cpu.Count){[math]::Round((Get-TelemetryPercentile $cpu 95),1)}else{$null}
        CpuUsageMaxPct=if($cpu.Count){[math]::Round(($cpu|Measure-Object -Maximum).Maximum,1)}else{$null}
        CpuPackageTempMaxC=if($temp.Count){[math]::Round(($temp|Measure-Object -Maximum).Maximum,1)}else{$null}
        ThermalThrottleSampleCount=$thermalPositive
        WheaTotalErrorsMax=$null
        DriveRemainingLifeMinPct=$minDriveLife
        DriveFailureSampleCount=$driveFailures
        DriveWarningSampleCount=$driveWarnings
        DiskActivityMaxPct=if($disk.Count){[math]::Round(($disk|Measure-Object -Maximum).Maximum,1)}else{$null}
        GpuRingLimitSampleCount=0
        CombinedWorkloadBurstCount=$burst
        FirstCombinedWorkloadBurst=if($null -ne $firstBurst){$firstBurst.ToString('o')}else{$null}
    }
    $f=New-Object System.Collections.Generic.List[object];Add-WcdCommonSensorFindings -Summary $s -Findings $f -HasMemory ($memory.Count -gt 0) -HasTemperature ($temp.Count -gt 0) -HasWhea $false -HasDriveHealth $hasDriveHealth -HasGpuLimits $false
    [pscustomobject][ordered]@{Available=$true;SourceFile=$File.Name;Provider='LibreHardwareMonitor';Summary=$s;Findings=$f.ToArray()}
}

function Find-WcdSensorEvidenceFile {
    param([Parameter(Mandatory=$true)][string]$EvidencePath)
    $directory=Get-Item -LiteralPath $EvidencePath -ErrorAction Stop
    $local=@(Get-ChildItem -LiteralPath $EvidencePath -File -ErrorAction SilentlyContinue|Where-Object{$_.Name -match '(?i)^(sensors?|hwinfo).*\.csv$|^(sensor|wcd-sensors).*\.jsonl$'}|Sort-Object LastWriteTimeUtc -Descending)
    if($local.Count){return $local[0]}
    # Desktop deep-capture files live beside snapshot folders. Associate only a nearby capture,
    # avoiding stale telemetry silently contaminating a later incident.
    $parent=$directory.Parent;if($null -eq $parent){return $null}
    $start=$directory.CreationTimeUtc.AddHours(-4)
    $end=$directory.CreationTimeUtc.AddHours(1)
    $nearby=@(Get-ChildItem -LiteralPath $parent.FullName -File -ErrorAction SilentlyContinue|Where-Object{$_.Name -match '(?i)^(sensor|wcd-sensors).*\.jsonl$' -and $_.LastWriteTimeUtc -ge $start -and $_.LastWriteTimeUtc -le $end}|Sort-Object LastWriteTimeUtc -Descending)
    if($nearby.Count){return $nearby[0]}
    $null
}

function Get-SensorTelemetry {param([Parameter(Mandatory=$true)][string]$EvidencePath);$file=Find-WcdSensorEvidenceFile -EvidencePath $EvidencePath;if($null -eq $file){return [pscustomobject]@{Available=$false;SourceFile=$null;Provider=$null;Summary=$null;Findings=@()}};if($file.Extension -ieq '.jsonl'){return Get-WcdLibreHardwareMonitorTelemetry -File $file};Get-WcdHWiNFOTelemetry -File $file}

function Get-PowerTelemetry {
    param([Parameter(Mandatory=$true)][string]$EvidencePath)
    $file=@(Get-ChildItem -LiteralPath $EvidencePath -File -ErrorAction SilentlyContinue|Where-Object{$_.Name -match '(?i)^(systempower|sleepstudy)-report.*\.html$'}|Sort-Object LastWriteTime -Descending|Select-Object -First 1);if(-not $file.Count){return [pscustomobject]@{Available=$false;SourceFile=$null;Summary=$null;Findings=@()}}
    $html=Get-Content -LiteralPath $file[0].FullName -Raw;$m=[regex]::Match($html,'(?s)var\s+LocalSprData\s*=\s*(\{.*?\});\s*(?:var\s+|</script>)');if(-not $m.Success){return [pscustomobject]@{Available=$false;SourceFile=$file[0].Name;Summary=$null;Findings=@()}};$json=[regex]::Replace($m.Groups[1].Value,":\s*'([^']*)'",': "$1"');try{$data=$json|ConvertFrom-Json -ErrorAction Stop}catch{return [pscustomobject]@{Available=$false;SourceFile=$file[0].Name;Summary=$null;Findings=@()}}
    $ri=$data.ReportInformation;$start=[datetime]::Parse([string]$ri.ReportStartTime,[System.Globalization.CultureInfo]::InvariantCulture).ToUniversalTime();$scan=[datetime]::Parse([string]$ri.ScanTime,[System.Globalization.CultureInfo]::InvariantCulture).ToUniversalTime();$ab=@();$bug=@();$stale=0
    foreach($x in @($data.ScenarioInstances)){if([int]$x.Type -notin @(9,10)){continue};$t=[datetime]::Parse([string]$x.EntryTimestamp,[System.Globalization.CultureInfo]::InvariantCulture).ToUniversalTime();if($t -lt $start -or $t -gt $scan){$stale++;continue};if([int]$x.Type -eq 9){$ab+=$x}else{$bug+=$x}}
    $s=[pscustomobject][ordered]@{ReportStartUtc=$start.ToString('o');ScanTimeUtc=$scan.ToString('o');UtcOffsetMinutes=[int]$ri.UtcOffset;InWindowAbnormalShutdownCount=$ab.Count;InWindowBugcheckCount=$bug.Count;OutOfWindowFailureRecordCount=$stale;LatestAbnormalShutdownLocal=$null;LatestAbnormalShutdownOnAc=$null;LatestBugcheckLocal=$null;LatestBugcheckCode=$null}
    if($ab.Count){$x=@($ab|Sort-Object EntryTimestamp|Select-Object -Last 1)[0];$s.LatestAbnormalShutdownLocal=[string]$x.EntryTimestampLocal;$s.LatestAbnormalShutdownOnAc=[bool]$x.OnAc};if($bug.Count){$x=@($bug|Sort-Object EntryTimestamp|Select-Object -Last 1)[0];$s.LatestBugcheckLocal=[string]$x.EntryTimestampLocal;if($null -ne $x.PSObject.Properties['Metadata']){foreach($v in @($x.Metadata.Values)){if([string]$v.Key -eq 'EventLog.BugcheckCode'){$s.LatestBugcheckCode=[string]$v.Value;break}}}}
    $f=New-Object System.Collections.Generic.List[object];if($ab.Count){$power=if($s.LatestAbnormalShutdownOnAc){'AC'}else{'battery'};$f.Add((New-TelemetryFinding 'power-report-abnormal-shutdown' 'Medium' 'High' 'System power report confirms an abnormal shutdown in the report window' "In-window abnormal shutdowns=$($ab.Count); latest=$($s.LatestAbnormalShutdownLocal); power source=$power." 'This precisely confirms an unclean incident boundary; it records the outcome rather than proving cause.' 'Correlate with final pre-incident System events and any sensor/ETW capture.'))};if($bug.Count){$f.Add((New-TelemetryFinding 'power-report-bugcheck' 'High' 'High' 'System power report contains an in-window bugcheck' "In-window bugchecks=$($bug.Count); latest=$($s.LatestBugcheckLocal); code=$($s.LatestBugcheckCode)." 'A true bugcheck provides a stronger diagnostic path than a generic reset.' 'Preserve and analyse the matching dump.'))};if($stale -gt 0){$f.Add((New-TelemetryFinding 'power-report-stale-failure-records' 'Info' 'High' 'Power report contains failure records outside its declared report window' "Failure records outside $($ri.ReportStartTime) to $($ri.ScanTime): $stale." 'Historical, cloned-image or clock-corrupted records can contaminate naive crash counts; Crash Doctor excludes them.' 'Use the report window and current-machine timestamps as hard boundaries.'))}
    [pscustomobject][ordered]@{Available=$true;SourceFile=$file[0].Name;Summary=$s;Findings=$f.ToArray()}
}

function Invoke-CrashDoctorTelemetryAnalysis {
    [CmdletBinding()]param([Parameter(Mandatory=$true)][string]$EvidencePath)
    if(-not(Test-Path -LiteralPath $EvidencePath -PathType Container)){throw "Evidence path does not exist or is not a directory: $EvidencePath"};$sensor=Get-SensorTelemetry -EvidencePath $EvidencePath;$power=Get-PowerTelemetry -EvidencePath $EvidencePath;$findings=@($sensor.Findings)+@($power.Findings);[pscustomobject][ordered]@{Available=[bool]($sensor.Available -or $power.Available);Sensor=$sensor;Power=$power;Findings=$findings}
}

function Add-CrashDoctorTelemetryToReport {
    [CmdletBinding()]param([Parameter(Mandatory=$true)]$Report,[Parameter(Mandatory=$true)]$Telemetry)
    $Report|Add-Member -NotePropertyName Telemetry -NotePropertyValue $Telemetry -Force;$Report.Findings=@($Report.Findings)+@($Telemetry.Findings);$Report
}

function ConvertTo-CrashDoctorTelemetryMarkdownSection {
    [CmdletBinding()]param([Parameter(Mandatory=$true)]$Telemetry)
    if(-not $Telemetry.Available){return ''};$l=New-Object System.Collections.Generic.List[string];$l.Add('## Telemetry summary');$l.Add('')
    if($Telemetry.Sensor.Available){$s=$Telemetry.Sensor.Summary;$l.Add("Sensor source: ``$($Telemetry.Sensor.SourceFile)`` ($($Telemetry.Sensor.Provider))");$l.Add('');$l.Add("- Sensor samples: **$($s.SampleCount)**");if($null -ne $s.DurationMinutes){$l.Add("- Duration: **$($s.DurationMinutes) minutes**")};if($null -ne $s.PhysicalMemoryLoadMedianPct){$l.Add("- Physical-memory load: median **$($s.PhysicalMemoryLoadMedianPct)%**, P95 **$($s.PhysicalMemoryLoadP95Pct)%**, max **$($s.PhysicalMemoryLoadMaxPct)%**")};if($null -ne $s.CpuUsageP95Pct){$l.Add("- CPU usage: P95 **$($s.CpuUsageP95Pct)%**, max **$($s.CpuUsageMaxPct)%**")};if($null -ne $s.CpuPackageTempMaxC){$l.Add("- CPU package max: **$($s.CpuPackageTempMaxC) C**")};if($null -ne $s.MaxSampleGapSeconds){$l.Add("- Maximum sample gap: **$($s.MaxSampleGapSeconds) seconds**")};$l.Add('')}
    if($Telemetry.Power.Available){$p=$Telemetry.Power.Summary;$l.Add("Power-report source: ``$($Telemetry.Power.SourceFile)``");$l.Add('');$l.Add("- In-window abnormal shutdowns: **$($p.InWindowAbnormalShutdownCount)**");$l.Add("- In-window bugchecks: **$($p.InWindowBugcheckCount)**");$l.Add("- Out-of-window failure records ignored: **$($p.OutOfWindowFailureRecordCount)**");if($p.LatestAbnormalShutdownLocal){$l.Add("- Latest abnormal shutdown: **$($p.LatestAbnormalShutdownLocal)**")};$l.Add('')};$l -join [Environment]::NewLine
}

Export-ModuleMember -Function Invoke-CrashDoctorTelemetryAnalysis,Add-CrashDoctorTelemetryToReport,ConvertTo-CrashDoctorTelemetryMarkdownSection