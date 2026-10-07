[CmdletBinding(DefaultParameterSetName = 'Evidence')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Evidence')] [string]$EvidencePath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Dump')] [string]$DumpPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Crashes')] [switch]$HistoricalCrashes,
    [string]$OutputDirectory,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

function Get-WcdProductInfo {
    $versionPath = Join-Path $PSScriptRoot 'version.json'
    $buildInfoPath = Join-Path $PSScriptRoot 'build-info.json'
    $version = $null
    $build = $null
    if (Test-Path -LiteralPath $versionPath -PathType Leaf) {
        try { $version = Get-Content -LiteralPath $versionPath -Raw | ConvertFrom-Json } catch { }
    }
    if (Test-Path -LiteralPath $buildInfoPath -PathType Leaf) {
        try { $build = Get-Content -LiteralPath $buildInfoPath -Raw | ConvertFrom-Json } catch { }
    }

    $commit = $env:WCD_COMMIT_SHA
    if ([string]::IsNullOrWhiteSpace($commit)) { $commit = $env:GITHUB_SHA }
    if ([string]::IsNullOrWhiteSpace($commit) -and $build -and $build.PSObject.Properties.Name -contains 'commit') { $commit = [string]$build.commit }
    if ([string]::IsNullOrWhiteSpace($commit)) { $commit = 'unknown' }

    [pscustomobject][ordered]@{
        ProductVersion = if ($version) { [string]$version.productVersion } else { 'unknown' }
        EngineVersion = if ($version) { [string]$version.engineVersion } else { 'unknown' }
        CollectorVersion = if ($version) { [string]$version.collectorVersion } else { 'unknown' }
        RuleSetVersion = if ($version) { [string]$version.ruleSetVersion } else { 'unknown' }
        SchemaVersion = if ($version) { [string]$version.schemaVersion } else { 'unknown' }
        AppBuild = if ($build) { [string]$build.appVersion } else { $null }
        Commit = $commit
    }
}

function Add-WcdProductInfo {
    param([Parameter(Mandatory = $true)]$Report)
    $product = Get-WcdProductInfo
    $Report | Add-Member -NotePropertyName Product -NotePropertyValue $product -Force
    if ($Report.PSObject.Properties.Name -contains 'SchemaVersion' -and $product.SchemaVersion -ne 'unknown') {
        $Report.SchemaVersion = $product.SchemaVersion
    }
    return $Report
}

function ConvertTo-CrashDoctorDumpMarkdown {
    param([Parameter(Mandatory = $true)]$Report)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# Windows Crash Doctor dump report')
    $lines.Add('')
    $lines.Add("Dump: ``$($Report.Path)``")
    if ($Report.Product) {
        $lines.Add('')
        $lines.Add("- **Windows Crash Doctor:** $($Report.Product.ProductVersion)")
        $lines.Add("- **Engine / rules:** $($Report.Product.EngineVersion) / $($Report.Product.RuleSetVersion)")
        $lines.Add("- **Commit:** ``$($Report.Product.Commit)``")
    }
    $lines.Add('')
    $lines.Add("- **Format:** $($Report.Format)")
    $lines.Add("- **Architecture:** $($Report.Architecture)")
    $lines.Add("- **File size:** $($Report.FileSize) bytes")
    $lines.Add("- **Parser coverage:** $($Report.ParseCoverage)")

    if ($Report.Format -eq 'MiniDump') {
        $lines.Add('')
        $lines.Add('## Minidump summary')
        $lines.Add('')
        $lines.Add("- Streams: $($Report.Header.NumberOfStreams)")
        $lines.Add("- Threads: $($Report.ThreadCount)")
        $lines.Add("- Modules: $($Report.ModuleCount)")
        if ($Report.SystemInfo) {
            $lines.Add("- Windows: $($Report.SystemInfo.MajorVersion).$($Report.SystemInfo.MinorVersion) build $($Report.SystemInfo.BuildNumber)")
            $lines.Add("- Processors: $($Report.SystemInfo.NumberOfProcessors)")
        }
        if ($Report.Exception) {
            $lines.Add("- Exception thread: $($Report.Exception.ThreadId)")
            $lines.Add(('- Exception code: `0x{0:X8}`' -f $Report.Exception.ExceptionCode))
            $lines.Add(('- Exception address: `0x{0:X16}`' -f $Report.Exception.ExceptionAddress))
        }

        if ($Report.Modules.Count -gt 0) {
            $lines.Add('')
            $lines.Add('## Modules')
            $lines.Add('')
            $lines.Add('| Module | Base | Size |')
            $lines.Add('|---|---:|---:|')
            foreach ($module in $Report.Modules) {
                $name = if ($module.Name) { $module.Name.Replace('|', '\|') } else { '(name unavailable)' }
                $lines.Add(('| {0} | `0x{1:X16}` | {2} |' -f $name, $module.BaseOfImage, $module.SizeOfImage))
            }
        }

        $lines.Add('')
        $lines.Add('## Streams')
        $lines.Add('')
        $lines.Add('| Type | Name | Bytes | RVA |')
        $lines.Add('|---:|---|---:|---:|')
        foreach ($stream in $Report.Streams) {
            $lines.Add("| $($stream.StreamType) | $($stream.Name) | $($stream.DataSize) | $($stream.Rva) |")
        }
    }
    elseif ($Report.Format -eq 'KernelCrashDump') {
        $lines.Add('')
        $lines.Add('## Kernel crash header')
        $lines.Add('')
        $lines.Add("- Valid marker: $($Report.Header.ValidDump)")
        $lines.Add("- Windows version fields: $($Report.Header.MajorVersion).$($Report.Header.MinorVersion)")
        $lines.Add("- Processors: $($Report.Header.NumberProcessors)")
        $lines.Add(('- Bugcheck: `0x{0:X8}`' -f $Report.Header.BugCheckCode))
        $lines.Add(('- Parameters: `0x{0:X}` `0x{1:X}` `0x{2:X}` `0x{3:X}`' -f $Report.Header.BugCheckParameter1, $Report.Header.BugCheckParameter2, $Report.Header.BugCheckParameter3, $Report.Header.BugCheckParameter4))
        if ($null -ne $Report.Header.PSObject.Properties['DumpTypeName']) {
            $lines.Add("- Dump type: $($Report.Header.DumpTypeName) ($($Report.Header.DumpType))")
        }
    }

    $lines.Add('')
    $lines.Add('> Parsing a dump identifies evidence contained in the file; it does not by itself establish root cause. Symbolization, stack unwinding and memory traversal are separate roadmap capabilities.')
    return ($lines -join [Environment]::NewLine)
}

if ($PSCmdlet.ParameterSetName -eq 'Dump') {
    $dumpModulePath = Join-Path $PSScriptRoot 'DumpParser.psm1'
    Import-Module $dumpModulePath -Force

    $resolvedDump = (Resolve-Path -LiteralPath $DumpPath).Path
    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Split-Path -Parent $resolvedDump }
    if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }

    $report = Get-CrashDoctorDumpInfo -Path $resolvedDump
    $report = Add-WcdProductInfo -Report $report
    $markdown = ConvertTo-CrashDoctorDumpMarkdown -Report $report
    $markdownPath = Join-Path $OutputDirectory 'crash-doctor-dump-report.md'
    $jsonPath = Join-Path $OutputDirectory 'crash-doctor-dump-report.json'

    $markdown | Out-File -LiteralPath $markdownPath -Encoding utf8 -Width 500
    $report | ConvertTo-Json -Depth 12 | Out-File -LiteralPath $jsonPath -Encoding utf8 -Width 500
    Write-Host "Crash Doctor dump report: $markdownPath"
    Write-Host "Machine-readable dump report: $jsonPath"
    if ($PassThru) { return $report }
    return
}

if ($PSCmdlet.ParameterSetName -eq 'Crashes') {
    $dumpModulePath = Join-Path $PSScriptRoot 'DumpParser.psm1'
    Import-Module $dumpModulePath -Force

    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = (Get-Location).Path }
    if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }

    $crashes = @(Get-CrashDoctorSystemCrashHistory)
    $markdown = ConvertTo-CrashDoctorCrashHistoryMarkdown -Crashes $crashes
    $markdownPath = Join-Path $OutputDirectory 'crash-history.md'
    $jsonPath = Join-Path $OutputDirectory 'crash-history.json'

    $markdown | Out-File -LiteralPath $markdownPath -Encoding utf8 -Width 500
    $crashes | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $jsonPath -Encoding utf8 -Width 500

    Write-Host "Windows Doctor crash history report: $markdownPath"
    Write-Host "Machine-readable crash history: $jsonPath"
    Write-Host ("Discovered {0} crash dump(s)." -f $crashes.Count)
    if ($PassThru) { return $crashes }
    return
}

$coreModulePath = Join-Path $PSScriptRoot 'CrashDoctor.psm1'
$telemetryModulePath = Join-Path $PSScriptRoot 'TelemetryAnalysis.psm1'
$registryModulePath = Join-Path $PSScriptRoot 'DiagnosticRegistry.psm1'
$dumpModulePath = Join-Path $PSScriptRoot 'DumpParser.psm1'
Import-Module $coreModulePath -Force
if (Test-Path -LiteralPath $telemetryModulePath -PathType Leaf) { Import-Module $telemetryModulePath -Force }
Import-Module $registryModulePath -Force
if (Test-Path -LiteralPath $dumpModulePath -PathType Leaf) { Import-Module $dumpModulePath -Force }

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = $EvidencePath }
if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }

$report = Invoke-CrashDoctorAnalysis -EvidencePath $EvidencePath
$report = Add-WcdProductInfo -Report $report
$registry = Get-WcdDiagnosticRegistry
$registryCoverage = Get-WcdRegistryCoverage -EvidencePath $EvidencePath -Registry $registry
$report.Coverage = [pscustomobject][ordered]@{
    PresentFiles = @($registryCoverage.PresentFiles)
    MissingFiles = @($registryCoverage.MissingFiles)
    PresentCount = $registryCoverage.PresentCount
    ExpectedCount = $registryCoverage.ExpectedCount
    Percent = $registryCoverage.Percent
}
$report | Add-Member -NotePropertyName DiagnosticRegistry -NotePropertyValue ([pscustomobject][ordered]@{
    RegistryVersion = [string]$registry.registryVersion
    SchemaVersion = [string]$registry.schemaVersion
    DiagnosticCount = @($registry.diagnostics).Count
    Diagnostics = @($registryCoverage.Diagnostics)
}) -Force

$telemetry = $null
if (Get-Command Invoke-CrashDoctorTelemetryAnalysis -ErrorAction SilentlyContinue) {
    $telemetry = Invoke-CrashDoctorTelemetryAnalysis -EvidencePath $EvidencePath
    if ($telemetry.Available) { $report = Add-CrashDoctorTelemetryToReport -Report $report -Telemetry $telemetry }
}

$crashes = @()
if (Get-Command Get-CrashDoctorSystemCrashHistory -ErrorAction SilentlyContinue) {
    try {
        $searchPaths = @($EvidencePath)
        $minidumpDir = Join-Path $env:SystemRoot 'Minidump'
        if (Test-Path -LiteralPath $minidumpDir -PathType Container) { $searchPaths += $minidumpDir }
        $memoryDmp = Join-Path $env:SystemRoot 'MEMORY.DMP'
        if (Test-Path -LiteralPath $memoryDmp -PathType Leaf) { $searchPaths += $memoryDmp }
        $crashes = @(Get-CrashDoctorSystemCrashHistory -SearchPaths $searchPaths)
    } catch { }
}

$report | Add-Member -NotePropertyName CrashHistory -NotePropertyValue $crashes -Force

if ($crashes.Count -gt 0) {
    $validCrashes = @($crashes | Where-Object { $_.Valid })
    if ($validCrashes.Count -gt 0) {
        $latest = $validCrashes[0]
        $recent = @($validCrashes | Where-Object {
            try { [datetime]$_.CrashTimeUtc -ge (Get-Date).ToUniversalTime().AddDays(-14) } catch { $false }
        })
        $sev = if ($recent.Count -gt 0) { 'High' } else { 'Medium' }
        $evidenceText = "{0} crash dump(s) discovered; latest crash {1} ({2}) with bugcheck {3}." -f $crashes.Count, $latest.CrashTimeLocal, $latest.BugCheckName, $latest.BugCheckCode
        if ($latest.FaultingModule) {
            $evidenceText += " Candidate faulting module: $($latest.FaultingModule)."
        }

        $finding = [pscustomobject][ordered]@{
            Id             = 'bsod-history-discovered'
            Severity       = $sev
            Confidence     = 'High'
            Title          = ("Historical crash dump detected ({0} dump{1})" -f $crashes.Count, $(if ($crashes.Count -eq 1) { '' } else { 's' }))
            Evidence       = $evidenceText
            Interpretation = 'The system has experienced one or more kernel bugchecks. The dump preserves register and memory state at the moment Windows halted execution; a driver identified on the stack is an active participant or victim, not automatically the ultimate root cause.'
            NextStep       = 'Review the bugcheck code, parameters and faulting stack in the Historical BSOD section; cross-reference with device driver updates or hardware error events.'
        }
        $report.Findings = @($report.Findings) + @($finding)
    }
}

$markdown = ConvertTo-CrashDoctorMarkdown -Report $report
$product = $report.Product
$productHeader = @(
    '## Build provenance',
    '',
    "- Windows Crash Doctor: **$($product.ProductVersion)**",
    "- Engine: **$($product.EngineVersion)**",
    "- Collector: **$($product.CollectorVersion)**",
    "- Rule set: **$($product.RuleSetVersion)**",
    "- Schema: **$($product.SchemaVersion)**",
    "- Diagnostic registry: **$($registry.registryVersion)**",
    "- Commit: ``$($product.Commit)``"
) -join [Environment]::NewLine
$markdown += [Environment]::NewLine + [Environment]::NewLine + $productHeader
if ($null -ne $telemetry -and $telemetry.Available) {
    $telemetryMarkdown = ConvertTo-CrashDoctorTelemetryMarkdownSection -Telemetry $telemetry
    if (-not [string]::IsNullOrWhiteSpace($telemetryMarkdown)) { $markdown += [Environment]::NewLine + [Environment]::NewLine + $telemetryMarkdown }
}
if ($crashes.Count -gt 0) {
    $crashMarkdown = ConvertTo-CrashDoctorCrashHistoryMarkdown -Crashes $crashes
    if (-not [string]::IsNullOrWhiteSpace($crashMarkdown)) { $markdown += [Environment]::NewLine + [Environment]::NewLine + $crashMarkdown }
}

$markdownPath = Join-Path $OutputDirectory 'crash-doctor-report.md'
$jsonPath = Join-Path $OutputDirectory 'crash-doctor-report.json'
$markdown | Out-File -LiteralPath $markdownPath -Encoding utf8 -Width 500
$report | ConvertTo-Json -Depth 14 | Out-File -LiteralPath $jsonPath -Encoding utf8 -Width 500
Write-Host "Crash Doctor report: $markdownPath"
Write-Host "Machine-readable report: $jsonPath"
if ($PassThru) { return $report }
