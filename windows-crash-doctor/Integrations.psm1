Set-StrictMode -Version Latest

function Get-WcdIntegrationCatalog {
    [CmdletBinding()]
    param()

    $path = Join-Path $PSScriptRoot 'integrations\catalog.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Integration catalog is missing: $path"
    }

    $catalog = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json
    return @($catalog.integrations)
}

function Get-WcdIntegration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Id
    )

    $entry = @(Get-WcdIntegrationCatalog | Where-Object { $_.id -eq $Id })
    if ($entry.Count -ne 1) {
        throw "Unknown integration id: $Id"
    }

    return $entry[0]
}

function Get-WcdToolRoot {
    [CmdletBinding()]
    param(
        [string]$ToolRoot
    )

    if (-not [string]::IsNullOrWhiteSpace($ToolRoot)) {
        return [System.IO.Path]::GetFullPath($ToolRoot)
    }

    $base = $env:LOCALAPPDATA
    if ([string]::IsNullOrWhiteSpace($base)) {
        $base = [Environment]::GetFolderPath('LocalApplicationData')
    }
    if ([string]::IsNullOrWhiteSpace($base)) {
        $base = $PSScriptRoot
    }

    return (Join-Path $base 'WindowsCrashDoctor\Tools')
}

function Get-WcdIntegrationMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Id,
        [string]$ToolRoot
    )

    $root = Get-WcdToolRoot -ToolRoot $ToolRoot
    $metadataPath = Join-Path (Join-Path $root $Id) 'installation.json'
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        return $null
    }

    try {
        return Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    }
    catch {
        return $null
    }
}

function Resolve-WcdIntegrationExecutable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Id,
        [string]$ToolRoot,
        [switch]$Required
    )

    $entry = Get-WcdIntegration -Id $Id

    if ($Id -eq 'smartmontools') {
        $command = Get-Command 'smartctl.exe' -ErrorAction SilentlyContinue
        if ($command) {
            return $command.Source
        }

        $known = @(
            (Join-Path $env:ProgramFiles 'smartmontools\bin\smartctl.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'smartmontools\bin\smartctl.exe')
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        foreach ($candidate in $known) {
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                return $candidate
            }
        }
    }

    if ($entry.PSObject.Properties.Name -contains 'executableRegex' -and
        -not [string]::IsNullOrWhiteSpace([string]$entry.executableRegex)) {
        $root = Get-WcdToolRoot -ToolRoot $ToolRoot
        $integrationRoot = Join-Path $root $Id
        if (Test-Path -LiteralPath $integrationRoot -PathType Container) {
            $match = Get-ChildItem -LiteralPath $integrationRoot -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match [string]$entry.executableRegex } |
                Select-Object -First 1
            if ($match) {
                return $match.FullName
            }
        }
    }

    if ($Required) {
        throw "Integration '$Id' is not installed or its executable could not be found."
    }

    return $null
}

function Resolve-WcdIntegrationLibrary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Id,
        [string]$ToolRoot,
        [switch]$Required
    )

    $entry = Get-WcdIntegration -Id $Id
    if (-not ($entry.PSObject.Properties.Name -contains 'libraryRegex')) {
        if ($Required) {
            throw "Integration '$Id' does not define a library artifact."
        }
        return $null
    }

    $root = Get-WcdToolRoot -ToolRoot $ToolRoot
    $integrationRoot = Join-Path $root $Id
    if (Test-Path -LiteralPath $integrationRoot -PathType Container) {
        $match = Get-ChildItem -LiteralPath $integrationRoot -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match [string]$entry.libraryRegex } |
            Select-Object -First 1
        if ($match) {
            return $match.FullName
        }
    }

    if ($Required) {
        throw "Integration '$Id' is not installed or its library could not be found."
    }

    return $null
}

function Get-WcdIntegrationStatus {
    [CmdletBinding()]
    param(
        [string]$ToolRoot
    )

    foreach ($entry in Get-WcdIntegrationCatalog) {
        $metadata = Get-WcdIntegrationMetadata -Id $entry.id -ToolRoot $ToolRoot
        $exe = $null
        try {
            $exe = Resolve-WcdIntegrationExecutable -Id $entry.id -ToolRoot $ToolRoot
        }
        catch {
            $exe = $null
        }

        [pscustomobject][ordered]@{
            Id            = $entry.id
            Name          = $entry.name
            Repository    = $entry.repository
            License       = $entry.license
            Tier          = $entry.tier
            Risk          = $entry.risk
            CatalogStatus = $entry.status
            Installed     = [bool]($metadata -or $exe)
            Version       = if ($metadata) { $metadata.Tag } else { $null }
            Executable    = $exe
        }
    }
}

function Install-WcdIntegration {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string]$Id,
        [string]$ToolRoot,
        [switch]$AllowUnverified
    )

    $entry = Get-WcdIntegration -Id $Id
    $supportedModes = @('github-release-zip', 'github-release-file', 'manual-installer-download')
    if ([string]$entry.installMode -notin $supportedModes) {
        throw "Integration '$Id' is catalogued as '$($entry.installMode)' and is intentionally not auto-downloaded."
    }

    if (-not ($entry.PSObject.Properties.Name -contains 'releaseApi') -or
        -not ($entry.PSObject.Properties.Name -contains 'assetRegex')) {
        throw "Integration '$Id' has no verified GitHub release source configured."
    }

    $root = Get-WcdToolRoot -ToolRoot $ToolRoot
    $destination = Join-Path $root $Id
    $headers = @{
        'User-Agent' = 'Windows-Crash-Doctor'
        'Accept'     = 'application/vnd.github+json'
    }

    $release = Invoke-RestMethod -Uri ([string]$entry.releaseApi) -Headers $headers -ErrorAction Stop
    $assets = @($release.assets | Where-Object { $_.name -match [string]$entry.assetRegex })
    if ($assets.Count -ne 1) {
        throw "Expected exactly one release asset for '$Id' matching '$($entry.assetRegex)', found $($assets.Count)."
    }

    $asset = $assets[0]
    $expectedDigest = $null
    if ($asset.PSObject.Properties.Name -contains 'digest' -and
        -not [string]::IsNullOrWhiteSpace([string]$asset.digest) -and
        [string]$asset.digest -match '^sha256:([0-9a-fA-F]{64})$') {
        $expectedDigest = $Matches[1].ToLowerInvariant()
    }

    if (-not $expectedDigest -and -not $AllowUnverified) {
        throw "GitHub does not publish a SHA-256 digest for '$($asset.name)'. Re-run with -AllowUnverified only after independently verifying the upstream asset."
    }

    if (-not $PSCmdlet.ShouldProcess("$($entry.repository) $($release.tag_name)", "Download and stage $($asset.name)")) {
        return
    }

    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $stage = Join-Path $root ('.stage-{0}-{1}' -f $Id, [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null

    try {
        $download = Join-Path $stage $asset.name
        Invoke-WebRequest -Uri $asset.browser_download_url -Headers $headers -OutFile $download -UseBasicParsing -ErrorAction Stop
        $actualHash = (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant()

        if ($expectedDigest -and $actualHash -ne $expectedDigest) {
            throw "SHA-256 mismatch for '$($asset.name)'. Expected $expectedDigest but got $actualHash."
        }

        $payload = Join-Path $stage 'payload'
        New-Item -ItemType Directory -Path $payload -Force | Out-Null

        if ([string]$entry.installMode -eq 'github-release-zip') {
            Expand-Archive -LiteralPath $download -DestinationPath $payload -Force
        }
        else {
            Copy-Item -LiteralPath $download -Destination (Join-Path $payload $asset.name) -Force
        }

        $metadata = [pscustomobject][ordered]@{
            Id               = $Id
            Repository       = $entry.repository
            License          = $entry.license
            Tag              = $release.tag_name
            Asset            = $asset.name
            SourceUrl        = $asset.browser_download_url
            ExpectedSHA256   = $expectedDigest
            ActualSHA256     = $actualHash
            VerifiedByDigest = [bool]$expectedDigest
            InstalledAt      = (Get-Date).ToString('o')
            InstallMode      = $entry.installMode
        }
        $metadata | ConvertTo-Json -Depth 5 | Out-File -LiteralPath (Join-Path $payload 'installation.json') -Encoding utf8

        if (Test-Path -LiteralPath $destination) {
            Remove-Item -LiteralPath $destination -Recurse -Force
        }
        Move-Item -LiteralPath $payload -Destination $destination

        return Get-WcdIntegrationStatus -ToolRoot $root | Where-Object Id -eq $Id
    }
    finally {
        if (Test-Path -LiteralPath $stage) {
            Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-WcdHardwareSensors {
    [CmdletBinding()]
    param(
        [string]$ToolRoot
    )

    $library = Resolve-WcdIntegrationLibrary -Id 'librehardwaremonitor' -ToolRoot $ToolRoot -Required
    $type = [Type]::GetType('LibreHardwareMonitor.Hardware.Computer, LibreHardwareMonitorLib', $false)
    if (-not $type) {
        Add-Type -Path $library -ErrorAction Stop
    }

    $computer = New-Object -TypeName 'LibreHardwareMonitor.Hardware.Computer'
    foreach ($property in @('IsCpuEnabled', 'IsGpuEnabled', 'IsMemoryEnabled', 'IsMotherboardEnabled', 'IsStorageEnabled')) {
        if ($computer.PSObject.Properties.Name -contains $property) {
            $computer.$property = $true
        }
    }

    $results = New-Object System.Collections.Generic.List[object]

    function Read-WcdHardwareNode {
        param($Hardware)

        $Hardware.Update()
        foreach ($sensor in @($Hardware.Sensors)) {
            $results.Add([pscustomobject][ordered]@{
                Timestamp    = (Get-Date).ToString('o')
                HardwareType = [string]$Hardware.HardwareType
                HardwareName = [string]$Hardware.Name
                SensorType   = [string]$sensor.SensorType
                SensorName   = [string]$sensor.Name
                Value        = $sensor.Value
                Min          = $sensor.Min
                Max          = $sensor.Max
                Identifier   = [string]$sensor.Identifier
            })
        }
        foreach ($subHardware in @($Hardware.SubHardware)) {
            Read-WcdHardwareNode -Hardware $subHardware
        }
    }

    try {
        $computer.Open()
        foreach ($hardware in @($computer.Hardware)) {
            Read-WcdHardwareNode -Hardware $hardware
        }
    }
    finally {
        $computer.Close()
    }

    return $results.ToArray()
}

function Start-WcdSensorWatch {
    [CmdletBinding()]
    param(
        [ValidateRange(0.1, 1440)] [double]$DurationMinutes = 30,
        [ValidateRange(1, 300)] [int]$IntervalSeconds = 2,
        [string]$OutputPath,
        [string]$ToolRoot
    )

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path (Get-Location) ('wcd-sensors-{0}.jsonl' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }

    $parent = Split-Path -Parent $OutputPath
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $deadline = (Get-Date).AddMinutes($DurationMinutes)
    $sample = 0
    while ((Get-Date) -lt $deadline) {
        $sample++
        $capturedAt = (Get-Date).ToString('o')
        try {
            foreach ($sensor in @(Get-WcdHardwareSensors -ToolRoot $ToolRoot)) {
                [pscustomobject][ordered]@{
                    Sample       = $sample
                    CapturedAt   = $capturedAt
                    HardwareType = $sensor.HardwareType
                    HardwareName = $sensor.HardwareName
                    SensorType   = $sensor.SensorType
                    SensorName   = $sensor.SensorName
                    Value        = $sensor.Value
                    Min          = $sensor.Min
                    Max          = $sensor.Max
                    Identifier   = $sensor.Identifier
                } | ConvertTo-Json -Compress -Depth 4 | Add-Content -LiteralPath $OutputPath -Encoding utf8
            }
        }
        catch {
            [pscustomobject][ordered]@{
                Sample     = $sample
                CapturedAt = $capturedAt
                Error      = $_.Exception.Message
            } | ConvertTo-Json -Compress | Add-Content -LiteralPath $OutputPath -Encoding utf8
        }
        Start-Sleep -Seconds $IntervalSeconds
    }

    return (Resolve-Path -LiteralPath $OutputPath).Path
}

function Convert-WcdEvtx {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$EvtxPath,
        [string]$OutputPath,
        [ValidateSet('json', 'jsonl', 'xml')] [string]$Format = 'jsonl',
        [string]$ToolRoot
    )

    if (-not (Test-Path -LiteralPath $EvtxPath -PathType Leaf)) {
        throw "EVTX file not found: $EvtxPath"
    }

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = "$EvtxPath.$Format"
    }

    $exe = Resolve-WcdIntegrationExecutable -Id 'evtx' -ToolRoot $ToolRoot -Required
    $args = @('-o', $Format, '-t', '1', '-f', $OutputPath, $EvtxPath)
    & $exe @args
    if ($LASTEXITCODE -ne 0) {
        throw "evtx_dump failed with exit code $LASTEXITCODE."
    }

    return (Resolve-Path -LiteralPath $OutputPath).Path
}

function Invoke-WcdHayabusaTimeline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$EvidencePath,
        [string]$OutputPath,
        [string]$ToolRoot
    )

    if (-not (Test-Path -LiteralPath $EvidencePath -PathType Container)) {
        throw "Evidence directory not found: $EvidencePath"
    }
    if (@(Get-ChildItem -LiteralPath $EvidencePath -Filter '*.evtx' -File -Recurse -ErrorAction SilentlyContinue).Count -eq 0) {
        throw "No EVTX files were found under: $EvidencePath"
    }

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path $EvidencePath 'hayabusa-timeline.csv'
    }

    $exe = Resolve-WcdIntegrationExecutable -Id 'hayabusa' -ToolRoot $ToolRoot -Required
    $exeRoot = Split-Path -Parent $exe
    $oldLocation = Get-Location
    try {
        Set-Location -LiteralPath $exeRoot
        $args = @('csv-timeline', '-d', $EvidencePath, '-o', $OutputPath, '-C', '-q', '-O')
        & $exe @args
        if ($LASTEXITCODE -ne 0) {
            throw "Hayabusa failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Set-Location -LiteralPath $oldLocation
    }

    return (Resolve-Path -LiteralPath $OutputPath).Path
}

function Invoke-WcdOsqueryInventory {
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        [string]$ToolRoot
    )

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path (Get-Location) ('osquery-inventory-{0}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }

    $exe = Resolve-WcdIntegrationExecutable -Id 'osquery' -ToolRoot $ToolRoot -Required
    $queries = [ordered]@{
        system_info = 'select * from system_info;'
        os_version  = 'select * from os_version;'
        drivers     = 'select * from drivers;'
        services    = 'select * from services;'
        programs    = 'select * from programs;'
        processes   = 'select * from processes;'
    }

    $result = [ordered]@{}
    foreach ($name in $queries.Keys) {
        try {
            $raw = (& $exe '--json' $queries[$name] 2>$null | Out-String).Trim()
            if ([string]::IsNullOrWhiteSpace($raw)) {
                $result[$name] = @()
            }
            else {
                $result[$name] = @($raw | ConvertFrom-Json)
            }
        }
        catch {
            $result[$name] = [pscustomobject]@{ Error = $_.Exception.Message }
        }
    }

    [pscustomobject]$result | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $OutputPath -Encoding utf8 -Width 1000
    return (Resolve-Path -LiteralPath $OutputPath).Path
}

function Invoke-WcdSmartctlInventory {
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        [string]$ToolRoot
    )

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path (Get-Location) ('smartctl-inventory-{0}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }

    $exe = Resolve-WcdIntegrationExecutable -Id 'smartmontools' -ToolRoot $ToolRoot -Required
    $scanLines = @(& $exe '--scan-open' 2>$null | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $drives = New-Object System.Collections.Generic.List[object]

    foreach ($line in $scanLines) {
        $spec = (($line -split '#', 2)[0]).Trim()
        if ([string]::IsNullOrWhiteSpace($spec)) {
            continue
        }

        $parts = @($spec -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($parts.Count -eq 0) {
            continue
        }

        $device = $parts[0]
        $extra = @()
        if ($parts.Count -gt 1) {
            $extra = @($parts[1..($parts.Count - 1)])
        }
        $args = @('-x', '-j') + $extra + @($device)

        try {
            $raw = (& $exe @args 2>$null | Out-String).Trim()
            $parsed = if ($raw) { $raw | ConvertFrom-Json } else { $null }
            $drives.Add([pscustomobject][ordered]@{
                Device = $device
                Scan   = $line
                Data   = $parsed
            })
        }
        catch {
            $drives.Add([pscustomobject][ordered]@{
                Device = $device
                Scan   = $line
                Error  = $_.Exception.Message
            })
        }
    }

    [pscustomobject][ordered]@{
        CollectedAt = (Get-Date).ToString('o')
        Smartctl    = $exe
        Drives      = @($drives)
    } | ConvertTo-Json -Depth 20 | Out-File -LiteralPath $OutputPath -Encoding utf8 -Width 2000

    return (Resolve-Path -LiteralPath $OutputPath).Path
}

Export-ModuleMember -Function @(
    'Get-WcdIntegrationCatalog',
    'Get-WcdIntegration',
    'Get-WcdIntegrationStatus',
    'Install-WcdIntegration',
    'Resolve-WcdIntegrationExecutable',
    'Resolve-WcdIntegrationLibrary',
    'Get-WcdHardwareSensors',
    'Start-WcdSensorWatch',
    'Convert-WcdEvtx',
    'Invoke-WcdHayabusaTimeline',
    'Invoke-WcdOsqueryInventory',
    'Invoke-WcdSmartctlInventory'
)
