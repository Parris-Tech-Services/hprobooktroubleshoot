Set-StrictMode -Version Latest

# Windows Error Reporting (WER) and LocalDumps diagnostic engine
# Roadmap items addressed:
# - WCD-061 [P0]: Read and index local Windows Error Reporting report stores.
# - WCD-062 [P0]: Parse .wer files, signatures, report IDs, bucket IDs.
# - WCD-063 [P0]: Audit current global and per-application LocalDumps configuration.
# - WCD-064 [P0]: Reversible helper for enabling per-application LocalDumps with user approval.
# - WCD-065 [P0]: Capture and catalogue user-mode crash dumps produced by WER.

function Get-CrashDoctorWerReportStores {
    [CmdletBinding()]
    param(
        [string[]]$CustomStorePaths,
        [int]$MaxReportsPerStore = 100
    )

    $storeTargets = New-Object System.Collections.Generic.List[object]
    if ($CustomStorePaths -and $CustomStorePaths.Count -gt 0) {
        foreach ($p in $CustomStorePaths) {
            if (-not [string]::IsNullOrWhiteSpace($p)) {
                $storeTargets.Add([pscustomobject]@{
                    Path = $p
                    Scope = 'Custom'
                    StoreType = (Split-Path -Leaf $p)
                })
            }
        }
    }
    else {
        if ($env:LOCALAPPDATA) {
            $userArchive = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportArchive'
            $userQueue   = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportQueue'
            $storeTargets.Add([pscustomobject]@{ Path = $userArchive; Scope = 'User'; StoreType = 'ReportArchive' })
            $storeTargets.Add([pscustomobject]@{ Path = $userQueue;   Scope = 'User'; StoreType = 'ReportQueue' })
        }
        if ($env:ProgramData) {
            $progArchive = Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportArchive'
            $progQueue   = Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportQueue'
            $storeTargets.Add([pscustomobject]@{ Path = $progArchive; Scope = 'Machine'; StoreType = 'ReportArchive' })
            $storeTargets.Add([pscustomobject]@{ Path = $progQueue;   Scope = 'Machine'; StoreType = 'ReportQueue' })
        }
    }

    $discoveredStores = New-Object System.Collections.Generic.List[object]
    $allReportDirectories = New-Object System.Collections.Generic.List[object]

    foreach ($target in $storeTargets) {
        $path = [string]$target.Path
        $scope = [string]$target.Scope
        $storeType = [string]$target.StoreType

        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            $discoveredStores.Add([pscustomobject][ordered]@{
                Path        = $path
                Scope       = $scope
                StoreType   = $storeType
                Present     = $false
                Accessible  = $false
                ReportCount = 0
                Error       = 'Store directory does not exist.'
            })
            continue
        }

        try {
            $dirs = @(Get-ChildItem -LiteralPath $path -Directory -ErrorAction Stop)
            $discoveredStores.Add([pscustomobject][ordered]@{
                Path        = $path
                Scope       = $scope
                StoreType   = $storeType
                Present     = $true
                Accessible  = $true
                ReportCount = $dirs.Count
                Error       = $null
            })

            $limitedDirs = if ($dirs.Count -gt $MaxReportsPerStore) { $dirs[0..($MaxReportsPerStore - 1)] } else { $dirs }
            foreach ($d in $limitedDirs) {
                $werFile = Join-Path $d.FullName 'Report.wer'
                $hasWer = Test-Path -LiteralPath $werFile -PathType Leaf
                $allReportDirectories.Add([pscustomobject][ordered]@{
                    StorePath     = $path
                    Scope         = $scope
                    StoreType     = $storeType
                    DirectoryName = $d.Name
                    DirectoryPath = $d.FullName
                    LastModified  = $d.LastWriteTimeUtc.ToString('o')
                    HasReportWer  = $hasWer
                    ReportWerPath = if ($hasWer) { $werFile } else { $null }
                })
            }
        }
        catch {
            $discoveredStores.Add([pscustomobject][ordered]@{
                Path        = $path
                Scope       = $scope
                StoreType   = $storeType
                Present     = $true
                Accessible  = $false
                ReportCount = 0
                Error       = $_.Exception.Message
            })
        }
    }

    return [pscustomobject][ordered]@{
        Stores          = $discoveredStores.ToArray()
        TotalStores     = $discoveredStores.Count
        Reports         = $allReportDirectories.ToArray()
        TotalReportDirs = $allReportDirectories.Count
    }
}

function Get-CrashDoctorWerReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path
    )

    $resolvedPath = $Path
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $candidate = Join-Path $Path 'Report.wer'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $resolvedPath = $candidate
        } else {
            throw "No Report.wer file found in directory '$Path'."
        }
    }

    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
        throw "Report.wer file does not exist: '$resolvedPath'."
    }

    $rawLines = @([System.IO.File]::ReadAllLines($resolvedPath))
    $properties = @{}
    $sigNames = @{}
    $sigValues = @{}
    $dynamicSigNames = @{}
    $dynamicSigValues = @{}
    $loadedModules = New-Object System.Collections.Generic.List[string]
    $files = New-Object System.Collections.Generic.List[string]

    foreach ($line in $rawLines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $eqIndex = $line.IndexOf('=')
        if ($eqIndex -le 0) { continue }
        $key = $line.Substring(0, $eqIndex).Trim()
        $val = $line.Substring($eqIndex + 1).Trim()

        $properties[$key] = $val

        if ($key -match '^Sig\[(\d+)\]\.Name$') {
            $sigNames[$matches[1]] = $val
        }
        elseif ($key -match '^Sig\[(\d+)\]\.Value$') {
            $sigValues[$matches[1]] = $val
        }
        elseif ($key -match '^DynamicSig\[(\d+)\]\.Name$') {
            $dynamicSigNames[$matches[1]] = $val
        }
        elseif ($key -match '^DynamicSig\[(\d+)\]\.Value$') {
            $dynamicSigValues[$matches[1]] = $val
        }
        elseif ($key -match '^LoadedModule\[') {
            $loadedModules.Add($val)
        }
        elseif ($key -match '^(Files\.|AppLargeDump|MemoryDump|DumpFile)') {
            $files.Add($val)
        }
    }

    $eventType = if ($properties.ContainsKey('EventType')) { $properties['EventType'] } else { 'Unknown' }
    $reportId = if ($properties.ContainsKey('ReportIdentifier')) { $properties['ReportIdentifier'] } else { $null }
    $bucketId = if ($properties.ContainsKey('Response.BucketId')) { $properties['Response.BucketId'] }
                elseif ($properties.ContainsKey('Response.BucketTable')) { $properties['Response.BucketTable'] }
                else { $null }

    # EventTime in WER is a Windows FILETIME 64-bit integer
    $eventTimeUtc = $null
    $eventTimeLocal = $null
    if ($properties.ContainsKey('EventTime')) {
        $ftRaw = [int64]0
        if ([int64]::TryParse($properties['EventTime'], [ref]$ftRaw) -and $ftRaw -gt 0) {
            try {
                $dt = [DateTime]::FromFileTimeUtc($ftRaw)
                $eventTimeUtc = $dt.ToString('o')
                $eventTimeLocal = $dt.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
            } catch { }
        }
    }

    # Reconstruct named signatures
    $signatures = [ordered]@{}
    foreach ($idx in ($sigNames.Keys | Sort-Object { [int]$_ })) {
        $n = $sigNames[$idx]
        $v = if ($sigValues.ContainsKey($idx)) { $sigValues[$idx] } else { $null }
        $signatures[$n] = $v
    }

    # Common fields resolution
    $appName = if ($signatures.Contains('Application Name')) { $signatures['Application Name'] }
               elseif ($sigValues.ContainsKey('0')) { $sigValues['0'] }
               elseif ($properties.ContainsKey('AppName')) { $properties['AppName'] }
               else { $null }

    $appVersion = if ($signatures.Contains('Application Version')) { $signatures['Application Version'] }
                  elseif ($sigValues.ContainsKey('1')) { $sigValues['1'] }
                  else { $null }

    $faultModule = if ($signatures.Contains('Fault Module Name')) { $signatures['Fault Module Name'] }
                   elseif ($sigValues.ContainsKey('3')) { $sigValues['3'] }
                   elseif ($properties.ContainsKey('FaultModule')) { $properties['FaultModule'] }
                   else { $null }

    $faultModuleVersion = if ($signatures.Contains('Fault Module Version')) { $signatures['Fault Module Version'] }
                          elseif ($sigValues.ContainsKey('4')) { $sigValues['4'] }
                          else { $null }

    $exceptionCodeRaw = if ($signatures.Contains('Exception Code')) { $signatures['Exception Code'] }
                        elseif ($sigValues.ContainsKey('6')) { $sigValues['6'] }
                        else { $null }

    $exceptionCodeHex = $null
    if (-not [string]::IsNullOrWhiteSpace($exceptionCodeRaw)) {
        $clean = $exceptionCodeRaw.Trim()
        if ($clean.StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) { $clean = $clean.Substring(2) }
        $parsedCode = [uint32]0
        if ([uint32]::TryParse($clean, [Globalization.NumberStyles]::HexNumber, [Globalization.CultureInfo]::InvariantCulture, [ref]$parsedCode)) {
            $exceptionCodeHex = ('0x{0:X8}' -f $parsedCode)
        } else {
            $exceptionCodeHex = $exceptionCodeRaw
        }
    }

    $exceptionOffset = if ($signatures.Contains('Exception Offset')) { $signatures['Exception Offset'] }
                       elseif ($sigValues.ContainsKey('7')) { $sigValues['7'] }
                       else { $null }

    # Discover attached dumps in report folder
    $reportDir = Split-Path -Parent $resolvedPath
    $attachedDumps = New-Object System.Collections.Generic.List[string]
    if (Test-Path -LiteralPath $reportDir -PathType Container) {
        $dumpFiles = @(Get-ChildItem -LiteralPath $reportDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match '(?i)^\.(dmp|mdmp)$' })
        foreach ($df in $dumpFiles) {
            $attachedDumps.Add($df.FullName)
        }
    }

    return [pscustomobject][ordered]@{
        ReportPath          = $resolvedPath
        ReportDirectory     = $reportDir
        EventType           = $eventType
        EventTimeUtc        = $eventTimeUtc
        EventTimeLocal      = $eventTimeLocal
        ReportIdentifier    = $reportId
        BucketId            = $bucketId
        ApplicationName     = $appName
        ApplicationVersion  = $appVersion
        FaultModuleName     = $faultModule
        FaultModuleVersion  = $faultModuleVersion
        ExceptionCode       = $exceptionCodeHex
        ExceptionOffset     = $exceptionOffset
        ProblemSignalingPath= if ($properties.ContainsKey('ProblemSignalingPath')) { $properties['ProblemSignalingPath'] } else { $null }
        TargetAppPath       = if ($properties.ContainsKey('TargetAppPath')) { $properties['TargetAppPath'] } else { $null }
        Signatures          = [pscustomobject]$signatures
        AttachedDumps       = $attachedDumps.ToArray()
        LoadedModulesCount  = $loadedModules.Count
        LoadedModules       = $loadedModules.ToArray()
        RawProperties       = $properties
    }
}

function Get-CrashDoctorLocalDumpsConfig {
    [CmdletBinding()]
    param(
        [string]$RegistryRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
    )

    $globalConfig = $null
    $hasRoot = Test-Path -LiteralPath $RegistryRoot

    $defaultDumpFolder = if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'CrashDumps' } else { 'C:\CrashDumps' }

    if ($hasRoot) {
        $props = Get-ItemProperty -LiteralPath $RegistryRoot -ErrorAction SilentlyContinue
        $dumpTypeNum = if ($null -ne $props.PSObject.Properties['DumpType']) { [int]$props.DumpType } else { 1 }
        $dumpTypeName = switch ($dumpTypeNum) { 0 { 'Custom' } 1 { 'Mini' } 2 { 'Full' } default { "Type$dumpTypeNum" } }
        $folder = if ($null -ne $props.PSObject.Properties['DumpFolder']) { [string]$props.DumpFolder } else { $defaultDumpFolder }
        $count = if ($null -ne $props.PSObject.Properties['DumpCount']) { [int]$props.DumpCount } else { 10 }
        $flags = if ($null -ne $props.PSObject.Properties['CustomDumpFlags']) { [uint32]$props.CustomDumpFlags } else { $null }

        $globalConfig = [pscustomobject][ordered]@{
            Configured      = $true
            RegistryPath    = $RegistryRoot
            DumpFolder      = $folder
            DumpCount       = $count
            DumpType        = $dumpTypeNum
            DumpTypeName    = $dumpTypeName
            CustomDumpFlags = $flags
        }
    }
    else {
        $globalConfig = [pscustomobject][ordered]@{
            Configured      = $false
            RegistryPath    = $RegistryRoot
            DumpFolder      = $defaultDumpFolder
            DumpCount       = 10
            DumpType        = 1
            DumpTypeName    = 'Mini (Windows default)'
            CustomDumpFlags = $null
        }
    }

    # Per-application configurations
    $perAppConfigs = New-Object System.Collections.Generic.List[object]
    if ($hasRoot) {
        $subkeys = @(Get-ChildItem -LiteralPath $RegistryRoot -ErrorAction SilentlyContinue)
        foreach ($sk in $subkeys) {
            $p = Get-ItemProperty -LiteralPath $sk.PSPath -ErrorAction SilentlyContinue
            $dtNum = if ($null -ne $p.PSObject.Properties['DumpType']) { [int]$p.DumpType } else { $globalConfig.DumpType }
            $dtName = switch ($dtNum) { 0 { 'Custom' } 1 { 'Mini' } 2 { 'Full' } default { "Type$dtNum" } }
            $df = if ($null -ne $p.PSObject.Properties['DumpFolder']) { [string]$p.DumpFolder } else { $globalConfig.DumpFolder }
            $dc = if ($null -ne $p.PSObject.Properties['DumpCount']) { [int]$p.DumpCount } else { $globalConfig.DumpCount }
            $dflags = if ($null -ne $p.PSObject.Properties['CustomDumpFlags']) { [uint32]$p.CustomDumpFlags } else { $null }

            $perAppConfigs.Add([pscustomobject][ordered]@{
                ApplicationName = $sk.PSChildName
                RegistryPath    = $sk.Name
                DumpFolder      = $df
                DumpCount       = $dc
                DumpType        = $dtNum
                DumpTypeName    = $dtName
                CustomDumpFlags = $dflags
            })
        }
    }

    # Folder health audit
    $foldersToCheck = New-Object System.Collections.Generic.List[string]
    if ($globalConfig.DumpFolder) { $foldersToCheck.Add($globalConfig.DumpFolder) }
    foreach ($pac in $perAppConfigs) {
        if ($pac.DumpFolder -and -not $foldersToCheck.Contains($pac.DumpFolder)) {
            $foldersToCheck.Add($pac.DumpFolder)
        }
    }

    $folderHealth = New-Object System.Collections.Generic.List[object]
    foreach ($f in $foldersToCheck) {
        $expanded = [Environment]::ExpandEnvironmentVariables($f)
        $exists = Test-Path -LiteralPath $expanded -PathType Container
        $writable = $false
        $freeGb = $null
        $warning = $null

        if ($exists) {
            try {
                $testFile = Join-Path $expanded (".wcd-write-test-" + [guid]::NewGuid().ToString('N'))
                [System.IO.File]::WriteAllText($testFile, 'test')
                [System.IO.File]::Delete($testFile)
                $writable = $true
            } catch {
                $writable = $false
                $warning = "Folder exists but is not writable: $($_.Exception.Message)"
            }

            try {
                $rootDrive = [System.IO.Path]::GetPathRoot($expanded)
                $driveInfo = New-Object System.IO.DriveInfo($rootDrive)
                $freeGb = [math]::Round($driveInfo.AvailableFreeSpace / 1GB, 1)
                if ($freeGb -lt 5.0) {
                    $warning = "Low disk space on volume ($freeGb GB available); crash dump capture may fail or exhaust storage."
                }
            } catch { }
        }
        else {
            $warning = 'Configured dump folder does not currently exist; Windows will create it on first crash if permissions permit.'
        }

        $folderHealth.Add([pscustomobject][ordered]@{
            FolderConfigured = $f
            FolderResolved   = $expanded
            Exists           = $exists
            Writable         = $writable
            FreeSpaceGb      = $freeGb
            Warning          = $warning
        })
    }

    return [pscustomobject][ordered]@{
        GlobalConfig     = $globalConfig
        PerAppConfigs    = $perAppConfigs.ToArray()
        PerAppCount      = $perAppConfigs.Count
        FolderHealth     = $folderHealth.ToArray()
        AuditTimeUtc     = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Set-CrashDoctorLocalDumps {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string]$ExecutableName,
        [string]$DumpFolder,
        [int]$DumpCount = 10,
        [ValidateSet('Mini', 'Full')] [string]$DumpType = 'Mini',
        [string]$RegistryRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps',
        [switch]$PassThru
    )

    $cleanExe = $ExecutableName.Trim()
    if (-not $cleanExe.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase) -and $cleanExe -ne '*') {
        $cleanExe += '.exe'
    }

    $targetKey = if ($cleanExe -eq '*') { $RegistryRoot } else { Join-Path $RegistryRoot $cleanExe }

    $targetFolder = if ([string]::IsNullOrWhiteSpace($DumpFolder)) {
        if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'CrashDumps' } else { 'C:\CrashDumps' }
    } else {
        $DumpFolder
    }

    $dumpTypeVal = if ($DumpType -eq 'Full') { 2 } else { 1 }

    $rollbackCommand = if ($cleanExe -eq '*') {
        "# Revert global LocalDumps settings`r`nRemove-ItemProperty -Path '$RegistryRoot' -Name DumpFolder, DumpCount, DumpType -ErrorAction SilentlyContinue"
    } else {
        "# Revert per-application LocalDumps setting for $cleanExe`r`nRemove-Item -Path '$targetKey' -Recurse -Force -ErrorAction SilentlyContinue"
    }

    if ($PSCmdlet.ShouldProcess($targetKey, "Configure LocalDumps (Folder='$targetFolder', Count=$DumpCount, Type=$DumpType)")) {
        if ($RegistryRoot.StartsWith('HKLM:', [StringComparison]::OrdinalIgnoreCase)) {
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                throw "Configuring LocalDumps in '$targetKey' requires Administrator elevation. Re-run from an elevated console or request UAC."
            }
        }

        if (-not (Test-Path -LiteralPath $targetKey)) {
            New-Item -Path $targetKey -Force | Out-Null
        }

        # Expand environment variables for directory creation if required
        $expandedFolder = [Environment]::ExpandEnvironmentVariables($targetFolder)
        if (-not (Test-Path -LiteralPath $expandedFolder -PathType Container)) {
            New-Item -ItemType Directory -Path $expandedFolder -Force | Out-Null
        }

        Set-ItemProperty -Path $targetKey -Name 'DumpFolder' -Value $targetFolder -Type ExpandString | Out-Null
        Set-ItemProperty -Path $targetKey -Name 'DumpCount' -Value $DumpCount -Type DWord | Out-Null
        Set-ItemProperty -Path $targetKey -Name 'DumpType' -Value $dumpTypeVal -Type DWord | Out-Null

        $result = [pscustomobject][ordered]@{
            Status          = 'Configured'
            Application     = $cleanExe
            RegistryKey     = $targetKey
            DumpFolder      = $targetFolder
            DumpCount       = $DumpCount
            DumpType        = $DumpType
            RollbackCommand = $rollbackCommand
        }

        if ($PassThru) { return $result }
        return
    }
}

function Remove-CrashDoctorLocalDumps {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string]$ExecutableName,
        [string]$RegistryRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps',
        [switch]$PassThru
    )

    $cleanExe = $ExecutableName.Trim()
    if (-not $cleanExe.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase) -and $cleanExe -ne '*') {
        $cleanExe += '.exe'
    }

    $targetKey = if ($cleanExe -eq '*') { $RegistryRoot } else { Join-Path $RegistryRoot $cleanExe }

    if ($PSCmdlet.ShouldProcess($targetKey, "Remove LocalDumps configuration for '$cleanExe'")) {
        if ($RegistryRoot.StartsWith('HKLM:', [StringComparison]::OrdinalIgnoreCase)) {
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                throw "Removing LocalDumps configuration from '$targetKey' requires Administrator elevation."
            }
        }

        if (Test-Path -LiteralPath $targetKey) {
            if ($cleanExe -eq '*') {
                Remove-ItemProperty -Path $RegistryRoot -Name 'DumpFolder', 'DumpCount', 'DumpType', 'CustomDumpFlags' -ErrorAction SilentlyContinue
            } else {
                Remove-Item -Path $targetKey -Recurse -Force | Out-Null
            }
        }

        $result = [pscustomobject][ordered]@{
            Status      = 'Removed'
            Application = $cleanExe
            RegistryKey = $targetKey
        }

        if ($PassThru) { return $result }
        return
    }
}

function Get-CrashDoctorUserModeCrashDumps {
    [CmdletBinding()]
    param(
        [string[]]$SearchFolders,
        [int]$MaxDumps = 50
    )

    $folders = New-Object System.Collections.Generic.List[string]
    if ($SearchFolders -and $SearchFolders.Count -gt 0) {
        foreach ($f in $SearchFolders) {
            if (-not [string]::IsNullOrWhiteSpace($f)) { $folders.Add($f) }
        }
    }
    else {
        # Standard user-mode dump locations
        if ($env:LOCALAPPDATA) {
            $folders.Add((Join-Path $env:LOCALAPPDATA 'CrashDumps'))
        }
        if ($env:ProgramData) {
            $folders.Add((Join-Path $env:ProgramData 'CrashDumps'))
        }
        if ($env:SystemDrive) {
            $folders.Add((Join-Path $env:SystemDrive 'CrashDumps'))
        }

        # Also add configured folders from registry if available
        try {
            $cfg = Get-CrashDoctorLocalDumpsConfig
            if ($cfg.GlobalConfig.DumpFolder) { $folders.Add([Environment]::ExpandEnvironmentVariables($cfg.GlobalConfig.DumpFolder)) }
            foreach ($app in $cfg.PerAppConfigs) {
                if ($app.DumpFolder) { $folders.Add([Environment]::ExpandEnvironmentVariables($app.DumpFolder)) }
            }
        } catch { }
    }

    $dumpFiles = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    $seenPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($folder in $folders) {
        if (-not (Test-Path -LiteralPath $folder -PathType Container)) { continue }
        $files = @(Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match '(?i)^\.(dmp|mdmp)$' })
        foreach ($file in $files) {
            if ($seenPaths.Add($file.FullName)) {
                $dumpFiles.Add($file)
            }
        }
    }

    $dumps = New-Object System.Collections.Generic.List[object]
    foreach ($file in $dumpFiles) {
        $exeName = $null
        $crashTime = $file.LastWriteTimeUtc
        # User-mode dumps created by WER typically follow naming: <app.exe>.<PID>.dmp
        if ($file.Name -match '^(.+?\.exe)\.\d+\.dmp$') {
            $exeName = $matches[1]
        }

        $parsed = $false
        $excCode = $null
        $faultMod = $null
        $arch = $null

        # If DumpParser is available, extract minidump stream headers
        if (Get-Command Get-CrashDoctorDumpInfo -ErrorAction SilentlyContinue) {
            try {
                $dumpInfo = Get-CrashDoctorDumpInfo -Path $file.FullName
                $parsed = $true
                $arch = $dumpInfo.Architecture
                if ($dumpInfo.Exception) {
                    $excCode = ('0x{0:X8}' -f [uint32]$dumpInfo.Exception.ExceptionCode)
                }
                if ($dumpInfo.PSObject.Properties.Name -contains 'FaultingModule') {
                    $faultMod = $dumpInfo.FaultingModule
                }
            } catch { }
        }

        $dumpFormat = if ($parsed -and $null -ne $dumpInfo.PSObject.Properties['Format']) { [string]$dumpInfo.Format } else { 'MiniDump' }
        $threadCnt = if ($parsed -and $null -ne $dumpInfo.PSObject.Properties['ThreadCount']) { [int]$dumpInfo.ThreadCount } else { $null }
        $modCnt = if ($parsed -and $null -ne $dumpInfo.PSObject.Properties['ModuleCount']) { [int]$dumpInfo.ModuleCount } else { $null }
        $candDrivers = if ($parsed -and $null -ne $dumpInfo.PSObject.Properties['StackDrivers']) { @($dumpInfo.StackDrivers) } else { @() }
        $probClass = if ($parsed -and $null -ne $dumpInfo.PSObject.Properties['ProblemClassification']) { $dumpInfo.ProblemClassification } else { $null }

        $dumps.Add([pscustomobject][ordered]@{
            Path                  = $file.FullName
            FileName              = $file.Name
            FileSize              = $file.Length
            CrashTimeUtc          = $crashTime.ToString('o')
            CrashTimeLocal        = $crashTime.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
            Application           = $exeName
            DumpType              = $dumpFormat
            ExceptionCode         = $excCode
            FaultingModule        = $faultMod
            Architecture          = $arch
            ThreadCount           = $threadCnt
            ModuleCount           = $modCnt
            CandidateDrivers      = $candDrivers
            ProblemClassification = $probClass
            Parsed                = $parsed
        })
    }

    $sorted = @($dumps | Sort-Object { [datetime]$_.CrashTimeUtc } -Descending)
    if ($sorted.Count -gt $MaxDumps) {
        $sorted = $sorted[0..($MaxDumps - 1)]
    }
    return $sorted
}

function ConvertTo-CrashDoctorWerMarkdown {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $StoresReport,
        $LocalDumpsConfig,
        [object[]]$UserModeDumps = @()
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# Windows Doctor Windows Error Reporting (WER) diagnostic summary')
    $lines.Add('')

    # Section 1: Store Inventory
    $lines.Add('## WER report store status')
    $lines.Add('')
    $lines.Add('| Scope | Store Type | Path | Present | Accessible | Report Count |')
    $lines.Add('|---|---|---|---|---|---:|')
    foreach ($s in @($StoresReport.Stores)) {
        $p = '`{0}`' -f $s.Path
        $lines.Add(('| {0} | {1} | {2} | {3} | {4} | {5} |' -f $s.Scope, $s.StoreType, $p, $s.Present, $s.Accessible, $s.ReportCount))
    }
    $lines.Add('')
    $lines.Add(('- Total indexed report directories: **{0}**' -f $StoresReport.TotalReportDirs))
    $lines.Add('')

    # Section 2: LocalDumps configuration
    if ($LocalDumpsConfig) {
        $lines.Add('## LocalDumps crash-capture configuration')
        $lines.Add('')
        $gc = $LocalDumpsConfig.GlobalConfig
        $cfgStatus = if ($gc.Configured) { 'Configured in Registry' } else { 'Not configured (using system defaults)' }
        $lines.Add(('- **Global configuration:** {0}' -f $cfgStatus))
        $lines.Add(('- **Default dump folder:** `{0}`' -f $gc.DumpFolder))
        $lines.Add(('- **Default dump count:** {0}' -f $gc.DumpCount))
        $lines.Add(('- **Default dump type:** {0}' -f $gc.DumpTypeName))
        $lines.Add(('- **Per-application configurations:** {0}' -f $LocalDumpsConfig.PerAppCount))
        $lines.Add('')

        if ($LocalDumpsConfig.PerAppCount -gt 0) {
            $lines.Add('| Application | Dump Folder | Count | Type |')
            $lines.Add('|---|---|---:|---|')
            foreach ($pa in @($LocalDumpsConfig.PerAppConfigs)) {
                $lines.Add(('| {0} | `{1}` | {2} | {3} |' -f $pa.ApplicationName, $pa.DumpFolder, $pa.DumpCount, $pa.DumpTypeName))
            }
            $lines.Add('')
        }

        if ($LocalDumpsConfig.FolderHealth -and $LocalDumpsConfig.FolderHealth.Count -gt 0) {
            $lines.Add('### Dump folder health')
            $lines.Add('')
            foreach ($fh in @($LocalDumpsConfig.FolderHealth)) {
                $warnText = if ($fh.Warning) { ' (Warning: {0})' -f $fh.Warning } else { '' }
                $lines.Add(('- `{0}`: Exists={1}, Writable={2}, Free={3} GB{4}' -f $fh.FolderConfigured, $fh.Exists, $fh.Writable, $fh.FreeSpaceGb, $warnText))
            }
            $lines.Add('')
        }
    }

    # Section 3: User-mode dumps
    if ($UserModeDumps -and $UserModeDumps.Count -gt 0) {
        $lines.Add('## User-mode crash dumps discovered')
        $lines.Add('')
        $lines.Add('| Date / Time (Local) | Application | Exception | Faulting Module | Dump File | Size |')
        $lines.Add('|---|---|---|---|---|---:|')
        foreach ($d in $UserModeDumps) {
            $app = if ($d.Application) { '`{0}`' -f $d.Application } else { '—' }
            $exc = if ($d.ExceptionCode) { '`{0}`' -f $d.ExceptionCode } else { '—' }
            $mod = if ($d.FaultingModule) { '`{0}`' -f $d.FaultingModule } else { '—' }
            $sizeKb = [math]::Round($d.FileSize / 1024, 0)
            $lines.Add(('| {0} | {1} | {2} | {3} | {4} | {5} KB |' -f $d.CrashTimeLocal, $app, $exc, $mod, $d.FileName, $sizeKb))
        }
        $lines.Add('')
    }

    return ($lines -join [Environment]::NewLine)
}

Export-ModuleMember -Function Get-CrashDoctorWerReportStores, Get-CrashDoctorWerReport, Get-CrashDoctorLocalDumpsConfig, Set-CrashDoctorLocalDumps, Remove-CrashDoctorLocalDumps, Get-CrashDoctorUserModeCrashDumps, ConvertTo-CrashDoctorWerMarkdown
