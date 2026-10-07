# DebuggerBackend.psm1 - optional Windows Debugger (cdb/DbgEng) backend
# Provides genuine debugger-engine stack unwinding and Microsoft symbol consumption.
# Heuristic raw-stack scans are deliberately kept separate from true debugger frames.

Set-StrictMode -Version Latest

function Get-CrashDoctorCdbPath {
    [CmdletBinding()]
    param()

    $cmd = Get-Command cdb.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -and (Test-Path -LiteralPath $cmd.Source -PathType Leaf)) {
        return $cmd.Source
    }

    $candidates = New-Object System.Collections.Generic.List[string]
    $pf86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
    $pf = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    foreach ($base in @($pf86, $pf)) {
        if ([string]::IsNullOrWhiteSpace($base)) { continue }
        $candidates.Add((Join-Path $base 'Windows Kits\10\Debuggers\x64\cdb.exe'))
        $candidates.Add((Join-Path $base 'Windows Kits\10\Debuggers\x86\cdb.exe'))
    }

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    return $null
}

function ConvertFrom-CrashDoctorCdbOutput {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Output)

    $failureBucket = $null
    $symbolName = $null
    $moduleName = $null
    $imageName = $null
    $exceptionCode = $null
    $threadStacks = New-Object System.Collections.Generic.List[object]
    $currentStack = $null

    foreach ($line in ($Output -split "`r?`n")) {
        if (-not $failureBucket -and $line -match '^\s*FAILURE_BUCKET_ID:\s*(.+?)\s*$') {
            $failureBucket = $Matches[1].Trim()
            continue
        }
        if (-not $symbolName -and $line -match '^\s*SYMBOL_NAME:\s*(.+?)\s*$') {
            $symbolName = $Matches[1].Trim()
            continue
        }
        if (-not $moduleName -and $line -match '^\s*MODULE_NAME:\s*(.+?)\s*$') {
            $moduleName = $Matches[1].Trim()
            continue
        }
        if (-not $imageName -and $line -match '^\s*IMAGE_NAME:\s*(.+?)\s*$') {
            $imageName = $Matches[1].Trim()
            continue
        }
        if (-not $exceptionCode -and $line -match '^\s*EXCEPTION_CODE:\s*(?:\([^)]*\)\s*)?([0-9A-Fa-f]+)') {
            $exceptionCode = ('0x' + $Matches[1].ToUpperInvariant())
            continue
        }

        if ($line -match '^\s*(?<current>\.)?\s*(?<index>\d+)\s+Id:\s+(?<pid>[0-9A-Fa-f]+)\.(?<tid>[0-9A-Fa-f]+)') {
            $tid = [Convert]::ToUInt32($Matches['tid'], 16)
            $currentStack = [pscustomobject][ordered]@{
                ThreadIndex      = [int]$Matches['index']
                ThreadId         = $tid
                IsFaultingThread = [bool]($Matches['current'] -eq '.')
                Rank             = if ($Matches['current'] -eq '.') { 1 } else { 2 }
                Tag              = if ($Matches['current'] -eq '.') { 'DEBUGGER_CURRENT_THREAD' } else { 'DEBUGGER_THREAD' }
                FrameCount       = 0
                TopFrame         = 'NoFrames'
                Method           = 'Cdb/DbgEng'
                IsTrueUnwind     = $true
                Frames           = New-Object System.Collections.Generic.List[object]
            }
            $threadStacks.Add($currentStack)
            continue
        }

        if ($null -ne $currentStack -and $line -match '^\s*(?<frame>[0-9A-Fa-f]{1,3})\s+(?<sp>[0-9A-Fa-f`]{8,20})\s+(?<ret>[0-9A-Fa-f`]{8,20})\s+(?<site>.+?)\s*$') {
            $site = $Matches['site'].Trim()
            if ($site -match '^(?<module>[^!\s]+)!(?<name>\S+)') {
                $frameModule = $Matches['module']
            } elseif ($site -match '^(?<module>[A-Za-z0-9_.-]+)\+0x[0-9A-Fa-f]+') {
                $frameModule = $Matches['module']
            } else {
                $frameModule = 'Unknown'
            }

            $frameNumber = [Convert]::ToInt32($Matches['frame'], 16)
            $sp = '0x' + ($Matches['sp'] -replace '`','').ToUpperInvariant()
            $ret = '0x' + ($Matches['ret'] -replace '`','').ToUpperInvariant()
            $currentStack.Frames.Add([pscustomobject][ordered]@{
                FrameNumber        = $frameNumber
                InstructionPointer = $null
                StackPointer       = $sp
                FramePointer       = $null
                ModuleName         = $frameModule
                Offset             = $null
                Symbol             = $site
                ReturnAddress      = $ret
                SymbolSource       = 'DbgEng'
                IsTrueUnwind       = $true
            })
        }
    }

    foreach ($stack in $threadStacks) {
        $stack.FrameCount = $stack.Frames.Count
        if ($stack.FrameCount -gt 0) {
            $stack.TopFrame = [string]$stack.Frames[0].Symbol
        }
        $stack.Frames = @($stack.Frames)
    }

    return [pscustomobject][ordered]@{
        FailureBucket = $failureBucket
        SymbolName    = $symbolName
        ModuleName    = $moduleName
        ImageName     = $imageName
        ExceptionCode = $exceptionCode
        CallStacks    = @($threadStacks | Sort-Object Rank, ThreadIndex)
    }
}

function Invoke-CrashDoctorDebuggerAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$DumpPath,
        [string]$CdbPath,
        [string]$SymbolCachePath,
        [string]$SymbolServerUrl = 'https://msdl.microsoft.com/download/symbols',
        [int]$TimeoutSeconds = 180
    )

    if (-not (Test-Path -LiteralPath $DumpPath -PathType Leaf)) {
        throw "Dump file does not exist: $DumpPath"
    }

    if ([string]::IsNullOrWhiteSpace($CdbPath)) {
        $CdbPath = Get-CrashDoctorCdbPath
    }
    if ([string]::IsNullOrWhiteSpace($CdbPath) -or -not (Test-Path -LiteralPath $CdbPath -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            Available       = $false
            Success         = $false
            Engine          = 'cdb/DbgEng'
            IsTrueUnwind    = $false
            SymbolsResolved = $false
            CdbPath         = $null
            SymbolPath      = $null
            FailureBucket   = $null
            SymbolName      = $null
            ModuleName      = $null
            ImageName       = $null
            ExceptionCode   = $null
            CallStacks      = @()
            RawOutput       = ''
            Error           = 'cdb.exe (Windows Debugging Tools) is not installed.'
        }
    }

    if ([string]::IsNullOrWhiteSpace($SymbolCachePath)) {
        $SymbolCachePath = if ($env:LOCALAPPDATA) {
            Join-Path $env:LOCALAPPDATA 'WindowsDoctor\Symbols'
        } else {
            Join-Path ([IO.Path]::GetTempPath()) 'WindowsDoctorSymbols'
        }
    }
    New-Item -ItemType Directory -Path $SymbolCachePath -Force | Out-Null

    $resolvedDump = (Resolve-Path -LiteralPath $DumpPath).Path
    $resolvedCdb = (Resolve-Path -LiteralPath $CdbPath).Path
    $server = $SymbolServerUrl.Trim().TrimEnd('/')
    $symbolPath = "srv*$SymbolCachePath*$server"

    $stdoutPath = Join-Path ([IO.Path]::GetTempPath()) ('WcdCdb-' + [guid]::NewGuid().ToString('N') + '.out.txt')
    $stderrPath = Join-Path ([IO.Path]::GetTempPath()) ('WcdCdb-' + [guid]::NewGuid().ToString('N') + '.err.txt')
    $commands = '.echo ===WCD_ANALYZE_BEGIN===; .reload /f ntdll.dll; !analyze -v; .echo ===WCD_STACKS_BEGIN===; ~* kpn; .echo ===WCD_END===; q'

    try {
        $args = @(
            '-z', ('"' + $resolvedDump + '"'),
            '-y', ('"' + $symbolPath + '"'),
            '-c', ('"' + $commands + '"')
        )
        $process = Start-Process -FilePath $resolvedCdb -ArgumentList $args -PassThru -NoNewWindow -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath

        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { & taskkill.exe /PID $process.Id /T /F | Out-Null } catch { }
            return [pscustomobject][ordered]@{
                Available       = $true
                Success         = $false
                Engine          = 'cdb/DbgEng'
                IsTrueUnwind    = $false
                SymbolsResolved = $false
                CdbPath         = $resolvedCdb
                SymbolPath      = $symbolPath
                FailureBucket   = $null
                SymbolName      = $null
                ModuleName      = $null
                ImageName       = $null
                ExceptionCode   = $null
                CallStacks      = @()
                RawOutput       = if (Test-Path $stdoutPath) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
                Error           = "cdb analysis exceeded $TimeoutSeconds seconds."
            }
        }

        $stdout = if (Test-Path -LiteralPath $stdoutPath) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
        $stderr = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
        $combined = ($stdout + [Environment]::NewLine + $stderr).Trim()
        $parsed = ConvertFrom-CrashDoctorCdbOutput -Output $combined
        $stacks = @($parsed.CallStacks)
        $allFrames = @($stacks | ForEach-Object { @($_.Frames) })
        $symbolizedFrames = @($allFrames | Where-Object { $_.Symbol -match '^[^\s!]+![^\s]+' })

        $success = ($combined -match '===WCD_STACKS_BEGIN===') -and ($stacks.Count -gt 0) -and ($allFrames.Count -gt 0)
        return [pscustomobject][ordered]@{
            Available       = $true
            Success         = [bool]$success
            Engine          = 'cdb/DbgEng'
            IsTrueUnwind    = [bool]$success
            SymbolsResolved = [bool]($symbolizedFrames.Count -gt 0)
            CdbPath         = $resolvedCdb
            SymbolPath      = $symbolPath
            FailureBucket   = $parsed.FailureBucket
            SymbolName      = $parsed.SymbolName
            ModuleName      = $parsed.ModuleName
            ImageName       = $parsed.ImageName
            ExceptionCode   = $parsed.ExceptionCode
            CallStacks      = $stacks
            RawOutput       = $combined
            Error           = if ($success) { $null } else { "cdb completed with exit code $($process.ExitCode) but no parseable debugger stack was produced." }
        }
    }
    finally {
        Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

Export-ModuleMember -Function Get-CrashDoctorCdbPath, ConvertFrom-CrashDoctorCdbOutput, Invoke-CrashDoctorDebuggerAnalysis
