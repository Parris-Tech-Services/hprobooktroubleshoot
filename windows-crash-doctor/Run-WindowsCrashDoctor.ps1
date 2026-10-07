[CmdletBinding()]
param(
    [string]$OutputRoot = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Windows Doctor Results'),
    [int]$EventHours = 12
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-WcdAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-WcdAdministrator)) {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        throw 'Windows Doctor needs Administrator rights for the full diagnostic collection.'
    }

    $argumentList = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $PSCommandPath),
        '-OutputRoot', ('"{0}"' -f $OutputRoot),
        '-EventHours', [string]$EventHours
    ) -join ' '

    $process = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argumentList -PassThru -Wait
    exit $process.ExitCode
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$collector = Join-Path $repositoryRoot 'scripts\collect-diagnostics.ps1'
$crashDoctor = Join-Path $PSScriptRoot 'Invoke-CrashDoctor.ps1'
$selfTest = Join-Path $PSScriptRoot 'tests\self-test.ps1'
$integrationSelfTest = Join-Path $PSScriptRoot 'tests\integration-self-test.ps1'
$integrationManager = Join-Path $PSScriptRoot 'Manage-Integrations.ps1'

foreach ($required in @($collector, $crashDoctor, $selfTest, $integrationSelfTest, $integrationManager)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required Windows Doctor file is missing: $required"
    }
}

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
$runStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$sessionLog = Join-Path $OutputRoot "CrashDoctor-Run-$runStamp.txt"

function Write-WcdStep {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message
    Write-Host $line -ForegroundColor Cyan
    Add-Content -LiteralPath $sessionLog -Value $line -Encoding UTF8
}

function Invoke-WcdLogged {
    param(
        [Parameter(Mandatory = $true)] [scriptblock]$Action
    )

    & $Action 2>&1 | ForEach-Object {
        $text = $_ | Out-String
        $text = $text.TrimEnd()
        if (-not [string]::IsNullOrWhiteSpace($text)) {
            Write-Host $text
            Add-Content -LiteralPath $sessionLog -Value $text -Encoding UTF8
        }
    }
}

Write-WcdStep 'Windows Doctor one-click test starting.'
Write-WcdStep 'Running built-in regression self-test.'
Invoke-WcdLogged { & $selfTest -RepositoryMode }

Write-WcdStep 'Running integration policy self-test.'
Invoke-WcdLogged { & $integrationSelfTest }

Write-WcdStep 'Collecting a fresh read-only diagnostic snapshot.'
$before = @(
    Get-ChildItem -LiteralPath $OutputRoot -Directory -Filter 'HPProBook-*' -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName
)
Invoke-WcdLogged { & $collector -OutputRoot $OutputRoot -EventHours $EventHours }

$after = @(
    Get-ChildItem -LiteralPath $OutputRoot -Directory -Filter 'HPProBook-*' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
)
$newSnapshot = $after | Where-Object { $_.FullName -notin $before } | Select-Object -First 1
if (-not $newSnapshot) {
    $newSnapshot = $after | Select-Object -First 1
}
if (-not $newSnapshot) {
    throw 'Diagnostic collection completed without creating an HPProBook snapshot folder.'
}

Write-WcdStep ("Analysing snapshot: {0}" -f $newSnapshot.FullName)
Invoke-WcdLogged { & $crashDoctor -EvidencePath $newSnapshot.FullName -OutputDirectory $newSnapshot.FullName }

Write-WcdStep 'Recording optional integration/provider status.'
$providerStatus = Join-Path $newSnapshot.FullName 'integration-status.txt'
& $integrationManager -Action status 2>&1 | Out-File -LiteralPath $providerStatus -Encoding UTF8 -Width 240

$report = Join-Path $newSnapshot.FullName 'crash-doctor-report.md'
$jsonReport = Join-Path $newSnapshot.FullName 'crash-doctor-report.json'
if (-not (Test-Path -LiteralPath $report -PathType Leaf) -or -not (Test-Path -LiteralPath $jsonReport -PathType Leaf)) {
    throw 'Crash Doctor did not produce both Markdown and JSON reports.'
}

Write-WcdStep 'PASS: installation, regression tests, collection and real-machine analysis all completed.'
Write-WcdStep ("Report: {0}" -f $report)

Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f $newSnapshot.FullName) | Out-Null
Start-Process -FilePath 'notepad.exe' -ArgumentList ('"{0}"' -f $report) | Out-Null

Write-Host ''
Write-Host 'Windows Doctor: PASS' -ForegroundColor Green
Write-Host "Your report is here: $report" -ForegroundColor Green
Write-Host 'The results folder and report have been opened for you.'
