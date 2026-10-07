[CmdletBinding()]
param(
    [string]$Root = $(if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolvedRoot = (Resolve-Path -LiteralPath $Root).Path
$textExtensions = @(
    '.md', '.txt', '.csv', '.ps1', '.psm1', '.psd1',
    '.json', '.yml', '.yaml', '.xml', '.html', '.log'
)

$rules = @(
    [pscustomobject]@{
        Name = 'BitLocker 48-digit recovery password'
        Pattern = '\b\d{6}(?:-\d{6}){7}\b'
    }
)

$violations = New-Object System.Collections.Generic.List[object]

Get-ChildItem -LiteralPath $resolvedRoot -Recurse -File -Force |
    Where-Object {
        $_.FullName -notmatch '[\\/]\.git[\\/]' -and
        $textExtensions -contains $_.Extension.ToLowerInvariant()
    } |
    ForEach-Object {
        $path = $_.FullName
        $relativePath = $path.Substring($resolvedRoot.Length).TrimStart('\', '/')
        $lineNumber = 0

        foreach ($line in Get-Content -LiteralPath $path -ErrorAction Stop) {
            $lineNumber++
            foreach ($rule in $rules) {
                if ($line -match $rule.Pattern) {
                    $violations.Add([pscustomobject]@{
                        Rule = $rule.Name
                        File = $relativePath
                        Line = $lineNumber
                    })
                }
            }
        }
    }

if ($violations.Count -gt 0) {
    Write-Host 'Public evidence guard: FAILED'
    $violations | Format-Table -AutoSize | Out-String | Write-Host
    throw "Public evidence guard found $($violations.Count) possible secret(s)."
}

Write-Host 'Public evidence guard: PASS'
