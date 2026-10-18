<#
.SYNOPSIS
    Sleuthline launcher: one command per step, or everything at once.

.DESCRIPTION
    sleuthline.ps1 <command> <case folder> [step options]

    Commands:
      inventory   1. inventory of the collection and artifact coverage
      parse       2. parsing by the tools (orchestrator)
      normalize   3. loading into DuckDB (timeline, detections, hash lists)
      analyze     4. analysis by the agent + Word report
      ask         one-off question to the agent: sleuthline.ps1 ask <case> "text"
      report      regenerate the Word report without calling the model
      all         1 -> 2 -> 3 -> 4 in a row (stops at the first error)

    Extra options are passed to the script of the step
    (e.g. sleuthline.ps1 parse <case> --only srumecmd --force).

.EXAMPLE
    C:\Sleuthline\pipeline\sleuthline.ps1 all C:\Sleuthline\cases\test01
.EXAMPLE
    C:\Sleuthline\pipeline\sleuthline.ps1 analyze C:\Sleuthline\cases\test01 --profile claude-sonnet
#>
param(
    [Parameter(Position = 0)][string]$Command = 'help',
    [Parameter(Position = 1)][string]$Case,
    [Parameter(Position = 2, ValueFromRemainingArguments = $true)][string[]]$Options
)

$ErrorActionPreference = 'Stop'
$env:PYTHONUTF8 = '1'; $env:PYTHONIOENCODING = 'utf-8'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

$pipe = $PSScriptRoot
$root = Split-Path $pipe -Parent
$scripts = [ordered]@{
    inventory = '1_inventory\inventory.py'
    parse     = '2_parsing\orchestrator.py'
    normalize = '3_normalize\normalize.py'
    analyze   = '4_analysis\analyze.py'
}
# Command names of the first (French) version, still accepted
$aliases = @{ inventaire = 'inventory'; parsing = 'parse'; normalisation = 'normalize'; analyse = 'analyze'
              question = 'ask'; rapport = 'report'; tout = 'all'; aide = 'help' }

function Invoke-Step([string]$Name, [string[]]$Extra) {
    $script = Join-Path $pipe $scripts[$Name]
    Write-Host ""
    Write-Host "==== $Name : $($scripts[$Name]) ====" -ForegroundColor Cyan
    & $py $script $Case @Extra
    if ($LASTEXITCODE -ne 0) { throw "$Name ended with code $LASTEXITCODE" }
}

$cmd = $Command.ToLowerInvariant()
if ($aliases.ContainsKey($cmd)) { $cmd = $aliases[$cmd] }
if ($cmd -in 'help', '-h', '--help' -or (-not $Case)) {
    Get-Help $PSCommandPath -Detailed | Out-String -Width 120 | Write-Host
    return
}
if (-not (Test-Path $Case)) { throw "Case folder not found: $Case" }
$py = $null
foreach ($name in 'sleuthline-config.json', 'dfir-config.json') {
    $cfgPath = Join-Path $root $name
    if (-not $py -and (Test-Path $cfgPath)) { $py = (Get-Content $cfgPath -Raw | ConvertFrom-Json).orchestrator_py }
}
if (-not $py -or -not (Test-Path $py)) { $py = Join-Path $root 'venvs\orchestrator\Scripts\python.exe' }
if (-not (Test-Path $py)) { throw "Orchestrator Python not found: $py (run Install-All.ps1)" }


switch ($cmd) {
    { $_ -in $scripts.Keys } { Invoke-Step $cmd $Options }
    'ask' {
        if (-not $Options) { throw 'Usage: sleuthline.ps1 ask <case> "text of the question"' }
        Invoke-Step 'analyze' @('--ask', ($Options -join ' '))
    }
    'report' { Invoke-Step 'analyze' (@('--report-only') + $Options) }
    'all' {
        foreach ($n in $scripts.Keys) { Invoke-Step $n @() }
    }
    default { throw "Unknown command: $Command (see sleuthline.ps1 help)" }
}
