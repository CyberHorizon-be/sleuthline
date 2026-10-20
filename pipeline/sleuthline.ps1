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
      check       tests the model: API key, model name and tool calling, with 2 tiny calls
                  (sleuthline.ps1 check [profile]; no case needed)

    Extra options are passed to the script of the step
    (e.g. sleuthline.ps1 parse <case> --only srumecmd --force).

    Memory: a memory image in <case>\memory\ is analyzed with Volatility 3 during parse;
    another location: sleuthline.ps1 parse <case> --memory D:\dumps\host.raw
    Network: the captures in <case>\pcap\ are analyzed with Suricata during parse;
    other files: sleuthline.ps1 parse <case> --pcap D:\captures\day1.pcap --pcap D:\captures\day2.pcap

.EXAMPLE
    C:\Sleuthline\pipeline\sleuthline.ps1 check
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

function Invoke-Step([string]$Name, [string[]]$Extra) {
    $script = Join-Path $pipe $scripts[$Name]
    Write-Host ""
    Write-Host "==== $Name : $($scripts[$Name]) ====" -ForegroundColor Cyan
    & $py $script $Case @Extra
    if ($LASTEXITCODE -ne 0) { throw "$Name ended with code $LASTEXITCODE" }
}

function Get-Python {
    $p = $null
    $cfgPath = Join-Path $root 'sleuthline-config.json'
    if (Test-Path $cfgPath) { $p = (Get-Content $cfgPath -Raw | ConvertFrom-Json).orchestrator_py }
    if (-not $p -or -not (Test-Path $p)) { $p = Join-Path $root 'venvs\orchestrator\Scripts\python.exe' }
    if (-not (Test-Path $p)) { throw "Orchestrator Python not found: $p (run Install-All.ps1)" }
    return $p
}

$cmd = $Command.ToLowerInvariant()
if ($cmd -eq 'check') {
    # No case: the second argument, if any, is the profile to test
    $py = Get-Python
    $extra = @('--check-model') + $(if ($Case) { @('--profile', $Case) } else { @() })
    & $py (Join-Path $pipe $scripts['analyze']) @extra
    exit $LASTEXITCODE
}
if ($cmd -in 'help', '-h', '--help' -or (-not $Case)) {
    Get-Help $PSCommandPath -Detailed | Out-String -Width 120 | Write-Host
    return
}
if (-not (Test-Path $Case)) { throw "Case folder not found: $Case" }
$py = Get-Python


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
