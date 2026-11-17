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

    Several hosts: one folder per host in <case>\hosts\ (each laid out like a single-host case:
    kape\, memory\), captures of the whole case in <case>\pcap\. inventory, parse and normalize run
    for each host (then for the case-level captures), normalize then merges everything into
    <case>\db\case.duckdb; analyze and report work on the merged database.
    --host <name> limits inventory / parse / normalize to one host (the merge still runs).

.EXAMPLE
    C:\Sleuthline\pipeline\sleuthline.ps1 check
.EXAMPLE
    C:\Sleuthline\pipeline\sleuthline.ps1 all C:\Sleuthline\cases\test01
.EXAMPLE
    C:\Sleuthline\pipeline\sleuthline.ps1 analyze C:\Sleuthline\cases\test01 --profile claude-sonnet
.EXAMPLE
    C:\Sleuthline\pipeline\sleuthline.ps1 parse C:\Sleuthline\cases\case05 --host CITADEL-DC01
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
$mergeScript = '3_normalize\merge.py'

function Invoke-Script([string]$Name, [string]$Rel, [string]$Target, [string[]]$Extra, [string]$Label) {
    $script = Join-Path $pipe $Rel
    Write-Host ""
    Write-Host "==== $Name$Label : $Rel ====" -ForegroundColor Cyan
    & $py $script $Target @Extra
    if ($LASTEXITCODE -ne 0) { throw "$Name$Label ended with code $LASTEXITCODE" }
}

function Test-CaseCaptures {
    $d = Join-Path $Case 'pcap'
    return [bool](Test-Path $d) -and [bool](Get-ChildItem $d -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -match '^\.(pcap|pcapng|cap)$' } | Select-Object -First 1)
}

function Invoke-Step([string]$Name, [string[]]$Extra) {
    # Single-host case, or analysis of a multi-host case (merged database): the case folder itself
    if (-not $hostDirs -or $Name -eq 'analyze') {
        Invoke-Script $Name $scripts[$Name] $Case $Extra ''
        return
    }
    foreach ($h in $hostDirs) {
        if ($onlyHost -and $h.Name -ne $onlyHost) { continue }
        Invoke-Script $Name $scripts[$Name] $h.FullName $Extra " [host $($h.Name)]"
    }
    # Captures of the whole case (<case>\pcap\): processed once, at case level
    if (-not $onlyHost -and (Test-CaseCaptures)) {
        $e = $Extra
        if ($Name -eq 'normalize') { $e = @('--db', (Join-Path $Case 'db\network.duckdb')) + $Extra }
        Invoke-Script $Name $scripts[$Name] $Case $e ' [case-level captures]'
    }
    if ($Name -eq 'normalize') { Invoke-Script 'merge' $mergeScript $Case @() ' [hosts -> case database]' }
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

# Several hosts: <case>\hosts\<host>\ ; --host <name> limits inventory / parse / normalize to one host
$onlyHost = $null
$rest = @()
for ($i = 0; $i -lt $Options.Count; $i++) {
    if ($Options[$i] -eq '--host') {
        if ($i + 1 -ge $Options.Count) { throw '--host needs a host name (folder of <case>\hosts\)' }
        $onlyHost = $Options[$i + 1]; $i++
    } else { $rest += $Options[$i] }
}
$Options = $rest
$hostsDir = Join-Path $Case 'hosts'
$hostDirs = @(if (Test-Path $hostsDir) { Get-ChildItem $hostsDir -Directory | Sort-Object Name })
if ($onlyHost -and -not ($hostDirs | Where-Object { $_.Name -eq $onlyHost })) {
    throw "Host not found: $hostsDir\$onlyHost"
}
if ($hostDirs) { Write-Host "Multi-host case: $(($hostDirs | ForEach-Object Name) -join ', ')" -ForegroundColor Cyan }


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
