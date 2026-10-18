<#
.SYNOPSIS
    Sleuthline - writes install\tools-lock.json: the exact versions of the current installation,
    to reinstall it identically (02_Install-Tools.ps1 -Locked / Install-All.ps1 -Locked).

.DESCRIPTION
    For each tool of the manifest (<root>\tools\tools-manifest.json):
      - GitHub release: tag, URL and SHA-256 of each downloaded file;
      - GitHub sources: exact commit (<commit>.zip archive and its SHA-256);
      - EZTools: version and SHA-256 of each .exe (Get-ZimmermanTools always installs the
        latest version: check only);
      - KAPE: SHA-256 of kape.zip.
    For each Python environment (<root>\venvs\*): pip freeze (exact versions, dependencies included).
    For the rule and mapping folders (Hayabusa, Chainsaw, Zircolite, EZTools maps):
    content fingerprint (check only).

    The file is meant to be versioned in git: it describes the reference VM.

.EXAMPLE
    .\install\Export-ToolsLock.ps1
    git add install\tools-lock.json ; git commit -m "Tools lock"
#>
[CmdletBinding()]
param(
    [string]$Root = 'C:\Sleuthline',
    [string]$OutFile,
    [string]$GitHubToken = $env:GITHUB_TOKEN
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
. (Join-Path $PSScriptRoot 'lib\Lock.ps1')
if (-not $OutFile) { $OutFile = Join-Path $PSScriptRoot 'tools-lock.json' }

$ToolsDir = Join-Path $Root 'tools'
$manifestPath = Join-Path $ToolsDir 'tools-manifest.json'
if (-not (Test-Path $manifestPath)) { throw "Manifest not found: $manifestPath (run Install-All.ps1 first)" }
$manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$UserAgent = 'Sleuthline-Installer'
$gh = @{ 'User-Agent' = $UserAgent; 'Accept' = 'application/vnd.github+json' }
if ($GitHubToken) { $gh['Authorization'] = "Bearer $GitHubToken" }

# Tool key (-Only parameter of 02_Install-Tools.ps1)
function Get-ToolKey ($t) {
    if ($t.PSObject.Properties['key'] -and $t.key) { return $t.key }
    return $null
}
function Get-Downloads ($t) {
    $d = [ordered]@{}
    if ($t.PSObject.Properties['downloads'] -and $t.downloads) {
        foreach ($p in $t.downloads.PSObject.Properties) { $d[$p.Name] = $p.Value }
    }
    if ($t.source_url -match '^https?://' -and $t.sha256 -and -not $d.Contains($t.source_url)) { $d[$t.source_url] = $t.sha256 }
    return $d
}

$tools = [ordered]@{}
$notes = @()
foreach ($t in $manifest.tools) {
    $key = Get-ToolKey $t
    if (-not $key -or $key -eq 'Pipeline') { continue }
    $e = [ordered]@{ name = $t.name; version = $t.version; sha256 = $t.sha256 }
    $url = [string]$t.source_url
    if ($key -eq 'EZTools') {
        $e.kind = 'eztools'
        $files = [ordered]@{}
        foreach ($p in $t.executables.PSObject.Properties) {
            if ($p.Value -like '*.exe' -and (Test-Path $p.Value)) {
                $files[$p.Name] = [ordered]@{ version = (Get-Item $p.Value).VersionInfo.FileVersion
                                              sha256  = (Get-FileHash $p.Value -Algorithm SHA256).Hash }
            }
        }
        $e.files = $files
    } elseif ($key -eq 'KAPE') {
        $e.kind = 'kape'
    } elseif ($url -match 'github\.com/[^/]+/[^/]+/releases/download/([^/]+)/') {
        $e.kind = 'release'; $e.release_tag = $Matches[1]; $e.downloads = Get-Downloads $t
    } elseif ($url -match 'github\.com/([^/]+/[^/]+)/archive/(refs/heads/(.+)|([0-9a-f]{40}))\.zip$') {
        $e.kind = 'source'
        $repo = $Matches[1]
        if ($Matches[4]) {
            $e.commit = $Matches[4]; $e.downloads = Get-Downloads $t
        } else {
            # Older manifest: installed from a branch, commit not recorded -> current commit of the branch
            $branch = $Matches[3]
            $sha = (Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/commits/$branch" -Headers $gh).sha
            $zipUrl = "https://github.com/$repo/archive/$sha.zip"
            $tmp = Join-Path $env:TEMP "lock_$($repo -replace '/', '_').zip"
            Invoke-WebRequest -Uri $zipUrl -OutFile $tmp -UseBasicParsing -Headers @{ 'User-Agent' = $UserAgent }
            $e.commit = $sha
            $e.downloads = [ordered]@{ $zipUrl = (Get-FileHash $tmp -Algorithm SHA256).Hash }
            $e.sha256 = $e.downloads[$zipUrl]
            Remove-Item $tmp -Force
            $e.note = "installed from the $branch branch: commit resolved at export time ($(Get-Date -Format 'yyyy-MM-dd')), reinstall with -ForceTools for an exact lock"
            $notes += "${key}: $($e.note)"
        }
    } else {
        $e.kind = 'pip'          # Dissect, plaso, pip fallback: versions in "venvs"
    }
    $tools[$key] = $e
}

# Python environments: exact versions (pip freeze)
$venvs = [ordered]@{}
foreach ($v in Get-ChildItem (Join-Path $Root 'venvs') -Directory) {
    $py = Join-Path $v.FullName 'Scripts\python.exe'
    if (-not (Test-Path $py)) { continue }
    $freeze = & $py -m pip freeze --disable-pip-version-check 2>$null | Where-Object { $_ -and $_ -notmatch '^(-e |#)' }
    $venvs[$v.Name] = @($freeze)
}

# Rule / mapping folders
$trees = [ordered]@{}
foreach ($rel in $script:LockTrees) {
    $h = Get-TreeHash (Join-Path $ToolsDir $rel)
    if ($h) { $trees[$rel] = $h }
}

$cfgPath = Join-Path $Root 'sleuthline-config.json'
$cfg = if (Test-Path $cfgPath) { Get-Content $cfgPath -Raw | ConvertFrom-Json } else { $null }
if (-not $cfg) { throw "sleuthline-config.json not found in $Root (run install\01_Prepare-VM.ps1)" }
$lock = [ordered]@{
    _doc         = 'Exact versions of the reference VM. Produced by install\Export-ToolsLock.ps1; used by Install-All.ps1 -Locked.'
    generated_at = (Get-Date).ToString('o')
    generated_on = $env:COMPUTERNAME
    python       = ((& $cfg.python_base --version 2>&1) -join '')
    tools        = $tools
    venvs        = $venvs
    trees        = $trees
}
$lock | ConvertTo-Json -Depth 8 | Set-Content -Path $OutFile -Encoding UTF8
Write-Host "Lock written: $OutFile ($($tools.Count) tools, $($venvs.Count) Python environments, $($trees.Count) rule folders)" -ForegroundColor Green
foreach ($n in $notes) { Write-Host "  [!] $n" -ForegroundColor Yellow }
