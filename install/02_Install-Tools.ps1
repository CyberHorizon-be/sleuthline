<#
.SYNOPSIS
    Sleuthline - step 2: installs every DFIR parsing tool used by the analysis pipeline.

.DESCRIPTION
    Downloads the LATEST version of each tool (through the GitHub API, no hard-coded
    version number) and installs it under <root>\tools (default C:\Sleuthline\tools):

      EVTX logs      : Hayabusa (+ rules), Chainsaw (+ mappings), Zircolite (+ rules),
                       SigmaHQ rules, EvtxECmd (through EZTools, + maps)
      Artifacts      : full EZTools (MFTECmd, PECmd, RECmd + Kroll batch,
                       AmcacheParser, AppCompatCacheParser, RecentFileCacheParser,
                       LECmd, JLECmd, RBCmd, SBECmd, SrumECmd, SumECmd, WxTCmd...)
      Complementary  : LogFileParser ($LogFile), SIDR (Windows Search),
                       BitsParser (BITS), WMI_Forensics (WMI persistence),
                       Hindsight (Chrome/Edge), bmc-tools (RDP bitmap cache)
      Frameworks     : Dissect (IE/legacy Edge WebCache, scheduled tasks, Defender,
                       PowerShell, WER...), plaso (setupapi, PCA), odl.py (OneDrive)
      Memory         : Volatility 3 (memory image of the case, <case>\memory\)
      Network        : Suricata + suricata-update / ET Open rules (captures of the case, <case>\pcap\)
      Optional       : KAPE (to be provided as a zip, download requires registration)
      Pipeline       : deploys <repository>\pipeline\ (inventory, orchestrator, normalization,
                       analysis agent, parser registry, complementary RECmd batch
                       config\recmd\Sleuthline_Complement.reb) to <root>\pipeline\ - at every run

    Writes <root>\tools\tools-manifest.json: version, path, source URL and SHA-256
    of every downloaded archive (traceability / reproducibility).

    Idempotent: a tool already installed is skipped, unless -Force is used.

.PARAMETER Root
    Installation root (default: C:\Sleuthline, or the value of sleuthline-config.json).

.PARAMETER Force
    Reinstalls even what is already present (= update to the latest version).

.PARAMETER Only
    Limits the installation to some tools. Values: EZTools, Hayabusa, Chainsaw,
    Sigma, Zircolite, LogFileParser, SIDR, BitsParser, WMIForensics, Hindsight,
    BmcTools, Dissect, Plaso, OneDriveODL, Volatility, Suricata, KAPE, Pipeline.

.PARAMETER KapeZip
    Path to kape.zip (downloaded manually from the Kroll website).
    Default: kape.zip placed in the same folder as this script (<repository>\install).

.PARAMETER SuricataMsi
    Path to a Suricata Windows installer (.msi) downloaded manually. Default: the latest
    Suricata-<version>-<n>-64bit.msi of https://www.openinfosecfoundation.org/download/windows/.

.PARAMETER GitHubToken
    Optional GitHub token (avoids the 60 requests/hour limit of the API).
    Default: GITHUB_TOKEN environment variable.

.PARAMETER Locked
    Reproducible installation: exact versions read from the lock file
    (install\tools-lock.json, produced by install\Export-ToolsLock.ps1) instead of the latest
    versions. Every download is compared with the locked SHA-256 (failure if different),
    Python packages are installed at the locked versions, and rule updates
    (hayabusa update-rules, zircolite -U, --sync of EZTools and KAPE) are not run.
    At the end of the installation, EZTools and the rule folders are compared with the lock.

.PARAMETER LockFile
    Lock file (default: tools-lock.json next to this script).

.EXAMPLE
    .\02_Install-Tools.ps1
    .\02_Install-Tools.ps1 -Force                 # update everything
    .\02_Install-Tools.ps1 -Only Hayabusa,Sigma -Force
    .\02_Install-Tools.ps1 -Only Pipeline         # redeploy the pipeline only
    .\02_Install-Tools.ps1 -KapeZip C:\Users\me\Downloads\kape.zip
#>
[CmdletBinding()]
param(
    [string]$Root,
    [switch]$Force,
    [ValidateSet('EZTools', 'Hayabusa', 'Chainsaw', 'Sigma', 'Zircolite', 'LogFileParser',
                 'SIDR', 'BitsParser', 'WMIForensics', 'Hindsight', 'BmcTools',
                 'Dissect', 'Plaso', 'OneDriveODL', 'Volatility', 'Suricata', 'KAPE', 'Pipeline')]
    [string[]]$Only,
    [string]$KapeZip,
    [string]$SuricataMsi,
    [string]$GitHubToken = $env:GITHUB_TOKEN,
    [switch]$Locked,
    [string]$LockFile
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Lock file (-Locked mode)
if (-not $LockFile) { $LockFile = Join-Path $PSScriptRoot 'tools-lock.json' }
$script:Lock = $null
if ($Locked) {
    if (-not (Test-Path $LockFile)) { throw "-Locked mode: lock file not found ($LockFile). Produce it with install\Export-ToolsLock.ps1." }
    $script:Lock = Get-Content $LockFile -Raw -Encoding UTF8 | ConvertFrom-Json
}
$script:Cur = $null        # result of the tool being installed (downloads, lock)
. (Join-Path $PSScriptRoot 'lib\Lock.ps1')
# UTF-8 output of native tools (Hayabusa, pip...) correctly decoded in the console
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
# Python in UTF-8 (otherwise accented characters of its output are badly decoded by the console)
$env:PYTHONUTF8 = '1'; $env:PYTHONIOENCODING = 'utf-8'

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
$DefaultRoot = 'C:\Sleuthline'
$cfg = $null
foreach ($base in @($Root, $DefaultRoot) | Where-Object { $_ }) {
    $p = Join-Path $base 'sleuthline-config.json'
    if (-not $cfg -and (Test-Path $p)) { $cfg = Get-Content $p -Raw | ConvertFrom-Json }
}
if (-not $Root) { $Root = if ($cfg -and $cfg.root) { $cfg.root } else { $DefaultRoot } }

$ToolsDir  = Join-Path $Root 'tools'
$RulesDir  = Join-Path $Root 'rules'
$VenvsDir  = Join-Path $Root 'venvs'
$DlDir     = Join-Path $ToolsDir '_downloads'
foreach ($d in $ToolsDir, $RulesDir, $VenvsDir, $DlDir, (Join-Path $Root 'logs')) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

# --------------------------------------------------------------------------
# Display helpers
# --------------------------------------------------------------------------
function Write-Step ($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok   ($m) { Write-Host "    [OK]   $m" -ForegroundColor Green }
function Write-Warn ($m) { Write-Host "    [WARN] $m" -ForegroundColor Yellow }
function Write-Err  ($m) { Write-Host "    [FAIL] $m" -ForegroundColor Red }
function Write-Info ($m) { Write-Host "    $m" }

# --------------------------------------------------------------------------
# Base Python (for the venvs of the Python tools)
# --------------------------------------------------------------------------
function Get-PythonExe {
    if ($cfg -and $cfg.python_base -and (Test-Path $cfg.python_base)) { return $cfg.python_base }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        try {
            $p = & py -3.12 -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $p -and (Test-Path $p.Trim())) { return $p.Trim() }
        } catch {}
    }
    foreach ($c in "$env:ProgramFiles\Python312\python.exe", "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe") {
        if (Test-Path $c) { return $c }
    }
    return $null
}
$PythonExe = Get-PythonExe
$SevenZip  = "$env:ProgramFiles\7-Zip\7z.exe"

# --------------------------------------------------------------------------
# Download helpers
# --------------------------------------------------------------------------
$UserAgent = 'Sleuthline-Installer'
$GhHeaders = @{ 'User-Agent' = $UserAgent; 'Accept' = 'application/vnd.github+json' }
if ($GitHubToken) { $GhHeaders['Authorization'] = "Bearer $GitHubToken" }

function Get-LockEntry {
    if (-not $script:Lock -or -not $script:Cur) { return $null }
    $e = $script:Lock.tools.PSObject.Properties[$script:Cur.key]
    if ($e) { return $e.Value }
    throw "-Locked mode: tool '$($script:Cur.key)' missing from the lock file"
}

function Get-GitHubLatestRelease ([string]$Repo) {
    $le = Get-LockEntry
    if ($le -and $le.release_tag) {
        # Locked version: exact release (not the latest one)
        return Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/tags/$($le.release_tag)" -Headers $GhHeaders
    }
    Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $GhHeaders
}

# Returns the first asset of the latest release matching the patterns (in order)
function Get-GitHubAsset ([string]$Repo, [string[]]$Patterns) {
    $rel = Get-GitHubLatestRelease $Repo
    foreach ($pat in $Patterns) {
        $a = $rel.assets | Where-Object { $_.name -match $pat } | Select-Object -First 1
        if ($a) { return [pscustomobject]@{ Tag = $rel.tag_name; Name = $a.name; Url = $a.browser_download_url } }
    }
    $names = ($rel.assets | ForEach-Object { $_.name }) -join ', '
    throw "No asset of $Repo ($($rel.tag_name)) matches [$($Patterns -join ' | ')]. Available: $names"
}

function Save-File ([string]$Url, [string]$FileName) {
    $dest = Join-Path $DlDir $FileName
    Write-Info "Downloading: $Url"
    $h = @{ 'User-Agent' = $UserAgent }
    $le = Get-LockEntry
    # EZTools: Get-ZimmermanTools.zip is only a bootstrap script (always the latest version);
    # the installed .exe files are what is compared with the lock (Compare-InstallToLock)
    if ($le -and $le.kind -eq 'eztools') { $le = $null }
    if ($le) {
        $expected = $null
        if ($le.downloads) { $p = $le.downloads.PSObject.Properties[$Url]; if ($p) { $expected = $p.Value } }
        if (-not $expected) { throw "-Locked mode: URL not locked for $($script:Cur.key): $Url" }
    }
    Invoke-WebRequest -Uri $Url -OutFile $dest -UseBasicParsing -Headers $h
    $sha = (Get-FileHash $dest -Algorithm SHA256).Hash
    if ($le -and $sha -ne $expected) {
        throw "-Locked mode: SHA-256 differs from the lock for $Url (expected $expected, got $sha)"
    }
    if ($script:Cur) { $script:Cur.downloads[$Url] = $sha }        # traceability: every downloaded file
    [pscustomobject]@{ Path = $dest; Sha256 = $sha }
}

# Source archive of a repository at a precise commit (not "the branch of the moment"): the commit of
# main / master is resolved through the GitHub API, or read from the lock in -Locked mode.
function Save-SourceZip ([string]$Repo) {
    $safe = $Repo -replace '/', '_'
    $le = Get-LockEntry
    if ($le -and $le.commit) {
        $url = "https://github.com/$Repo/archive/$($le.commit).zip"
        $f = Save-File $url "$safe-$($le.commit.Substring(0, 12)).zip"
        $f | Add-Member -NotePropertyName Ref -NotePropertyValue "commit $($le.commit.Substring(0, 12))"
        $f | Add-Member -NotePropertyName Commit -NotePropertyValue $le.commit
        $f | Add-Member -NotePropertyName Url -NotePropertyValue $url
        return $f
    }
    $lastError = $null
    foreach ($branch in 'main', 'master') {
        try {
            $sha = (Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/commits/$branch" -Headers $GhHeaders).sha
            $url = "https://github.com/$Repo/archive/$sha.zip"
            $f = Save-File $url "$safe-$($sha.Substring(0, 12)).zip"
        } catch { $lastError = $_.Exception.Message; continue }     # missing branch or failed download: next branch
        $f | Add-Member -NotePropertyName Ref -NotePropertyValue "$branch @ $($sha.Substring(0, 12))"
        $f | Add-Member -NotePropertyName Commit -NotePropertyValue $sha
        $f | Add-Member -NotePropertyName Url -NotePropertyValue $url
        if ($script:Cur) { $script:Cur.commit = $sha }
        return $f
    }
    throw "Cannot download the sources of $Repo ($lastError)"
}

# Extracts an archive; if it contains a single root folder, its content is moved up.
# 7-Zip + robocopy (handle paths > 260 characters, unlike Expand-Archive in PowerShell 5.1);
# short temporary folder under the root (covered by the Defender exclusion).
function Expand-Flat ([string]$Archive, [string]$Dest) {
    $tmp = Join-Path $DlDir ('_x' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        if (Test-Path $SevenZip) {
            & $SevenZip x $Archive "-o$tmp" -y -bso0 -bsp0 | Out-Null
            if ($LASTEXITCODE -gt 1) { throw "7-Zip failed on $Archive (code $LASTEXITCODE)" }
        } elseif ($Archive -match '\.zip$') {
            Expand-Archive -Path $Archive -DestinationPath $tmp -Force
        } else { throw "Format not handled without 7-Zip: $Archive" }

        $items = @(Get-ChildItem -LiteralPath $tmp -Force)
        $src = if ($items.Count -eq 1 -and $items[0].PSIsContainer) { $items[0].FullName } else { $tmp }
        New-Item -ItemType Directory -Force -Path $Dest | Out-Null
        & robocopy.exe $src $Dest /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($src -> $Dest, code $LASTEXITCODE)" }
        $global:LASTEXITCODE = 0
    } finally {
        try { & cmd.exe /c rd /s /q "\\?\$tmp" | Out-Null } catch {}
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Find-First ([string]$Dir, [string]$Filter) {
    Get-ChildItem -Path $Dir -Filter $Filter -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
}

# Runs a native command: its output (stdout + stderr) goes to the console and the log,
# without ErrorActionPreference=Stop turning a message on stderr into a blocking error
# (PowerShell 5.1 behaviour). Returns the exit code.
function Invoke-Native ([string]$Exe, [string[]]$Arguments) {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Exe @Arguments 2>&1 | ForEach-Object { Write-Host "      $_" }
        return $LASTEXITCODE
    } finally { $ErrorActionPreference = $prevEap }
}

# Dependencies of a Python project: requirements.txt, otherwise [project].dependencies
# of pyproject.toml (Zircolite v4+). Returns the path of a requirements file or $null.
function Get-PythonRequirements ([string]$ProjectDir) {
    $req = Join-Path $ProjectDir 'requirements.txt'
    if (Test-Path $req) { return $req }
    $pyproject = Join-Path $ProjectDir 'pyproject.toml'
    if ((Test-Path $pyproject) -and $PythonExe) {
        $out = Join-Path $DlDir ('req_' + (Split-Path $ProjectDir -Leaf) + '.txt')
        $code = "import sys, tomllib; d = tomllib.load(open(sys.argv[1], 'rb')); print('\n'.join(d.get('project', {}).get('dependencies', [])))"
        $deps = & $PythonExe -c $code $pyproject
        if ($LASTEXITCODE -eq 0 -and $deps) { $deps | Set-Content -Path $out -Encoding ASCII; return $out }
    }
    return $null
}

function New-ToolVenv ([string]$Name, [string[]]$PipArgs) {
    if (-not $PythonExe) { throw 'Python 3.12 not found. Run 01_Prepare-VM.ps1 first.' }
    $venv = Join-Path $VenvsDir $Name
    if ($Force -and (Test-Path $venv)) { Remove-Item $venv -Recurse -Force }
    if (-not (Test-Path "$venv\Scripts\python.exe")) { & $PythonExe -m venv $venv }
    $vpy = "$venv\Scripts\python.exe"
    & $vpy -m pip install --upgrade pip wheel setuptools --quiet
    if ($script:Lock) {
        # Exact versions of the lock (pip freeze of the reference installation, dependencies included)
        $lp = $script:Lock.venvs.PSObject.Properties[$Name]
        if (-not $lp) { throw "-Locked mode: Python environment '$Name' missing from the lock file" }
        $req = Join-Path $DlDir "lock_$Name.txt"
        @($lp.Value) | Set-Content -Path $req -Encoding ASCII
        & $vpy -m pip install --no-deps -r $req --quiet
        if ($LASTEXITCODE -ne 0) { throw "pip install (locked versions) failed for $Name" }
        return $vpy
    }
    if ($PipArgs) {
        & $vpy -m pip install @PipArgs --quiet
        if ($LASTEXITCODE -ne 0) { throw "pip install failed for $Name ($($PipArgs -join ' '))" }
    }
    return $vpy
}

# --------------------------------------------------------------------------
# Tool state management (idempotence + manifest)
# --------------------------------------------------------------------------
$Results = New-Object System.Collections.Generic.List[object]
$script:ExitCode = 0

function New-Result ($Name, $Category, [bool]$Required, $Key = $null) {
    [ordered]@{
        key = $Key; name = $Name; category = $Category; required = $Required
        status = 'PENDING'; version = $null; path = $null
        source_url = $null; sha256 = $null; executables = @{}; notes = @()
        downloads = @{}; commit = $null; file_versions = @{}; installed_at = $null
    }
}

function Test-AlreadyInstalled ([string]$Dir) {
    $m = Join-Path $Dir '.installed.json'
    if (-not $Force -and (Test-Path $m)) { return (Get-Content $m -Raw | ConvertFrom-Json) }
    return $null
}

function Save-Marker ([string]$Dir, $Result) {
    $Result.installed_at = (Get-Date).ToString('o')
    ($Result | ConvertTo-Json -Depth 5) | Set-Content -Path (Join-Path $Dir '.installed.json') -Encoding UTF8
}

function Reset-ToolDir ([string]$Dir) {
    if (Test-Path $Dir) { Remove-Item $Dir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
}

# Runs an installation block with uniform error handling
function Invoke-ToolInstall ([string]$Key, [string]$Name, [string]$Category, [bool]$Required, [string]$Dir, [scriptblock]$Body) {
    if ($Only -and ($Only -notcontains $Key)) { return }
    Write-Step $Name
    $r = New-Result $Name $Category $Required $Key
    $r.path = $Dir
    $script:Cur = $r

    $prev = Test-AlreadyInstalled $Dir
    if ($prev -and $script:Lock) {
        # -Locked mode: an installed tool is only kept if it matches the lock
        $le = $script:Lock.tools.PSObject.Properties[$Key]
        if ($le -and (($le.Value.sha256 -and $prev.sha256 -ne $le.Value.sha256) -or
                      (-not $le.Value.sha256 -and $prev.version -ne $le.Value.version))) {
            Write-Warn "Installed version ($($prev.version)) differs from the lock ($($le.Value.version)): reinstalling"
            $prev = $null
        }
    }
    if ($prev) {
        Write-Ok "Already installed ($($prev.version)) - use -Force to update"
        $prev.status = 'OK (existing)'
        $Results.Add($prev)
        return
    }

    try {
        & $Body $r
        if ($r.status -eq 'PENDING') { $r.status = 'OK' }
        if ($r.status -like 'OK*' -or $r.status -eq 'WARN') { Save-Marker $Dir $r }
        if ($r.status -eq 'WARN') { Write-Warn "$Name installed with warnings" } else { Write-Ok "$Name $($r.version)" }
    } catch {
        $r.status = 'FAIL'
        $r.notes += $_.Exception.Message
        Write-Err "${Name}: $($_.Exception.Message)"
    }
    $Results.Add($r)
}

# --------------------------------------------------------------------------
# Log
# --------------------------------------------------------------------------
$log = Join-Path $Root ("logs\02_tools_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $log | Out-Null

try {
    Write-Host "Sleuthline root: $Root"
    if (-not $PythonExe) { Write-Warn 'Python 3.12 not found: the Python tools will fail (run 01_Prepare-VM.ps1).' }
    if (-not $GitHubToken) { Write-Info 'Tip: set GITHUB_TOKEN if you hit the GitHub API rate limit.' }

    # ======================================================================
    # 1. EZTools (Eric Zimmerman) - every Windows artifact parser
    # ======================================================================
    $ezDir = Join-Path $ToolsDir 'EZTools'
    Invoke-ToolInstall 'EZTools' 'EZTools (Eric Zimmerman)' 'artifacts' $true $ezDir {
        param($r)
        Reset-ToolDir $ezDir
        $url = 'https://download.ericzimmermanstools.com/Get-ZimmermanTools.zip'
        $f = Save-File $url 'Get-ZimmermanTools.zip'
        $r.source_url = $url; $r.sha256 = $f.Sha256
        Expand-Archive -Path $f.Path -DestinationPath $ezDir -Force
        $gzt = Join-Path $ezDir 'Get-ZimmermanTools.ps1'
        if (-not (Test-Path $gzt)) { throw 'Get-ZimmermanTools.ps1 missing from the archive' }

        Write-Info 'Running Get-ZimmermanTools.ps1 (.NET 9) - several minutes...'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $gzt -Dest $ezDir -NetVersion 9 | Out-Host

        # Check every expected parser
        $expected = 'MFTECmd', 'PECmd', 'RECmd', 'EvtxECmd', 'AmcacheParser', 'AppCompatCacheParser',
                    'RecentFileCacheParser', 'LECmd', 'JLECmd', 'RBCmd', 'SBECmd', 'SrumECmd',
                    'SumECmd', 'WxTCmd', 'SQLECmd', 'bstrings'
        $missing = @()
        foreach ($t in $expected) {
            $exe = Find-First $ezDir "$t.exe"
            if ($exe) { $r.executables[$t] = $exe.FullName } else { $missing += $t }
        }
        if ($missing) { $r.status = 'WARN'; $r.notes += "Missing parsers: $($missing -join ', ')" }

        # Update of the EvtxECmd maps and the RECmd batches (Kroll_Batch.reb included); not in -Locked mode
        foreach ($t in 'EvtxECmd', 'RECmd', 'SQLECmd') {
            if ($script:Lock) { $r.notes += '--sync not run (-Locked mode): maps compared with the lock at the end of the installation'; break }
            if ($r.executables[$t]) {
                Write-Info "$t --sync"
                Push-Location (Split-Path $r.executables[$t])
                try { & $r.executables[$t] --sync | Out-Null } catch { $r.notes += "$t --sync failed" }
                Pop-Location
            }
        }
        $kroll = Find-First $ezDir 'Kroll_Batch.reb'
        if ($kroll) { $r.executables['RECmd_KrollBatch'] = $kroll.FullName }
        else { $r.status = 'WARN'; $r.notes += 'Kroll_Batch.reb not found (RECmd --sync?)' }

        # Version and hash of EACH parser: Get-ZimmermanTools always installs the latest version,
        # so the only reliable trace of what produced the results is the file version of each .exe
        foreach ($t in $r.executables.Keys) {
            $p = $r.executables[$t]
            if ($p -like '*.exe') {
                $r.file_versions[$t] = [ordered]@{ version = (Get-Item $p).VersionInfo.FileVersion
                                                   sha256  = (Get-FileHash $p -Algorithm SHA256).Hash }
            }
        }
        $r.version = 'latest (' + (Get-Date -Format 'yyyy-MM-dd') + ', net9); MFTECmd ' + $r.file_versions['MFTECmd'].version
    }

    # ======================================================================
    # 2. Hayabusa
    # ======================================================================
    $hbDir = Join-Path $ToolsDir 'hayabusa'
    Invoke-ToolInstall 'Hayabusa' 'Hayabusa' 'evtx' $true $hbDir {
        param($r)
        Reset-ToolDir $hbDir
        # Standard package (not "live-response", whose rules are encoded)
        $a = Get-GitHubAsset 'Yamato-Security/hayabusa' @('^hayabusa-[\d.]+-win-x64\.zip$')
        $f = Save-File $a.Url $a.Name
        $r.version = $a.Tag; $r.source_url = $a.Url; $r.sha256 = $f.Sha256
        Expand-Flat $f.Path $hbDir

        $exe = Get-ChildItem $hbDir -Filter 'hayabusa*.exe' -Recurse | Select-Object -First 1
        if (-not $exe) { throw 'Hayabusa executable not found' }
        $stable = Join-Path $hbDir 'hayabusa.exe'
        if ($exe.FullName -ne $stable) { Copy-Item $exe.FullName $stable -Force }
        $r.executables['hayabusa'] = $stable

        if ($script:Lock) {
            $r.notes += 'update-rules not run (-Locked mode): rules of the release, compared with the lock at the end of the installation'
        } else {
            Write-Info 'hayabusa update-rules'
            Push-Location $hbDir
            try {
                if ((Invoke-Native $stable @('update-rules')) -ne 0) { $r.notes += 'update-rules failed: embedded rules used' }
            } finally { Pop-Location }
        }
        $r.notes += 'Hayabusa v4+: the JSONL timeline is produced with "dfir-timeline -t jsonl"'
    }

    # ======================================================================
    # 3. Chainsaw
    # ======================================================================
    $csDir = Join-Path $ToolsDir 'chainsaw'
    Invoke-ToolInstall 'Chainsaw' 'Chainsaw' 'evtx' $true $csDir {
        param($r)
        Reset-ToolDir $csDir
        $a = Get-GitHubAsset 'WithSecureLabs/chainsaw' @(
            # Without "+examples": useless here, and its EVTX samples (sigma\regression_data)
            # have paths > 260 characters
            'all_platforms\+rules\.zip$',
            'x86_64-pc-windows-msvc\.zip$',
            'windows.*\.zip$',
            'all_platforms\+rules\+examples\.zip$')
        $f = Save-File $a.Url $a.Name
        $r.version = $a.Tag; $r.source_url = $a.Url; $r.sha256 = $f.Sha256
        Expand-Flat $f.Path $csDir

        $exe = Get-ChildItem $csDir -Filter 'chainsaw*.exe' -Recurse |
               Sort-Object { if ($_.Name -match 'windows') { 0 } else { 1 } } | Select-Object -First 1
        if (-not $exe) { throw 'Chainsaw Windows executable not found' }
        $stable = Join-Path $csDir 'chainsaw.exe'
        if ($exe.FullName -ne $stable) { Copy-Item $exe.FullName $stable -Force }
        $r.executables['chainsaw'] = $stable

        # The Sigma mappings are required by "chainsaw hunt --sigma"
        $map = Find-First $csDir 'sigma-event-logs-all.yml'
        if (-not $map) {
            Write-Info 'Mappings missing from the package: fetching them from the sources'
            $src = Save-SourceZip 'WithSecureLabs/chainsaw'
            $tmpSrc = Join-Path $DlDir ('_cs' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            Expand-Flat $src.Path $tmpSrc
            foreach ($sub in 'mappings', 'rules') {
                if (Test-Path "$tmpSrc\$sub") { Copy-Item "$tmpSrc\$sub" $csDir -Recurse -Force }
            }
            try { & cmd.exe /c rd /s /q "\\?\$tmpSrc" | Out-Null } catch {}
            $map = Find-First $csDir 'sigma-event-logs-all.yml'
        }
        if ($map) { $r.executables['chainsaw_mapping'] = $map.FullName }
        else { $r.status = 'WARN'; $r.notes += 'Mapping sigma-event-logs-all.yml not found' }
        $csRules = Join-Path $csDir 'rules'
        if (Test-Path $csRules) { $r.executables['chainsaw_rules'] = $csRules }
    }

    # ======================================================================
    # 4. SigmaHQ rules (used by Chainsaw; common reference)
    # ======================================================================
    $sgDir = Join-Path $RulesDir 'sigma'
    Invoke-ToolInstall 'Sigma' 'SigmaHQ rules' 'rules' $true $sgDir {
        param($r)
        Reset-ToolDir $sgDir
        $a = Get-GitHubAsset 'SigmaHQ/sigma' @('^sigma_all_rules\.zip$', '^sigma_core\+\+\.zip$', '^sigma_core\+\.zip$', '^sigma_core\.zip$')
        $f = Save-File $a.Url $a.Name
        $r.version = $a.Tag; $r.source_url = $a.Url; $r.sha256 = $f.Sha256
        Expand-Flat $f.Path $sgDir
        $count = @(Get-ChildItem $sgDir -Filter '*.yml' -Recurse).Count
        if ($count -eq 0) { throw 'No .yml rule extracted' }
        $r.executables['sigma_rules_dir'] = $sgDir
        $r.notes += "$count rules ($($a.Name))"
    }

    # ======================================================================
    # 5. Zircolite (Python)
    # ======================================================================
    $zcDir = Join-Path $ToolsDir 'zircolite'
    Invoke-ToolInstall 'Zircolite' 'Zircolite' 'evtx' $true $zcDir {
        param($r)
        Reset-ToolDir $zcDir
        $rel = Get-GitHubLatestRelease 'wagga40/Zircolite'
        $r.version = $rel.tag_name

        # 1) Standalone Windows binary (Zircolite v4+): no Python dependency to resolve.
        #    The project dependencies cannot be installed with pip (pysigma<3 override
        #    only handled by uv/PDM).
        $bin = $rel.assets | Where-Object { $_.name -match 'windows-x64\.zip$' } | Select-Object -First 1
        $exe = $null
        if ($bin) {
            $f = Save-File $bin.browser_download_url $bin.name
            $r.source_url = $bin.browser_download_url; $r.sha256 = $f.Sha256
            Expand-Flat $f.Path $zcDir
            $exe = Get-ChildItem $zcDir -Filter 'zircolite*.exe' -Recurse | Select-Object -First 1
        }

        # 2) Release sources: rules / config / templates (if missing from the binary),
        #    and Python fallback if no binary is usable
        $needSrc = (-not $exe) -or -not (Find-First $zcDir 'rules_windows_generic*.json')
        if ($needSrc) {
            $src = Save-File $rel.zipball_url "zircolite-src-$($rel.tag_name).zip"
            $srcDir = Join-Path $zcDir 'src'
            Expand-Flat $src.Path $srcDir
            foreach ($sub in 'rules', 'config', 'templates') {
                if ((Test-Path "$srcDir\$sub") -and -not (Test-Path "$zcDir\$sub")) {
                    & robocopy.exe "$srcDir\$sub" "$zcDir\$sub" /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
                    $global:LASTEXITCODE = 0
                }
            }
            if (-not $r.source_url) { $r.source_url = $rel.zipball_url; $r.sha256 = $src.Sha256 }
        }

        if ($exe) {
            $r.executables['zircolite'] = $exe.FullName
            $r.notes += 'Standalone binary (no venv)'
            $runner = $exe.FullName; $baseArgs = @()
        } else {
            # Fallback: Python installation through uv, which applies the override-dependencies of pyproject
            $main = Find-First $srcDir 'zircolite.py'
            if (-not $main) { throw 'Neither a Windows binary nor zircolite.py available' }
            $vpy = New-ToolVenv 'zircolite' @('uv')
            $uv = Join-Path (Split-Path $vpy) 'uv.exe'
            $ovr = Join-Path $DlDir 'zircolite_overrides.txt'
            $code = "import sys, tomllib; d = tomllib.load(open(sys.argv[1], 'rb')); print('\n'.join(d.get('tool', {}).get('uv', {}).get('override-dependencies', [])))"
            & $vpy -c $code (Join-Path (Split-Path $main.FullName) 'pyproject.toml') | Set-Content $ovr -Encoding ASCII
            $req = Get-PythonRequirements (Split-Path $main.FullName)
            $uvArgs = @('pip', 'install', '--python', $vpy, '-r', $req)
            if ((Get-Item $ovr).Length -gt 2) { $uvArgs += @('--override', $ovr) }
            if ((Invoke-Native $uv $uvArgs) -ne 0) { throw 'uv pip install failed for Zircolite' }
            $r.executables['python'] = $vpy
            $r.executables['zircolite'] = $main.FullName
            $r.notes += 'Python installation (venv + uv): Windows binary unavailable'
            $runner = $vpy; $baseArgs = @($main.FullName)
        }
        $rulesDir = Join-Path $zcDir 'rules'
        if (Test-Path $rulesDir) { $r.executables['zircolite_rules'] = $rulesDir }
        else { $r.status = 'WARN'; $r.notes += 'Rules folder not found' }

        # Start-up test then rules update (not blocking)
        Push-Location $zcDir
        try {
            if ((Invoke-Native $runner ($baseArgs + '--help')) -ne 0) { throw 'zircolite --help fails' }
            if ($script:Lock) {
                $r.notes += 'Rules update (-U) not run (-Locked mode)'
            } else {
                Write-Info 'zircolite -U (rules update)'
                if ((Invoke-Native $runner ($baseArgs + '-U')) -ne 0) {
                    $r.notes += 'Rules update (-U) failed: embedded rules used'
                }
            }
        } finally { Pop-Location }
    }

    # ======================================================================
    # 6. LogFileParser (NTFS $LogFile)
    # ======================================================================
    $lfDir = Join-Path $ToolsDir 'LogFileParser'
    Invoke-ToolInstall 'LogFileParser' 'LogFileParser ($LogFile)' 'artifacts' $false $lfDir {
        param($r)
        Reset-ToolDir $lfDir
        $f = $null
        try {
            $a = Get-GitHubAsset 'jschicht/LogFileParser' @('\.zip$')
            $f = Save-File $a.Url $a.Name; $r.version = $a.Tag; $r.source_url = $a.Url
        } catch {
            $f = Save-SourceZip 'jschicht/LogFileParser'; $r.version = "branch $($f.Ref)"; $r.source_url = $f.Url
        }
        $r.sha256 = $f.Sha256
        Expand-Flat $f.Path $lfDir
        $exe = Get-ChildItem $lfDir -Filter 'LogFileParser64.exe' -Recurse | Select-Object -First 1
        if (-not $exe) { $exe = Get-ChildItem $lfDir -Filter 'LogFileParser*.exe' -Recurse | Select-Object -First 1 }
        if ($exe) { $r.executables['LogFileParser'] = $exe.FullName }
        else { $r.status = 'WARN'; $r.notes += 'No .exe found: AutoIt sources only, compilation required' }
    }

    # ======================================================================
    # 7. SIDR (Windows Search index: Windows.edb / Windows.db)
    # ======================================================================
    $sdDir = Join-Path $ToolsDir 'sidr'
    Invoke-ToolInstall 'SIDR' 'SIDR (Windows Search)' 'artifacts' $false $sdDir {
        param($r)
        Reset-ToolDir $sdDir
        $a = Get-GitHubAsset 'strozfriedberg/sidr' @('windows.*\.zip$', 'win.*\.zip$', '^sidr.*\.exe$', 'windows', 'win')
        $f = Save-File $a.Url $a.Name
        $r.version = $a.Tag; $r.source_url = $a.Url; $r.sha256 = $f.Sha256
        if ($a.Name -match '\.exe$') { Copy-Item $f.Path (Join-Path $sdDir 'sidr.exe') -Force }
        else { Expand-Flat $f.Path $sdDir }
        $exe = Get-ChildItem $sdDir -Filter 'sidr*.exe' -Recurse | Select-Object -First 1
        if (-not $exe) { throw 'sidr.exe not found' }
        $r.executables['sidr'] = $exe.FullName
    }

    # ======================================================================
    # 8. BitsParser (BITS jobs: qmgr.db / qmgr*.dat)
    # ======================================================================
    $bpDir = Join-Path $ToolsDir 'BitsParser'
    Invoke-ToolInstall 'BitsParser' 'BitsParser (BITS)' 'artifacts' $false $bpDir {
        param($r)
        Reset-ToolDir $bpDir
        $f = Save-SourceZip 'fireeye/BitsParser'
        $r.version = "branch $($f.Ref)"; $r.source_url = $f.Url; $r.sha256 = $f.Sha256
        Expand-Flat $f.Path $bpDir
        $main = Find-First $bpDir 'BitsParser.py'
        if (-not $main) { throw 'BitsParser.py not found' }
        $req = Join-Path (Split-Path $main.FullName) 'requirements.txt'
        $vpy = if (Test-Path $req) { New-ToolVenv 'bitsparser' @('-r', $req) } else { New-ToolVenv 'bitsparser' @() }
        $r.executables['python'] = $vpy
        $r.executables['BitsParser'] = $main.FullName
        if ((Invoke-Native $vpy @($main.FullName, '--help')) -ne 0) { throw 'BitsParser.py --help fails' }
    }

    # ======================================================================
    # 9. WMI_Forensics (WMI persistence: OBJECTS.DATA)
    # ======================================================================
    $wmDir = Join-Path $ToolsDir 'WMI_Forensics'
    Invoke-ToolInstall 'WMIForensics' 'WMI_Forensics (WMI persistence)' 'artifacts' $false $wmDir {
        param($r)
        Reset-ToolDir $wmDir
        $f = Save-SourceZip 'davidpany/WMI_Forensics'
        $r.version = "branch $($f.Ref)"; $r.source_url = $f.Url; $r.sha256 = $f.Sha256
        Expand-Flat $f.Path $wmDir
        $main = Find-First $wmDir 'PyWMIPersistenceFinder.py'
        if (-not $main) { throw 'PyWMIPersistenceFinder.py not found' }
        $r.executables['PyWMIPersistenceFinder'] = $main.FullName
        $r.status = 'WARN'
        $r.notes += 'Python 2 script: not used by the orchestrator (WMI persistence through Dissect cim.consumerbindings)'
    }

    # ======================================================================
    # 10. Hindsight (Chrome / Chromium Edge history)
    # ======================================================================
    $hsDir = Join-Path $ToolsDir 'hindsight'
    Invoke-ToolInstall 'Hindsight' 'Hindsight (Chromium browsers)' 'artifacts' $false $hsDir {
        param($r)
        Reset-ToolDir $hsDir
        # 1) Standalone binary published with the GitHub release (hindsight.exe)
        $exePath = $null
        try {
            $a = Get-GitHubAsset 'obsidianforensics/hindsight' @('^hindsight\.exe$')
            $f = Save-File $a.Url $a.Name
            $exePath = Join-Path $hsDir 'hindsight.exe'
            Copy-Item $f.Path $exePath -Force
            $r.version = $a.Tag; $r.source_url = $a.Url; $r.sha256 = $f.Sha256
            if ((Invoke-Native $exePath @('-h')) -ne 0) { throw 'hindsight.exe -h fails' }
            $r.executables['hindsight'] = $exePath
            $r.notes += 'Standalone binary (no venv)'
        } catch {
            # 2) Fallback: pyhindsight Python package in a dedicated venv
            Write-Warn "Hindsight binary unavailable ($($_.Exception.Message)): falling back to pip"
            $vpy = New-ToolVenv 'hindsight' @('pyhindsight')
            $hsScript = Find-First (Split-Path $vpy) 'hindsight.py'
            if (-not $hsScript) { throw 'hindsight.py not found after pip install pyhindsight' }
            $ver = & $vpy -m pip show pyhindsight 2>$null | Select-String '^Version:' | ForEach-Object { ($_ -split ':\s*')[1] }
            $r.version = "pyhindsight $ver"; $r.source_url = 'https://pypi.org/project/pyhindsight/'; $r.sha256 = $null
            if ((Invoke-Native $vpy @($hsScript.FullName, '-h')) -ne 0) { throw 'hindsight.py -h fails' }
            $r.executables['python'] = $vpy
            $r.executables['hindsight'] = $hsScript.FullName
            $r.notes += 'Python installation (venv): binary unavailable'
        }
    }

    # ======================================================================
    # 11. bmc-tools (RDP bitmap cache - ANSSI)
    # ======================================================================
    $bmDir = Join-Path $ToolsDir 'bmc-tools'
    Invoke-ToolInstall 'BmcTools' 'bmc-tools (RDP bitmap cache)' 'artifacts' $false $bmDir {
        param($r)
        Reset-ToolDir $bmDir
        $f = Save-SourceZip 'ANSSI-FR/bmc-tools'
        $r.version = "branch $($f.Ref)"; $r.source_url = $f.Url; $r.sha256 = $f.Sha256
        Expand-Flat $f.Path $bmDir
        $main = Find-First $bmDir 'bmc-tools.py'
        if (-not $main) { throw 'bmc-tools.py not found' }
        $r.executables['python'] = (New-ToolVenv 'bmc-tools' @())
        $r.executables['bmc-tools'] = $main.FullName
        if ((Invoke-Native $r.executables['python'] @($main.FullName, '-h')) -ne 0) { throw 'bmc-tools.py -h fails' }
    }

    # ======================================================================
    # 12. Dissect (Fox-IT) - reads a KAPE output directly.
    #     Covers: WebCacheV01.dat (iexplore.history), XML scheduled tasks (tasks),
    #     Defender (defender.*), PowerShell (powershell_history), WER, Recycle Bin...
    # ======================================================================
    $dsDir = Join-Path $ToolsDir 'dissect'
    Invoke-ToolInstall 'Dissect' 'Dissect (Fox-IT)' 'frameworks' $false $dsDir {
        param($r)
        Reset-ToolDir $dsDir
        $vpy = New-ToolVenv 'dissect' @('dissect')
        $scripts = Split-Path $vpy
        $tq = Join-Path $scripts 'target-query.exe'
        $rd = Join-Path $scripts 'rdump.exe'
        if (-not (Test-Path $tq)) { throw 'target-query.exe not found after pip install dissect' }
        $ver = & $vpy -m pip show dissect.target 2>$null | Select-String '^Version:' | ForEach-Object { ($_ -split ':\s*')[1] }
        $r.version = "dissect.target $ver"; $r.source_url = 'https://pypi.org/project/dissect/'
        $r.executables['python'] = $vpy
        $r.executables['dissect'] = $tq
        if (Test-Path $rd) { $r.executables['rdump'] = $rd }

        # Checks that the plugins used by the orchestrator exist in this version
        $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $list = (& $tq --list 2>&1 | Out-String) } finally { $ErrorActionPreference = $prevEap }
        $needed = 'iexplore.history', 'tasks', 'powershell_history', 'defender.mplog', 'defender.quarantine', 'recyclebin', 'wer'
        $missing = @($needed | Where-Object { $list -notmatch [regex]::Escape($_) })
        if ($missing.Count -eq $needed.Count) { throw 'target-query --list returns none of the expected plugins' }
        if ($missing) { $r.status = 'WARN'; $r.notes += "Plugins missing from this version: $($missing -join ', ')" }
        Set-Content -Path (Join-Path $dsDir 'plugins.txt') -Value $list -Encoding UTF8
        $r.notes += 'List of plugins: tools\dissect\plugins.txt'
    }

    # ======================================================================
    # 13. plaso (log2timeline) - parsers not covered elsewhere: setupapi, PCA
    # ======================================================================
    $plDir = Join-Path $ToolsDir 'plaso'
    Invoke-ToolInstall 'Plaso' 'plaso (log2timeline)' 'frameworks' $false $plDir {
        param($r)
        Reset-ToolDir $plDir
        $vpy = New-ToolVenv 'plaso' @('plaso')
        $scripts = Split-Path $vpy
        foreach ($t in 'log2timeline', 'psort', 'pinfo') {
            $exe = Join-Path $scripts "$t.exe"
            if (-not (Test-Path $exe)) { throw "$t.exe not found after pip install plaso" }
            $r.executables[$t] = $exe
        }
        if ((Invoke-Native $r.executables['log2timeline'] @('--version')) -ne 0) { throw 'log2timeline --version fails' }
        $ver = & $vpy -m pip show plaso 2>$null | Select-String '^Version:' | ForEach-Object { ($_ -split ':\s*')[1] }
        $r.version = "plaso $ver"; $r.source_url = 'https://pypi.org/project/plaso/'
        $r.executables['python'] = $vpy
        $r.notes += 'Used for: text/setupapi, winpca_db0, winpca_dic'
    }

    # ======================================================================
    # 14. odl.py (Yogesh Khatri) - OneDrive .odl/.odlgz/.aodl logs
    # ======================================================================
    $odDir = Join-Path $ToolsDir 'OneDriveODL'
    Invoke-ToolInstall 'OneDriveODL' 'odl.py (OneDrive logs)' 'artifacts' $false $odDir {
        param($r)
        Reset-ToolDir $odDir
        $f = Save-SourceZip 'ydkhatri/OneDrive'
        $r.version = "branch $($f.Ref)"; $r.source_url = $f.Url; $r.sha256 = $f.Sha256
        Expand-Flat $f.Path $odDir
        $main = Find-First $odDir 'odl.py'
        if (-not $main) { throw 'odl.py not found' }
        $req = Get-PythonRequirements (Split-Path $main.FullName)
        $vpy = if ($req) { New-ToolVenv 'onedrive-odl' @('-r', $req) } else { New-ToolVenv 'onedrive-odl' @('construct', 'pycryptodome') }
        $r.executables['python'] = $vpy
        $r.executables['odl'] = $main.FullName
        if ((Invoke-Native $vpy @($main.FullName, '-h')) -ne 0) { throw 'odl.py -h fails' }
    }

    # ======================================================================
    # 14b. Volatility 3 - memory image of the case (job "volatility" of the orchestrator)
    #      [full] extras: yara-python and capstone, needed by mftscan, malfind (disassembly)
    #      and the system call plugins. Windows symbols are downloaded from the Microsoft symbol
    #      server at the first analysis of a Windows build (cached in tools\volatility\symbols).
    # ======================================================================
    $volDir = Join-Path $ToolsDir 'volatility'
    Invoke-ToolInstall 'Volatility' 'Volatility 3 (memory)' 'frameworks' $false $volDir {
        param($r)
        if ($script:Lock -and -not $script:Lock.venvs.PSObject.Properties['volatility3']) {
            throw 'Volatility 3 is not in the lock file: install it without -Locked (then export a new lock)'
        }
        foreach ($d in 'symbols', 'cache') { New-Item -ItemType Directory -Force -Path (Join-Path $volDir $d) | Out-Null }
        try {
            $vpy = New-ToolVenv 'volatility3' @('volatility3[full]')
        } catch {
            $vpy = New-ToolVenv 'volatility3' @('volatility3')
            $r.status = 'WARN'
            $r.notes += 'Installed without the [full] extras (yara-python / capstone): mftscan, the system call plugins and the malfind disassembly will fail'
        }
        $vol = Join-Path (Split-Path $vpy) 'vol.exe'
        if (-not (Test-Path $vol)) { throw 'vol.exe not found after pip install volatility3' }
        $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $help = (& $vol -h 2>&1 | Out-String) } finally { $ErrorActionPreference = $prevEap }
        $needed = 'windows.info.Info', 'windows.pslist.PsList', 'windows.netscan.NetScan', 'windows.malware.malfind.Malfind'
        $missing = @($needed | Where-Object { $help -notmatch [regex]::Escape($_) })
        if ($missing.Count -eq $needed.Count) { throw 'vol -h lists none of the expected plugins' }
        if ($missing) { $r.status = 'WARN'; $r.notes += "Plugins missing from this version: $($missing -join ', ')" }
        Set-Content -Path (Join-Path $volDir 'plugins.txt') -Value $help -Encoding UTF8
        $ver = & $vpy -m pip show volatility3 2>$null | Select-String '^Version:' | ForEach-Object { ($_ -split ':\s*')[1] }
        $r.version = "volatility3 $ver"; $r.source_url = 'https://pypi.org/project/volatility3/'
        $r.executables['vol'] = $vol
        $r.executables['python'] = $vpy
        $r.notes += 'Symbols downloaded at the first analysis of each Windows build (msdl.microsoft.com); list of plugins: tools\volatility\plugins.txt'
    }

    # ======================================================================
    # 14c. Suricata - network captures of the case (job "suricata" of the orchestrator)
    #      The MSI is EXTRACTED (msiexec /a), not installed: no service, no driver, nothing in
    #      Program Files. Rules: suricata-update (ET Open) in its own venv.
    #      Live capture would need Npcap; reading capture files is all the pipeline does.
    # ======================================================================
    $suDir = Join-Path $ToolsDir 'suricata'
    Invoke-ToolInstall 'Suricata' 'Suricata (network captures)' 'frameworks' $false $suDir {
        param($r)
        Reset-ToolDir $suDir
        $le = Get-LockEntry
        if ($SuricataMsi) {
            if (-not (Test-Path $SuricataMsi)) { throw "Suricata installer not found: $SuricataMsi" }
            $msi = (Resolve-Path $SuricataMsi).Path
            $sha = (Get-FileHash $msi -Algorithm SHA256).Hash
            $r.downloads[$msi] = $sha
            $msiName = Split-Path $msi -Leaf
        } else {
            if ($le -and $le.downloads) {
                $url = @($le.downloads.PSObject.Properties)[0].Name
            } else {
                $index = 'https://www.openinfosecfoundation.org/download/windows/'
                $page = (Invoke-WebRequest -Uri $index -UseBasicParsing -Headers @{ 'User-Agent' = $UserAgent }).Content
                $names = [regex]::Matches($page, 'Suricata-(\d+)\.(\d+)\.(\d+)-(\d+)-64bit\.msi') |
                    Sort-Object { [int]$_.Groups[1].Value }, { [int]$_.Groups[2].Value }, { [int]$_.Groups[3].Value }, { [int]$_.Groups[4].Value } |
                    ForEach-Object { $_.Value } | Select-Object -Unique
                if (-not $names) { throw "No Suricata-*-64bit.msi found on $index (use -SuricataMsi <file.msi>)" }
                $url = $index + @($names)[-1]
            }
            $msiName = Split-Path $url -Leaf
            $f = Save-File $url $msiName
            $msi = $f.Path; $sha = $f.Sha256
            $r.source_url = $url
        }
        $r.sha256 = $sha
        $ver = if ($msiName -match 'Suricata-(\d+\.\d+\.\d+)') { $Matches[1] } else { $null }
        $app = Join-Path $suDir 'app'
        $p = Start-Process msiexec.exe -ArgumentList @('/a', "`"$msi`"", '/qn', "TARGETDIR=`"$app`"") -Wait -PassThru
        if ($p.ExitCode -ne 0) { throw "msiexec /a (extraction) failed with code $($p.ExitCode)" }
        $exe = Get-ChildItem $app -Recurse -Filter 'suricata.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $exe) { throw 'suricata.exe not found in the extracted installer' }
        $yaml = Get-ChildItem $app -Recurse -Filter 'suricata.yaml' -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $yaml) { throw 'suricata.yaml not found in the extracted installer' }
        $r.version = "Suricata $ver"
        $r.executables['suricata'] = $exe.FullName
        $r.executables['suricata_yaml'] = $yaml.FullName
        $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $bi = (& $exe.FullName --build-info 2>&1 | Out-String); $rc = $LASTEXITCODE } finally { $ErrorActionPreference = $prevEap }
        if ($rc -ne 0) {
            $r.status = 'WARN'
            $r.notes += "suricata.exe --build-info fails (code $rc): if a DLL is missing (wpcap.dll), install Npcap (https://npcap.com) on the VM - your decision, it is a system driver"
        } else {
            Set-Content -Path (Join-Path $suDir 'build-info.txt') -Value $bi -Encoding UTF8
        }
        # Rules: ET Open through suricata-update (not in -Locked mode: rules folder compared with the lock)
        $rulesDir = Join-Path $suDir 'rules'
        New-Item -ItemType Directory -Force -Path $rulesDir | Out-Null
        if ($script:Lock) {
            $r.notes += '-Locked mode: rules not updated (tools\suricata\rules compared with the lock)'
        } else {
            try {
                $vpy = New-ToolVenv 'suricata-update' @('suricata-update')
                # suricata-update is installed as a Python script without extension (Scripts\suricata-update),
                # not as an .exe: it is run with the Python of its venv
                $su = Join-Path (Split-Path $vpy) 'suricata-update'
                if (-not (Test-Path $su)) { throw "suricata-update not found in its venv ($su)" }
                $suArgs = @('--suricata-conf', $yaml.FullName, '-D', (Join-Path $suDir 'update'), '-o', $rulesDir, '--no-test', '--no-reload')
                if ($ver) { $suArgs = @('--suricata-version', $ver) + $suArgs }
                if ((Invoke-Native $vpy (@($su) + $suArgs)) -ne 0) { throw 'suricata-update failed' }
                $r.executables['suricata_update'] = $su
            } catch {
                $r.status = 'WARN'
                $r.notes += "ET Open rules not installed ($($_.Exception.Message)): protocol metadata without alerts"
            }
        }
        $rules = Join-Path $rulesDir 'suricata.rules'
        if (Test-Path $rules) {
            $r.executables['suricata_rules'] = $rules
            $n = @(Select-String -Path $rules -Pattern '^(alert|drop|reject|pass) ' -ErrorAction SilentlyContinue).Count
            # suricata-update still succeeds when the ET Open download fails (only the rules shipped with
            # Suricata, a few hundred): ET Open holds tens of thousands
            if ($n -lt 5000) {
                $r.status = 'WARN'
                $r.notes += "Only $n rules: the ET Open download probably failed (rules.emergingthreats.net); run install\02_Install-Tools.ps1 -Only Suricata -Force again"
            } else {
                $r.notes += "$n rules (ET Open, suricata-update); MSI extracted, not installed"
            }
        }
    }

    # ======================================================================
    # 15. KAPE (optional, zip provided manually)
    # ======================================================================
    $kpDir = Join-Path $ToolsDir 'KAPE'
    # kape.zip placed next to this script (<repository>\install\kape.zip): used automatically
    if (-not $KapeZip) { $kz = Join-Path $PSScriptRoot 'kape.zip'; if (Test-Path $kz) { $KapeZip = $kz } }
    if ((-not $Only -and $KapeZip) -or ($Only -contains 'KAPE')) {
        Invoke-ToolInstall 'KAPE' 'KAPE' 'collection' $false $kpDir {
            param($r)
            if (-not $KapeZip -or -not (Test-Path $KapeZip)) {
                throw 'Provide -KapeZip <path\kape.zip> (download requires registration with Kroll)'
            }
            Reset-ToolDir $kpDir
            $r.sha256 = (Get-FileHash $KapeZip -Algorithm SHA256).Hash
            if ($script:Lock -and $script:Lock.tools.KAPE -and $script:Lock.tools.KAPE.sha256 -ne $r.sha256) {
                $r.status = 'WARN'; $r.notes += "kape.zip differs from the lock (expected $($script:Lock.tools.KAPE.sha256))"
            }
            $r.source_url = (Resolve-Path $KapeZip).Path
            Expand-Flat $KapeZip $kpDir
            $exe = Find-First $kpDir 'kape.exe'
            if (-not $exe) { throw 'kape.exe not found in the archive' }
            $r.executables['kape'] = $exe.FullName
            $r.version = (Get-Item $exe.FullName).VersionInfo.FileVersion
            if (-not $script:Lock) {
                Push-Location (Split-Path $exe.FullName)
                try { & $exe.FullName --sync | Out-Null } catch { $r.notes += 'kape --sync failed' }
                Pop-Location
            }
        }
    }

    # ======================================================================
    # 16. Analysis pipeline: <repository>\pipeline -> <root>\pipeline
    #     The repository is the source of truth. Redeployed at every run (no
    #     idempotence) so that <root>\pipeline always reflects the validated version.
    #     Files produced by the LLM agent during analyses (parser proposals, logs,
    #     hash lists in local\) are never overwritten or deleted.
    # ======================================================================
    if (-not $Only -or ($Only -contains 'Pipeline')) {
        Write-Step 'Analysis pipeline (inventory, orchestrator, normalization, agent, rules, registries)'
        $r = New-Result 'Sleuthline pipeline' 'pipeline' $true 'Pipeline'
        $script:Cur = $null
        # Source: <repository>\pipeline (this script is in <repository>\install)
        $repo = Split-Path $PSScriptRoot -Parent
        $pipeSrc = Join-Path $repo 'pipeline'
        $pipeDst = Join-Path $Root 'pipeline'
        $localDir = Join-Path $pipeDst 'local'
        $r.path = $pipeDst; $r.source_url = $pipeSrc
        try {
            if (-not (Test-Path $pipeSrc)) { throw "Source folder not found: $pipeSrc" }
            New-Item -ItemType Directory -Force -Path $pipeDst, $localDir | Out-Null
            # API keys: config\api_keys.txt (excluded from git) created from the template on first deployment
            $keysSrc = Join-Path $pipeSrc 'config\api_keys.txt'
            $keysTpl = Join-Path $pipeSrc 'config\api_keys_template.txt'
            if (-not (Test-Path $keysSrc) -and (Test-Path $keysTpl)) {
                Copy-Item $keysTpl $keysSrc
                Write-Info "Created $keysSrc from the template: fill in the key of your provider there"
            }
            # Offline hash lists (normalize.py -> hash_hits table): specific to the VM, never overwritten
            $hsDir = Join-Path $localDir 'hashsets'
            if (-not (Test-Path $hsDir)) {
                New-Item -ItemType Directory -Force -Path $hsDir | Out-Null
                Set-Content -Path (Join-Path $hsDir 'README.txt') -Encoding UTF8 -Value @(
                    'Hash lists compared with every hash column of the database (hash_hits table),',
                    'including the hashes embedded in the EVTX (Sysmon Hashes field, Hayabusa / Zircolite details).',
                    '.txt or .csv files: one MD5, SHA-1 or SHA-256 hash per line, optionally followed by ; and a label.',
                    'The file name gives the nature of the list:',
                    '  known_bad*.txt   malicious hashes (IOCs, threat reports, MISP...)',
                    '  known_good*.txt  known-good files (e.g. SHA-1 extract of the NSRL RDS)',
                    '  any other name   "watch" list (to monitor)',
                    'Case-specific lists can also be placed in <case>\hashsets\.',
                    'Taken into account at the next normalization (sleuthline.ps1 normalize <case>).')
            }
            # Mirror of the source (removes obsolete files); local\ and the logs are preserved
            & robocopy.exe $pipeSrc $pipeDst /MIR /R:1 /W:1 /XD 'local' '__pycache__' /XF '*.log' /NFL /NDL /NJH /NJS /NP | Out-Null
            if ($LASTEXITCODE -ge 8) { throw "robocopy failed (code $LASTEXITCODE)" }
            $global:LASTEXITCODE = 0
            # RECmd batch complementing the Kroll batch (recmd_complement job of the orchestrator), versioned in the repository
            $complement = Join-Path $pipeDst 'config\recmd\Sleuthline_Complement.reb'
            if (-not (Test-Path $complement)) { throw "Complementary RECmd batch missing from the deployment: $complement" }

            # Fingerprint of the deployment: SHA-256 of every source file (api_keys.txt excluded)
            $files = Get-ChildItem $pipeSrc -Recurse -File | Where-Object { $_.FullName -notmatch '__pycache__' -and $_.Name -ne 'api_keys.txt' }
            foreach ($f in $files) {
                $rel = $f.FullName.Substring($pipeSrc.Length).TrimStart('\')
                $r.executables[$rel] = (Join-Path $pipeDst $rel)
            }
            $combined = ($files | Sort-Object FullName | ForEach-Object { (Get-FileHash $_.FullName -Algorithm SHA256).Hash }) -join ''
            $r.sha256 = [BitConverter]::ToString(
                [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($combined))).Replace('-', '')
            # Pipeline version: git commit of the repository (+ report of uncommitted changes)
            $commit = $null; $dirty = $null
            if (Get-Command git -ErrorAction SilentlyContinue) {
                $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
                try {
                    $commit = (& git -C $repo rev-parse HEAD 2>$null)
                    if ($LASTEXITCODE -eq 0) { $dirty = [bool](& git -C $repo status --porcelain -- pipeline install 2>$null) } else { $commit = $null }
                } finally { $ErrorActionPreference = $prevEap; $global:LASTEXITCODE = 0 }
            }
            $label = if ($commit) { "commit $($commit.Substring(0, 12))" + $(if ($dirty) { ' + uncommitted changes' } else { '' }) }
                     else { 'outside git (version not identifiable)' }
            $label += "; content sha256 $($r.sha256.Substring(0, 16)); deployed $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
            $r.version = $label; $r.commit = $commit
            if ($dirty) { $r.status = 'WARN'; $r.notes += "Uncommitted changes in ${repo}: the deployed version cannot be identified by its commit" }
            if (-not $commit) { $r.status = 'WARN'; $r.notes += "$repo is not a git repository (or git is missing): version not identifiable" }
            [ordered]@{ label = $label; commit = $commit; dirty = $dirty; content_sha256 = $r.sha256
                        deployed_at = (Get-Date).ToString('o'); source = $pipeSrc } |
                ConvertTo-Json | Set-Content -Path (Join-Path $pipeDst 'VERSION.json') -Encoding UTF8

            # Tests: every script starts with the orchestrator's Python
            $orchPy = if ($cfg -and $cfg.orchestrator_py -and (Test-Path $cfg.orchestrator_py)) { $cfg.orchestrator_py } else { Join-Path $VenvsDir 'orchestrator\Scripts\python.exe' }
            if (Test-Path $orchPy) {
                # Analysis agent: Word report (python-docx); in -Locked mode, version of the lock (01_Prepare-VM.ps1)
                if (-not $script:Lock -and (Invoke-Native $orchPy @('-m', 'pip', 'install', '--quiet', '--disable-pip-version-check', 'python-docx')) -ne 0) { throw 'python-docx installation failed' }
                foreach ($script in '1_inventory\inventory.py', '2_parsing\orchestrator.py', '3_normalize\normalize.py', '4_analysis\analyze.py') {
                    $sp = Join-Path $pipeDst $script
                    if (-not (Test-Path $sp)) { throw "$script missing from the deployment" }
                    if ((Invoke-Native $orchPy @($sp, '--help')) -ne 0) { throw "$script --help fails" }
                }
                # API key: config\api_keys.txt (never versioned)
                $keysTxt = Get-Content (Join-Path $pipeDst 'config\api_keys.txt') -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match '^\s*[A-Z_]+_API_KEY\s*=\s*\S' }
                if (-not $keysTxt) { $r.notes += "No API key filled in $keysSrc (needed for a remote model)" }
            } else { $r.status = 'WARN'; $r.notes += 'Orchestrator Python not found: tests not run' }
            if ($r.status -eq 'PENDING') { $r.status = 'OK' }
            Write-Ok "Pipeline deployed to $pipeDst ($($files.Count) files)"
        } catch {
            $r.status = 'FAIL'; $r.notes += $_.Exception.Message
            Write-Err "Pipeline: $($_.Exception.Message)"
        }
        $Results.Add($r)
    }

    # ======================================================================
    # 17. Online help of every installed tool -> <root>\tools\_help\
    #     Syntax reference for the orchestrator and the agent (exact installed version).
    #     Always run; each command is limited to 60 s and killed beyond.
    # ======================================================================
    Write-Step 'Online help of the tools (syntax reference)'
    $helpDir = Join-Path $ToolsDir '_help'
    New-Item -ItemType Directory -Force -Path $helpDir | Out-Null

    function Save-ToolHelp ([string]$Name, [string]$Exe, [string[]]$Arguments) {
        if (-not $Exe -or -not (Test-Path $Exe)) { return }
        $out = Join-Path $helpDir "$Name.txt"
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $Exe
            $psi.Arguments = ($Arguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
            $psi.WorkingDirectory = Split-Path $Exe
            $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
            $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
            $psi.StandardOutputEncoding = [Text.Encoding]::UTF8; $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
            $p = [Diagnostics.Process]::Start($psi)
            $so = $p.StandardOutput.ReadToEndAsync(); $se = $p.StandardError.ReadToEndAsync()
            if (-not $p.WaitForExit(60000)) { $p.Kill(); $note = '(stopped after 60 s)' } else { $note = "(code $($p.ExitCode))" }
            $text = "# $Exe $($psi.Arguments)  $note`r`n`r`n" + $so.Result + "`r`n" + $se.Result
            Set-Content -Path $out -Value $text -Encoding UTF8
        } catch { Set-Content -Path $out -Value "# Failure: $($_.Exception.Message)" -Encoding UTF8 }
    }

    # Known executables of the manifest (tools already installed)
    $known = @{}
    $manifestNow = Join-Path $ToolsDir 'tools-manifest.json'
    if (Test-Path $manifestNow) {
        foreach ($t in (Get-Content $manifestNow -Raw | ConvertFrom-Json).tools) {
            if ($t.executables) { $t.executables.PSObject.Properties | ForEach-Object { $known[$_.Name] = $_.Value } }
        }
    }
    foreach ($res in $Results) { foreach ($k in $res.executables.Keys) { $known[$k] = $res.executables[$k] } }

    # EZTools: every command-line .exe (-h)
    foreach ($t in 'MFTECmd', 'PECmd', 'RECmd', 'EvtxECmd', 'AmcacheParser', 'AppCompatCacheParser',
                   'RecentFileCacheParser', 'LECmd', 'JLECmd', 'RBCmd', 'SBECmd', 'SrumECmd',
                   'SumECmd', 'WxTCmd', 'SQLECmd', 'bstrings') {
        Save-ToolHelp $t $known[$t] @('-h')
    }
    Save-ToolHelp 'hayabusa'                $known['hayabusa'] @('help')
    Save-ToolHelp 'hayabusa_dfir-timeline'  $known['hayabusa'] @('dfir-timeline', '--help')
    Save-ToolHelp 'hayabusa_list-profiles'  $known['hayabusa'] @('list-profiles')
    Save-ToolHelp 'chainsaw'                $known['chainsaw'] @('--help')
    Save-ToolHelp 'chainsaw_hunt'           $known['chainsaw'] @('hunt', '--help')
    Save-ToolHelp 'zircolite'               $known['zircolite'] @('--help')
    Save-ToolHelp 'sidr'                    $known['sidr'] @('--help')
    Save-ToolHelp 'hindsight'               $known['hindsight'] @('-h')
    Save-ToolHelp 'dissect_target-query'    $known['dissect'] @('--help')
    Save-ToolHelp 'dissect_rdump'           $known['rdump'] @('--help')
    Save-ToolHelp 'plaso_log2timeline'      $known['log2timeline'] @('--help')
    Save-ToolHelp 'plaso_log2timeline_parsers' $known['log2timeline'] @('--parsers', 'list')
    Save-ToolHelp 'plaso_psort'             $known['psort'] @('--help')
    Save-ToolHelp 'plaso_psort_formats'     $known['psort'] @('-o', 'list')
    # Python scripts: venv interpreter + script
    $pyTools = @(
        @('BitsParser', 'bitsparser', 'BitsParser', '-h'),
        @('bmc-tools', 'bmc-tools', 'bmc-tools', '-h'),
        @('odl', 'onedrive-odl', 'odl', '-h')
    )
    foreach ($pt in $pyTools) {
        $vpy = Join-Path $VenvsDir "$($pt[1])\Scripts\python.exe"
        if ($known[$pt[2]]) { Save-ToolHelp $pt[0] $vpy @($known[$pt[2]], $pt[3]) }
    }
    # LogFileParser is an AutoIt application with a GUI: not called (blocking window)
    Set-Content -Path (Join-Path $helpDir 'LogFileParser.txt') -Encoding UTF8 -Value @(
        '# LogFileParser: AutoIt application, no capturable command-line help.',
        '# Documented parameters: https://github.com/jschicht/LogFileParser (README, command line section)')
    Write-Ok "Help saved in $helpDir ($(@(Get-ChildItem $helpDir -Filter *.txt).Count) files)"

    # ======================================================================
    # Manifest and summary
    # ======================================================================
    Write-Step 'Tool manifest'
    $manifestPath = Join-Path $ToolsDir 'tools-manifest.json'
    $existing = @{}
    if ((Test-Path $manifestPath) -and $Only) {
        # Partial installation: the entries of the other tools are kept
        (Get-Content $manifestPath -Raw | ConvertFrom-Json).tools | ForEach-Object { $existing[$_.name] = $_ }
    }
    foreach ($res in $Results) { $existing[$res.name] = $res }
    $manifest = [ordered]@{
        generated_at = (Get-Date).ToString('o')
        host         = $env:COMPUTERNAME
        root         = $Root
        python_base  = $PythonExe
        python_version = $(if ($PythonExe) { (& $PythonExe --version 2>&1) -join '' } else { $null })
        install_mode = $(if ($script:Lock) { "locked ($LockFile, generated on $($script:Lock.generated_at))" } else { 'latest versions' })
        lock_check   = $null
        tools        = @($existing.Values)
    }

    # -Locked mode: EZTools and rule folders compared with the lock (not downloadable at a precise version)
    if ($script:Lock) {
        Write-Step 'Compliance with the lock file'
        $diffs = @(Compare-InstallToLock $script:Lock $ToolsDir ($manifest | ConvertTo-Json -Depth 6 | ConvertFrom-Json))
        $manifest.lock_check = [ordered]@{ compliant = ($diffs.Count -eq 0); differences = $diffs }
        if ($diffs) {
            foreach ($d in $diffs) { Write-Warn $d }
            Write-Warn "Differences: EZTools and rules can only be downloaded in their latest version. For an exact reproduction, restore an archive of $ToolsDir (see README)."
        } else { Write-Ok 'Installation compliant with the lock' }
    }
    ($manifest | ConvertTo-Json -Depth 6) | Set-Content -Path $manifestPath -Encoding UTF8
    Write-Ok $manifestPath

    Write-Step 'Summary'
    $Results | ForEach-Object {
        $color = switch -Wildcard ($_.status) { 'OK*' { 'Green' } 'WARN' { 'Yellow' } default { 'Red' } }
        Write-Host ("    {0,-34} {1,-14} {2}" -f $_.name, $_.status, $_.version) -ForegroundColor $color
        foreach ($n in $_.notes) { Write-Host "        - $n" -ForegroundColor DarkGray }
    }

    $failedRequired = @($Results | Where-Object { $_.status -eq 'FAIL' -and $_.required })
    $failedOptional = @($Results | Where-Object { $_.status -eq 'FAIL' -and -not $_.required })
    if ($failedRequired) {
        Write-Host "`nREQUIRED tools failed: $(($failedRequired | ForEach-Object { $_.name }) -join ', ')" -ForegroundColor Red
        Write-Host 'Fix and run again (only the missing tools will be reinstalled).' -ForegroundColor Red
        $script:ExitCode = 1
    } else {
        if ($failedOptional) { Write-Warn "Optional tools failed: $(($failedOptional | ForEach-Object { $_.name }) -join ', ')" }
        Write-Host "`nInstallation complete. The environment is ready: <root>\pipeline\sleuthline.ps1 help" -ForegroundColor Green
        $script:ExitCode = 0
    }
}
finally {
    Stop-Transcript | Out-Null
    Write-Host "Log: $log"
}
exit $script:ExitCode
