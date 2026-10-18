<#
.SYNOPSIS
    Sleuthline - step 1: prepares a Windows DFIR analysis VM.

.DESCRIPTION
    - Checks administrator rights and disk space
    - Installs Python 3.12, the .NET 9 runtime (console + desktop), 7-Zip and Git
      (through winget, with a direct-download fallback when winget is missing)
    - Creates the folder tree under the installation root (default C:\Sleuthline)
    - Creates the Python environment of the orchestrator (venv + libraries)
    - Options: Windows Defender exclusion on the root, long path support

    Idempotent: can be run again safely, what is already installed is skipped.

.PARAMETER Root
    Installation root (default: C:\Sleuthline). Alias: -DfirRoot.

.PARAMETER AddDefenderExclusion
    Adds the root to the Windows Defender exclusions.
    Recommended: Sigma rules (.yml) and KAPE artifacts (suspicious binaries,
    startup folders...) trigger false positives, and Defender may quarantine
    EVIDENCE. Changes a security setting: only enable it on an isolated
    analysis VM.

.PARAMETER EnableLongPaths
    Enables support for paths longer than 260 characters (common in KAPE outputs).

.PARAMETER SkipGit
    Does not install Git.

.EXAMPLE
    .\01_Prepare-VM.ps1 -AddDefenderExclusion -EnableLongPaths
#>
[CmdletBinding()]
param(
    [Alias('DfirRoot')][string]$Root = 'C:\Sleuthline',
    [switch]$AddDefenderExclusion,
    [switch]$EnableLongPaths,
    [switch]$SkipGit,
    [int]$MinFreeGB = 100,
    [string]$PythonFallbackVersion = '3.12.10',
    [switch]$Locked,                 # orchestrator libraries at the versions of install\tools-lock.json
    [string]$LockFile
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # makes Invoke-WebRequest much faster
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --------------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------------
function Write-Step ($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok   ($m) { Write-Host "    [OK]   $m" -ForegroundColor Green }
function Write-Warn ($m) { Write-Host "    [WARN] $m" -ForegroundColor Yellow }
function Write-Info ($m) { Write-Host "    $m" }

$script:Summary = [ordered]@{}

function Update-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user    = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$machine;$user"
}

function Test-Command ($name) { [bool](Get-Command $name -ErrorAction SilentlyContinue) }

function Test-Winget { Test-Command 'winget' }

function Install-WithWinget ([string]$Id, [string]$Label) {
    Write-Info "winget install $Id"
    $wgArgs = @('install', '--id', $Id, '--exact', '--silent',
                '--accept-package-agreements', '--accept-source-agreements',
                '--scope', 'machine')
    & winget @wgArgs | Out-Host
    # 0 = installed; -1978335189 = already installed / no update
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1978335189) {
        # some packages do not support --scope machine: try again without it
        & winget install --id $Id --exact --silent --accept-package-agreements --accept-source-agreements | Out-Host
        if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1978335189) {
            throw "winget failed for $Label (code $LASTEXITCODE)"
        }
    }
    Update-SessionPath
}

function Get-PythonExe {
    # 1. py launcher
    if (Test-Command 'py') {
        try {
            $p = & py -3.12 -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $p -and (Test-Path $p)) { return $p.Trim() }
        } catch {}
    }
    # 2. standard locations
    $candidates = @(
        "$env:ProgramFiles\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    return $null
}

# --------------------------------------------------------------------------
# 0. Prerequisites
# --------------------------------------------------------------------------
Write-Step 'Checking prerequisites'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'This script must be run in a PowerShell started with "Run as administrator".' }
Write-Ok 'Administrator rights'

$os = Get-CimInstance Win32_OperatingSystem
Write-Ok "OS: $($os.Caption) (build $($os.BuildNumber))"
if (-not [Environment]::Is64BitOperatingSystem) { throw 'A 64-bit Windows is required.' }

$driveLetter = (Split-Path -Qualifier $Root).TrimEnd(':')
$freeGB = [math]::Round((Get-PSDrive $driveLetter).Free / 1GB, 1)
if ($freeGB -lt $MinFreeGB) {
    Write-Warn "Only $freeGB GB free on ${driveLetter}: (recommended: $MinFreeGB GB+). A parsed KAPE collection can weigh several tens of GB."
} else { Write-Ok "$freeGB GB free on ${driveLetter}:" }

# Full installation log
New-Item -ItemType Directory -Force -Path (Join-Path $Root 'logs') | Out-Null
$log = Join-Path $Root ("logs\01_prepare_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $log | Out-Null

try {
    $hasWinget = Test-Winget
    if ($hasWinget) { Write-Ok 'winget available' } else { Write-Warn 'winget missing: falling back to direct downloads' }

    # ----------------------------------------------------------------------
    # 1. Folder tree
    # ----------------------------------------------------------------------
    Write-Step "Creating the folder tree $Root"
    $dirs = 'tools', 'tools\_downloads', 'cases', 'venvs', 'logs', 'rules'
    foreach ($d in $dirs) { New-Item -ItemType Directory -Force -Path (Join-Path $Root $d) | Out-Null }
    Write-Ok ($dirs -join ', ')
    $script:Summary['Folder tree'] = $Root

    # ----------------------------------------------------------------------
    # 2. Python 3.12
    # ----------------------------------------------------------------------
    Write-Step 'Python 3.12'
    $py = Get-PythonExe
    if ($py) {
        Write-Ok "Already present: $py"
    } else {
        if ($hasWinget) {
            Install-WithWinget 'Python.Python.3.12' 'Python 3.12'
        } else {
            $url = "https://www.python.org/ftp/python/$PythonFallbackVersion/python-$PythonFallbackVersion-amd64.exe"
            $exe = Join-Path $env:TEMP "python-$PythonFallbackVersion-amd64.exe"
            Write-Info "Downloading $url"
            Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing
            Start-Process -FilePath $exe -Wait -ArgumentList '/quiet', 'InstallAllUsers=1', 'PrependPath=1', 'Include_launcher=1', 'Include_test=0'
            Update-SessionPath
        }
        $py = Get-PythonExe
        if (-not $py) { throw 'Python 3.12 not found after installation.' }
        Write-Ok "Installed: $py"
    }
    $script:Summary['Python'] = (& $py --version)

    # ----------------------------------------------------------------------
    # 3. .NET 9 (required by the net9 EZTools)
    # ----------------------------------------------------------------------
    Write-Step '.NET 9 runtime'
    $dotnetOk = $false
    if (Test-Command 'dotnet') {
        $runtimes = & dotnet --list-runtimes 2>$null
        if (($runtimes -match 'Microsoft\.NETCore\.App 9\.') -and ($runtimes -match 'Microsoft\.WindowsDesktop\.App 9\.')) { $dotnetOk = $true }
    }
    if ($dotnetOk) {
        Write-Ok '.NET 9 runtimes (NETCore + WindowsDesktop) already present'
    } else {
        if ($hasWinget) {
            Install-WithWinget 'Microsoft.DotNet.Runtime.9'        '.NET 9 Runtime'
            Install-WithWinget 'Microsoft.DotNet.DesktopRuntime.9' '.NET 9 Desktop Runtime'
        } else {
            $inst = Join-Path $env:TEMP 'dotnet-install.ps1'
            Invoke-WebRequest -Uri 'https://dot.net/v1/dotnet-install.ps1' -OutFile $inst -UseBasicParsing
            $dest = "$env:ProgramFiles\dotnet"
            & $inst -Channel 9.0 -Runtime dotnet       -InstallDir $dest
            & $inst -Channel 9.0 -Runtime windowsdesktop -InstallDir $dest
            $mp = [Environment]::GetEnvironmentVariable('Path', 'Machine')
            if ($mp -notlike "*$dest*") { [Environment]::SetEnvironmentVariable('Path', "$mp;$dest", 'Machine') }
            Update-SessionPath
        }
        Write-Ok '.NET 9 installed'
    }
    $net9 = @(& dotnet --list-runtimes 2>$null) -match ' 9\.'
    $script:Summary['.NET'] = ($net9 | ForEach-Object { ($_ -split ' \[')[0] }) -join ' | '

    # ----------------------------------------------------------------------
    # 4. 7-Zip (KAPE outputs in .7z, tool archives)
    # ----------------------------------------------------------------------
    Write-Step '7-Zip'
    $sevenZip = "$env:ProgramFiles\7-Zip\7z.exe"
    if (Test-Path $sevenZip) { Write-Ok 'Already present' }
    elseif ($hasWinget) { Install-WithWinget '7zip.7zip' '7-Zip'; Write-Ok 'Installed' }
    else { Write-Warn '7-Zip not installed (winget missing). Only .zip files will be handled.' }
    $script:Summary['7-Zip'] = (Test-Path $sevenZip)

    # ----------------------------------------------------------------------
    # 5. Git (optional; identifies the deployed pipeline version)
    # ----------------------------------------------------------------------
    if (-not $SkipGit) {
        Write-Step 'Git'
        if (Test-Command 'git') { Write-Ok 'Already present' }
        elseif ($hasWinget) { Install-WithWinget 'Git.Git' 'Git'; Write-Ok 'Installed' }
        else { Write-Warn 'Git not installed (winget missing). Not blocking.' }
        $script:Summary['Git'] = (Test-Command 'git')
    }

    # ----------------------------------------------------------------------
    # 6. Python environment of the orchestrator
    # ----------------------------------------------------------------------
    Write-Step 'Python environment of the orchestrator'
    $venv = Join-Path $Root 'venvs\orchestrator'
    if (-not (Test-Path "$venv\Scripts\python.exe")) {
        & $py -m venv $venv
        Write-Ok "venv created: $venv"
    } else { Write-Ok "existing venv: $venv" }
    $vpy = "$venv\Scripts\python.exe"
    & $vpy -m pip install --upgrade pip wheel setuptools --quiet

    # Core libraries of the orchestrator / normalization / report
    $core = 'duckdb', 'pandas', 'pyarrow', 'pyyaml', 'rich', 'python-dateutil', 'tqdm', 'orjson', 'python-docx'
    if ($Locked) {
        if (-not $LockFile) { $LockFile = Join-Path $PSScriptRoot 'tools-lock.json' }
        if (-not (Test-Path $LockFile)) { throw "-Locked mode: $LockFile not found (install\Export-ToolsLock.ps1)" }
        $lock = Get-Content $LockFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not $lock.venvs.orchestrator) { throw "-Locked mode: environment 'orchestrator' missing from $LockFile" }
        $pyVer = (& $py --version 2>&1) -join ''
        if ($lock.python -and $lock.python -ne $pyVer) { Write-Warn "Installed Python ($pyVer) differs from the lock ($($lock.python))" }
        $req = Join-Path $env:TEMP 'lock_orchestrator.txt'
        @($lock.venvs.orchestrator) | Set-Content -Path $req -Encoding ASCII
        & $vpy -m pip install --no-deps -r $req --quiet
        if ($LASTEXITCODE -ne 0) { throw 'Python libraries installation failed (locked versions)' }
        Write-Ok "Installed at the locked versions ($(@($lock.venvs.orchestrator).Count) packages)"
    } else {
        & $vpy -m pip install @core --quiet
        if ($LASTEXITCODE -ne 0) { throw 'Core Python libraries installation failed' }
        Write-Ok ("Installed: " + ($core -join ', '))
    }

    # Optional forensic libraries (wheels sometimes unavailable: not blocking)
    $optional = 'libesedb-python', 'python-registry', 'python-evtx'
    $failedOpt = @()
    foreach ($pkg in $optional) {
        & $vpy -m pip install $pkg --quiet 2>$null
        if ($LASTEXITCODE -eq 0) { Write-Ok "Optional: $pkg" } else { Write-Warn "Optional not installed: $pkg"; $failedOpt += $pkg }
    }
    $script:Summary['Orchestrator venv'] = $venv
    if ($failedOpt) { $script:Summary['Missing optional Python packages'] = ($failedOpt -join ', ') }

    # ----------------------------------------------------------------------
    # 7. System options
    # ----------------------------------------------------------------------
    if ($EnableLongPaths) {
        Write-Step 'Long path support'
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'LongPathsEnabled' -Value 1 -Type DWord
        Write-Ok 'LongPathsEnabled = 1 (effective for new processes)'
        $script:Summary['Long paths'] = 'enabled'
    }

    if ($AddDefenderExclusion) {
        Write-Step 'Windows Defender exclusion'
        Write-Warn "Adding $Root to the Defender exclusions. ONLY use this on an isolated analysis VM."
        try {
            Add-MpPreference -ExclusionPath $Root
            Write-Ok "Exclusion added: $Root"
            $script:Summary['Defender exclusion'] = $Root
        } catch {
            Write-Warn "Cannot add the exclusion (Defender missing or managed by a policy): $($_.Exception.Message)"
        }
    }

    # Configuration file read by script 02 and the launcher
    $cfg = [ordered]@{
        root            = $Root
        tools_dir       = (Join-Path $Root 'tools')
        cases_dir       = (Join-Path $Root 'cases')
        venvs_dir       = (Join-Path $Root 'venvs')
        python_base     = $py
        orchestrator_py = $vpy
        seven_zip       = $(if (Test-Path $sevenZip) { $sevenZip } else { $null })
        prepared_at     = (Get-Date).ToString('o')
    }
    $cfg | ConvertTo-Json | Set-Content -Path (Join-Path $Root 'sleuthline-config.json') -Encoding UTF8
    Write-Ok "Configuration written: $Root\sleuthline-config.json"

    # ----------------------------------------------------------------------
    Write-Step 'Summary'
    $script:Summary.GetEnumerator() | ForEach-Object { Write-Host ("    {0,-32} {1}" -f $_.Key, $_.Value) }
    Write-Host "`nVM ready. Next step: .\02_Install-Tools.ps1" -ForegroundColor Green
}
finally {
    Stop-Transcript | Out-Null
    Write-Host "Log: $log"
}
