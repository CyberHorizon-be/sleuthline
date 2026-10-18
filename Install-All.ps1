<#
.SYNOPSIS
    Sleuthline - complete, non-interactive installation of the analysis VM (steps 1 + 2).

.DESCRIPTION
    Runs install\01_Prepare-VM.ps1 then install\02_Install-Tools.ps1.
    kape.zip, if placed in install\, is installed automatically.
    Designed to be run as is by anyone, or from an automation tool
    (Packer, Ansible, VM provisioning...).

.EXAMPLE
    # In an administrator PowerShell, from the repository folder:
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\Install-All.ps1 -AddDefenderExclusion -EnableLongPaths

.EXAMPLE
    # Update every tool to its latest version
    .\Install-All.ps1 -ForceTools

.EXAMPLE
    # Identical reinstallation of the reference VM (install\tools-lock.json)
    .\Install-All.ps1 -AddDefenderExclusion -EnableLongPaths -Locked
#>
[CmdletBinding()]
param(
    [string]$Root = 'C:\Sleuthline',
    [switch]$AddDefenderExclusion,
    [switch]$EnableLongPaths,
    [switch]$ForceTools,
    [string]$KapeZip,
    [string]$GitHubToken = $env:GITHUB_TOKEN,
    [switch]$Locked,          # exact versions of install\tools-lock.json (reproducible installation)
    [string]$LockFile
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$prep = @{ Root = $Root }
if ($AddDefenderExclusion) { $prep.AddDefenderExclusion = $true }
if ($EnableLongPaths)      { $prep.EnableLongPaths = $true }
if ($Locked)               { $prep.Locked = $true; if ($LockFile) { $prep.LockFile = $LockFile } }
& (Join-Path $here 'install\01_Prepare-VM.ps1') @prep

$tools = @{ Root = $Root }
if ($Locked)      { $tools.Locked = $true; if ($LockFile) { $tools.LockFile = $LockFile } }
if ($ForceTools)  { $tools.Force = $true }
if ($KapeZip)     { $tools.KapeZip = $KapeZip }
if ($GitHubToken) { $tools.GitHubToken = $GitHubToken }
& (Join-Path $here 'install\02_Install-Tools.ps1') @tools
exit $LASTEXITCODE
