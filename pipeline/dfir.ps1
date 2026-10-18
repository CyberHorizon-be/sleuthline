<#
.SYNOPSIS
    Former name of the launcher, kept for compatibility: forwards everything to sleuthline.ps1.
#>
& (Join-Path $PSScriptRoot 'sleuthline.ps1') @args
exit $LASTEXITCODE
