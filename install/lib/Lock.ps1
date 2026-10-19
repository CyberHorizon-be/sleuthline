<#
    Sleuthline - common functions of version locking (tools-lock.json):
    used by 02_Install-Tools.ps1 (-Locked mode) and Export-ToolsLock.ps1.
#>

# Rule and mapping folders whose content affects the results. They are updated outside the
# releases (update-rules, -U, --sync): their fingerprint is locked and checked.
$script:LockTrees = @(
    'hayabusa\rules', 'hayabusa\config',
    'chainsaw\rules', 'chainsaw\mappings',
    'zircolite\rules',
    'EZTools\net9\EvtxeCmd\Maps', 'EZTools\net9\RECmd\BatchExamples', 'EZTools\net9\RECmd\Plugins',
    'EZTools\net9\SQLECmd\Maps',
    'suricata\rules'
)

# Fingerprint of a folder: SHA-256 of the sorted list "relative path | SHA-256 of the file"
function Get-TreeHash ([string]$Dir) {
    if (-not (Test-Path $Dir)) { return $null }
    $root = (Resolve-Path $Dir).Path.TrimEnd('\')
    $lines = Get-ChildItem -LiteralPath $root -Recurse -File -Force |
        Where-Object { $_.Name -ne '.installed.json' } |
        ForEach-Object { $_.FullName.Substring($root.Length + 1).ToLowerInvariant() + '|' + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } |
        Sort-Object
    $bytes = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))
    [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-', '')
}

# Compares an installation with the lock: EZTools (version + SHA-256 of each .exe) and rule folders.
# Returns the list of differences (empty = compliant).
function Compare-InstallToLock ($Lock, [string]$ToolsDir, $Manifest) {
    $diffs = @()
    $ez = $Lock.tools.PSObject.Properties['EZTools']
    $cur = $Manifest.tools | Where-Object { $_.key -eq 'EZTools' -or $_.name -like 'EZTools*' } | Select-Object -First 1
    if ($ez -and $ez.Value.files) {
        foreach ($f in $ez.Value.files.PSObject.Properties) {
            $exe = if ($cur -and $cur.executables) { $cur.executables.PSObject.Properties[$f.Name] } else { $null }
            if (-not $exe -or -not (Test-Path $exe.Value)) { $diffs += "EZTools $($f.Name): missing"; continue }
            $sha = (Get-FileHash $exe.Value -Algorithm SHA256).Hash
            if ($sha -ne $f.Value.sha256) {
                $diffs += "EZTools $($f.Name): version $((Get-Item $exe.Value).VersionInfo.FileVersion) instead of $($f.Value.version)"
            }
        }
    }
    if ($Lock.trees) {
        foreach ($t in $Lock.trees.PSObject.Properties) {
            $h = Get-TreeHash (Join-Path $ToolsDir $t.Name)
            if ($h -ne $t.Value) { $diffs += "Rules/mappings $($t.Name): content differs from the lock" }
        }
    }
    return $diffs
}
