[← README](../README.md) · [Installation](installation.md) · [Walkthrough](walkthrough.md) · [Usage](usage.md) · [Analysis and report](analysis.md) · [Limitations](limitations.md) · [Development](development.md)

# Installation

| Script | Role |
|---|---|
| `Install-All.ps1` | Runs the two scripts below |
| `install\01_Prepare-VM.ps1` | Python 3.12, .NET 9, 7-Zip, Git, folder tree under the root, orchestrator venv, system options |
| `install\02_Install-Tools.ps1` | Downloads the latest version of each tool, writes `tools-manifest.json` and deploys `pipeline\` to `<root>\pipeline` |

The installation root is `C:\Sleuthline` by default (`-Root` to change it). The scripts can be run again: what is already installed is skipped.

| Option | Effect |
|---|---|
| `-Root <folder>` | Installation root (default `C:\Sleuthline`). |
| `-AddDefenderExclusion` | Excludes the root from Defender. **Recommended**: otherwise Defender flags the Sigma rules and may quarantine evidence coming from KAPE. Only on an isolated VM. |
| `-EnableLongPaths` | Allows paths > 260 characters, common in KAPE outputs. |
| `-ForceTools` / `-Force` | Reinstalls everything, i.e. updates to the latest versions. |
| `-Only Dissect,Plaso,OneDriveODL` / `-Only Pipeline` | (Re)installs only some tools (`install\02_Install-Tools.ps1`). |
| `-Locked` | Identical reinstallation of the reference VM from `install\tools-lock.json`. |
| `-KapeZip <path>` | Installs KAPE from this zip (default: `install\kape.zip` if present). |
| `-InstallNpcap` | Suricata: if `suricata.exe` does not start (missing `wpcap.dll`), downloads Npcap from npcap.com and opens its installer window (network driver: your decision). |
| `-SuricataMsi <file>` | Suricata from this MSI instead of the latest one from openinfosecfoundation.org (`02_Install-Tools.ps1` only). |
| `GITHUB_TOKEN` (env. variable) | Avoids the 60 requests/hour limit of the GitHub API. |

What is installed:

```
<root>\                     (default C:\Sleuthline)
├── sleuthline-config.json  ← paths read by the launcher and the installer
├── tools\
│   ├── EZTools\            MFTECmd, PECmd, RECmd (+ Kroll_Batch), EvtxECmd (+ maps),
│   │                       AmcacheParser, AppCompatCacheParser, RecentFileCacheParser,
│   │                       LECmd, JLECmd, RBCmd, SBECmd, SrumECmd, SumECmd, WxTCmd, SQLECmd
│   ├── hayabusa\           hayabusa.exe + up-to-date rules
│   ├── chainsaw\           chainsaw.exe + mappings + rules
│   ├── zircolite\          Zircolite.exe (standalone binary, no venv) + rules
│   ├── LogFileParser\      $LogFile
│   ├── sidr\               Windows Search (Windows.edb / Windows.db)
│   ├── BitsParser\         BITS jobs
│   ├── WMI_Forensics\      WMI persistence (installed, not used: see Known issues)
│   ├── hindsight\          hindsight.exe (release binary, pyhindsight venv fallback)
│   ├── bmc-tools\          RDP bitmap cache
│   ├── dissect\            Dissect (venv): WebCache, tasks, Defender, PowerShell, WER...
│   ├── plaso\              plaso (venv): setupapi, PCA
│   ├── OneDriveODL\        odl.py (venv): OneDrive logs
│   ├── volatility\         Volatility 3 (venv volatility3): symbols\ and cache\ of the memory analysis
│   ├── suricata\           Suricata (MSI extracted, not installed) + rules\ (ET Open, suricata-update)
│   ├── _help\              online help of each installed tool (syntax reference)
│   └── tools-manifest.json ← version, URL and SHA-256 of each tool
├── pipeline\               deployed copy of <repository>\pipeline (do not edit here) + VERSION.json
│   └── local\              proposals, hash lists, report.json and report images (never overwritten)
├── rules\sigma\            SigmaHQ rules
├── venvs\                  one Python environment per tool + orchestrator
├── cases\                  analysis folders
└── logs\                   installation logs, duration history
```

After the installation, check the displayed summary: only the **required** tools block (EZTools, Hayabusa, Chainsaw, Sigma, Zircolite). `<root>\tools\tools-manifest.json` is the traceability reference: it states which version of each tool produced the results of an analysis.
