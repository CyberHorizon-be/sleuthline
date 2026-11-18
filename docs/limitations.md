[← README](../README.md) · [Installation](installation.md) · [Walkthrough](walkthrough.md) · [Usage](usage.md) · [Analysis and report](analysis.md) · [Limitations](limitations.md) · [Development](development.md)

# Known limitations and issues

## Known limitations

Found during the tests, planned for the next versions:

- **Clocks of several sources.** Local-time sources are converted with the time zone of their own host; clock offsets between hosts or with the captures (e.g. one hour between the capture and the host on Case 001) are found by the agent on pivots, not computed by the program (`clock_offset_s` is reserved for it).
- **Several hosts (1.2)**: tested here on synthetic data only; the two-host run of Case 001 (workstation + domain controller + capture) is still to be done. Only Windows hosts. The case database is a copy of the host databases (about twice the disk space).
- **Steps that always run**: only the steps dedicated to an absent source (memory, network) are skipped. With a memory image or a capture only, the other steps still call the model, on purpose (they found critical and high findings on the memory-only and network-only cases).
- **Validation**: tested on two public cases (four runs). The installation was tested on the test VM: clean installation from GitHub with `Install-All.ps1`, then Volatility 3, Suricata and Npcap with `02_Install-Tools.ps1`.
- **Suricata (Windows build)**: 9 recent ET Open rules are rejected (`file.magic`); since 1.1 they are listed in the job log.
- **Conservation checks** compare tool counts only for Volatility and Suricata; for the other tools, the file → table and table → timeline checks apply.

## Known issues

- **WMI_Forensics** is written in Python 2: it is installed but not used; WMI persistence is analyzed with Dissect (`cim.consumerbindings`).
- **LogFileParser**: if the archive contains no executable, the status is `WARN`. It may loop on some `$LogFile`; it is stopped after 15 minutes without output and its partial results are kept.
- **Zircolite** (v4+) is installed from its Windows binary: its Python dependencies cannot be installed with pip (pySigma conflict only resolved by uv/PDM). Automatic fallback to a venv installed with `uv` if the binary is missing.
- **Hindsight**: `hindsight.exe` from the GitHub release; fallback to pyhindsight (venv) if unavailable.
- **BitsParser, bmc-tools, WMI_Forensics**: no published binary, they remain Python scripts installed at a precise commit.
- **Chainsaw**: the `+examples` package is not used (EVTX samples with paths > 260 characters).
- **KAPE** cannot be downloaded automatically (registration required). It is only needed to collect, not to analyze.

## Artifact coverage: accepted limits

- **Not covered, out of scope:** volume shadow copies (VSS), pagefile / hiberfil, PST / OST, Teams / Slack LevelDB databases, WSL, DPAPI (deliberately excluded: secrets).
- **Pending validation:** OneDrive `SyncEngineDatabase.db`. No SQLECmd map exists; the reference tool, OneDriveExplorer, is proposed in `parser_registry.json` but not installed (analyst validation required by `POLICY_parsers.md`). The inventory reports the database as NOT COVERED. Meanwhile: ODL logs (odl.py), `$MFT` / `$J`.
- **Windows 11 Notepad tabs:** Dissect plugin `windowsnotepad.tabs`. Collect with the KAPE target `WindowsNotepad` if it is not included in the triage target used.
