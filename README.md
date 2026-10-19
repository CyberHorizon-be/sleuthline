# Sleuthline

**From a KAPE collection to an evidence-backed incident response report.**

Sleuthline is a Windows DFIR pipeline for an isolated analysis VM. It takes a KAPE triage collection (e.g. `!SANS_Triage`), parses it with recognized forensic tools, normalizes every output into a single DuckDB database with a UTC timeline, then lets an LLM agent investigate the case step by step and write a technical Word report in which **every finding cites verifiable records** of the database.

```
KAPE collection ──> 1. inventory ──> 2. parsing ──> 3. normalization ──> 4. analysis agent ──> Word report
                    coverage,         EZTools,        DuckDB: raw tables,   playbook steps,       findings, timeline,
                    integrity         Hayabusa,       UTC timeline,         SQL tools, evidence   IOCs, MITRE, answers,
                    (KAPE SHA-1)      Chainsaw,       detections,           checked against       recommendations,
                                      Zircolite,      hash lists            the database          traceability
                                      Dissect, plaso…
```

- **Recognized tools only.** EZTools, Hayabusa, Chainsaw, Zircolite, SigmaHQ, Dissect, plaso, Hindsight, SIDR, LogFileParser, BitsParser, bmc-tools, odl.py. A custom parser is written only when no tool exists (`pipeline\docs\POLICY_parsers.md`).
- **Evidence first.** Read-only collection, integrity check against the KAPE SHA-1, working copies for tools that write into databases, every timeline row and finding traceable to `<output>#<record>` and to the original path on the machine.
- **Any model.** Claude (default), any OpenAI-compatible API, or a local model (Ollama, LM Studio, vLLM) so that no data leaves the VM.
- **Reproducible.** Tool versions locked in `install\tools-lock.json`, pipeline version (git commit) recorded in the database and the report, tests and regression references.

**Tested on** [Threat Hunting Lab 1](https://github.com/medmondson44/Threat_Hunting_Labs/blob/main/Lab_1), a public exercise (Windows 10 workstation compromised with a Meterpreter agent), in a blind run with only the 8 questions of the exercise: **about 50 minutes** from the KAPE collection to the Word report (parsing 27 min, normalization 1 min, analysis 22 min) and **about 7 USD** of Claude Opus 5.5 API usage. The agent answered all 8 questions with their evidence (see [the walkthrough](#analyzing-a-case-step-by-step)).

> Sleuthline assists an analyst; it is not an automated expert. The report must be reviewed and validated by a qualified analyst before any distribution or decision (see [Limitations and responsibility](#limitations-and-responsibility)).

## Requirements

- Windows 10/11 or Server 2019+ **64-bit**, dedicated and isolated VM
- Internet access (github.com, api.github.com, pypi.org, download.ericzimmermanstools.com, python.org)
- 100 GB of free space recommended
- PowerShell started **as administrator**
- KAPE (optional, only to collect): download it yourself from Kroll and drop `kape.zip` in `install\`

## Quick start

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
git clone https://github.com/CyberHorizon-be/sleuthline.git C:\Sleuthline-setup
cd C:\Sleuthline-setup
.\Install-All.ps1 -AddDefenderExclusion -EnableLongPaths     # 10 to 20 minutes
```

Then set up the API key once and analyze a case step by step: see **[Analyzing a case, step by step](#analyzing-a-case-step-by-step)**. In short:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force                      # in every new PowerShell window
C:\Sleuthline\pipeline\sleuthline.ps1 check                           # API key and model OK?
C:\Sleuthline\pipeline\sleuthline.ps1 inventory C:\Sleuthline\cases\<case>
C:\Sleuthline\pipeline\sleuthline.ps1 parse     C:\Sleuthline\cases\<case>
C:\Sleuthline\pipeline\sleuthline.ps1 normalize C:\Sleuthline\cases\<case>
#   pause: review the results, fill in <case>\analysis\guidance.txt (context, questions, IOCs)
C:\Sleuthline\pipeline\sleuthline.ps1 analyze   C:\Sleuthline\cases\<case>
```

The report is written to `<case>\analysis\report_<case>_<date>.docx`.

## Repository layout

```
<repository>\                       ← source of truth (e.g. C:\Sleuthline-setup)
├── Install-All.ps1                  ← ENTRY POINT: installs everything
├── LICENSE, README.md, CHANGELOG.md
├── install\                         ← VM installation
│   ├── 01_Prepare-VM.ps1                Python, .NET, 7-Zip, Git, folder tree, venv
│   ├── 02_Install-Tools.ps1             parsing tools + deployment of the pipeline
│   ├── Export-ToolsLock.ps1             freezes the installed versions -> tools-lock.json
│   ├── tools-lock.json                  exact versions of the reference VM (-Locked installation)
│   ├── lib\Lock.ps1                     common lock functions
│   └── kape.zip                         (to be added yourself; installed automatically; NEVER published)
├── tests\run_tests.py               ← tests (fast + optional regression on your own case)
└── pipeline\                        ← the analysis pipeline (deployed to <root>\pipeline)
    ├── sleuthline.ps1                   ← LAUNCHER: sleuthline.ps1 <step> <case>
    ├── 1_inventory\     inventory.py         collection inventory, coverage, integrity, gaps
    ├── 2_parsing\       orchestrator.py      runs the tools on the collection
    │                    sample_outputs.py    samples of the outputs (development aid)
    ├── 3_normalize\     normalize.py         loading into DuckDB: timeline, detections, hash lists
    ├── 4_analysis\      analyze.py           analysis agent (LLM)
    │                    llm.py               model access (Claude, OpenAI-compatible, Ollama...)
    │                    guards.py            evidence policy and untrusted-evidence protection
    │                    report_docx.py       Word report
    ├── config\          ← WHAT THE ANALYST EDITS
    │                    PLAYBOOK.md          analysis steps of the agent
    │                    normalize_map.json   outputs -> timeline mappings
    │                    parser_registry.json artifact -> validated parsing tool (and registry keys: registry_keys)
    │                    recmd\Sleuthline_Complement.reb   RECmd batch complementing the Kroll batch
    │                    llm_config.json      model profiles (active profile: claude) and report language
    │                    api_keys_template.txt     template of api_keys.txt (the real file is never versioned)
    │                    guidance_template.txt     template of the questions / IOCs file of a case
    └── docs\            POLICY_parsers.md    rule "existing tool before custom parser"
```

On the VM, `<root>\pipeline\` receives the same tree, plus `local\` (files specific to the VM, never overwritten): `registry_proposals.json` and `normalize_proposals.json` (proposals produced during analyses) and `hashsets\` (offline hash lists).

## Installation

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
│   ├── _help\              online help of each installed tool (syntax reference)
│   └── tools-manifest.json ← version, URL and SHA-256 of each tool
├── pipeline\               deployed copy of <repository>\pipeline (do not edit here) + VERSION.json
│   └── local\              proposals and hash lists (never overwritten)
├── rules\sigma\            SigmaHQ rules
├── venvs\                  one Python environment per tool + orchestrator
├── cases\                  analysis folders
└── logs\                   installation logs, duration history
```

After the installation, check the displayed summary: only the **required** tools block (EZTools, Hayabusa, Chainsaw, Sigma, Zircolite). `<root>\tools\tools-manifest.json` is the traceability reference: it states which version of each tool produced the results of an analysis.

## Analyzing a case, step by step

This walkthrough follows a real run on a public exercise, [Threat Hunting Lab 1](https://github.com/medmondson44/Threat_Hunting_Labs/blob/main/Lab_1) (a Windows 10 workstation compromised with a Meterpreter agent, KAPE `!SANS_Triage` collection). Times and figures are those measured on that case.

### 0. Before you start (once per VM, then once per PowerShell window)

**Allow the scripts in the current window.** Windows blocks PowerShell scripts by default. In **every new** PowerShell window, run first:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
```

`-Scope Process` changes nothing on the system: the permission ends when the window is closed. Without it, every command fails with *"running scripts is disabled on this system"*.

**Set up the API key (once).** Skip this for a local model (Ollama, LM Studio).

1. Get an API key for your model (for Claude: [Claude Console](https://platform.claude.com/settings/keys)).
2. Write it in the **repository** copy of the key file, not in the deployed one:
   ```powershell
   notepad C:\Sleuthline-setup\pipeline\config\api_keys.txt    # line: ANTHROPIC_API_KEY = sk-ant-...   (Ctrl+S)
   cd C:\Sleuthline-setup
   .\install\02_Install-Tools.ps1 -Only Pipeline               # copies the pipeline, and the key, to C:\Sleuthline\pipeline
   ```
   Why redeploy: Sleuthline runs from `C:\Sleuthline\pipeline`, a copy of the repository made by the installer. A file edited in `C:\Sleuthline\pipeline` would be overwritten by the next deployment, so every change goes into `C:\Sleuthline-setup` followed by a redeployment. `api_keys.txt` is excluded from git.
3. Check the key and the model (two tiny calls, a fraction of a cent):
   ```powershell
   C:\Sleuthline\pipeline\sleuthline.ps1 check
   # OK: tool call and tool result accepted (8.9 s, 893 input / 54 output tokens). Final answer: 'OK'
   ```
   On failure, `check` prints the error returned by the API.

**Optional: run the tests** (37 tests, about 10 seconds, no network, no cost):
```powershell
C:\Sleuthline\venvs\orchestrator\Scripts\python.exe C:\Sleuthline-setup\tests\run_tests.py
```

### 1. Put the collection in place

Copy the KAPE output into its own case folder, `C:\Sleuthline\cases\<case>\`. The `*_CopyLog.csv` and the volume folders (`C\`, ...) go at the root of the case folder, or in a `raw\` subfolder:

```
C:\Sleuthline\cases\test01\
├── 2023-11-10T123304_CopyLog.csv
├── 2023-11-10T123304_SkipLog.csv
├── C\
└── LongFileNames\
```

**Dates of the copy.** Copying the collection to the VM can give some files the date of the copy: on Lab 1, LNK files appeared in the timeline with the date of the analysis day. Say so in the guidance file (step 5) so that the agent treats those dates as copy artifacts, not evidence.

### 2. Inventory: `sleuthline.ps1 inventory <case>`

```powershell
C:\Sleuthline\pipeline\sleuthline.ps1 inventory C:\Sleuthline\cases\test01
```

Classifies every collected file by artifact type, finds which installed tool parses it, and checks its integrity against the SHA-1 recorded by KAPE. A few seconds to a few minutes (SHA-1 of every file).

Look at `<case>\inventory\coverage.md`: which artifacts are present, which ones are covered by a parser, and the integrity verdict (`INTACT` expected; a difference on `$MFT` / `$LogFile` copied live is normal).

### 3. Parsing: `sleuthline.ps1 parse <case>`

```powershell
C:\Sleuthline\pipeline\sleuthline.ps1 parse C:\Sleuthline\cases\test01
```

Runs every applicable tool (EZTools, Hayabusa, Chainsaw, Zircolite, Dissect, plaso, SIDR, LogFileParser...) on the collection, three at a time, read-only. On Lab 1: **about 30 minutes**, almost all of it **LogFileParser** ($LogFile, 27 minutes). LogFileParser prints nothing while it works: it is not stuck. Its results grow in `parsed\logfileparser\LogFile_<date>\`, and it is stopped automatically if it writes nothing for 15 minutes.

Look at `<case>\parsed\run_summary.md`. On Lab 1: 22 `ok`, 8 `no_input`, 1 `partial`, 1 `warning`:

| Status | Meaning | What to do |
|---|---|---|
| `ok` | Outputs produced | Nothing |
| `no_input` | The artifact is not in the collection (no Chrome, no BITS, no OneDrive...) | Nothing: normal |
| `warning` | Return code 0 but a warning message (e.g. SIDR: *"database state is not clean"*, usual on a live collection) | Read `parsed\<job>\_run.log` |
| `partial` | Some sub-commands failed (on Lab 1: the Dissect `search` plugin) | Check whether another tool covers the same artifact (SIDR covers Windows Search) |

The summary also states whether a collection file was modified by parsing (expected: *no file modified*).

### 4. Normalization: `sleuthline.ps1 normalize <case>`

```powershell
C:\Sleuthline\pipeline\sleuthline.ps1 normalize C:\Sleuthline\cases\test01
```

Loads every output into one DuckDB database, `<case>\db\case.duckdb`, and builds the UTC timeline. About a minute on Lab 1: 394 MB, **1 007 010 timeline rows**, 7 018 detections (21 critical, 57 high).

Look at `<case>\db\normalize_report.md`: the period covered per artifact (it tells you when the machine was active and when the collection was made), the number of detections per level, and the outputs without validated mapping (`mapping = 'auto'`).

### 5. Pause: review, then fill in the guidance file

This is the moment to tell the agent what you know, **before** the paid analysis. The guidance file is `<case>\analysis\guidance.txt`. Create it from the template:

```powershell
New-Item -ItemType Directory -Force C:\Sleuthline\cases\test01\analysis | Out-Null
Copy-Item C:\Sleuthline\pipeline\config\guidance_template.txt C:\Sleuthline\cases\test01\analysis\guidance.txt
notepad C:\Sleuthline\cases\test01\analysis\guidance.txt
```

If it does not exist, `analyze` creates it from the same template, **empty**, and starts the analysis immediately without waiting: create and fill it first if you have anything to say. `sleuthline.ps1 all` runs the four steps in a row, with no pause, for the same reason.

Every section is optional; lines starting with `#` are comments.

| Section | What to write | Example |
|---|---|---|
| `[CONTEXT]` | What is known: alert, symptoms, people, how the collection was made | `EDR alert on 2023-11-10 around 10:40 UTC on the workstation of the accountant` |
| `[PERIOD]` | Window of interest in UTC (`YYYY-MM-DD HH:MM`); also limits `incident_timeline.csv` | `start = 2023-11-10 09:00` / `end = 2023-11-10 13:00` |
| `[QUESTIONS]` | One question per line, starting with `-`. The agent answers each one in the report, with its evidence | `- How did the attacker get in?` |
| `[IOC]` | One indicator per line: `type = value  # comment`. Types: `sha1`, `sha256`, `md5`, `file`, `path`, `ip`, `domain`, `url`, `user`, `sid`, `registry`, `service`, `task`, `command`, `text`. Each IOC is **searched automatically across the whole database** before the analysis | `ip = 203.0.113.45  # C2 from the EDR` |
| `[SUSPECTS]` | Accounts, machines or processes already suspected | `jdoe` |
| `[EXCLUSIONS]` | What is legitimate and must be ignored (the collection and analysis tools are already excluded) | `C:\Tools\ (admin toolkit)` |
| `[INSTRUCTIONS]` | Free instructions: priorities, steps to dig into | `Focus on persistence and network activity` |

The guidance file used for Lab 1, a blind test with the questions of the exercise and no IOC:

```
[CONTEXT]
Threat Hunting Lab 1 (github.com/medmondson44/Threat_Hunting_Labs): security has been alerted that this
computer may have been compromised. The environment is "a little dirty" (lab setup activity).
KAPE collection made on 2023-11-10 around 12:33 UTC. It was copied to the analysis VM on 2026-10-19:
dates of 2026-10-19 are copy artefacts, not evidence.

[QUESTIONS]
- What is the malicious executable?
- What process did the malicious executable migrate to?
- Were any situational awareness commands run? If so, what were they?
- Which IP and port is the malicious executable communicating with?
- Are there any other weird processes that can be associated with the malicious executable? If so, did they run?
- Give the chain of processes used by the malicious executable (mal.exe -> migrated.exe -> other exes), using ProcessGuid and ParentProcessGuid.
- What executable was the malicious executable masquerading as?
- What are the hashes of the malicious executable(s), for submission to VirusTotal by the analyst?
```

**A blind run is a good test.** On a known case, give only the context and the questions, then compare the report with what you know. That is what was done on Lab 1.

### 6. Analysis: `sleuthline.ps1 analyze <case>`

```powershell
C:\Sleuthline\pipeline\sleuthline.ps1 analyze C:\Sleuthline\cases\test01
```

The only paid step. The agent works through the 12 steps of `PLAYBOOK.md` (context, detections, execution, persistence, accounts, remote access, files, browsing, anti-forensics, exfiltration, timeline, summary), queries the database, records evidence-backed findings, answers the questions, then writes the Word report. Progress is shown step by step in the console.

On Lab 1: **22 minutes** for the 12 steps, 153 model calls, 9.0 million input tokens of which 93 % read back from the prompt cache, 124 000 output tokens: **about 7.2 USD** at the Claude Opus 5.5 list prices (cache read 0.20, cache write 5, output 20 USD per million tokens). The exact amount is shown per key in the Claude Console.

What the agent found with no IOC given, in its own answers to the questions of the exercise:

| Lab question | Agent's answer |
|---|---|
| Malicious executable | `C:\Payloads\pscp.exe`, a Meterpreter payload downloaded from `http://10.0.0.12:8080/pscp.exe` (Defender: `Trojan:Win64/Meterpreter.E`), run at 11:03:09 UTC from an elevated PowerShell |
| Migrated to | A new `explorer.exe` (PID 7324) started by pscp.exe and injected with a remote thread (Sysmon 1 and 8) |
| Situational awareness commands | `tracert`, `quser`, `tasklist`, `netstat -ntb`, `whoami /user`, `net user administrator`, with times and parent processes |
| IP and port | `10.0.0.12`, TCP `8080` |
| Other weird processes | `C:\Payloads\test.exe` and `C:\Users\medmondson\1.exe`, same size as the payload, downloaded but with no evidence of execution |
| Process chain | `powershell.exe` (1088) → `pscp.exe` (2196) → `explorer.exe` (7324) → `cmd.exe` shells → discovery commands, linked by ProcessGuid / ParentProcessGuid |
| Masquerading as | PuTTY PSCP (OriginalFileName `PSCP`, product "PuTTY suite") |
| Hashes | MD5, SHA256 and IMPHASH of `pscp.exe` from Sysmon |

Every answer cites the records it relies on, and each critical or high finding was kept as `confirmed` only with two independent sources. The report also lists what was **not** found (persistence, lateral movement, exfiltration) and why.

## Usage

```powershell
C:\Sleuthline\pipeline\sleuthline.ps1 all C:\Sleuthline\cases\<case>   # 1 -> 2 -> 3 -> 4 + report
```

| Command | Step |
|---|---|
| `sleuthline.ps1 inventory <case>` | 1. inventory, coverage and integrity |
| `sleuthline.ps1 parse <case> [--only job --force]` | 2. parsing |
| `sleuthline.ps1 normalize <case>` | 3. DuckDB database |
| `sleuthline.ps1 analyze <case> [--profile ...]` | 4. agent + Word report |
| `sleuthline.ps1 ask <case> "text"` | one-off question to the agent |
| `sleuthline.ps1 report <case>` | regenerate the report without calling the model |

The KAPE collection goes into `<root>\cases\<case>\` (or its `raw\` subfolder).

**Recommended KAPE targets.** The pipeline only parses what was collected. `!SANS_Triage` covers the essentials; depending on the case add `RemoteAdmin` (AnyDesk, TeamViewer, ScreenConnect...), `ThumbCache`, `WindowsNotepad`, `PowerShellTranscripts` (if transcription is enabled), `OutlookPSTOST`, `$I30`, and volume shadow copies (`--vss`) for earlier versions of files and registry.

### 1-2. Inventory and parsing

| Orchestrator option | Effect |
|---|---|
| `--list` | Jobs applicable to the collection |
| `--dry-run` | Commands displayed without being run |
| `--only <jobs> --force` | Runs specific jobs again (the other results are kept) |
| `--workers N` | Parallel jobs (default: 3) |
| `--no-live` | Text progress every 30 s instead of the live display |
| `--no-verify` | No integrity re-check after parsing |

How it works:

- **Read-only collection.** Outputs go to `<case>\parsed\<job>\`. The Dissect cache is disabled. The collection files get the **read-only attribute** before parsing (defense in depth). ESE (SRUM, Windows Search) and SQLite databases (ActivitiesCache, browsers, Windows.db) are handed to the tools as **working copies** (`parsed\<job>\_work\`, deleted afterwards): SQLite writes into a database as soon as it opens it. To delete a case folder later, remove the attribute first: `attrib -r /s /d "C:\Sleuthline\cases\<case>\*"`.
- **Integrity.** `inventory.py` recomputes the SHA-1 of every collected file and compares it with the one recorded by KAPE (`*_CopyLog.csv`). A difference on a file copied live in raw mode (`$MFT`, `$LogFile`) is expected; any other difference, or a modification date later than the copy, reveals a file modified since collection. The orchestrator re-checks after parsing. Results: `inventory\coverage.md`, `parsed\run_summary.md`, Word report (Traceability appendix).
- **Traceability.** `parsed\jobs.jsonl` keeps, for every execution: exact command, tool version, duration, return code, input files and SHA-256 of the outputs. The full tool log is in `parsed\<job>\_run.log`, the summary in `parsed\run_summary.md`.
- **Statuses.** `ok`, `warning` (return code 0 but an error or data-loss message was detected), `partial`, `failed`, `empty`, `no_input`, `tool_missing`.
- **Progress.** Live display per job. The remaining time is estimated from previous runs (`<root>\logs\job_durations.jsonl`). LogFileParser also reports its real progress.
- **Hayabusa** runs with all rules (deprecated, noisy, unsupported), without channel filter, and recovers EVTX records from slack space.
- **Dissect** excludes by default the plugins that extract secrets (passwords, LSA, SAM, DPAPI).
- **Registry.** RECmd runs two batches on every hive: `Kroll_Batch.reb` (job `recmd_kroll`) then `pipeline\config\recmd\Sleuthline_Complement.reb` (job `recmd_complement`), which adds keys missing from Kroll: EMDMgmt (volume serial numbers), Active Setup, Print Monitors / Processors, BootExecute / SetupExecute / Execute, Compatibility Assistant Store (PCA).
- **Internal parsing** (job `native`, only for text formats without a recognized tool, see `parser_registry.json`): Startup folders, hosts, Wi-Fi profiles (`Wlansvc\Profiles`, Wi-Fi key never extracted), `.rdp` files including `Default.rdp` (passwords excluded), Panther logs (`setupact.log`, `setuperr.log`). `unattend.xml` is not parsed (possible passwords).

### 3. Normalization into DuckDB

```powershell
C:\Sleuthline\pipeline\sleuthline.ps1 normalize "C:\Sleuthline\cases\<case>"   # -> <case>\db\case.duckdb
```

The database is fully rebuilt at each run (written to a temporary file, then replaced). A global progress bar shows the phase, percentage, elapsed and remaining time, estimated from previous runs (`<root>\logs\normalize_durations.jsonl`).

| Object | Content |
|---|---|
| `raw.<table>` | One table per output type. Every column as text, untransformed, with `_src_file` (original output under `parsed\`) and `_src_row` (record number: CSV data line or JSONL line). |
| `timeline` | Unified timeline in **UTC**. One row per record and timestamp; identical timestamps of a same record are merged (e.g. `$SI modification (M) ; $SI access (A)`). Columns: `ts`, `ts_desc`, `artifact`, `category`, `tool`, `host`, `user_name`, `path`, `description`, `evidence`, `ref`, `mapping`. |
| `detections` | Hayabusa, Chainsaw and Zircolite alerts: rule, normalized level, channel, EventID, RecordID, details, tactics. |
| `timeline_all` | View: timeline + detections. |
| `hashset`, `hash_hits` | Offline hash lists (`<root>\pipeline\local\hashsets\` and `<case>\hashsets\`: `known_bad*.txt`, `known_good*.txt` such as an NSRL extract, any other name = `watch`) and their matches with every hash column of the database (Amcache SHA1...) **and the hashes embedded in the EVTX** (Sysmon `Hashes` field, Hayabusa / Zircolite details). |
| `artifact_summary` | View: row count and period covered per artifact. |
| `sources` | Every file of `parsed\`: status (loaded, empty, ignored, error), table, rows, rejected rows, SHA-256. |
| `jobs`, `meta` | Status of the parsing jobs; normalization parameters (version and SHA-256 of the mapping table, time zone, pipeline version, collection integrity). |

**Citing evidence.** `ref` is `<output>#<record number>`, which points to the exact line in `parsed\`. `evidence` is the original path of the artifact on the analyzed machine (`C:\Windows\System32\winevt\logs\Security.evtx`, not the copy in the case folder).

**Rules applied.**

- Paths of the copy (`<root>\cases\<case>\C\...`, working copies `...\_work\C\...`) are mapped back to the original path (`C:\...`).
- Timestamps outside [1980, today + 1 year] stay in the raw tables but not in the timeline; they are counted in the report.
- Expiry and scheduling dates (`expiration_time`, `start_boundary`, ...) are not events: they are excluded.
- Local-time sources (setupapi.dev.log, KnownNetworks, Panther logs) are converted to UTC with the `ActiveTimeBias` read from the SYSTEM hive. A daylight saving change during the period is not taken into account; this is stated in the report.
- Excluded from the timeline but kept as raw tables: `SourceAccessed` dates (modified by the collection), ActivitiesCache as seen by SQLECmd (converted to the analysis machine's local time: WxTCmd and Dissect are used instead), internal structures of `$LogFile`.

**Mappings** are described in `pipeline\config\normalize_map.json` (first match wins): `glob` (outputs concerned), `times` (date columns and their meaning), `path`, `description`, `user`, `host`, `evidence` (DuckDB SQL expression or list of columns), `detection` (mapping of an alert output), `local_time`, `note`. For Dissect, date columns are read directly from the `recorddescriptor` lines.

**New undescribed output.** It is still loaded as a raw table; its date columns are detected automatically and added to the timeline with `mapping = 'auto'` (not validated), and a proposal is added to `<root>\pipeline\local\normalize_proposals.json`. To validate it, carry it over into `pipeline\config\normalize_map.json` in the repository and redeploy with `install\02_Install-Tools.ps1 -Only Pipeline` (same circuit as for parsers, see `POLICY_parsers.md`).

**Report.** `<case>\db\normalize_report.md` (and `.json`): errors, outputs without mapping, rows per artifact, hash lists, status of each file.

### 4. Analysis agent and Word report

```powershell
C:\Sleuthline\pipeline\sleuthline.ps1 analyze "C:\Sleuthline\cases\<case>"   # full analysis + Word report
```

**Flow.** The agent follows `pipeline\config\PLAYBOOK.md`, one step per conversation: 1. system context; 2. triage of detections; 3. program execution; 4. persistence; 5. accounts and authentication; 6. remote access and lateral movement; 7. file activity; 8. web browsing; 9. anti-forensics; 10. exfiltration; 11. incident timeline; 12. summary. The steps are recommendations (inspired by SANS FOR500/FOR508) and can be edited freely.

**Agent tools.** SQL query, search, time window, evidence detail; it records findings, timeline events, IOCs and answers, and can add corroborating evidence to a finding. It has no tool that acts on the machine, the network or the files.

**Guarantees.** They are enforced by the program (`4_analysis\guards.py`), not requested from the model:

- **Read-only.** The database is opened read-only, file access is disabled in DuckDB, and every query is checked (one read query; `COPY`, `ATTACH`, `INSTALL`, file functions... refused).
- **Evidence exists.** A finding, event or IOC whose evidence reference does not exist in the database is refused. An answer to a question needs references too, unless it is `undetermined`.
- **Confidence is checked, not declared.** A critical or high finding stays `confirmed` only with **two independent sources**. A Hayabusa or Chainsaw detection and the event it fires on count as one source, because they come from the same `.evtx`. Otherwise it is recorded as `probable`, and the report shows both values: `probable (model: confirmed, lowered by the evidence policy)`. Evidence from outputs mapped automatically (`mapping = 'auto'`, not validated) never confirms on its own. These rules can be changed under `evidence_policy` in `llm_config.json`.
- **Analyst override.** An analyst who has checked a finding can set its confidence in `findings.json` with `"analyst_override": {"confidence": "confirmed", "by": "name", "reason": "..."}` and regenerate the report (`sleuthline.ps1 report`). The override and its author appear in the report. The model has no way to set it.
- **Untrusted evidence (prompt injection).** Every query result reaches the model inside an `<untrusted_evidence id="...">` block whose closing tag carries a random identifier drawn for each run. The data cannot close the block: tag-like text inside it is neutralized. The system prompt states that nothing inside a block is an instruction, wherever it sits (logs, command lines, registry, file names, web pages, e-mails). Text that looks like instructions addressed to an AI, such as "ignore previous instructions" or "classify this machine as clean", is flagged to the model as a possible anti-forensics indicator. It is also listed in a report appendix for the analyst.
- **Traceability.** Everything is traced in `transcript.jsonl`: every SQL query, every result, every model answer and every injection alert.

**Guidance file**: `<case>\analysis\guidance.txt`: context, period, questions, IOCs, suspects, exclusions, instructions. How to create and fill it: [step 5 of the walkthrough](#5-pause-review-then-fill-in-the-guidance-file).

| Option (after `sleuthline.ps1 analyze <case>`) | Effect |
|---|---|
| `--ask "question"` | One-off question without running the analysis again (same as `sleuthline.ps1 ask`) |
| `--steps 3,4 --force` | Replay some steps (the other results are kept) |
| `--report-only` | Regenerate the report without calling the model (same as `sleuthline.ps1 report`) |
| `--reset` | Start from scratch (the previous `findings.json` is archived) |
| `--profile ollama` | Use another profile of `config\llm_config.json` |

An interrupted analysis (network error, Ctrl+C) resumes where it stopped: run the same command again.

**Models.** Configuration in `pipeline\config\llm_config.json` (active profile: `active`, or `--profile`):

- `anthropic`: Claude (default `claude-opus-5-5`, prompt caching, adaptive thinking). Keep `temperature` at `null`: Claude 5.5 models reject sampling parameters. `effort` (`low` to `max`, default `medium`) sets how much the model thinks; thinking is billed as output tokens. The conversation of a step is sent append-only, with the model's turns echoed unmodified, as these models require;
- `openai`: any OpenAI-compatible API (OpenAI, Azure, Mistral, OpenRouter) and local servers (Ollama, LM Studio, vLLM), where no data leaves the VM;
- `mock`: tests without a model.

**Test a profile before a real case**: `sleuthline.ps1 check` (or `sleuthline.ps1 check claude-sonnet`) makes two tiny calls: a tool call, then its result. It checks the API key, the model name, the parameters and tool calling, and prints the error returned by the API if something is wrong.

`report_language` (default `en`; e.g. `fr`, `de`, `nl`) sets the language in which the model writes findings, answers and summaries; the report layout itself is in English. For a model without tool calling, use `"tool_mode": "json"`.

**API keys**: see [step 0 of the walkthrough](#0-before-you-start-once-per-vm-then-once-per-powershell-window). The installer creates `api_keys.txt` from `api_keys_template.txt`; fill in the line of your provider in the repository copy, then redeploy. An environment variable with the same name takes precedence. Local models need no key.

**Cost.** The system prompt and the conversation of each step are cached (Claude). With Claude the conversation is append-only; with other providers, old results are truncated in batches to save context. Usage (including the share read from cache) is recorded in `findings.json` and the report. `limits.max_billed_tokens_per_run` in `llm_config.json` (0 = no limit) caps a run: the state is saved and the command can be run again.

**Deliverables** (in `<case>\analysis\`):

- `report_<case>_<date>.docx`: full incident response report: executive summary and verdict; scope, tools and versions; methodology and limitations; incident timeline; detailed findings with, for each piece of evidence, UTC timestamp, artifact, detail, reference and original path; IOCs, MITRE ATT&CK mapping, answers to the questions, recommendations; appendices (steps, detections, notes, coverage, traceability with SHA-256).
- `key_timeline.csv`, `iocs.csv`, `incident_timeline.csv` (every event of the incident window).
- `findings.json` (analysis state) and `transcript.jsonl` (full trace).

After opening the report in Word, update the table of contents (F9).

## Reproducibility and versions

- **Git.** The deployment writes the commit of the repository to `<root>\pipeline\VERSION.json`; it is copied into the database (`meta.pipeline_version`) and the report. Uncommitted changes are reported (`WARN` status of the pipeline): commit before an analysis meant to be produced.
- **Tool lock.** By default, the installation takes the latest version of each tool. To freeze the reference VM: `.\install\Export-ToolsLock.ps1`, then commit `install\tools-lock.json`. To reinstall identically: `.\Install-All.ps1 -Locked`:
  - GitHub releases: exact tag, SHA-256 of each file checked (failure if different);
  - repositories without releases (BitsParser, bmc-tools, odl.py, WMI_Forensics): exact commit;
  - Python packages (Dissect, plaso, orchestrator...): exact versions (`pip freeze`);
  - rule updates (`hayabusa update-rules`, `zircolite -U`, `--sync` of EZTools and KAPE) not run;
  - EZTools and rule folders can only be downloaded in their latest version, so they are **compared** with the lock at the end of the installation (`lock_check` of the manifest). For an exact reproduction of these, archive `<root>\tools` with the lock.
- **Manifest.** `tools-manifest.json` also records every downloaded URL and its SHA-256, the commit of source repositories and the file version of each EZTools executable.

## Tests

```powershell
C:\Sleuthline\venvs\orchestrator\Scripts\python.exe C:\Sleuthline-setup\tests\run_tests.py
C:\Sleuthline\venvs\orchestrator\Scripts\python.exe C:\Sleuthline-setup\tests\run_tests.py --regression C:\Sleuthline\cases\test01
```

The fast tests (about ten seconds) cover the SQL safeguards of the agent, the evidence policy (independent sources, automatic mappings, answers without evidence), the untrusted-evidence blocks and injection detection, the guidance, step replay, DuckDB macros, hash extraction, inventory and integrity, the internal parsers, the payload sent to Claude, and an end-to-end analysis with the `mock` provider. `--regression` (optional) normalizes one of your own cases into a temporary database and compares the row count per artifact with a reference: the first run records it in `tests\golden\<case>.json` (local, ignored by git), later runs detect any parser or mapping change that adds or loses rows (`--update-golden` after an intended change).

## Known issues

- **WMI_Forensics** is written in Python 2: it is installed but not used; WMI persistence is analyzed with Dissect (`cim.consumerbindings`).
- **LogFileParser**: if the archive contains no executable, the status is `WARN`. It may loop on some `$LogFile`; it is stopped after 15 minutes without output and its partial results are kept.
- **Zircolite** (v4+) is installed from its Windows binary: its Python dependencies cannot be installed with pip (pySigma conflict only resolved by uv/PDM). Automatic fallback to a venv installed with `uv` if the binary is missing.
- **Hindsight**: `hindsight.exe` from the GitHub release; fallback to pyhindsight (venv) if unavailable.
- **BitsParser, bmc-tools, WMI_Forensics**: no published binary, they remain Python scripts installed at a precise commit.
- **Chainsaw**: the `+examples` package is not used (EVTX samples with paths > 260 characters).
- **KAPE** cannot be downloaded automatically (registration required). It is only needed to collect, not to analyze.

## Artifact coverage: accepted limits

- **Not covered, out of scope:** memory, volume shadow copies (VSS), pagefile / hiberfil, PST / OST, Teams / Slack LevelDB databases, WSL, DPAPI (deliberately excluded: secrets).
- **Pending validation:** OneDrive `SyncEngineDatabase.db`. No SQLECmd map exists; the reference tool, OneDriveExplorer, is proposed in `parser_registry.json` but not installed (analyst validation required by `POLICY_parsers.md`). The inventory reports the database as NOT COVERED. Meanwhile: ODL logs (odl.py), `$MFT` / `$J`.
- **Windows 11 Notepad tabs:** Dissect plugin `windowsnotepad.tabs`. Collect with the KAPE target `WindowsNotepad` if it is not included in the triage target used.

## Rule: existing tool before custom parser

Before writing a parser, check that no recognized tool exists: see `pipeline\docs\POLICY_parsers.md`.

- **Validated decisions:** `pipeline\config\parser_registry.json`.
- **Proposals of the agent during an analysis:** `<root>\pipeline\local\registry_proposals.json` (parsers) and `<root>\pipeline\local\normalize_proposals.json` (normalization mappings). These files are never overwritten by deployment.
- **Automatic reporting:** `inventory.py` lists uncovered artifacts and unknown files in `gaps.json`.

The repository is the single source of truth. A validated decision is added there (installation script and registry), then deployed with `install\02_Install-Tools.ps1 -Only <Tool>,Pipeline`.

## Limitations and responsibility

- **Analysis aid, not automated expertise.** The Word report is produced by a language model from the evidence in the database. It must be reviewed, verified and validated by a qualified analyst before any distribution or decision. Every finding cites its references (`ref`) to allow this verification.
- **Confidentiality.** With an external provider (Claude, OpenAI...), the data queried by the agent is sent to its API. For sensitive data, use a local model (profiles `ollama`, `lmstudio`) or check that the processing is authorized (contract, client, GDPR).
- **Dedicated VM.** The installation changes system settings (Defender exclusion, long paths) and handles potentially malicious files: keep the tool on an isolated analysis VM.
- **Third-party tools.** This repository redistributes no third-party tool: KAPE, Eric Zimmerman's tools, Hayabusa, Chainsaw, Zircolite, the Sigma rules, Dissect, plaso, etc. are downloaded from their official sources and remain subject to their own licenses. Each user must obtain KAPE from Kroll.
- **Secrets excluded.** Plugins and parsers that extract secrets (browser passwords, LSA, SAM, DPAPI, Wi-Fi keys, `.rdp` passwords) are deliberately excluded.

## Publishing a fork

`.gitignore` already excludes `pipeline\config\api_keys.txt` (only `api_keys_template.txt` is versioned) and `install\kape.zip` (KAPE's license forbids redistribution). `install\tools-lock.json` describes the reference VM (machine name included): regenerate it with `Export-ToolsLock.ps1` if needed.

## License

MIT (see `LICENSE`). Provided "as is", without warranty of any kind.
