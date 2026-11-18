[← README](../README.md) · [Installation](installation.md) · [Walkthrough](walkthrough.md) · [Usage](usage.md) · [Analysis and report](analysis.md) · [Limitations](limitations.md) · [Development](development.md)

# Analyzing a case, step by step

This walkthrough follows a real run on a public exercise, [Threat Hunting Lab 1](https://github.com/medmondson44/Threat_Hunting_Labs/blob/main/Lab_1) (a Windows 10 workstation compromised with a Meterpreter agent, KAPE `!SANS_Triage` collection). Times and figures are those measured on that case.

## 0. Before you start (once per VM, then once per PowerShell window)

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

**Optional: run the tests** (85 tests, about 10 seconds, no network, no cost):
```powershell
C:\Sleuthline\venvs\orchestrator\Scripts\python.exe C:\Sleuthline-setup\tests\run_tests.py
```

## 1. Put the collection in place

Copy the KAPE output into its own case folder, `C:\Sleuthline\cases\<case>\`. The `*_CopyLog.csv` and the volume folders (`C\`, ...) go at the root of the case folder, or in a `raw\` subfolder:

```
C:\Sleuthline\cases\test01\
├── 2023-11-10T123304_CopyLog.csv
├── 2023-11-10T123304_SkipLog.csv
├── C\
├── LongFileNames\
├── memory\              optional: the memory image of the same machine (one image)
└── pcap\                optional: network captures of the incident (.pcap, .pcapng)
```

**Several machines in one case (1.2).** When the intrusion touches several machines (e.g. a workstation and the domain controller), put one folder per machine in `hosts\`, each laid out like a single-machine case, and the captures of the whole network in `pcap\` at the root:

```
C:\Sleuthline\cases\case05\
├── hosts\
│   ├── DESKTOP-SDN1RPT\
│   │   ├── kape\        KAPE collection of this machine (or raw\, or at the root of the folder)
│   │   └── memory\      optional: its memory image
│   └── CITADEL-DC01\
│       ├── kape\
│       └── memory\
└── pcap\                optional: captures of the whole network (tap, firewall)
```

The folder names are the host ids used everywhere (letters, digits, `-` and `_`; `network` is reserved). The same commands work: `inventory`, `parse` and `normalize` run for each machine (with its own time zone), then for the captures of the case, and `normalize` merges everything into `<case>\db\case.duckdb` (`<case>\db\merge_report.md`). `--host <name>` limits `inventory`, `parse` or `normalize` to one machine, e.g. to parse the DC again. In the analysis, the steps about one machine (execution, persistence, accounts...) run once per machine, and the steps that link them (network, lateral movement, exfiltration, timeline, summary) once for the case. References become `<host>:<output>#<record>`, every finding lists its machines, and evidence from two machines counts as two sources. A case without `hosts\` works exactly as before.

**Dates of the copy.** Copying the collection to the VM can give some files the date of the copy: on Lab 1, LNK files appeared in the timeline with the date of the analysis day. Say so in the guidance file (step 5) so that the agent treats those dates as copy artifacts, not evidence.

## 2. Inventory: `sleuthline.ps1 inventory <case>`

```powershell
C:\Sleuthline\pipeline\sleuthline.ps1 inventory C:\Sleuthline\cases\test01
```

Classifies every collected file by artifact type, finds which installed tool parses it, and checks its integrity against the SHA-1 recorded by KAPE. A few seconds to a few minutes (SHA-1 of every file).

Look at `<case>\inventory\coverage.md`: which artifacts are present, which ones are covered by a parser, and the integrity verdict (`INTACT` expected; a difference on `$MFT` / `$LogFile` copied live is normal).

## 3. Parsing: `sleuthline.ps1 parse <case>`

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

## 4. Normalization: `sleuthline.ps1 normalize <case>`

```powershell
C:\Sleuthline\pipeline\sleuthline.ps1 normalize C:\Sleuthline\cases\test01
```

Loads every output into one DuckDB database, `<case>\db\case.duckdb`, and builds the UTC timeline. About a minute on Lab 1: 394 MB, **1 007 010 timeline rows**, 7 018 detections (21 critical, 57 high).

Look at `<case>\db\normalize_report.md`: the period covered per artifact (it tells you when the machine was active and when the collection was made), the number of detections per level, and the outputs without validated mapping (`mapping = 'auto'`).

## 5. Pause: review, then fill in the guidance file

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

## 6. Analysis: `sleuthline.ps1 analyze <case>`

```powershell
C:\Sleuthline\pipeline\sleuthline.ps1 analyze C:\Sleuthline\cases\test01
```

The only paid step. The agent works through the steps of `PLAYBOOK.md` (context, detections, execution, memory and network if provided, persistence, accounts, remote access, files, browsing, anti-forensics, exfiltration, timeline, summary), queries the database, records evidence-backed findings, answers the questions, then writes the Word report. Progress is shown step by step in the console.

On Lab 1: **22 minutes** for the 12 steps, 153 model calls, 9.0 million input tokens of which 93 % read back from the prompt cache, 124 000 output tokens: **7.23 USD billed** (Claude Console, `check` included), in line with the Claude Opus 5.5 list prices (cache read 0.20, cache write 5, output 20 USD per million tokens).

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

Every answer cites the records it relies on, and each critical or high finding was kept as `confirmed` only with two independent sources. The report also lists what was **not** found (persistence, lateral movement, exfiltration) and why. Full report: [PDF](examples/report_threat_hunting_lab1.pdf) (table of contents updated) or [Word](examples/report_threat_hunting_lab1.docx), exactly as produced.
