# Sleuthline

> **Which version?** The latest **validated** version is **[v1.0.0](https://github.com/CyberHorizon-be/sleuthline/releases/tag/v1.0.0)**: tested end to end on public cases (README of that version: [v1.0.0](https://github.com/CyberHorizon-be/sleuthline/tree/v1.0.0)). The `main` branch holds the next version, **2.0 in testing** (several hosts per case, entity graph, decision graph with investigation tasks, hypotheses and counter-evidence): it passes the automated tests but has not yet been validated on real cases. To install the validated version, clone that tag:
> ```powershell
> git clone --branch v1.0.0 https://github.com/CyberHorizon-be/sleuthline.git C:\Sleuthline-setup
> ```
> then follow the README of v1.0.0. The command `git clone https://github.com/CyberHorizon-be/sleuthline.git` (without `--branch`) installs `main`, the version in testing.

**A DFIR evidence platform with an AI investigation layer: from a KAPE collection, a memory image and network captures to an evidence-backed incident response report.**

Sleuthline is a Windows DFIR pipeline for an isolated analysis VM. It takes a KAPE triage collection (e.g. `!SANS_Triage`) and, if you have them, a memory image of the machine and network captures of the incident, parses them with recognized forensic tools (Volatility 3 for the memory, Suricata for the network), normalizes every output into a single DuckDB database with a UTC timeline, then lets an LLM agent investigate the case step by step and write a technical Word report in which **every finding cites verifiable records** of the database.

```
KAPE collection ──> 1. inventory ──> 2. parsing ──────┐
                    coverage,         EZTools,        │
                    integrity         Hayabusa,       │
                    (KAPE SHA-1)      Chainsaw,       │
                                      Zircolite,      ├──> 3. normalization ──> 4. analysis agent ──> Word report
                                      Dissect, plaso… │    DuckDB: raw tables,   playbook steps        findings, timeline,
                                                      │    UTC timeline,         (memory and           IOCs, MITRE, answers,
Memory image ──────────────────────> 2. parsing ──────┤    detections,           network steps),       recommendations,
(optional)                            Volatility 3:   │    hash lists            SQL tools, evidence   traceability
                                      SHA-256,        │                          checked against
                                      58 plugins      │                          the database
                                                      │
Network captures ──────────────────> 2. parsing ──────┘
(optional, .pcap)                     Suricata:
                                      SHA-256, ET Open
                                      rules, EVE output
```

- **Recognized tools only.** EZTools, Hayabusa, Chainsaw, Zircolite, SigmaHQ, Dissect, plaso, Hindsight, SIDR, LogFileParser, BitsParser, bmc-tools, odl.py, Volatility 3, Suricata (ET Open rules). A custom parser is written only when no tool exists (`pipeline\docs\POLICY_parsers.md`).
- **Evidence first.** Read-only collection, memory image and captures, integrity check against the KAPE SHA-1, SHA-256 of the memory image and of the captures, conservation checks from each tool output to the timeline, provenance of every timestamp, coverage of every artifact computed by the program, working copies for tools that write into databases, every timeline row and finding traceable to `<output>#<record>` and to the original path on the machine.
- **Disk, memory and network together.** The memory image shows what was running at the moment of the capture (processes, injected code, network connections, services); the network captures show what crossed the wire (alerts, connections, DNS, HTTP, TLS, transferred files). Dedicated playbook steps confront them with the disk artifacts, and the evidence policy counts disk, memory and network as independent sources.
- **Any model.** Claude (default), any OpenAI-compatible API, or a local model (Ollama, LM Studio, vLLM) so that no data leaves the VM.
- **Reproducible.** Tool versions locked in `install\tools-lock.json`, pipeline version (git commit) recorded in the database and the report, tests and regression references.

## Tested on public cases (version 1.0)

Blind runs, from the collection to the Word report; costs are the Claude Opus 5.5 API usage.

| Case | Sources | Duration | Cost | What the agent found | Report |
|---|---|---|---|---|---|
| [Threat Hunting Lab 1](https://github.com/medmondson44/Threat_Hunting_Labs/blob/main/Lab_1) (Windows 10, Meterpreter) | KAPE collection, the 8 questions of the exercise | about 50 min (parsing 27, normalization 1, analysis 22) | 7.23 USD (billed) | all 8 questions answered with their evidence ([walkthrough](docs/walkthrough.md)) | [PDF](docs/examples/report_threat_hunting_lab1.pdf) · [Word](docs/examples/report_threat_hunting_lab1.docx) |
| [DFIR Madness Case 001](https://dfirmadness.com/the-stolen-szechuan-sauce/), memory only (`DESKTOP-SDN1RPT`, 2 GB) | memory image, no guidance | parsing 11 min (58 plugins OK), normalization 1, analysis 80 | about 10 USD | RDP logon of the domain Administrator, `coreupdater.exe` and its service, its download with Edge, code injected into `spoolsv.exe` with access to `lsass.exe`, C2 `203.78.103.109:443` ([Memory](docs/usage.md#memory-volatility-3)) | [PDF](docs/examples/report_dfirmadness_case001_memory.pdf) · [Word](docs/examples/report_dfirmadness_case001_memory.docx) |
| Same case, network only (`case001.pcap`, 198 MB) | capture, no guidance | parsing 12 s (461 Suricata alerts), normalization < 1 min, analysis 62 | about 6 USD | RDP brute force from `194.61.24.102` (95 failures in 21 s, then success), download of `coreupdater.exe` by the DC and the workstation, Meterpreter C2 on both hosts, RDP pivot, C2 restarting at each logon ([Network](docs/usage.md#network-captures-suricata)) | [PDF](docs/examples/report_dfirmadness_case001_network.pdf) · [Word](docs/examples/report_dfirmadness_case001_network.docx) |
| Same workstation, full case | KAPE `!SANS_Triage` of the disk image (2,703 files, INTACT) + memory + capture, no guidance | parsing 25 min, normalization 1 (847,322 timeline rows), analysis 31 (237 model calls) | 11.76 USD (billed, includes a first attempt stopped by a network error) | 17 critical / high findings confirmed by independent sources (e.g. the same `coreupdater.exe` SHA-256 on the wire and in Amcache); the whole intrusion, and the one-hour offset between the capture clock and the host clock, with its cause in the Security log (4616) | [PDF](docs/examples/report_dfirmadness_case001_full.pdf) · [Word](docs/examples/report_dfirmadness_case001_full.docx) |

> Sleuthline assists an analyst; it is not an automated expert. The report must be reviewed and validated by a qualified analyst before any distribution or decision (see [Limitations and responsibility](#limitations-and-responsibility)).

## Requirements

- Windows 10/11 or Server 2019+ **64-bit**, dedicated and isolated VM
- Internet access (github.com, api.github.com, pypi.org, download.ericzimmermanstools.com, python.org; msdl.microsoft.com for the Windows symbols used by Volatility 3, at the first analysis of each Windows build; www.openinfosecfoundation.org and rules.emergingthreats.net for Suricata and its ET Open rules)
- 100 GB of free space recommended
- PowerShell started **as administrator**
- KAPE (optional, only to collect): download it yourself from Kroll and drop `kape.zip` in `install\`

## How it works, and how to run it

**How it works.** Four commands, run one after the other on a case folder:

| Step | Command | What it does | What it produces |
|---|---|---|---|
| 1 | `inventory` | Lists every file of the KAPE collection, finds the tool that parses it, checks its integrity against the KAPE SHA-1 | `inventory\coverage.md` |
| 2 | `parse` | Runs the forensic tools on the collection, Volatility 3 on the memory image and Suricata on the network captures if there are any, read-only | `parsed\` (one folder per tool), `parsed\run_summary.md` |
| 3 | `normalize` | Loads every output into one DuckDB database with a UTC timeline and the detections | `db\case.duckdb`, `db\normalize_report.md` |
| | *pause* | You tell the agent what you know: context, questions, IOCs | `analysis\guidance.txt` |
| 4 | `analyze` | The agent investigates following the playbook (with memory and network steps if there is an image or captures), answers your questions, every finding backed by database records | `analysis\report_<case>_<date>.docx` |

**How to run it.** Every command, from the clone to the report, as run on [Threat Hunting Lab 1](https://github.com/medmondson44/Threat_Hunting_Labs/blob/main/Lab_1). In a PowerShell window **opened as administrator**:

```powershell
# --- Installation (once) ------------------------------------------------------------------
Set-ExecutionPolicy -Scope Process Bypass -Force          # allows the scripts in this window only
git clone https://github.com/CyberHorizon-be/sleuthline.git C:\Sleuthline-setup
cd C:\Sleuthline-setup
.\Install-All.ps1 -AddDefenderExclusion -EnableLongPaths  # about 6 minutes (measured before Volatility 3 and Suricata were added)
#   optional, network captures: Npcap, needed by suricata.exe (opens the Npcap installer window: complete it)
.\install\02_Install-Tools.ps1 -Only Suricata -Force -InstallNpcap
#   optional, to collect with KAPE: kape.zip downloaded from Kroll
.\install\02_Install-Tools.ps1 -Only KAPE -KapeZip C:\Users\<you>\Downloads\kape.zip

# --- API key (once) -------------------------------------------------------------------------
notepad C:\Sleuthline-setup\pipeline\config\api_keys.txt  # line: ANTHROPIC_API_KEY = sk-ant-...  (Ctrl+S)
.\install\02_Install-Tools.ps1 -Only Pipeline             # copies the key to C:\Sleuthline\pipeline

# --- Checks ---------------------------------------------------------------------------------
C:\Sleuthline\venvs\orchestrator\Scripts\python.exe C:\Sleuthline-setup\tests\run_tests.py   # 85 tests, OK
C:\Sleuthline\pipeline\sleuthline.ps1 check               # OK: tool call and tool result accepted

# --- A case ---------------------------------------------------------------------------------
#   copy the KAPE collection (CopyLog + C\ folder) to C:\Sleuthline\cases\test01\
#   in a new PowerShell window, run Set-ExecutionPolicy -Scope Process Bypass -Force again
C:\Sleuthline\pipeline\sleuthline.ps1 inventory C:\Sleuthline\cases\test01
C:\Sleuthline\pipeline\sleuthline.ps1 parse     C:\Sleuthline\cases\test01   # about 30 minutes
C:\Sleuthline\pipeline\sleuthline.ps1 normalize C:\Sleuthline\cases\test01   # about 1 minute

#   pause: create the guidance file and write the context and the questions
New-Item -ItemType Directory -Force C:\Sleuthline\cases\test01\analysis | Out-Null
Copy-Item C:\Sleuthline\pipeline\config\guidance_template.txt C:\Sleuthline\cases\test01\analysis\guidance.txt
notepad C:\Sleuthline\cases\test01\analysis\guidance.txt

C:\Sleuthline\pipeline\sleuthline.ps1 analyze   C:\Sleuthline\cases\test01   # about 22 minutes, 7.23 USD
#   -> C:\Sleuthline\cases\test01\analysis\report_test01_<date>.docx
```

Each step, what to look at between them and how to fill in the guidance file: **[Analyzing a case, step by step](docs/walkthrough.md)**.

**First installation.** `Install-All.ps1` installs every tool, Volatility 3 and Suricata included: nothing else to install for a memory image or network captures. Two exceptions: KAPE (put `kape.zip` in `install\` before, or install it later with `.\install\02_Install-Tools.ps1 -Only KAPE`), and Npcap, needed by `suricata.exe`, which is installed only on request: add `-InstallNpcap` to `Install-All.ps1`, or run `.\install\02_Install-Tools.ps1 -Only Suricata -Force -InstallNpcap` later (as done on the test VM). The `-Only ...` commands below are those used to update the test VM, which already existed.

**With a memory image.** Put it in `<case>\memory\` before `parse`: the `volatility` job runs with the other tools, nothing else changes. As run on [DFIR Madness Case 001](https://dfirmadness.com/the-stolen-szechuan-sauce/), with the memory image only (installation that already existed, updated with `.\install\02_Install-Tools.ps1 -Only Volatility,Pipeline`):

```powershell
#   extract DESKTOP-SDN1RPT.mem to C:\Sleuthline\cases\test02\memory\   (nothing else in the case)
C:\Sleuthline\pipeline\sleuthline.ps1 inventory C:\Sleuthline\cases\test02
C:\Sleuthline\pipeline\sleuthline.ps1 parse     C:\Sleuthline\cases\test02   # 11 minutes: 58 Volatility plugins
C:\Sleuthline\pipeline\sleuthline.ps1 normalize C:\Sleuthline\cases\test02   # about 1 minute
C:\Sleuthline\pipeline\sleuthline.ps1 analyze   C:\Sleuthline\cases\test02   # 80 minutes, about 10 USD, no guidance
```

Details and results: **[Memory (Volatility 3)](docs/usage.md#memory-volatility-3)**.

**With network captures.** Put them in `<case>\pcap\` before `parse`: the `suricata` job runs with the other tools. As run on the same case, with the capture only (installation that already existed, updated with `.\install\02_Install-Tools.ps1 -Only Suricata,Pipeline -Force -InstallNpcap`, which also installed Npcap):

```powershell
#   extract case001.pcap to C:\Sleuthline\cases\test03\pcap\   (nothing else in the case)
C:\Sleuthline\pipeline\sleuthline.ps1 inventory C:\Sleuthline\cases\test03
C:\Sleuthline\pipeline\sleuthline.ps1 parse     C:\Sleuthline\cases\test03   # 12 seconds: Suricata
C:\Sleuthline\pipeline\sleuthline.ps1 normalize C:\Sleuthline\cases\test03   # under 1 minute
C:\Sleuthline\pipeline\sleuthline.ps1 analyze   C:\Sleuthline\cases\test03   # 62 minutes, about 6 USD, no guidance
```

Details and results: **[Network captures (Suricata)](docs/usage.md#network-captures-suricata)**.

A case may contain any combination of the three sources. Since 1.1 the inventory detects them (`inventory\sources.json`) and accepts a case without KAPE collection; with 1.0 these two runs needed an empty `C` folder in the case.

**With the three sources (full case).** As run on the same workstation, 1.0: the disk image `DESKTOP-E01` (4 segments) mounted read-only with Arsenal Image Mounter (Windows partition as `F:`), then a KAPE collection with the KAPE GUI, into a `kape` folder (renamed `raw` for 1.0; since 1.1 the collection is found at the root of the case, in `raw\`, in `kape\` or in any single sub-folder holding a `*_CopyLog.csv`); the memory image and the capture copied from the two previous cases:

```powershell
#   KAPE (GUI): --tsource F: --tdest C:\Sleuthline\cases\test04\kape --tflush --target !SANS_Triage
#   C:\Sleuthline\cases\test04\  ->  kape\ (CopyLog + F\), memory\DESKTOP-SDN1RPT.mem, pcap\case001.pcap
C:\Sleuthline\pipeline\sleuthline.ps1 inventory C:\Sleuthline\cases\test04   # INTACT, 2,703 files
C:\Sleuthline\pipeline\sleuthline.ps1 parse     C:\Sleuthline\cases\test04   # 25 minutes: disk tools, Volatility, Suricata
C:\Sleuthline\pipeline\sleuthline.ps1 normalize C:\Sleuthline\cases\test04   # about 1 minute
C:\Sleuthline\pipeline\sleuthline.ps1 analyze   C:\Sleuthline\cases\test04   # 31 minutes, 11.76 USD, no guidance
```


## Documentation

| Document | Contents |
|---|---|
| [Installation](docs/installation.md) | Scripts, options, root folder, optional components (Volatility 3, Suricata, Npcap, KAPE), API keys, update |
| [Walkthrough](docs/walkthrough.md) | A case step by step, with what to check at each step and the guidance file |
| [Usage](docs/usage.md) | Commands; inventory and parsing; memory (Volatility 3); network captures (Suricata); normalization into DuckDB |
| [Analysis and report](docs/analysis.md) | The agent, the playbook, the evidence policy, several hosts, the decision graph (2.0), comparing two analyses, unbounded test run, customizing the report (company name, logo) |
| [Limitations](docs/limitations.md) | Known limitations, known issues, artifact coverage |
| [Development](docs/development.md) | Repository layout, reproducibility and tool lock, tests, parser policy, publishing a fork |
| [CHANGELOG](CHANGELOG.md) · [design notes](docs/design/) | Versions; design of 1.1, 1.2 and 2.0 |

## Limitations and responsibility

- **Analysis aid, not automated expertise.** The Word report is produced by a language model from the evidence in the database. It must be reviewed, verified and validated by a qualified analyst before any distribution or decision. Every finding cites its references (`ref`) to allow this verification.
- **Confidentiality.** With an external provider (Claude, OpenAI...), the data queried by the agent is sent to its API. For sensitive data, use a local model (profiles `ollama`, `lmstudio`) or check that the processing is authorized (contract, client, GDPR).
- **Dedicated VM.** The installation changes system settings (Defender exclusion, long paths) and handles potentially malicious files: keep the tool on an isolated analysis VM.
- **Third-party tools.** This repository redistributes no third-party tool: KAPE, Eric Zimmerman's tools, Hayabusa, Chainsaw, Zircolite, the Sigma rules, Dissect, plaso, etc. are downloaded from their official sources and remain subject to their own licenses. Each user must obtain KAPE from Kroll.
- **Secrets excluded.** Plugins and parsers that extract secrets (browser passwords, LSA, SAM, DPAPI, Wi-Fi keys, `.rdp` passwords) are deliberately excluded.

## License

MIT (see `LICENSE`). Provided "as is", without warranty of any kind.
