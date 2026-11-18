[← README](../README.md) · [Installation](installation.md) · [Walkthrough](walkthrough.md) · [Usage](usage.md) · [Analysis and report](analysis.md) · [Limitations](limitations.md) · [Development](development.md)

# Usage: inventory, parsing, memory, network, normalization

```powershell
C:\Sleuthline\pipeline\sleuthline.ps1 all C:\Sleuthline\cases\<case>   # 1 -> 2 -> 3 -> 4 + report
```

| Command | Step |
|---|---|
| `sleuthline.ps1 inventory <case>` | 1. inventory, coverage and integrity |
| `sleuthline.ps1 parse <case> [--only job --force] [--memory <image>] [--pcap <capture>]` | 2. parsing (and the memory image and network captures, if any) |
| `sleuthline.ps1 normalize <case>` | 3. DuckDB database |
| `sleuthline.ps1 analyze <case> [--profile ...]` | 4. agent + Word report |
| `sleuthline.ps1 ask <case> "text"` | one-off question to the agent |
| `sleuthline.ps1 report <case>` | regenerate the report without calling the model |

The KAPE collection goes into `<root>\cases\<case>\` (or its `raw\` subfolder).

**Recommended KAPE targets.** The pipeline only parses what was collected. `!SANS_Triage` covers the essentials; depending on the case add `RemoteAdmin` (AnyDesk, TeamViewer, ScreenConnect...), `ThumbCache`, `WindowsNotepad`, `PowerShellTranscripts` (if transcription is enabled), `OutlookPSTOST`, `$I30`, and volume shadow copies (`--vss`) for earlier versions of files and registry.

## 1-2. Inventory and parsing

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

## Memory (Volatility 3)

A memory image of the same machine can be analyzed with the collection. Put it in `<case>\memory\` (`.raw`, `.mem`, `.vmem`, `.dmp`, `.img`, `.bin`, `.lime`; one image per case), or give its path: `sleuthline.ps1 parse <case> --memory D:\dumps\host.raw`. The `parse` step then runs the `volatility` job; nothing else changes.

- **The image is evidence.** It gets the read-only attribute, and its SHA-256 is computed before anything else (`parsed\volatility\memory_image.jsonl`, table `raw.vol_image`).
- **`windows.info` first.** It identifies the kernel and downloads its symbols from the Microsoft symbol server (internet access needed the first time a Windows build is analyzed; cached in `<root>\tools\volatility\symbols\`). If it fails (image not recognized), the other plugins are not run and the job is `partial`.
- **58 plugins, 3 at a time** (`pipeline\2_parsing\memory.py`): processes (pslist, psscan, pstree, psxview, cmdline, envars, SIDs, privileges, sessions), DLLs, modules and drivers, handles, mutexes, file objects and MFT records in memory, network (netscan, netstat), injection and evasion (malfind, hollowing, ghosting, PEB masquerading, suspicious threads, direct / indirect system calls, ETW patching, hooks), services (svcscan, svcdiff), registry (UserAssist, scheduled tasks, Amcache, ShimCache), console history (consoles, cmdscan). Every command is traced in `jobs.jsonl`.
- **Never run:** plugins that extract secrets (`hashdump`, `lsadump`, `cachedump`, `truecrypt`) or files (`dumpfiles`, `pedump`, `memmap --dump`), and plugins that need a parameter (`strings`, `yarascan`, `vadregexscan`).
- **In the database:** one table per plugin (`raw.vol_pslist`, `raw.vol_netscan`, `raw.vol_malfind`...); tree outputs are flattened with a `TreeDepth` column. Process creations, network endpoints, DLL loads and the other timestamped records go into the timeline with an artifact name starting with `Memory:`.
- **Analysis:** step 4 of the playbook examines the memory and confronts it with the disk. For the evidence policy, everything from the memory image counts as **one** source, distinct from the disk artifacts: a critical finding is `confirmed` with a memory record and a disk record, not with two memory records.

**As tested on Case 001 (memory image only, no KAPE collection).** On an installation that already existed, Volatility 3 and the new pipeline were installed with `.\install\02_Install-Tools.ps1 -Only Volatility,Pipeline` (Volatility 3 2.28.2). With 1.0, the `inventory` step needed a KAPE collection: an empty folder `C` was created in the case (not needed since 1.1).

```powershell
New-Item -ItemType Directory -Force C:\Sleuthline\cases\test02\memory       # then extract DESKTOP-SDN1RPT.mem into it
New-Item -ItemType Directory -Force C:\Sleuthline\cases\test02\C            # empty: no KAPE collection in this case
C:\Sleuthline\pipeline\sleuthline.ps1 inventory C:\Sleuthline\cases\test02   # 0 files: expected
C:\Sleuthline\pipeline\sleuthline.ps1 parse     C:\Sleuthline\cases\test02   # 11 minutes: only the volatility job runs
C:\Sleuthline\pipeline\sleuthline.ps1 normalize C:\Sleuthline\cases\test02   # 1 minute: 45 vol_* tables, 177,718 timeline rows
C:\Sleuthline\pipeline\sleuthline.ps1 analyze   C:\Sleuthline\cases\test02   # 80 minutes, about 10 USD, no guidance
```

- **Parsing:** the SHA-256 of the image, then `windows.info` (38 s, symbols downloaded) and the 58 plugins, all `ok`. The slowest: `svcdiff`, `mftscan`, `svcscan` (2 to 3 minutes each). 15 plugins found nothing (e.g. no hollowing or ghosting in this case; `userassist` and `amcache` because these registry keys were incomplete in memory).
- **Analysis:** 13 steps, 242 model calls, 26 findings and 17 IOCs. The responder's tools (FTK Imager, msinfo32, autorunsc) and the Microsoft traffic were ruled out as noise. Every high and critical finding is `probable`, not `confirmed`: with a memory image alone, all the evidence comes from one source. What needs the disk (the source address of the RDP logon, proof of exfiltration, event logs) is reported as not determinable.

## Network captures (Suricata)

Network captures of the same incident can be analyzed with the collection. Put them in `<case>\pcap\` (`.pcap`, `.pcapng`, `.cap`, sub-folders included, several files allowed), or give them: `sleuthline.ps1 parse <case> --pcap D:\captures\day1.pcap --pcap D:\captures\day2.pcap`. The `parse` step then runs the `suricata` job.

- **The captures are evidence.** They get the read-only attribute, and their SHA-256 is computed first (`parsed\suricata\pcap_files.jsonl`, table `raw.pcap_files`).
- **Suricata reads them offline** (`suricata -r`), one run per capture, with the `suricata.yaml` shipped with Suricata adjusted for an offline analysis (`parsed\suricata\_suricata.yaml`): EVE output only, file hashes (MD5, SHA-1, SHA-256), community-id, checksum validation off, ET Open rules installed by `suricata-update`. Without rules, the protocol metadata is still produced.
- **In the database:** the EVE output (`<capture>\raw\eve.jsonl`, kept and hashed) is split by event type, nested fields flattened: `raw.suricata_flow`, `raw.suricata_dns`, `raw.suricata_http`, `raw.suricata_tls`, `raw.suricata_fileinfo`, `raw.suricata_anomaly`, `raw.suricata_eve_smb`, `raw.suricata_eve_rdp`... Alerts go into `detections` (engine `Suricata`, severity 1 / 2 / 3 = high / medium / low); flows, DNS, HTTP, TLS and files go into the timeline. File hashes are compared with the hash lists.
- **Installation:** the Suricata Windows MSI is **extracted** (`msiexec /a`), not installed: no service, no driver, nothing in Program Files. The Windows build of Suricata needs `wpcap.dll`, provided by Npcap, a network driver: installing it is your decision. With `-InstallNpcap` (`02_Install-Tools.ps1` or `Install-All.ps1`), if `suricata.exe` does not start, the installer downloads the latest Npcap from npcap.com and opens its installer window in WinPcap API-compatible mode (the free edition has no silent install).
- **Analysis:** step 5 of the playbook examines the traffic and confronts it with the disk and the memory. For the evidence policy, everything from the captures counts as **one** source, distinct from the disk and the memory.

**As tested on Case 001 (network capture only, no KAPE collection).** On the existing installation, `.\install\02_Install-Tools.ps1 -Only Suricata,Pipeline -Force -InstallNpcap` extracted Suricata 8.0.7, installed Npcap 1.89 (its installer window had to be completed), and installed the ET Open rules for Suricata 8.0.7 (68,731 rules, 52,834 enabled). As for the memory, 1.0 needed an empty folder `C` in the case (not since 1.1).

- **Parsing:** 12 seconds for `case001.pcap` (198 MB, 411,797 packets). 52,825 rules loaded: 9 recent ET Open rules are rejected by the Windows build of Suricata (keyword `file.magic`), and, with 1.0, a warning said that `threshold.config` is missing (not in the MSI; since 1.1 an empty one is written next to the configuration, and the rejected rules are listed in the job log).
- **Normalization:** 13 `suricata_*` tables, 99,868 timeline rows, 461 detections (7 high, 4 medium, 450 low). Times are converted to UTC (Suricata writes them in the time zone of the analysis VM).
- **Analysis:** 14 steps, 159 model calls, 22 findings and 12 IOCs (IPs, URL, MD5 / SHA-1 / SHA-256 of `coreupdater.exe`, JA3 / JA4 of the brute-force client). Execution and persistence on the hosts are `probable`, not `confirmed`: they are inferred from the traffic, without host artifacts.

## 3. Normalization into DuckDB

```powershell
C:\Sleuthline\pipeline\sleuthline.ps1 normalize "C:\Sleuthline\cases\<case>"   # -> <case>\db\case.duckdb
```

The database is fully rebuilt at each run (written to a temporary file, then replaced). A global progress bar shows the phase, percentage, elapsed and remaining time, estimated from previous runs (`<root>\logs\normalize_durations.jsonl`).

| Object | Content |
|---|---|
| `raw.<table>` | One table per output type. Every column as text, untransformed, with `_src_file` (original output under `parsed\`) and `_src_row` (record number: CSV data line or JSONL line). |
| `timeline` | Unified timeline in **UTC**. One row per record and timestamp; identical timestamps of a same record are merged (e.g. `$SI modification (M) ; $SI access (A)`). Columns: `ts`, `ts_desc`, `artifact`, `category`, `tool`, `host`, `user_name`, `path`, `description`, `evidence`, `ref`, `mapping`, and (1.1) the provenance of the time: `ts_original` (raw value written by the tool), `ts_conversion` (`utc`, `offset` = explicit offset in the value, `local_bias` = local time converted with the host's ActiveTimeBias, `auto`), `ts_tz_detail`, `ts_confidence` (`high`, `medium` for local times, `low` for automatic mappings) and `clock_offset_s` (reserved for the clock offset between sources). |
| `detections` | Hayabusa, Chainsaw and Zircolite alerts: rule, normalized level, channel, EventID, RecordID, details, tactics. |
| `timeline_all` | View: timeline + detections. |
| `hashset`, `hash_hits` | Offline hash lists (`<root>\pipeline\local\hashsets\` and `<case>\hashsets\`: `known_bad*.txt`, `known_good*.txt` such as an NSRL extract, any other name = `watch`) and their matches with every hash column of the database (Amcache SHA1...) **and the hashes embedded in the EVTX** (Sysmon `Hashes` field, Hayabusa / Zircolite details). |
| `artifact_summary` | View: row count and period covered per artifact. |
| `sources` | Every file of `parsed\`: status (loaded, empty, ignored, error), table, rows, rejected rows, SHA-256. |
| `coverage` | (1.1) What happened to every kind of artifact, computed from the inventory, the parsing jobs and the loaded tables: `not_collected` (absent from the case), `not_covered` (no installed tool), `not_parsed` (the tool failed or did not run), `empty` (parsed, no record), `analyzed`. The agent must check it before writing that something was not found; the report lists it in an appendix. |
| `entities`, `entity_refs` | (2.0) Entity graph, computed by the program: every file (path normalized without the drive: `F:\Windows\x.exe` = `\Device\HarddiskVolume3\Windows\x.exe`), file name of an executable / script / archive, hash, IPv4 address, URL, domain, account, SID and host, linked to the records (`ref`) where it appears, with the **relation** (`subject`: the record is about it, its path, account, remote address or hash; `cited`: only mentioned in its text) and the **family** of the artifact (executed, present, file_system, network, memory, opened, browsing, persistence, event_log, detected), so that a file executed and a file quoted in a log line are not read as the same evidence; from the timeline, the detections and the hash matches. The same entity has the same `entity_id` on every host of a case. `common` flags the entities seen everywhere (`svchost.exe`, `SYSTEM`...). The agent pivots with the `pivot` and `neighbours` tools; the report lists the entities shared by several findings. |
| `conservation` | (1.1) Checks that nothing was lost silently: records counted in each output file = rows loaded + rows rejected (`file_to_raw`); rows written by Volatility and EVE events of Suricata = rows of their outputs (`tool_to_output`); a mapped table whose dates are present but none understood is a failure (`raw_to_timeline`). Summary at the top of `normalize_report.md` and in the report's traceability appendix. |
| `jobs`, `meta` | Status of the parsing jobs; normalization parameters (version and SHA-256 of the mapping table, time zone, pipeline version, collection integrity). |

**Citing evidence.** `ref` is `<output>#<record number>`, which points to the exact line in `parsed\`. `evidence` is the original path of the artifact on the analyzed machine (`C:\Windows\System32\winevt\logs\Security.evtx`, not the copy in the case folder).

**Rules applied.**

- Paths of the copy (`<root>\cases\<case>\C\...`, working copies `...\_work\C\...`) are mapped back to the original path (`C:\...`).
- Timestamps outside [1980, today + 1 year] stay in the raw tables but not in the timeline; they are counted in the report.
- Expiry and scheduling dates (`expiration_time`, `start_boundary`, ...) are not events: they are excluded.
- Local-time sources (setupapi.dev.log, KnownNetworks, Panther logs) are converted to UTC with the `ActiveTimeBias` read from the SYSTEM hive, in the current control set (`Select\Current`), as a signed value (negative east of UTC, e.g. -60 for Belgium in winter, even when RECmd shows it unsigned). A daylight saving change during the period is not taken into account: in Europe, a local-time event of the other season is one hour off. This is stated in the report.
- Excluded from the timeline but kept as raw tables: `SourceAccessed` dates (modified by the collection), ActivitiesCache as seen by SQLECmd (converted to the analysis machine's local time: WxTCmd and Dissect are used instead), internal structures of `$LogFile`.

**Mappings** are described in `pipeline\config\normalize_map.json` (first match wins): `glob` (outputs concerned), `times` (date columns and their meaning), `path`, `description`, `user`, `host`, `evidence` (DuckDB SQL expression or list of columns), `detection` (mapping of an alert output), `local_time`, `note`. For Dissect, date columns are read directly from the `recorddescriptor` lines.

**New undescribed output.** It is still loaded as a raw table; its date columns are detected automatically and added to the timeline with `mapping = 'auto'` (not validated), and a proposal is added to `<root>\pipeline\local\normalize_proposals.json`. To validate it, carry it over into `pipeline\config\normalize_map.json` in the repository and redeploy with `install\02_Install-Tools.ps1 -Only Pipeline` (same circuit as for parsers, see `POLICY_parsers.md`).

**Report.** `<case>\db\normalize_report.md` (and `.json`): errors, outputs without mapping, rows per artifact, hash lists, status of each file.
