# Analysis playbook (Sleuthline agent)

This file drives `analyze.py`. Each `## Step N: title` section is run in order, in a separate conversation: the agent receives the text of the step, the findings of the previous steps, the guidance file of the case (questions, IOCs, context) and the tools to query the DuckDB database.

The playbook can be edited freely: add, remove or reorder steps, refine queries. The `## Rules` section applies to every step. Source of truth: `<repository>\pipeline\config\PLAYBOOK.md`, to be redeployed with `install\02_Install-Tools.ps1 -Only Pipeline`.

Inspired by the SANS FOR500/FOR508 methodologies (triage, execution, persistence, accounts, lateral movement, user activity, anti-forensics, exfiltration, timeline).

## Rules

1. **Observed facts only.** Every statement relies on records of the database, cited by their `ref` (`ref` column of `timeline` / `detections`, or `<_src_file>#<_src_row>` for a raw table). A finding without verifiable evidence is refused by the tool.
2. **Distinguish fact, interpretation and hypothesis.** The `confidence` field (`confirmed`, `probable`, `possible`) and the text must reflect it. Absence of evidence is not evidence of absence: state whether the artifact was available (`sources`, `jobs` tables).
3. **All times are UTC.** The time zone of the machine is in `meta` (`machine_active_time_bias_min`): mention it when it helps the interpretation.
4. **Know the evidential value of each artifact**:
   - ShimCache = presence / modification date of the file, not an execution (except the Executed field on Windows 7);
   - Amcache = presence and SHA1, not necessarily an execution;
   - Prefetch / BAM / UserAssist / SRUM / 4688 / Sysmon 1 = execution;
   - Compatibility Assistant Store (PCA, `raw.registry_complement`) = program started by the user, without a reliable execution date (the key date only applies to the last value written);
   - Wi-Fi profile (`raw.native_wifi`) = configured network; the XML creation approximates the first connection, connection dates are in `raw.reg_knownnetworks` / `raw.dissect_network_history`;
   - `$FN` dates are more reliable than `$SI` in case of timestomping (SI<FN);
   - rows with `mapping = 'auto'` are not validated: check the raw table before citing them;
   - memory (`raw.vol_*`, Volatility 3, only if a memory image was provided) = state of the machine at the moment of the capture: running processes and their command lines, live and recently closed connections, injected code. A process seen in `vol_psscan` but not in `vol_pslist` is unlinked (hidden or exited); `vol_malfind` has false positives (.NET, JIT, some security products): an RWX region starting with `MZ` or shellcode is significant, an empty one is not. Everything from the memory image counts as **one** source for corroboration;
   - network capture (`raw.suricata_*`, `detections` with engine `Suricata`, only if captures were provided) = what crossed the wire during the capture window, not what the machine did: an ET Open alert is a lead to qualify, not a finding. Everything from the captures counts as **one** source, distinct from the disk and the memory.
5. **Corroborate.** An important finding relies on at least two independent sources (e.g. Prefetch + 4688 + Sysmon 1). The program enforces it: a critical or high finding is kept as `confirmed` only with two independent sources (a Hayabusa/Chainsaw detection and the event it fires on are ONE source: the same .evtx), otherwise it is recorded as `probable`. Add corroborating references with `add_evidence` when you find them. Evidence with `mapping = 'auto'` never confirms on its own.
   Separate in each finding the **facts** (`description`: what the records show, with UTC times and identifiers) from the **interpretation** (`analysis`: what it means, alternatives, certainty). An answer to a question cites its evidence, unless it is `undetermined`.
6. **Pivot.** Every new item (file, hash, user, IP, time) is searched in the other sources: time window around it (± 5 to 30 min), same path in `$MFT`/`$J`, same name in the EVTX.
7. **Separate the noise from the analyst's activity.** Collection and analysis tools (KAPE, Sleuthline, EZTools, Hayabusa...) and normal system activity are not findings, unless the guidance says otherwise. Report them once as context.
8. **Be exhaustive and technical.** Full paths, hashes, EventIDs, SIDs, RecordIDs, registry values, command lines: the final report must allow another analyst to re-check everything.
9. **SQL queries.** One query at a time, with `LIMIT`. Use `ILIKE` for text searches. Raw table columns are text: convert with `ts_parse(col)` or `TRY_CAST`. The `ts_parse`, `orig_path`, `user_from_path` macros are available.
10. **End each step** with `step_complete`, with a technical summary of what was checked, found, and what could not be.

## Step 1: System context and scope

Goal: describe the analyzed machine and its users to frame the analysis.

- Host name, domain, Windows version, installation date, time zone: `raw.registry_kroll` (KeyPath `%CurrentVersion`, `%ComputerName%`, `%TimeZoneInformation`), `raw.reg_timezoneinfo`, `meta`, `Computer` values of the EVTX.
- Local accounts and profiles: `raw.reg_useraccounts`, `raw.reg_profilelist`, SIDs observed in `raw.evtx`.
- Network: `raw.reg_networkadapters`, `raw.reg_knownnetworks`, `raw.dissect_network_history`, Wi-Fi profiles `raw.native_wifi` (SSID, authentication).
- Volumes, known storage devices: `raw.reg_volumeinfo`, `raw.reg_usb`, `raw.reg_usbstor`, `raw.reg_scsi` (FirstInstalled / LastConnected / LastRemoved = properties 0064 / 0066 / 0067), `raw.amcache_devices`, EMDMgmt (`raw.registry_complement` where `Description` = 'EMDMgmt (ReadyBoost)': volume serial number at the end of the key name, in decimal).
- Windows installation and upgrades: `raw.native_panther` (setupact.log / setuperr.log, local time converted to UTC).
- Period covered by each source (`artifact_summary`) and missing or failed sources (`jobs` where status ≠ 'ok', `sources` where status = 'error').
- Identify the collection itself (KAPE execution, analysis tools) to exclude it from the findings.

Expected findings: one context finding "System description" (severity `info`) citing the evidence, plus one per scope anomaly (empty log, missing source).

## Step 2: Triage of automatic detections

Goal: use the Hayabusa, Chainsaw, Zircolite and Windows Defender alerts as pivots.

- `SELECT level, engine, rule_title, count(*) FROM detections GROUP BY ALL ORDER BY ...` then detail of the `critical`, `high`, `medium` levels.
- For each significant rule: source events (`raw.evtx` through `EventRecordId` = `record_id` and `Channel`), context ± 10 min in `timeline`.
- Defender: `raw.evtx` Channel `%Windows Defender%` (1116, 1117, 1118, 1119, 5001, 5007, 5010, 5012), `raw.dissect_defender_mplog`, `raw.dissect_defender_quarantine`, `raw.dissect_defender_exclusions`.
- Offline hash lists: `hash_hits` (list = `known_bad`: finding to establish; `known_good`: known-good file, useful to rule out a false positive; `watch`: to monitor). Hashes are compared with the hash columns of every raw table (Amcache SHA1...) and with the hashes embedded in the EVTX (Sysmon `Hashes` field, Hayabusa / Zircolite details). No match proves nothing if `hashset` is empty.
- Classify each alert: true positive, false positive (justify), analyst activity, to dig into.

Expected findings: one finding per true positive or coherent group of alerts; notable false positives are listed in the step summary.

## Step 3: Program execution

Goal: establish which programs were executed, when, by whom and from where.

- Prefetch: `raw.prefetch` (LastRun, PreviousRun0-6, RunCount, FilesLoaded, Directories).
- Amcache: `raw.amcache_files` (FullPath, SHA1), `raw.amcache_programs`.
- ShimCache: `raw.shimcache` (presence).
- BAM/DAM: `raw.reg_bam`, `raw.dissect_bam`; UserAssist: `raw.reg_userassist`, `raw.dissect_userassist`; MUICache: `raw.dissect_muicache`.
- Program Compatibility Assistant: `raw.registry_complement` where `Category` = 'Program Execution' (`ValueName` = path of the executable started); Windows 11 PCA files (`timeline` artifact Program Compatibility Assistant, plaso).
- SRUM: `raw.srum_app_resource`, `raw.srum_app_timeline`, `raw.srum_network_usage`.
- EVTX: 4688 (Security), Sysmon 1 (with `Hashes`), 4103/4104 (PowerShell), 400/403/600 (Windows PowerShell), PSReadLine history `raw.dissect_powershell_history`.
- Look first for: executables in unusual folders (`\Users\*\AppData`, `\Temp`, `\ProgramData`, `\Downloads`, `\Public`, volume root), names imitating system binaries, dual-use tools (psexec, procdump, mimikatz, rclone, 7z, certutil, bitsadmin, wmic, powershell -enc, mshta, rundll32, regsvr32), scripts.
- For each suspicious executable: SHA1 (Amcache) or hashes (Sysmon) and their presence in `hash_hits`, first/last execution, run count, user, file creation (`raw.mft`), origin (Zone.Identifier, download).
- If a memory image was analyzed: was the executable still running at the capture (`raw.vol_pslist`, `raw.vol_cmdline`)? Memory is examined in detail at the next step.

## Step 4: Memory (RAM)

Goal: if a memory image was analyzed (tables `raw.vol_*`; `raw.vol_image` gives its name and SHA-256), establish what was running at the moment of the capture and confront it with the disk. If there is no `raw.vol_*` table, record in step_complete that no memory image was provided, and move on.

- System: `raw.vol_info` (kernel, build, time of the capture: `SystemTime`). Compare the capture time with the KAPE collection time.
- Processes: `raw.vol_pslist`, `raw.vol_psscan` (also exited and unlinked processes), `raw.vol_pstree` (`Cmd`, `Path`, `Audit`), `raw.vol_psxview` (a process missing from some lists is suspicious), `raw.vol_cmdline`. Look for: wrong parent (e.g. `explorer.exe` not started by `userinit.exe`, `svchost.exe` not started by `services.exe`), system names in unusual paths, a second `lsass.exe`, short-lived `cmd.exe` / `powershell.exe` children of unusual parents.
- Injection and evasion: `raw.vol_malfind` (RWX private regions; `Hexdump` / `Disasm` starting with `MZ` or shellcode), `raw.vol_hollowprocesses`, `raw.vol_processghosting`, `raw.vol_pebmasquerade`, `raw.vol_ldrmodules` (DLL not in the three lists), `raw.vol_suspicious_threads`, `raw.vol_direct_system_calls` / `raw.vol_indirect_system_calls`, `raw.vol_etwpatch`, `raw.vol_unhooked_system_calls`.
- Network: `raw.vol_netscan` (connections and listening ports with their owning process, including recently closed ones). For each external address: process, PID, creation time, and the same address on the disk side (browser, Defender, Sysmon 3, SRUM).
- Code loaded: `raw.vol_dlllist` (DLLs loaded from user folders), `raw.vol_modules` / `raw.vol_modscan` / `raw.vol_driverscan` / `raw.vol_drivermodule` (drivers without a module: rootkit), `raw.vol_callbacks`, `raw.vol_ssdt`, `raw.vol_driverirp`.
- Persistence and activity still in memory: `raw.vol_svcscan` / `raw.vol_svcdiff` (services hidden from the service list), `raw.vol_scheduled_tasks`, `raw.vol_userassist`, `raw.vol_shimcachemem`, `raw.vol_amcache`, console history `raw.vol_consoles` / `raw.vol_cmdscan` (commands typed in cmd.exe, often absent from the disk), `raw.vol_mutantscan` (known malware mutexes), `raw.vol_mftscan` / `raw.vol_ads` (MFT records and alternate data streams still in memory).
- Accounts: `raw.vol_sessions`, `raw.vol_getsids`, `raw.vol_privileges` (SeDebugPrivilege enabled in a user process), `raw.vol_skeleton_key`.
- **Confront memory and disk** for every suspicious process: its executable on disk (`raw.mft`, Prefetch, Amcache SHA1), its creation in the event logs (4688, Sysmon 1 with the same PID and time), its network activity. A process in memory with no trace on disk (deleted file, fileless code) and a disk artifact contradicted by memory are findings in themselves. Cite the memory record **and** the disk records: they are independent sources.

## Step 5: Network traffic (PCAP)

Goal: if network captures were analyzed (tables `raw.suricata_*`; `raw.pcap_files` gives their names and SHA-256), establish who the machine talked to, what was transferred, and confront it with the disk and the memory. If there is no `raw.suricata_*` table, record in step_complete that no capture was provided, and move on.

- Capture window: first and last `timestamp` of `raw.suricata_flow`. Findings outside this window cannot be seen on the network: say so.
- Alerts: `detections` where `engine = 'Suricata'` (signature, severity, `details` with the endpoints and the community-id); the HTTP / DNS / TLS context of each alert is in `raw.suricata_alert` (`http_url`, `dns_rrname`, `tls_sni`, `payload_printable`). Qualify each alert: many ET Open rules flag policy or noise (`ET INFO`, `ET POLICY`).
- Conversations: `raw.suricata_flow` (endpoints, application protocol, bytes in each direction, duration). Look for: external addresses, unusual ports, long-lived or periodic connections (beaconing), large uploads (exfiltration), internal hosts reached on 445 / 3389 / 5985 (lateral movement).
- Names and URLs: `raw.suricata_dns` (queries and answers: rare or algorithmic domains, newly seen domains), `raw.suricata_http` (host, URL, method, user agent, content type), `raw.suricata_tls` (SNI, certificate subject / issuer, JA3 / JA4: self-signed certificates, SNI absent or not matching).
- Files: `raw.suricata_fileinfo` (file name, magic, size, MD5 / SHA-1 / SHA-256 of the files transferred in clear text); their hashes are compared with the hash lists (`hash_hits`) and must be searched on the disk (Amcache SHA1, Sysmon hashes, Zone.Identifier) and in memory.
- **Confront network, disk and memory**: for each suspicious connection, the process that owned it (memory `raw.vol_netscan`: same endpoints and time; disk: Sysmon 3, SRUM network usage, browser history, Defender), and for each downloaded file, its creation and execution on the disk. Cite the network record **and** the disk / memory records: they are independent sources.

## Step 6: Persistence

Goal: identify any mechanism allowing to survive a reboot or to start again.

- Services: 7045 (System), 4697 (Security), `raw.reg_services` (ImagePath, ServiceDLL, NameKeyLastWrite), `raw.dissect_services`.
- Scheduled tasks: 4698/4699/4700/4702 (Security), 106/140/141/200/201 (TaskScheduler/Operational), `raw.reg_taskcache`, `raw.dissect_tasks` (command, arguments, author, date).
- Run/RunOnce keys, Winlogon, IFEO: `raw.dissect_runkeys`, `raw.registry_kroll` (Category `%Persistence%`, `%Autoruns%`).
- AppInit_DLLs: `raw.dissect_appinit` (any non-empty value is loaded into every process using user32.dll).
- COM hijacking: `raw.dissect_clsid_user` (per-user CLSID registrations in HKCU\Software\Classes\CLSID, which take precedence over HKLM; an InprocServer32 / LocalServer32 outside System32, SysWOW64 or Program Files must be explained).
- Active Setup (`StubPath`), Print Monitors / Print Processors (`Driver`), BootExecute / SetupExecute / Execute: `raw.registry_complement` where `Category` = 'Persistence'. Normal values: BootExecute = `autocheck autochk *`, SetupExecute and Execute empty, Microsoft monitor DLLs (localspl.dll, tcpmon.dll, usbmon.dll, APMon.dll, AppMon.dll, FXSMON.DLL); any other value must be explained.
- WMI: `raw.dissect_cim_consumerbindings`, EVTX WMI-Activity 5861.
- Startup: Startup folders (`raw.native_startup`: SHA-256 and original timestamps, then `raw.mft` / `raw.lnk`), modified hosts file (`raw.native_hosts`), Office (`raw.dissect_msoffice_startup`), PendingFileRenameOperations.
- Compare the creation dates with the incident window; rule out legitimate Microsoft / vendor entries with a justification.

## Step 7: Accounts, authentication and privileges

Goal: trace logons, accounts used or created and privilege escalations.

- Security: 4624 (logon type in PayloadData), 4625, 4634/4647, 4648, 4672, 4720, 4722, 4724, 4728/4732/4756, 4738, 4740, 4768/4769/4776 if present; TerminalServices 21/22/24/25, RemoteConnectionManager 1149, RDPClient 1024/1102.
- Summarize per account: first/last logons, logon types, source addresses (`RemoteHost`), failures.
- SAM accounts (`raw.reg_useraccounts`): creation, last logon, password changes, group membership.
- Look for: new accounts, accounts added to the administrators, unusual type 3/10 logons, bursts of failures, use of explicit credentials (4648).

## Step 8: Remote access and lateral movement

Goal: determine whether the machine was controlled remotely or used as a pivot.

- Inbound/outbound RDP: events of step 7, `raw.dissect_mru_mstsc`, `raw.registry_kroll` (Terminal Server Client), bitmap cache (if present), .rdp files `raw.native_rdp` (Default.rdp = last mstsc connection: host, account, gateway; a .rdp received by e-mail or downloaded is a known phishing vector).
- PsExec and equivalents: `PSEXESVC` services, `\ADMIN$`, 5140/5145, 7045 with random names.
- WinRM / remote PowerShell: WinRM/Operational 6, 91, 168; Windows PowerShell 400 with HostName `ServerRemoteHost`.
- Remote access tools (AnyDesk, TeamViewer, ScreenConnect, RustDesk, Splashtop...): execution, services, logs (`raw.dissect_remoteaccess_*`: AnyDesk, TeamViewer, Splashtop, RustDesk). ScreenConnect, Atera and other RMM tools: no parser, look for their folders in `raw.mft`, their services and the Application log ("ScreenConnect" source).
- Network shares and mapped drives: `raw.dissect_mru_networkdrive`, ShellBags of UNC paths.
- Memory (if available): connections of `raw.vol_netscan` on 3389, 445, 5985/5986 and to other internal hosts, and the process owning them.
- Network (if available): flows of `raw.suricata_flow` to or from internal hosts on 445, 3389, 5985/5986, 135, and SMB / DCERPC / Kerberos / RDP events (`raw.suricata_eve_smb`, `raw.suricata_eve_dcerpc`, `raw.suricata_eve_krb5`, `raw.suricata_eve_rdp`).

## Step 9: User activity on files and folders

Goal: rebuild the files and folders opened, created, renamed or deleted around the identified pivots.

- LNK and Jump Lists: `raw.lnk`, `raw.jumplist_auto`, `raw.jumplist_custom` (targets, volumes, machines, MAC).
- ShellBags: `raw.shellbags`; RecentDocs, OpenSave, LastVisited: `raw.reg_recentdocs`, `raw.reg_opensave`, `raw.reg_lastvisited`, `raw.dissect_mru_*`; WordWheelQuery (Explorer searches).
- Windows Timeline: `raw.wxt_activity`; Windows Search: `raw.sidr_files`, `raw.sidr_activity`, `raw.dissect_search`.
- Thumbcache: `raw.dissect_thumbcache` (images and documents viewed in Explorer, including files deleted since).
- Windows 11 Notepad: `raw.dissect_windowsnotepad_tabs` (tab content, including never-saved tabs, and deleted content `deleted_content`): notes, commands, credentials copied by the user or the attacker.
- File system: `raw.mft` (files created in the incident window, ZoneIdContents, SI<FN), `raw.usnjrnl` (creations, renames, deletions: UpdateReasons), `raw.logfile_usn`.
- Recycle Bin: `raw.recyclebin`, `raw.dissect_recyclebin`.
- Removable devices: `raw.reg_usb`, `raw.reg_usbstor`, `raw.reg_portabledevices`, EMDMgmt (`raw.registry_complement`), setupapi (`timeline` artifact `setupapi.dev.log`), volumes in LNK/Jump Lists (volume serial number to match with EMDMgmt, converted to hexadecimal).

## Step 10: Web browsing, downloads and e-mail

Goal: identify the origin of the suspicious files and the relevant web activity.

- Chromium (Chrome, Edge): `raw.chromium_visits`, `raw.chromium_downloads`, `raw.chromium_keywords`, `raw.chromium_omnibox`, `raw.hindsight`, `raw.dissect_browser_*`.
- Firefox: `raw.firefox_history`, `raw.firefox_downloads`, `raw.firefox_formhistory`.
- Internet Explorer / WebCache, `file://` accesses: `raw.dissect_iexplore_history`.
- Correlate each download with the creation of the file (`raw.mft`, Zone.Identifier `HostUrl`/`ReferrerUrl`) and its execution (step 3).
- Typed searches revealing the intent (tools, techniques, evasion).

## Step 11: Defense evasion and anti-forensics

Goal: detect attempts to hide the activity or to weaken security.

- Log clearing: 1102 (Security), 104 (System), gaps in the RecordIDs or empty periods.
- Defender: 5001, 5004, 5007, 5010, 5012, exclusions (`raw.dissect_defender_exclusions`), disabling through the registry.
- Timestomping: `raw.mft` where `"SI<FN" = 'True'` or `"uSecZeros" = 'True'` on relevant files; compare $SI, $FN, $J, $LogFile.
- Mass deletions ($J: FileDelete), wiping tools (sdelete, cipher /w, CCleaner, BleachBit), emptied Recycle Bin, deleted Prefetch, disabled PowerShell logging.
- System time changes: 4616, Kernel-General 1.
- Memory (if available): injection, hollowing, hooks and hidden processes found at step 4 (`raw.vol_malfind`, `raw.vol_psxview`, `raw.vol_ldrmodules`, `raw.vol_etwpatch`...).

## Step 12: Collection, exfiltration and communications

Goal: assess whether data was gathered, compressed or sent outside.

- Archives created (`raw.mft`, `raw.usnjrnl`: .zip, .7z, .rar, .tar, large files), compression tools executed, 7-Zip history (`raw.dissect_sevenzip`).
- Network volumes per application: `raw.srum_network_usage` (high BytesSent), `raw.srum_network_conn`.
- Cloud synchronization and transfers: OneDrive (`raw.odl`), rclone, browsers (uploads), BITS (Bits-Client events 3, 59, 60). The OneDrive SyncEngineDatabase.db database is not parsed (no tool installed, see `parser_registry.json`): report it in the limitations if OneDrive is involved.
- Network connections visible in the EVTX (5156 if enabled, Sysmon 3, 22 DNS), firewall (`raw.dissect_firewall_*`, added rules: 2004/2005).
- Network captures (if available, step 5): outbound flows with high `flow_bytes_toserver` in `raw.suricata_flow`, uploads in `raw.suricata_http` (POST / PUT), files in `raw.suricata_fileinfo`, DNS tunneling (long or numerous queries in `raw.suricata_dns`).
- Network indicators to extract as IOCs: IPs, domains, URLs.

## Step 13: Incident timeline and correlation

Goal: assemble the findings into a coherent incident timeline.

- Re-read the findings of the previous steps and fill the gaps: first malicious event (initial access), sequence of actions, last event.
- Add each key event with `add_timeline_event`, in order, with its phase (initial access, execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, exfiltration, impact), its MITRE ATT&CK technique and its evidence.
- Check the consistency of times between sources; report inconsistencies (clock, time zone, timestomping).
- List the final IOCs with `add_ioc` (hash, path, file name, IP, domain, URL, account, registry key, service, task), each with its evidence.

## Step 14: Summary, answers and recommendations

Goal: produce the summary elements of the report.

- `set_summary`:
  - executive summary: what happened, when, impact, confidence level;
  - detailed technical assessment;
  - limitations of the analysis: missing sources, absent artifacts, uncertainties.
- `answer_question` for each question of the guidance file: reasoned answer with evidence, or "undetermined" explaining why.
- `set_recommendations`:
  - immediate containment, eradication, recovery;
  - hardening, detection (rules to create);
  - further investigation: other machines, memory, network logs.
