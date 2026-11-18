# Changelog

## Unreleased

1.1 and 1.2, designs in `docs/design/v1.1.md` and `docs/design/v1.2.md`. To be released after the Case 001 runs on the test VM (memory only, network only, full case, then workstation + domain controller).

- **Sources of a case.** The inventory detects the disk collection, the memory image and the network captures in any combination and writes `inventory\sources.json` (stored in the database `meta`). A case without KAPE collection no longer needs an empty `C` folder. The collection is found at the root of the case, in `raw\`, in `kape\` or in the single sub-folder that holds a `*_CopyLog.csv` (several: stop).
- **Steps that require a source.** A playbook step can declare `Requires: memory` / `network` / `disk`; without the source, the step is recorded `not_applicable` without any model call. Only steps 4 (memory) and 5 (network) declare it: on the 1.0 runs, every other step found findings with any single source. The agent is told the sources of the case at the start.
- **Coverage** table, computed by the program: `not_collected` / `not_covered` / `not_parsed` / `empty` / `analyzed` for every kind of artifact; new agent tool `coverage()`; playbook rule ("not found" only for an analyzed artifact); report appendix E bis.
- **Conservation** table: file → raw table (independent record count = rows loaded + rejected), tool → output (Volatility rows written, Suricata EVE events), raw table → timeline (dates present but none understood = failure). Summary in `normalize_report.md` and in the report.
- **Timestamp provenance**: new timeline columns `ts_original`, `ts_conversion`, `ts_tz_detail`, `ts_confidence`, `clock_offset_s` (reserved). `ts` is unchanged.
- Fixes from the 1.0 tests: parse summary shows the elapsed time of a job (`cpu_s` = sum of its steps); Volatility warnings make the job `warning`; Suricata gets an empty `threshold.config` when the MSI has none, and the rules it rejects are listed (e.g. `file.magic`); the report takes the host name from the memory image when no disk artifact gives one.
- README: positioning ("a DFIR evidence platform with an AI investigation layer"), new tables and columns, known limitations updated.
- **New Word report layout.** The report is built on `config\report_template.docx`: cover page, contents, header with TLP, footer with page X of Y, numbered sections on new pages, navy tables with zebra rows, call-out boxes. New structure: about this report; introduction (purpose, sources analysed, limitations); executive summary (in brief, verdict, main findings); incident overview (attack timeline, MITRE ATT&CK techniques with their tactic, affected systems and accounts, IOCs); technical analysis per finding with its evidence; conclusions; recommendations; appendices. The model's Markdown (bold, bullets, numbered lists, code, tables) is rendered instead of shown raw.
- New `report` section in `llm_config.json`: title, client, subtitle, prepared for / by, classification, version, footer, lead investigator, "About" block, and logo and cover image. Your own values go in `<root>\pipeline\local\report.json` (never overwritten by an update; example in `config\report_example.json`), images in the same folder. README: *Customizing the report*. The table of contents is refreshed by Word when the report is opened.
- **Several hosts in one case** (design in `docs/design/v1.2.md`). One folder per host in `<case>\hosts\` (each one laid out like a single-host case), captures of the whole case in `<case>\pcap\`. `sleuthline.ps1` runs inventory, parse and normalize for each host (with its own time zone) and for the case-level captures (`--host <name>` for one host only); the new `3_normalize\merge.py` merges them into `<case>\db\case.duckdb`: `host_id` on every common table, references `<host>:<output>#<record>`, raw tables per host (`raw_<host>.*`) and union views `raw.<table>` with `_host`, merge conservation checks, hosts in `meta` and `merge_report.md`. A case without `hosts\` is unchanged.
- Playbook: `Scope: host` (steps 1-4, 6, 7, 9-11: run once per host, queries limited to it) or `Scope: case` (steps 5, 8, 12-14: once, to link the hosts); rule 11 for multi-host cases. Agent: `hosts()` tool, `host` filter on `search` / `timeline_window`, hosts of each finding / event / IOC computed from its references; evidence policy: the same artifact on two hosts = two sources. Report: systems analysed, sources per host, Host column in the timeline and the main findings, hosts of the case in the affected systems, technical analysis per host.
- **Fixes from the code audit of November 2026:**
  - error messages of the data tools (e.g. a DuckDB conversion error quoting a log line) now reach the model inside the untrusted-evidence block and are scanned for text addressed to an AI, like every other result;
  - `ActiveTimeBias` read as a signed 32-bit value (east of UTC, e.g. Belgium -60 shown as 4294967236) and from the current control set (`Select\Current`), with a warning when control sets disagree;
  - list arguments sent as a single string by some models (`exclude_artifacts`, `refs`, `mitre`) are taken as one element, not one per character;
  - `%` and `_` are literal in `search`, `timeline_window`, `coverage` and the IOC sweep (`svc_host.exe` no longer matches `svcXhost.exe`);
  - timestamps given by the model with an offset are converted to UTC; an invalid timestamp is refused by `add_timeline_event`;
  - the tool-call limit applies inside one answer: beyond it, only recording tools run; new limit `max_context_tokens_per_step` (180,000 by default): beyond it, the step records its results and ends;
  - a 200 answer of the model API that is not JSON is retried instead of stopping the analysis.
- README: the EZTools bootstrap runs before the lock comparison (supply chain); daylight saving time not handled (one hour off in Europe for the other season).

**2.0 (decision graph).** Design in `docs/design/v2.0.md` (decision graph, in three parts).

- **2.0a, entity graph.** `normalize.py` (and `merge.py` for a multi-host case) builds `entities` and `entity_refs`: files (paths normalized without the drive or volume), file names of executables / scripts / archives, hashes, IPv4 addresses, URLs, domains, accounts, SIDs and hosts, linked to the records where they appear (timeline, detections, hash matches). Deterministic, no model call; same `entity_id` on every host; `common` entities flagged. New agent tools `pivot` and `neighbours` (results wrapped as untrusted evidence); playbook rule 6 uses them. Report: *Links between findings* (entities shared by several findings or several hosts).
- **2.0b, leads and investigation tasks (the decision graph itself).** Playbook steps 1-12 become a triage (30 tool calls), steps 13-14 `Phase: final`. New agent tools `add_lead` and `task_complete`; decision rules in `config\decision_rules.json` (23 rules: on findings, on the data, on IOCs beyond the findings), each firing once per origin; scheduler (`run_tasks`): leads by priority, focused tasks (15 tool calls, seeds resolved with `pivot`, host scope, instruction to look for counter-evidence), new leads from the tasks and the rules, bounds `max_tasks` 30 and `max_lead_depth` 3, leads beyond a bound kept with the reason. Report: tasks in the technical analysis, appendix *Decision trace*, leads not investigated in the limitations. `--classic` keeps the 1.2 flow.
- **2.0c, hypotheses and counter-evidence.** New agent tools `add_hypothesis` and `link_hypothesis` (supports / contradicts / context); status and confidence computed by the program (`decision.evaluate_hypothesis`): confirmed only with >= 2 independent sources, no unresolved contradiction and, for a critical / high stage, a challenge task run with no contradiction found; refuted when a contradicting finding is confirmed; contested when the challenge found a contradiction. A challenge lead is opened for every hypothesis backed by a critical / high finding; challenges run between the correlation step and the summary, with their own bound (`max_challenge_tasks`, 10). Playbook steps 13 and 14 updated. Report: *Attack path* figure (SVG drawn by the program, with PNG fallback; no plotting library), *Hypotheses* table, hypotheses in the *In brief* box.
- **Fixes from the 2.0 code audit (November 2026):** challenge tasks end with their own outcomes (`contradiction_found` / `no_contradiction` / `inconclusive`, checked by `task_complete`), so that "confirmed" can no longer be misread as "contradiction confirmed"; a task interrupted by an error is run again at the next start; leads of the same rule about the same subject (shared record, or shared file / hash / address / URL / domain of the entity graph) become one lead with several origins; the rule `staging-exfiltration` is narrower (high findings, no bare `.zip` / `upload`); a challenge is opened when a critical / high finding is linked to a hypothesis later, always at depth 1, and a *contested* hypothesis is challenged again when new supporting evidence arrives (2 challenges at most); IPv6 addresses in the entity graph (times and MAC addresses excluded).
- **From the third review (November 2026):** independence of sources by **primary source** (`guards.source_key`): container files read by several parsers or holding several artifacts (registry hives, Amcache.hve, `$MFT`, `$J`, `$LogFile`, ESE / SQLite databases) count as one source whatever the parser, user hives qualified by their folder; entity graph with the **relation** of each reference (`subject`, `cited`, `endpoint`, `hash`, `hash_match`) and the **family** of the artifact (executed, present, file_system, network, memory...), shown by `pivot`, with a reminder that co-occurrence is not causality; report: **cost and yield per origin** of the leads (rule, agent, challenge: leads, tasks, calls, tokens, new findings, outcomes); new `4_analysis\compare_runs.py` to compare two analyses of the same evidence (replay with another model, playbook, rules, `--classic`, or the same run twice).
- **From the fourth review (November 2026):** rule leads now carry their **seeds** (`entity_ids`, rarest entity first instead of the hash order), used by the task; agent leads too, given entities first. **Quota per rule** (`max_leads_per_rule`, 5, or `max_leads` on a rule), findings taken most severe first: the leads beyond it are listed with the reason *rule quota*. **Challenge as an independent review**: fresh context (hypothesis and its findings only) and optional `challenge_profile` (another model reviews the hypotheses). **Agent lead dedup**: a lead with the same subject and a similar question (similarity >= 0.5) as an existing agent lead is refused with its id. Documented limit: the finding rules read the model's wording.
- **`analyze --unbounded`** (test run): no token budget, no rule quota, bounds raised (150 calls per step, 60 per task, 500 tasks, depth 8, 200 challenges), finite ceilings kept as a guard against a loop, context limit per step kept; the run is marked *unbounded* in the report.
- Tests: 85 tests.

## 1.0.0 (2026-10-25)

First stable release: KAPE collection, memory image and network captures analyzed together, from the collection to an evidence-backed report.

- **Tested on the full DFIR Madness Case 001** (KAPE collection of the disk image + memory image + network capture, blind run): parsing 25 minutes, analysis 31 minutes, 11.76 USD. 17 critical / high findings confirmed by independent sources (none with memory or network alone). README: the full case, its commands and its report; new section *Known limitations of 1.0*.
- **Fix: analysis stopped by a transient network error.** A TLS error while reading the model's answer (`ssl.SSLError: bad record mac`, seen on the full KAPE + memory + PCAP case) was not retried and ended the analysis. Every network error (TLS, connection reset, timeout, truncated answer) is now retried like HTTP 429 / 5xx, with the same back-off. The state was saved: `analyze` continues from the interrupted step.
- Tests: 49 tests, including the retry of a TLS error and of a connection reset.

## 0.9.6 (2026-10-20)

- **Network capture analysis with Suricata.** Captures in `<case>\pcap\` (or `parse <case> --pcap <file>`, repeatable) are analyzed by the new `suricata` job: SHA-256 of the captures, offline configuration derived from the shipped `suricata.yaml`, one Suricata run per capture. EVE output split by event type (`raw.suricata_*`), alerts in `detections`, flows / DNS / HTTP / TLS / files in the timeline.
- Installer: Suricata (Windows MSI extracted, not installed; `-Only Suricata`, `-SuricataMsi <file>`) and ET Open rules through `suricata-update`; the rules folder is locked. `-InstallNpcap` installs Npcap (needed by `suricata.exe`, interactive installer).
- Playbook: new step 5 *Network traffic (PCAP)*, plus network checks in the remote access and exfiltration steps (14 steps). Evidence policy: the captures count as one source.
- Orchestrator: jobs run sequentially also honour their preliminary steps (used by the Suricata job).
- Installer fixes found on Windows: `suricata-update` is run with the Python of its venv (it is a script, not an `.exe`), and the ET Open archive is downloaded by the installer, then `suricata-update` runs `--offline` (it cannot download on Windows: Permission denied on its temporary file).
- Tested on DFIR Madness Case 001 (network capture only, blind run): parsing 12 s, 461 alerts, analysis 62 minutes, about 6 USD. README: the test, its commands and results; network captures in the introduction and the schema.
- Tests: 48 tests, including the Suricata job end to end with EVE events recorded from a real Suricata run, its normalization and the evidence policy.

## 0.9.5 (2026-10-20)

- **Memory analysis with Volatility 3.** A memory image in `<case>\memory\` (or `parse <case> --memory <path>`) is analyzed by the new `volatility` job: SHA-256 of the image, `windows.info`, then 58 plugins 3 at a time (processes, injection, network, drivers, services, registry, consoles...). No secret or file extraction. One table per plugin (`raw.vol_*`), timestamped records in the timeline (`Memory: ...`).
- Installer: Volatility 3 (`volatility3[full]` in its own venv, `-Only Volatility`).
- Playbook: new step 4 *Memory (RAM)*, which confronts memory and disk, plus memory checks in the execution, remote access and anti-forensics steps. Steps after it are renumbered (13 steps).
- Evidence policy: everything from the memory image counts as one source, distinct from the disk artifacts.
- Orchestrator: jobs can run their steps in parallel after preliminary steps (used by the Volatility plugins).
- Tested on DFIR Madness Case 001 (memory image of the workstation only, blind run): all 58 plugins OK in 11 minutes, analysis 80 minutes, about 10 USD. README: the test, its commands and results.
- Tests: 42 tests, including the Volatility job end to end with a fake `vol` (JSON output, tree flattening, failure of `windows.info`), its normalization and the evidence policy.

## 0.9.2 (2026-10-19)

- Docs: new README walkthrough *Analyzing a case, step by step*: based on a real run on Threat Hunting Lab 1: per-window script permission, API key setup and `check`, each step with its duration and what to look at, the guidance file in detail with the Lab 1 example.
- **Fix: Claude API with Claude 5.5 models.** The analysis had only been run through the mock provider and could not work against the real API:
  - the Claude profiles sent `temperature: 0.1`, which Claude 5.5 models reject (HTTP 400). It is now `null`;
  - the thinking blocks of the model's answers were dropped when the conversation was sent back (HTTP 400). Assistant turns are now echoed exactly as received;
  - old tool results were truncated, which edits the history (HTTP 400 on recent accounts). The conversation is now append-only with Claude.
- New `effort` setting in the Claude profiles (default `medium`).
- New `sleuthline.ps1 check [profile]` command: tests the API key, the model and tool calling with two tiny calls.
- Tests: a local fake of the Messages API that rejects what Claude 5.5 rejects. It runs `check` and a full analysis over HTTP through the real provider code.
- Removed the compatibility with the pre-release French version (`dfir.ps1`, `-DfirRoot`, `dfir-config.json`, French command, guidance and playbook names, French values in `findings.json`).
- Regression references (`tests/golden/`) are local to each machine and no longer published.

## 0.9.1 (2026-10-19)

Forensic guarantees are now enforced by the program instead of requested from the model, following the first public review.

- **Answers need evidence.** `answer_question` refuses an answer without references unless its confidence is `undetermined`.
- **Corroboration enforced.** A critical or high finding stays `confirmed` only with 2 independent sources. A detection and the event log it fires on count as one source. Otherwise it is recorded as `probable`, and the confidence declared by the model is kept and shown in the report. The new `add_evidence` tool adds corroborating references and re-assesses the finding.
- **Unvalidated mappings.** Evidence from outputs mapped automatically (`mapping = 'auto'`) cannot confirm a finding or an answer on its own. The report flags it.
- **Analyst override.** `analyst_override` in `findings.json` sets the confidence of a finding, with an author and a reason shown in the report.
- **Prompt injection.** Case data reaches the model only inside `<untrusted_evidence>` blocks with a per-run random closing identifier. Tag-like text in the data is neutralized. Truncated results keep their block closed. Text addressed to an AI is detected, flagged to the model as a possible anti-forensics indicator and listed in a report appendix. The system prompt has a stricter security policy.
- Configuration: new `evidence_policy` section in `llm_config.json`. Playbook rule 5 updated (corroboration, facts vs interpretation).
- Tests: 35 tests, including the evidence policy, untrusted blocks, injection detection, and an end-to-end run with an injected event.
- CI: the GitHub release of each version is created automatically from this changelog (`.github/workflows/release.yml`).

## 0.9 (2026-10-18)

First public release: KAPE collection → inventory and integrity → parsing with recognized tools → DuckDB normalization (UTC timeline, detections, hash lists) → LLM analysis agent with verified evidence → Word report.
