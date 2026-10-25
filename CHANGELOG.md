# Changelog

## Unreleased

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
