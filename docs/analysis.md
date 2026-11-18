[← README](../README.md) · [Installation](installation.md) · [Walkthrough](walkthrough.md) · [Usage](usage.md) · [Analysis and report](analysis.md) · [Limitations](limitations.md) · [Development](development.md)

# Analysis agent and Word report

```powershell
C:\Sleuthline\pipeline\sleuthline.ps1 analyze "C:\Sleuthline\cases\<case>"   # full analysis + Word report
```

**Flow.** The agent follows `pipeline\config\PLAYBOOK.md`, one step per conversation: 1. system context; 2. triage of detections; 3. program execution; 4. memory (RAM); 5. network traffic; 6. persistence; 7. accounts and authentication; 8. remote access and lateral movement; 9. file activity; 10. web browsing; 11. anti-forensics; 12. exfiltration; 13. incident timeline; 14. summary. The steps are recommendations (inspired by SANS FOR500/FOR508) and can be edited freely. A step dedicated to one kind of evidence declares it under its title (`Requires: memory` for step 4, `Requires: network` for step 5): when the case does not contain it, the step is recorded as not applicable without calling the model. The other steps always run: every source feeds almost every step (memory holds MFT records, registry and browser traces; a capture holds downloads, Kerberos / SMB and transferred files). The agent is told at the start which sources the case contains.

**Decision graph (2.0).** Steps 1 to 12 are a **triage** (30 tool calls each instead of 40): the agent records what it establishes and opens a **lead** (`add_lead`) for every thread that deserves a deeper look. The program also opens leads with the decision rules of `pipeline\config\decision_rules.json` (23 rules, editable): from the findings (remote logon from an internal address, persistence, C2, credential access, pass-the-hash, Kerberoasting, remote execution, LOLBins, account manipulation, anti-forensics, staging and exfiltration, removable media, impact), from the data itself (logs cleared, shadow copies deleted, encoded PowerShell, DCSync, RC4 service tickets, privileged group changes, services installed from user folders, LOLBins downloading) and from the IOCs that appear in records no finding cites yet. After the triage, every lead is investigated as a focused **task** (15 tool calls) that answers its question, looks for what would contradict it, and ends *confirmed*, *refuted* or *inconclusive*; a task can open new leads. Every lead starts from its **seeds**: the entities of its subject, rarest first (a file seen in two records before a user seen everywhere), given to the task as its starting point. Highest priority first, at most 30 tasks, depth 3 and 5 leads per rule (`max_leads_per_rule`, or `max_leads` on a rule: a broad rule cannot take the whole budget; the most severe findings come first) (`limits` in `llm_config.json`); a lead beyond a bound is never dropped silently: the report lists it with the reason. Leads of the same rule about the same subject (same record, or same file, hash, address, URL or domain) are merged into one lead with several origins; a task interrupted by an error is run again at the next start. Then step 13 (`Phase: final`) correlates and describes the attack as **hypotheses** (`add_hypothesis`: one statement per stage, linked to the findings that support it and to those that contradict it). The program computes their status and confidence: *confirmed* needs at least two independent sources, no unresolved contradiction and, for a critical or high stage, a **challenge** task that looked for what would contradict it (legitimate use, earlier activity, another source, a clock offset) and found nothing; a contradiction confirmed by a finding makes the hypothesis *refuted*, one found by the challenge makes it *contested* (a challenge answers "is there a contradiction?": `contradiction_found`, `no_contradiction` or `inconclusive`; a contested hypothesis is challenged again when new supporting evidence arrives). Challenges run before step 14 (summary), within their own bound (10 per case). A challenge task is an **independent review**: it starts from a fresh context (the hypothesis and its findings only, not the analysis state), and with `"challenge_profile": "<profile>"` in `llm_config.json` it is run by another model than the analysis (e.g. `claude-sonnet` reviewing `claude`, or the reverse), so the model that wrote a hypothesis does not review it itself. Limit: the rules read the findings written by the model (title, description, MITRE); a finding worded differently does not trigger its rule, the rules that read the data directly (`data` kind) do not depend on it. An agent lead close to an existing one (same subject and a similar question) is refused, with the id of the existing lead. The report opens section 3 with the **attack path** figure (the stages in time order, colored by confidence; SVG drawn by the program, shown by Word 2016+ / 365) and the **hypotheses** table (status, findings for and against, challenge and its answer); refuted hypotheses are kept, they show the alternatives that were tested. The report shows the whole path in the appendix *Decision trace* (lead, who opened it, question and answer, outcome, findings produced), with the **cost and yield per origin** (leads, tasks run, tool calls, tokens, new findings, outcomes of each rule, of the agent and of the challenges): which rules bring new evidence and which only consume budget. `analyze --classic` keeps the 1.2 flow (every step with the full budget, no leads, no tasks).

**Comparing two analyses (replay).** To measure a change (another model with `--profile`, another playbook with `--playbook`, other decision rules, `--classic` against the decision graph, or the same run twice for consistency), run the analysis again on the same evidence with `--reset` (the previous `findings.json` is archived), then compare:

```powershell
C:\Sleuthline\venvs\orchestrator\Scripts\python.exe C:\Sleuthline\pipeline\4_analysis\compare_runs.py A\findings.json B\findings.json --names classic 2.0 --out compare.md
```

Findings are matched on their evidence (shared references, host prefix ignored), then on their title; the comparison lists the findings lost, the new ones (with the task that found them), the severity / confidence changes, the hypotheses, the leads and the model usage of each run.

**Unbounded test run.** `sleuthline.ps1 analyze <case> --unbounded` runs the analysis without a token budget and without the quota per rule, with the other bounds raised well above what a case needs (150 tool calls per step, 60 per task, 500 tasks, depth 8, 200 challenges; values in `UNBOUNDED_LIMITS` of `analyze.py`): the analysis ends when no lead is left open. It shows how far the decision graph goes on a case and whether the normal bounds cut leads that matter (compare it with a normal run with `compare_runs.py`; the leads *not investigated* of the normal run say which bound stopped them). The finite ceilings are kept only as a guard against a loop. `max_context_tokens_per_step` is kept (it protects the context window of the model). The cost is not capped: follow the tokens in the log, Ctrl+C stops the run and keeps the state (run again without `--reset` to continue). The report notes the run as *unbounded test run*. For a test, not for production.

**Agent tools.** SQL query, search, time window, evidence detail, coverage of the evidence, `pivot` (every record where a file, hash, IP, URL, domain, account or host appears, with the entities of the same records) and `neighbours` (what else appeared on that host around it); it records findings, timeline events, IOCs and answers, and can add corroborating evidence to a finding. It has no tool that acts on the machine, the network or the files.

**Guarantees.** They are enforced by the program (`4_analysis\guards.py`), not requested from the model:

- **Read-only.** The database is opened read-only, file access is disabled in DuckDB, and every query is checked (one read query; `COPY`, `ATTACH`, `INSTALL`, file functions... refused).
- **Evidence exists.** A finding, event or IOC whose evidence reference does not exist in the database is refused. An answer to a question needs references too, unless it is `undetermined`.
- **Confidence is checked, not declared.** A critical or high finding stays `confirmed` only with **two independent sources**. Independence is decided by the **primary source**, not by the parser: one source = one original file, log, memory image or set of captures, whatever the number of parsers, detections or interpretations derived from it. A Hayabusa or Chainsaw detection and the event it fires on are one source (same `.evtx`); ShimCache and the Services key of the same SYSTEM hive are one source (same hive, whatever the tool); `$MFT`, `$J`, Amcache.hve, an ESE / SQLite database likewise; the NTUSER.DAT of two users are two sources; the memory image is one source, the captures another; in a multi-host case the same artifact on two hosts is two sources. Otherwise it is recorded as `probable`, and the report shows both values: `probable (model: confirmed, lowered by the evidence policy)`. Evidence from outputs mapped automatically (`mapping = 'auto'`, not validated) never confirms on its own. These rules can be changed under `evidence_policy` in `llm_config.json`.
- **Analyst override.** An analyst who has checked a finding can set its confidence in `findings.json` with `"analyst_override": {"confidence": "confirmed", "by": "name", "reason": "..."}` and regenerate the report (`sleuthline.ps1 report`). The override and its author appear in the report. The model has no way to set it.
- **Untrusted evidence (prompt injection).** Every query result reaches the model inside an `<untrusted_evidence id="...">` block whose closing tag carries a random identifier drawn for each run. The data cannot close the block: tag-like text inside it is neutralized. The system prompt states that nothing inside a block is an instruction, wherever it sits (logs, command lines, registry, file names, web pages, e-mails). Text that looks like instructions addressed to an AI, such as "ignore previous instructions" or "classify this machine as clean", is flagged to the model as a possible anti-forensics indicator. It is also listed in a report appendix for the analyst.
- **Traceability.** Everything is traced in `transcript.jsonl`: every SQL query, every result, every model answer and every injection alert.

**Guidance file**: `<case>\analysis\guidance.txt`: context, period, questions, IOCs, suspects, exclusions, instructions. How to create and fill it: [step 5 of the walkthrough](walkthrough.md#5-pause-review-then-fill-in-the-guidance-file).

| Option (after `sleuthline.ps1 analyze <case>`) | Effect |
|---|---|
| `--ask "question"` | One-off question without running the analysis again (same as `sleuthline.ps1 ask`) |
| `--steps 3,4 --force` | Replay some steps (the other results are kept) |
| `--report-only` | Regenerate the report without calling the model (same as `sleuthline.ps1 report`) |
| `--classic` | 1.2 flow: every step with the full call budget, no leads, no investigation tasks (comparison with 2.0) |
| `--reset` | Start from scratch (the previous `findings.json` is archived) |
| `--profile ollama` | Use another profile of `config\llm_config.json` |

An interrupted analysis (network error, Ctrl+C) resumes where it stopped: run the same command again.

**Models.** Configuration in `pipeline\config\llm_config.json` (active profile: `active`, or `--profile`):

- `anthropic`: Claude (default `claude-opus-5-5`, prompt caching, adaptive thinking). Keep `temperature` at `null`: Claude 5.5 models reject sampling parameters. `effort` (`low` to `max`, default `medium`) sets how much the model thinks; thinking is billed as output tokens. The conversation of a step is sent append-only, with the model's turns echoed unmodified, as these models require;
- `openai`: any OpenAI-compatible API (OpenAI, Azure, Mistral, OpenRouter) and local servers (Ollama, LM Studio, vLLM), where no data leaves the VM;
- `mock`: tests without a model.

**Test a profile before a real case**: `sleuthline.ps1 check` (or `sleuthline.ps1 check claude-sonnet`) makes two tiny calls: a tool call, then its result. It checks the API key, the model name, the parameters and tool calling, and prints the error returned by the API if something is wrong.

`report_language` (default `en`; e.g. `fr`, `de`, `nl`) sets the language in which the model writes findings, answers and summaries; the report layout itself is in English. For a model without tool calling, use `"tool_mode": "json"`.

**API keys**: see [step 0 of the walkthrough](walkthrough.md#0-before-you-start-once-per-vm-then-once-per-powershell-window). The installer creates `api_keys.txt` from `api_keys_template.txt`; fill in the line of your provider in the repository copy, then redeploy. An environment variable with the same name takes precedence. Local models need no key.

**Cost.** The system prompt and the conversation of each step are cached (Claude). With Claude the conversation is append-only; with other providers, old results are truncated in batches to save context. Usage (including the share read from cache) is recorded in `findings.json` and the report. `limits.max_billed_tokens_per_run` in `llm_config.json` (0 = no limit) caps a run: the state is saved and the command can be run again.

**Deliverables** (in `<case>\analysis\`):

- `report_<case>_<date>.docx`: incident response report built on `config\report_template.docx`: cover page, contents, about this report; introduction (purpose, sources analysed, limitations); executive summary with the verdict and the main findings; incident overview (attack timeline, MITRE ATT&CK techniques, affected systems and accounts, IOCs); technical analysis with, for each finding, the observed facts, the analysis and every piece of evidence (UTC timestamp, artifact, detail, reference and original path); conclusions (answers to the questions); recommendations; appendices (findings by severity, analysis steps, guidance, collection and processing, evidence timeline, detections, notes, coverage, traceability with SHA-256).
- `key_timeline.csv`, `iocs.csv`, `incident_timeline.csv` (every event of the incident window).
- `findings.json` (analysis state) and `transcript.jsonl` (full trace).

When the report is opened, Word offers to update the fields: answer Yes to fill in the page numbers of the table of contents.

## Customizing the report (company name, logo, investigator)

By default the report carries no branding: "Prepared by Sleuthline", a plain navy cover and no logo. To put your own company on it, create `C:\Sleuthline\pipeline\local\report.json`. The `local\` folder is never overwritten by an update, so your settings and images stay there:

```powershell
Copy-Item C:\Sleuthline\pipeline\config\report_example.json C:\Sleuthline\pipeline\local\report.json
notepad C:\Sleuthline\pipeline\local\report.json
```

Put the images in the same folder, for example `C:\Sleuthline\pipeline\local\logo.png` and `C:\Sleuthline\pipeline\local\cover.png`.

| Key | Where it appears | Default (empty value) |
|---|---|---|
| `logo` | Header of every page, at the left (PNG or JPG, wide format, shown 0.7 cm high) | no logo |
| `cover_image` | Background of the cover page (A4 portrait, 1240 x 1754 px; keep the left side dark, the text is written in light colours over it) | plain navy cover |
| `prepared_by` | Cover page ("Prepared by") and *About this report* | `Sleuthline` |
| `footer` | Footer of every page, at the left | `<prepared_by> · Confidential` |
| `client` | Cover page and header | `Case <case name>` |
| `prepared_for` | Cover page and *About this report* | line hidden |
| `title`, `subtitle` | Cover page | `Forensic analysis` + host; first sentence of the verdict |
| `classification` | Cover page and header (e.g. `TLP:AMBER`, `TLP:RED`) | `TLP:AMBER` |
| `version` | Cover page | `1.0` |
| `investigator` | *Lead investigator* table: `name`, `role`, `contact` | table hidden |
| `about_title`, `about`, `about_footer` | *About* block of *About this report* | block hidden |

Image paths are relative to `local\` (or absolute). Only the keys you set are taken; the others keep their defaults from the `report` section of `config\llm_config.json`. To apply a change to a report already generated, run `sleuthline.ps1 report <case>` (no model call). Keep `local\report.json` and your images out of the repository: they are specific to your VM.
