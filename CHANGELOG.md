# Changelog

## Unreleased

- Docs: new README walkthrough *Analyzing a case, step by step*: per-window script permission, API key setup (workspace, credit, `check`), copying a collection without losing its timestamps, each step with its duration and what to look at, the guidance file in detail with the Threat Hunting Lab 1 example, what to do after the analysis.
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
