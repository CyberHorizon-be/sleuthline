# Changelog

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
