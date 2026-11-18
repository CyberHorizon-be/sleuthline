[← README](../README.md) · [Installation](installation.md) · [Walkthrough](walkthrough.md) · [Usage](usage.md) · [Analysis and report](analysis.md) · [Limitations](limitations.md) · [Development](development.md)

# Development: layout, reproducibility, tests

## Repository layout

```
<repository>\                       ← source of truth (e.g. C:\Sleuthline-setup)
├── Install-All.ps1                  ← ENTRY POINT: installs everything
├── LICENSE, README.md, CHANGELOG.md
├── docs\examples\                 ← reports generated on Threat Hunting Lab 1 and on DFIR Madness Case 001 (memory, network, full case) (PDF and Word)
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
    │                    memory.py            Volatility 3 job (memory image)
    │                    network.py           Suricata job (network captures)
    │                    sample_outputs.py    samples of the outputs (development aid)
    ├── 3_normalize\     normalize.py         loading into DuckDB: timeline, detections, hash lists
    │                    merge.py             several hosts: merges the host databases into the case database
    ├── 4_analysis\      analyze.py           analysis agent (LLM)
    │                    llm.py               model access (Claude, OpenAI-compatible, Ollama...)
    │                    guards.py            evidence policy and untrusted-evidence protection
    │                    report_docx.py       Word report
    ├── config\          ← WHAT THE ANALYST EDITS
    │                    PLAYBOOK.md          analysis steps of the agent
    │                    normalize_map.json   outputs -> timeline mappings
    │                    parser_registry.json artifact -> validated parsing tool (and registry keys: registry_keys)
    │                    recmd\Sleuthline_Complement.reb   RECmd batch complementing the Kroll batch
    │                    llm_config.json      model profiles (active profile: claude), report language, report cover
    │                    report_template.docx Word template of the report (cover, header, footer, fonts, styles)
    │                    report_example.json  example of local\report.json (company name, logo, investigator)
    │                    api_keys_template.txt     template of api_keys.txt (the real file is never versioned)
    │                    guidance_template.txt     template of the questions / IOCs file of a case
    └── docs\            POLICY_parsers.md    rule "existing tool before custom parser"
```

On the VM, `<root>\pipeline\` receives the same tree, plus `local\` (files specific to the VM, never overwritten): `registry_proposals.json` and `normalize_proposals.json` (proposals produced during analyses) and `hashsets\` (offline hash lists).

## Reproducibility and versions

- **Git.** The deployment writes the commit of the repository to `<root>\pipeline\VERSION.json`; it is copied into the database (`meta.pipeline_version`) and the report. Uncommitted changes are reported (`WARN` status of the pipeline): commit before an analysis meant to be produced.
- **Tool lock.** By default, the installation takes the latest version of each tool. To freeze the reference VM: `.\install\Export-ToolsLock.ps1`, then commit `install\tools-lock.json`. To reinstall identically: `.\Install-All.ps1 -Locked`:
  - GitHub releases: exact tag, SHA-256 of each file checked (failure if different);
  - repositories without releases (BitsParser, bmc-tools, odl.py, WMI_Forensics): exact commit;
  - Python packages (Dissect, plaso, orchestrator...): exact versions (`pip freeze`);
  - rule updates (`hayabusa update-rules`, `zircolite -U`, `--sync` of EZTools and KAPE) not run;
  - EZTools and rule folders can only be downloaded in their latest version, so they are **compared** with the lock at the end of the installation (`lock_check` of the manifest). For an exact reproduction of these, archive `<root>\tools` with the lock.
  - Supply chain: the EZTools bootstrap script (`Get-ZimmermanTools.ps1`, from ericzimmermanstools.com over HTTPS) is run before that comparison, in every mode, because it is only published in its latest version. Outside `-Locked`, every tool is taken in its latest version without a reference hash. For an analysis meant to be produced, install with `-Locked` from a lock you exported yourself, or restore an archive of `<root>\tools`.
- **Manifest.** `tools-manifest.json` also records every downloaded URL and its SHA-256, the commit of source repositories and the file version of each EZTools executable.

## Tests

```powershell
C:\Sleuthline\venvs\orchestrator\Scripts\python.exe C:\Sleuthline-setup\tests\run_tests.py
C:\Sleuthline\venvs\orchestrator\Scripts\python.exe C:\Sleuthline-setup\tests\run_tests.py --regression C:\Sleuthline\cases\test01
```

The fast tests (about ten seconds) cover the SQL safeguards of the agent, the evidence policy (independent sources, automatic mappings, answers without evidence), the untrusted-evidence blocks and injection detection, the guidance, step replay, DuckDB macros, hash extraction, inventory and integrity, the internal parsers, the payload sent to Claude, the detection of the sources of a case, the steps that require a source, the coverage and conservation tables, the timestamp provenance, and an end-to-end analysis with the `mock` provider. `--regression` (optional) normalizes one of your own cases into a temporary database and compares the row count per artifact with a reference: the first run records it in `tests\golden\<case>.json` (local, ignored by git), later runs detect any parser or mapping change that adds or loses rows (`--update-golden` after an intended change).

## Rule: existing tool before custom parser

Before writing a parser, check that no recognized tool exists: see `pipeline\docs\POLICY_parsers.md`.

- **Validated decisions:** `pipeline\config\parser_registry.json`.
- **Proposals of the agent during an analysis:** `<root>\pipeline\local\registry_proposals.json` (parsers) and `<root>\pipeline\local\normalize_proposals.json` (normalization mappings). These files are never overwritten by deployment.
- **Automatic reporting:** `inventory.py` lists uncovered artifacts and unknown files in `gaps.json`.

The repository is the single source of truth. A validated decision is added there (installation script and registry), then deployed with `install\02_Install-Tools.ps1 -Only <Tool>,Pipeline`.

## Publishing a fork

`.gitignore` already excludes `pipeline\config\api_keys.txt` (only `api_keys_template.txt` is versioned) and `install\kape.zip` (KAPE's license forbids redistribution). `install\tools-lock.json` describes the reference VM (machine name included): regenerate it with `Export-ToolsLock.ps1` if needed.
