# Rule: an existing tool before any custom parser

This rule applies to **any person or agent (LLMs included)** adding support for an artifact. The analysis agent loads it at every start.

## The rule

**Never write a custom Python parser without first checking that no recognized tool already does the job.**

A custom parser is one more piece of code to maintain and validate. Its results are also less defensible than those of a known tool proven by the DFIR community.

## When to apply it

- `inventory.py` writes a `gaps.json` file listing **unclassified** files or **NOT COVERED** artifacts.
- During an analysis, the agent meets a file type or format that no parser of the registry handles.
- A tool of the registry disappears, is no longer maintained or no longer handles a format correctly.

## Checking procedure (in this order)

1. **Tools already installed**: look at `<root>\tools\tools-manifest.json`, `config\parser_registry.json` and `local\registry_proposals.json` (check already done?). Also check:
   - the list of Dissect plugins: `<root>\tools\dissect\plugins.txt`;
   - the plaso parsers: `log2timeline --parsers list`;
   - the SQLECmd and EvtxECmd maps, and the RECmd batches.
2. **Reference projects**:
   - EZTools (Eric Zimmerman);
   - Dissect plugins (Fox-IT);
   - plaso parsers;
   - KAPE Modules (KapeFiles repository);
   - Velociraptor Artifact Exchange;
   - Hayabusa, Chainsaw and Zircolite for logs.
3. **Web / GitHub search**: published and documented DFIR tools.

## Criteria to choose a tool

- Maintained (recent activity) and recognized in the DFIR community.
- Works **offline on Windows**, from the command line.
- Produces a usable output (CSV, JSON, JSONL or Dissect records).
- Compatible license and identifiable source (traceability).

## Where files live (source of truth)

The repository (e.g. `C:\Sleuthline-setup`) is **the single source of truth**. Everything that defines the analysis environment is versioned there, then deployed by `install\02_Install-Tools.ps1` to the installation root (`<root>`, default `C:\Sleuthline`):

| File | Source (to edit) | Deployed to (do not edit) |
|---|---|---|
| Tools and versions | `install\02_Install-Tools.ps1`, `install\tools-lock.json` | `<root>\tools\` + `tools-manifest.json` |
| Pipeline code | `pipeline\1_inventory` … `4_analysis` | `<root>\pipeline\` (same tree) |
| This rule | `pipeline\docs\POLICY_parsers.md` | `<root>\pipeline\docs\` |
| Registry of validated parsers | `pipeline\config\parser_registry.json` | `<root>\pipeline\config\` |
| Validated normalization mappings | `pipeline\config\normalize_map.json` | `<root>\pipeline\config\` |
| Playbook of the analysis agent | `pipeline\config\PLAYBOOK.md` | `<root>\pipeline\config\` |
| Agent: models, API keys, guidance | `pipeline\config\llm_config.json`, `api_keys.txt` (never versioned, see `api_keys_template.txt`), `guidance_template.txt` | `<root>\pipeline\config\` |

Files produced during analyses, in **`<root>\pipeline\local\`** (never touched by deployment):

- `registry_proposals.json`: parser proposals;
- `normalize_proposals.json`: mapping proposals;
- `hashsets\`: offline hash lists of this VM.

A validated proposal is carried over into the repository (see below).

Deployment replaces `<root>\pipeline\` (except `local\`) at every run of the script (`install\02_Install-Tools.ps1 -Only Pipeline` to redeploy only the pipeline). **Never edit the deployed files by hand.**

## Recording the decision

The agent records every check, even when it concludes that a custom parser is needed, in **`<root>\pipeline\local\registry_proposals.json`**. It is a runtime file that deployment never touches. Each entry states:

- the artifact;
- the proposed tool;
- the alternatives examined;
- the date;
- the sources consulted;
- the justification;
- the status `proposed`.

The agent never edits `parser_registry.json`: only validated decisions go into it.

## Validating a proposal (analyst)

1. Review the proposal in `registry_proposals.json`.
2. If a tool is chosen: add it to `install\02_Install-Tools.ps1`, with a start-up test (and regenerate `install\tools-lock.json` with `install\Export-ToolsLock.ps1`).
3. Carry the entry over into `pipeline\config\parser_registry.json` (validated status, date).
4. Run `install\02_Install-Tools.ps1 -Only <Tool>,Pipeline`: the tool is installed and the registry redeployed.

## Installing a new tool

The agent **never downloads or installs a tool by itself**. It **proposes** the tool, and installation only goes through the repository script after validation.

Reason: integrity of the analysis chain and reproducibility. An unverified tool must neither run on evidence nor modify the environment. A VM rebuilt with `Install-All.ps1` must be identical.

## If no tool exists

1. The custom parser is developed in the repository (`pipeline\2_parsing\`, "native" job of `orchestrator.py`), with a test on a real sample, then deployed by the script.
2. It is marked `"type": "native"` (or `"trivial"` for a format with nothing to decode) in `pipeline\config\parser_registry.json`, with the justification ("no tool found", sources consulted, date).
3. The check is redone periodically: if a tool appears, it replaces the custom parser.

## Same circuit for normalization

When a new parsing output appears (new validated tool, new Dissect plugin, new file produced by a tool), `normalize.py`:

1. still loads it into DuckDB (raw table `raw.<table>`);
2. adds the automatically detected date columns to the timeline, with `mapping = 'auto'`;
3. writes a proposal to **`<root>\pipeline\local\normalize_proposals.json`**.

This runtime file is never touched by deployment. Each proposal states: table, file pattern, detected columns, proposed mapping, case, date, status `proposed`.

The agent never edits `normalize_map.json`. It completes the proposal:

- real meaning of each date, to be checked in the documentation of the tool;
- time zone: UTC or local time (`local_time`);
- path, description, user, original evidence.

The analyst then carries the validated mapping over into `pipeline\config\normalize_map.json` and redeploys with `-Only Pipeline`. Rows with `mapping = 'auto'` must not be cited as evidence without checking the raw table.
