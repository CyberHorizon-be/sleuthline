#!/usr/bin/env python3
"""
Sleuthline - step 3: normalization of a case into DuckDB.

Input   : <case>\\parsed\\   (orchestrator outputs)
Output  : <case>\\db\\case.duckdb
          <case>\\db\\normalize_report.json / normalize_report.md

Database content:
  raw.<table>     one table per output type, ALL columns as text, as produced by the
                  tool, + _src_file (original output) and _src_row (record number in
                  that file: CSV data line, JSONL line).
  timeline        unified timeline (UTC): one row per (record, timestamp); identical
                  timestamps of a same record are merged.
                  Every row cites its evidence: ref = "<output>#<record number>"
                  and evidence = original path of the artifact on the analyzed machine.
  detections      Hayabusa / Chainsaw / Zircolite alerts (same reference principle).
  timeline_all    view: timeline + detections.
  hashset         offline hash lists (local\\hashsets\\, <case>\\hashsets\\).
  hash_hits       hashes of the database found in those lists.
  sources         every output file: table, row count, rejects, mapping status.
  jobs            status of every parsing job (tool, version, inputs, warnings).
  meta            information about the normalization (case, date, map version, etc.).

The output -> timeline mapping is described in config\\normalize_map.json. An output that is
not described there is still loaded (raw table) and its date columns are detected
automatically: its timeline rows carry mapping = 'auto' (not validated) and a proposal is
written to local\\normalize_proposals.json (same circuit as registry_proposals.json, see
docs\\POLICY_parsers.md).

  python normalize.py "C:\\Sleuthline\\cases\\test02 - SANS"
  python normalize.py <case> --map other_map.json --no-auto
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

try:
    import duckdb
except ImportError:  # pragma: no cover
    sys.exit("duckdb is not installed in this Python environment (pip install duckdb).")

VERSION = "1.1"
HERE = Path(__file__).resolve().parent
PIPE = Path(__file__).resolve().parents[1]      # <root>\pipeline (1_inventory, 2_parsing, 3_normalize, 4_analysis, config, docs, local)
CONFIG_DIR = PIPE / "config"                       # validated files (source: <repository>\pipeline\config)
LOCAL_DIR = PIPE / "local"                         # files specific to this VM (never overwritten by deployment)
DEFAULT_MAP = CONFIG_DIR / "normalize_map.json"
PROPOSALS = LOCAL_DIR / "normalize_proposals.json"
DATA_EXT = {".csv": "csv", ".jsonl": "jsonl", ".json": "json"}
AUTO_SAMPLE = 2000          # rows examined to detect the date columns of an undescribed output
AUTO_MIN_RATIO = 0.9        # minimum share of values recognized as dates
AUTO_MAX_TIME_COLS = 12

# File statuses (sources table)
LOADED, EMPTY, IGNORED, ERROR = "loaded", "empty", "ignored", "error"
# Proposal statuses
PROPOSED, INTEGRATED = "proposed", "integrated"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


# ----------------------------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------------------------
def q(ident: str) -> str:
    """Quoted SQL identifier."""
    return '"' + ident.replace('"', '""') + '"'


def lit(value) -> str:
    """SQL text literal (or NULL)."""
    if value is None:
        return "NULL"
    return "'" + str(value).replace("'", "''") + "'"


def re2_escape(s: str) -> str:
    return re.sub(r"([\\.^$|?*+()\[\]{}])", r"\\\1", s)


def sanitize(name: str) -> str:
    s = re.sub(r"[^0-9A-Za-z]+", "_", name).strip("_").lower()
    return s or "x"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rel_of(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def glob_match(rel: str, patterns) -> bool:
    if isinstance(patterns, str):
        patterns = [patterns]
    low = rel.lower()
    return any(fnmatch.fnmatchcase(low, p.lower()) for p in patterns)


def auto_table_name(rel: str) -> str:
    """Stable table name for an undescribed output (timestamps / GUIDs removed)."""
    parts = rel.split("/")
    job = parts[0]
    stem = Path(parts[-1]).stem
    stem = re.sub(r"^\d{8,}_", "", stem)                                   # 20261018172202_
    stem = re.sub(r"_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", "", stem, flags=re.I)
    stem = re.sub(r"_\d{8}_\d{6}(\.\d+)?$", "", stem)                       # _20261018_172207.59
    stem = re.sub(r"_\d+$", "", stem)                                        # _0
    return sanitize(f"{job}__{stem}")


def proposal_glob(rel: str) -> str:
    """File pattern for a proposal: leading timestamp and trailing GUID replaced by *."""
    head, _, name = rel.rpartition("/")
    name = re.sub(r"^\d{8,}_", "*_", name)
    name = re.sub(r"_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(\.\w+)$", r"_*\1", name, flags=re.I)
    name = re.sub(r"_\d{8}_\d{6}\.\d+(\.\w+)$", r"_*\1", name)
    head = re.sub(r"/\d{8,}(?=/|$)", "/*", head)
    return f"{head}/{name}" if head else name


def first_line(path: Path) -> str:
    with path.open("rb") as fh:
        raw = fh.readline(1 << 16)
    return raw.decode("utf-8-sig", errors="replace").strip()


def sniff_delim(header: str) -> str:
    counts = {d: header.count(d) for d in (",", "|", "\t", ";")}
    return max(counts, key=counts.get) if max(counts.values()) else ","


# Default speeds (measured on test02: 600 MB of outputs, 3.8 M timestamps, 1.56 M timeline rows).
# Replaced by the median of the last 5 runs (<root>\logs\normalize_durations.jsonl).
DEFAULT_RATES = {"load_s_per_mb": 0.03, "tl_s_per_unit": 4.5e-6, "final_s_per_row": 3.5e-6, "units_per_mb": 6500.0,
                 "rows_per_unit": 0.41}
LOAD_READ_SHARE = 0.4        # share of loading spent reading files (the rest: writing tables)


class RateHistory:
    """Speeds observed during previous normalizations, used to estimate the remaining time."""

    def __init__(self, path: Path):
        self.path = path

    def rates(self) -> dict:
        rates = dict(DEFAULT_RATES)
        try:
            runs = [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()][-5:]
        except (OSError, ValueError):
            return rates
        for k in rates:
            vals = sorted(r[k] for r in runs if isinstance(r.get(k), (int, float)) and r[k] > 0)
            if vals:
                rates[k] = vals[len(vals) // 2]
        return rates

    def add(self, entry: dict):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass


def fmt_duration(sec: float) -> str:
    sec = max(0, int(round(sec)))
    if sec < 60:
        return f"{sec} s"
    m, s_ = divmod(sec, 60)
    if m < 60:
        return f"{m} min {s_:02d} s"
    h, m = divmod(m, 60)
    return f"{h} h {m:02d} min"


class Progress:
    """Timestamped log + global progress bar (percentage, elapsed time, remaining time).

    Progress is counted in "estimated seconds": each step (file loaded, table written,
    source added to the timeline) is worth its expected duration based on past speeds.
    The remaining time is recomputed at each step with the real speed of the run.
    Live rich display when the console allows it, otherwise one progress line every
    10 s at most (--no-live)."""

    def __init__(self, live: bool = True):
        self.t0 = time.time()
        self.total = 1.0
        self.done = 0.0
        self.phase = "Preparation"
        self.last_text = 0.0
        self.rich = None
        if live and sys.stdout.isatty():
            try:
                from rich.console import Console
                from rich.progress import (Progress as RP, BarColumn, TextColumn, TaskProgressColumn,
                                           TimeElapsedColumn)
                self.console = Console()
                self.rich = RP(TextColumn("[bold]{task.fields[phase]}"), BarColumn(), TaskProgressColumn(),
                               TextColumn("elapsed"), TimeElapsedColumn(), TextColumn("~{task.fields[eta]} left"),
                               TextColumn("[dim]{task.fields[label]}"), console=self.console, transient=False)
                self.task = self.rich.add_task("", total=1000, phase="", eta="?", label="")
                self.rich.start()
            except Exception:
                self.rich = None

    # log
    def __call__(self, msg: str = ""):
        line = f"[{time.time() - self.t0:7.1f}s] {msg}"
        if self.rich:
            self.rich.console.print(line, markup=False, highlight=False)
        else:
            print(line, flush=True)

    # progress
    def eta(self) -> float:
        # At first the estimate is trusted; the further the work goes, the more the really
        # observed speed is trusted (ratio real time / estimated time already done).
        elapsed = time.time() - self.t0
        remaining = max(0.0, self.total - self.done)
        if self.done <= 0 or elapsed <= 0:
            return remaining
        ratio = min(max(elapsed / self.done, 0.1), 10.0)
        w = min(1.0, self.done / (0.25 * self.total))
        return remaining * (w * ratio + (1 - w))

    def set_phase(self, phase: str):
        self.phase = phase
        self._refresh("", force=True)

    def set_remaining(self, remaining_est: float):
        """Re-evaluates the total: work already done + estimate of what remains."""
        self.total = max(self.done + max(remaining_est, 0.0), 1e-6)
        self._refresh("")

    def advance(self, est: float, label: str = ""):
        self.done = min(self.done + max(est, 0.0), self.total)
        self._refresh(label)

    def _refresh(self, label: str, force: bool = False):
        pct = 100.0 * self.done / self.total if self.total else 0.0
        eta = fmt_duration(self.eta())
        if self.rich:
            self.rich.update(self.task, completed=int(10 * pct), phase=self.phase, eta=eta, label=label[-60:])
        elif force or time.time() - self.last_text >= 10:
            self.last_text = time.time()
            print(f"  >>> {self.phase}: {pct:5.1f} % | elapsed {fmt_duration(time.time() - self.t0)} | "
                  f"~{eta} left", flush=True)

    def finish(self):
        self.done = self.total
        if self.rich:
            self.rich.update(self.task, completed=1000, phase="Done", eta="0 s", label="")
            self.rich.stop()
        else:
            print(f"  >>> Done: 100 % in {fmt_duration(time.time() - self.t0)}", flush=True)


Log = Progress


# ----------------------------------------------------------------------------------------
# SQL macros: dates, paths
# ----------------------------------------------------------------------------------------
def create_macros(con, case_root: str):
    root = re2_escape(case_root.rstrip("\\/"))
    con.execute(r"""
CREATE OR REPLACE MACRO ts_parse(s) AS (
  CASE WHEN s IS NULL OR trim(CAST(s AS VARCHAR)) IN ('', '0', '0000-00-00 00:00:00', '0000-00-00') THEN NULL ELSE
  CAST(coalesce(
    try_cast(regexp_replace(regexp_replace(trim(CAST(s AS VARCHAR)), '(\.\d{6})\d+', '\1'),
                            '\s+([+-]\d\d:?\d\d|Z)$', '\1') AS TIMESTAMPTZ),
    try_strptime(trim(CAST(s AS VARCHAR)), '%m/%d/%Y %H:%M:%S %z'),
    CAST(try_strptime(trim(CAST(s AS VARCHAR)), '%a, %d %b %Y %H:%M:%S GMT') AS TIMESTAMPTZ)
  ) AS TIMESTAMP) END)
""")
    # Path of the copy (C:\Sleuthline\cases\<case>\C\...) -> original path (C:\...)
    con.execute(rf"""
CREATE OR REPLACE MACRO orig_path(p) AS (
  CASE WHEN p IS NULL OR CAST(p AS VARCHAR) = '' THEN NULL ELSE
  regexp_replace(
    regexp_replace(
      regexp_replace(
        -- orchestrator working copies: ...\parsed\<job>\_work\C\... -> C:\...
        regexp_replace(CAST(p AS VARCHAR), '(?i)^.*\\_work\\([A-Za-z])\\', '\1:\\'),
        '(?i)^{root}\\([A-Za-z])\\', '\1:\\'),
      '(?i)^\\?sysvol\\', 'C:\\'),
    '^\\([A-Za-z]:\\)', '\1') END)
""")
    # Path relative to the volume (".\Windows\..." from MFTECmd) -> "C:\Windows\..."
    con.execute(r"""
CREATE OR REPLACE MACRO vol_path(rel, src) AS (
  CASE WHEN rel IS NULL THEN NULL
       WHEN rel LIKE '.\%' THEN coalesce(substr(orig_path(src), 1, 2), '?:') || substr(rel, 2)
       ELSE rel END)
""")
    con.execute(r"""
CREATE OR REPLACE MACRO user_from_path(p) AS (
  nullif(regexp_extract(CAST(p AS VARCHAR), '(?i)^[A-Z]:[\\/](?:Users|Documents and Settings)[\\/]([^\\/]+)', 1), ''))
""")
    con.execute(r"""
CREATE OR REPLACE MACRO level_norm(l) AS (
  CASE lower(trim(CAST(l AS VARCHAR)))
    WHEN 'crit' THEN 'critical' WHEN 'critical' THEN 'critical'
    WHEN 'high' THEN 'high' WHEN 'med' THEN 'medium' WHEN 'medium' THEN 'medium'
    WHEN 'low' THEN 'low' WHEN 'info' THEN 'informational' WHEN 'informational' THEN 'informational'
    ELSE lower(trim(CAST(l AS VARCHAR))) END)
""")


# ----------------------------------------------------------------------------------------
# Raw loading
# ----------------------------------------------------------------------------------------
JSON_TO_TEXT = "CASE WHEN json_type({c}) IN ('OBJECT', 'ARRAY') THEN CAST({c} AS VARCHAR) ELSE {c} ->> '$' END"


def _read_csv_sql(path: Path, delim: str, quote: str, escape: str, lenient: bool = False) -> str:
    extra = ", strict_mode=false, null_padding=true" if lenient else ""
    return (f"read_csv({lit(str(path))}, all_varchar=true, header=true, delim={lit(delim)}, quote={lit(quote)}, "
            f"escape={lit(escape)}, store_rejects=true, rejects_table='_rejects', rejects_scan='_rejects_scan', "
            f"sample_size=-1{extra})")


def stage_csv(con, path: Path, opts: dict, stage: str, tmp_dir: Path) -> tuple[int, str | None]:
    """Loads a CSV (all columns as text). Returns (rejected rows, note).
    Fallback: if DuckDB cannot read the file (irregular line endings, e.g. CR CR LF from
    odl.py), it is re-read by Python's csv module and rewritten cleanly in db\\_tmp."""
    delim = opts.get("delim") or sniff_delim(first_line(path))
    quote = opts.get("quote", '"')
    escape = opts.get("escape", quote)
    con.execute("DROP TABLE IF EXISTS _rejects; DROP TABLE IF EXISTS _rejects_scan")
    try:
        con.execute(f"CREATE OR REPLACE TEMP TABLE {stage} AS SELECT * FROM {_read_csv_sql(path, delim, quote, escape)}")
        rej = con.execute("SELECT count(*) FROM _rejects").fetchone()[0]
        if not rej:
            return 0, None
        # Rows not matching the header (e.g. one more column than the header): lenient re-read,
        # extra values are kept in columnNN columns.
        con.execute("DROP TABLE IF EXISTS _rejects; DROP TABLE IF EXISTS _rejects_scan")
        con.execute(f"CREATE OR REPLACE TEMP TABLE {stage}_l AS SELECT * FROM {_read_csv_sql(path, delim, quote, escape, True)}")
        rej2 = con.execute("SELECT count(*) FROM _rejects").fetchone()[0]
        if rej2 < rej:
            con.execute(f"DROP TABLE {stage}; ALTER TABLE {stage}_l RENAME TO {stage}")
            return rej2, (f"{rej} rows not matching the header re-read in lenient mode "
                          f"(extra values in columnNN columns, missing values set to NULL)")
        con.execute(f"DROP TABLE {stage}_l")
        return rej, None
    except duckdb.Error as first_error:
        import csv
        tmp_dir.mkdir(parents=True, exist_ok=True)
        clean = tmp_dir / (sanitize(str(path.name)) + ".csv")
        csv.field_size_limit(1 << 30)
        blank = 0
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fi, \
                clean.open("w", encoding="utf-8", newline="") as fo:
            w = csv.writer(fo, delimiter=delim, quotechar='"', lineterminator="\n")
            for row in csv.reader(fi, delimiter=delim, quotechar=quote or '"', quoting=csv.QUOTE_MINIMAL if quote else csv.QUOTE_NONE):
                if not row or all(not c.strip() for c in row):
                    blank += 1
                    continue
                w.writerow(c.rstrip("\r") for c in row)
        con.execute("DROP TABLE IF EXISTS _rejects; DROP TABLE IF EXISTS _rejects_scan")
        try:
            sql = _read_csv_sql(clean, delim, '"', '"')
            con.execute(f"CREATE OR REPLACE TEMP TABLE {stage} AS SELECT * FROM {sql}")
        except duckdb.Error:
            raise first_error
        rej = con.execute("SELECT count(*) FROM _rejects").fetchone()[0]
        return rej, (f"re-read with Python's csv module (format irregular for DuckDB); {blank} blank rows skipped; "
                     f"_src_row = number of the non-blank record")


def stage_json(con, path: Path, kind: str, stage: str):
    fmt = "array" if kind == "json" else "newline_delimited"
    con.execute(f"""
CREATE OR REPLACE TEMP TABLE _j AS
SELECT * FROM read_json({lit(str(path))}, format={lit(fmt)}, maximum_depth=1, sample_size=-1,
                        union_by_name=true, maximum_object_size=268435456)""")
    cols = [r[0] for r in con.execute("DESCRIBE _j").fetchall()]
    sel = ", ".join(f"{JSON_TO_TEXT.format(c=q(c))} AS {q(c)}" for c in cols)
    con.execute(f"CREATE OR REPLACE TEMP TABLE {stage} AS SELECT {sel} FROM _j")
    con.execute("DROP TABLE _j")
    return 0


def dissect_descriptors(path: Path) -> dict[str, list[tuple[str, str]]]:
    """Dissect record types and their fields (read from the recorddescriptor lines)."""
    out = {}
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith('{"_type": "recorddescriptor"'):
                try:
                    name, fields = json.loads(line)["_data"]
                    out[name] = [(t, f) for t, f in fields]
                except (ValueError, KeyError, TypeError):
                    pass
    return out


# ----------------------------------------------------------------------------------------
# Engine
# ----------------------------------------------------------------------------------------
class Normalizer:
    def __init__(self, case: Path, map_path: Path, db_path: Path, auto: bool, log: Log, case_root: str | None = None):
        self.case = case
        self.case_root = case_root or self.detect_case_root(case)
        self.parsed = case / "parsed"
        self.map_path = map_path
        self.mapping = json.loads(map_path.read_text(encoding="utf-8"))
        self.db_path = db_path
        self.auto = auto
        self.log = log
        d = self.mapping.get("defaults", {})
        self.min_ts = d.get("min_ts", "1980-01-01")
        self.ignore_fields = d.get("ignore_time_fields", [])
        self.max_ts = (dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) + dt.timedelta(days=366 * d.get("max_years_ahead", 1))).strftime("%Y-%m-%d")
        self.files: list[dict] = []          # one entry per output file
        self.tables: dict[str, dict] = {}    # raw table -> {"source": ..., "files": [...]}
        self.report: dict = {"errors": [], "warnings": []}
        self.jobs: dict[str, dict] = {}
        self.dissect_desc: dict[str, dict] = {}
        self.tz_bias: int | None = None
        logs = PIPE.parent / "logs"
        self.history = RateHistory((logs if logs.is_dir() else db_path.parent) / "normalize_durations.jsonl")
        self.rates = self.history.rates()
        self.tl_units = 0

    def detect_tz_bias(self, con):
        """Time zone bias of the analyzed machine (UTC = local + bias, in minutes), read from the SYSTEM
        hive (TimeZoneInformation\\ActiveTimeBias). Used for sources flagged local_time."""
        queries = []
        if "registry_kroll" in self.tables:
            queries.append("SELECT ValueData FROM raw.registry_kroll WHERE KeyPath ILIKE '%\\TimeZoneInformation' "
                           "AND ValueName = 'ActiveTimeBias' LIMIT 1")
        if "reg_timezoneinfo" in self.tables:
            queries.append("SELECT ValueData FROM raw.reg_timezoneinfo WHERE ValueName = 'ActiveTimeBias' LIMIT 1")
        for sql in queries:
            try:
                r = con.execute(sql).fetchone()
                if r and r[0] is not None and re.fullmatch(r"-?\d+", str(r[0]).strip()):
                    self.tz_bias = int(str(r[0]).strip())
                    self.report["warnings"].append(
                        f"Local time -> UTC: ActiveTimeBias = {self.tz_bias} min (value at collection time; "
                        f"a daylight saving change during the period is not taken into account).")
                    return
            except duckdb.Error:
                continue

    @staticmethod
    def detect_case_root(case: Path) -> str:
        """Case path as it appears in the outputs (run_summary.json), otherwise the local path."""
        try:
            d = json.loads((case / "parsed" / "run_summary.json").read_text(encoding="utf-8-sig"))
            root = d.get("collection_root") or d.get("case")
            if root:
                return str(root)
        except (OSError, ValueError):
            pass
        return str(case)

    # -- discovery ---------------------------------------------------------------------
    def discover(self):
        skip = self.mapping.get("skip", [])
        sources = self.mapping.get("sources", [])
        for p in sorted(self.parsed.rglob("*")):
            if not p.is_file():
                continue
            rel = rel_of(p, self.parsed)
            parts = rel.split("/")
            if parts[0].startswith("_") or p.name.startswith("_") or len(parts) < 2:
                continue                      # _samples, _status.json, _run.log, jobs.jsonl, run_summary.json
            if any(x in ("_tmp", "_work") for x in parts):
                continue
            entry = {"rel": rel, "path": p, "bytes": p.stat().st_size, "job": parts[0]}
            rule = next((s for s in skip if glob_match(rel, s["glob"])), None)
            if rule:
                entry.update(status=IGNORED, reason=rule.get("reason", ""))
                self.files.append(entry)
                continue
            kind = DATA_EXT.get(p.suffix.lower())
            if kind is None:
                entry.update(status=IGNORED, reason=f"extension {p.suffix or '(none)'} not loaded")
                self.files.append(entry)
                continue
            src = next((s for s in sources if glob_match(rel, s["glob"])), None)
            entry["kind"] = kind
            if src:
                entry["source"] = src
                entry["table"] = auto_table_name(rel) if src.get("table_per_file") else (src.get("table") or sanitize(src["id"]))
                entry["mapping"] = "validated"
            else:
                entry["source"] = None
                entry["table"] = auto_table_name(rel)
                entry["mapping"] = "auto" if self.auto else "raw"
            if entry["bytes"] == 0:
                entry.update(status=EMPTY, reason="0-byte file")
            self.files.append(entry)

    def load_jobs(self, con):
        rows = []
        for st in sorted(self.parsed.glob("*/_status.json")):
            try:
                d = json.loads(st.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError) as e:
                self.report["warnings"].append(f"{st}: unreadable ({e})")
                continue
            job = d.get("job") or st.parent.name
            self.jobs[st.parent.name] = d
            outputs = {o.get("file", "").replace("\\", "/"): o for o in d.get("outputs", []) if isinstance(o, dict)}
            d["_outputs"] = outputs
            rows.append((job, st.parent.name, d.get("title"), d.get("status"), d.get("started_utc"), d.get("ended_utc"),
                         d.get("duration_s"), json.dumps(d.get("tools"), ensure_ascii=False),
                         json.dumps(d.get("inputs"), ensure_ascii=False),
                         json.dumps(d.get("warnings"), ensure_ascii=False), d.get("note")))
        con.execute("""CREATE TABLE jobs (job VARCHAR, dir VARCHAR, title VARCHAR, status VARCHAR, started_utc VARCHAR,
                       ended_utc VARCHAR, duration_s DOUBLE, tools VARCHAR, inputs VARCHAR, warnings VARCHAR, note VARCHAR)""")
        if rows:
            con.executemany("INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)

    def job_single_input(self, job_dir: str):
        d = self.jobs.get(job_dir) or {}
        inputs = d.get("inputs") or []
        if len(inputs) == 1 and isinstance(inputs[0], str):
            v = inputs[0]
            m = re.match(r"^([A-Za-z])[\\/](.*)$", v)
            return f"{m.group(1).upper()}:\\{m.group(2)}".replace("/", "\\") if m else v
        return None

    # -- raw loading -------------------------------------------------------------------
    def load_raw(self, con):
        todo = [f for f in self.files if "table" in f and f.get("status") is None]
        n = len(todo)
        r_load = self.rates["load_s_per_mb"]
        for i, f in enumerate(todo, 1):
            t0 = time.time()
            self.log.advance(0, f["rel"])
            stage = f"_stage_{i}"
            src = f["source"] or {}
            fmt = src.get("format") or ("dissect" if f["job"] == "dissect" else f["kind"])
            try:
                if f["kind"] == "csv":
                    f["rejects"], note = stage_csv(con, f["path"], src.get("csv", {}), stage, self.db_path.parent / "_tmp")
                    if f["rejects"]:
                        # _src_row is the rank of the LOADED row: after a rejected row it no longer matches the
                        # record number in the file. This is reported rather than citing shifted evidence.
                        shift = (f"{f['rejects']} rejected row(s): references (_src_row) of this file may be "
                                 f"shifted after the first rejected row; check in parsed\\ before citing")
                        note = f"{note}; {shift}" if note else shift
                    if note:
                        f["reason"] = note
                        self.report["warnings"].append(f"{f['rel']}: {note}")
                else:
                    f["rejects"] = stage_json(con, f["path"], f["kind"], stage)
                cols = [r[0] for r in con.execute(f"DESCRIBE {stage}").fetchall()]
                extra = ""
                where = ""
                if fmt == "dissect":
                    self.dissect_desc[f["rel"]] = dissect_descriptors(f["path"])
                    if "_type" in cols:
                        where = "WHERE _type IS DISTINCT FROM 'recorddescriptor'"
                    if "_recorddescriptor" in cols:
                        extra = ", json_extract_string(_recorddescriptor, '$[0]') AS _record_type"
                    drop = [c for c in ("_type", "_data") if c in cols]
                    keep = ", ".join(q(c) for c in cols if c not in drop)
                else:
                    keep = ", ".join(q(c) for c in cols)
                con.execute(f"""CREATE OR REPLACE TEMP TABLE {stage}_n AS
                    SELECT {lit(f['rel'])} AS _src_file, CAST(rowid + 1 AS BIGINT) AS _src_row, {keep}{extra}
                    FROM {stage} {where}""")
                con.execute(f"DROP TABLE {stage}")
                rows = con.execute(f"SELECT count(*) FROM {stage}_n").fetchone()[0]
                f["rows"] = rows
                f["status"] = LOADED if rows else EMPTY
                f["stage"] = f"{stage}_n"
                f["format"] = fmt
                self.tables.setdefault(f["table"], {"source": f["source"], "files": [], "format": fmt})["files"].append(f)
                rj = f" ({f['rejects']} rejected rows)" if f.get("rejects") else ""
                self.log(f"  [{i}/{n}] {f['rel']} -> raw.{f['table']}: {rows:,} rows{rj} ({time.time() - t0:.1f} s)".replace(",", " "))
            except duckdb.Error as e:
                f["status"] = ERROR
                f["reason"] = str(e).splitlines()[0][:500]
                self.report["errors"].append(f"{f['rel']}: cannot be loaded: {f['reason']}")
                self.log(f"  [{i}/{n}] {f['rel']}: LOAD ERROR: {f['reason']}")
            self.log.advance(LOAD_READ_SHARE * f["bytes"] / 1e6 * r_load, f["rel"])
        for f in todo:                      # files in error: their writing share will not happen
            if f.get("status") == ERROR:
                self.log.advance((1 - LOAD_READ_SHARE) * f["bytes"] / 1e6 * r_load)
        # Group the files of a same table (columns united by name)
        con.execute("CREATE SCHEMA IF NOT EXISTS raw")
        for table, info in self.tables.items():
            stages = [f["stage"] for f in info["files"]]
            union = " UNION ALL BY NAME ".join(f"SELECT * FROM {s}" for s in stages)
            con.execute(f"CREATE TABLE raw.{q(table)} AS {union}")
            for s in stages:
                con.execute(f"DROP TABLE {s}")
            info["columns"] = [r[0] for r in con.execute(f"DESCRIBE raw.{q(table)}").fetchall()]
            self.log.advance((1 - LOAD_READ_SHARE) * sum(f["bytes"] for f in info["files"]) / 1e6 * r_load, f"raw.{table}")

    # -- mapping expressions -----------------------------------------------------------
    @staticmethod
    def expr(spec, columns: list[str], kind: str):
        """spec: string = SQL expression; list = column names (only those present are used)
        combined according to kind: coalesce / concat / path."""
        if spec is None:
            return None
        if isinstance(spec, str):
            return spec
        present = [c for c in spec if c in columns]
        if not present:
            return None
        if kind == "concat":
            parts = [f"CASE WHEN nullif(trim({q(c)}), '') IS NOT NULL THEN {lit(c + '=')} || {q(c)} END" if len(present) > 1
                     else q(c) for c in present]
            return f"nullif(concat_ws(' | ', {', '.join(parts)}), '')"
        inner = f"coalesce({', '.join('nullif(' + q(c) + ', ' + lit('') + ')' for c in present)})"
        return f"orig_path({inner})" if kind == "path" else inner

    def time_specs(self, table: str, info: dict) -> list[dict]:
        src = info["source"] or {}
        cols = info["columns"]
        times = list(src.get("times", []))
        if info["format"] == "dissect" and src.get("dissect_times", True):
            # datetime fields declared by Dissect recorddescriptors
            seen = {t.get("ts") for t in times}
            for f in info["files"]:
                for rtype, fields in self.dissect_desc.get(f["rel"], {}).items():
                    for ftype, fname in fields:
                        if (ftype == "datetime" and fname in cols and q(fname) not in seen
                                and fname not in src.get("ignore_times", []) + self.ignore_fields):
                            times.append({"ts": q(fname), "desc": f"{rtype.split('/')[-1]}: {fname}"})
                            seen.add(q(fname))
        return times

    def detect_auto_times(self, con, table: str, cols: list[str]) -> list[dict]:
        cand = [c for c in cols if not c.startswith("_")]
        if not cand:
            return []
        sel = ", ".join(
            f"count({q(c)}) FILTER (WHERE nullif(trim({q(c)}), '') IS NOT NULL), "
            f"count({q(c)}) FILTER (WHERE ts_parse({q(c)}) IS NOT NULL)" for c in cand)
        r = con.execute(f"SELECT {sel} FROM (SELECT * FROM raw.{q(table)} LIMIT {AUTO_SAMPLE})").fetchone()
        out = []
        for i, c in enumerate(cand):
            nonnull, ok = r[2 * i], r[2 * i + 1]
            if nonnull and ok / nonnull >= AUTO_MIN_RATIO and not re.fullmatch(r"(?i).*(version|size|id|count|number)", c):
                out.append({"ts": q(c), "desc": f"{c} (auto, not validated)"})
        return out[:AUTO_MAX_TIME_COLS]

    # -- timeline ----------------------------------------------------------------------
    def build_timeline(self, con):
        con.execute("""CREATE TABLE _tl (ts TIMESTAMP, ts_desc VARCHAR, artifact VARCHAR, category VARCHAR, tool VARCHAR,
            host VARCHAR, user_name VARCHAR, path VARCHAR, description VARCHAR, evidence VARCHAR,
            src_table VARCHAR, src_file VARCHAR, src_row BIGINT, source_id VARCHAR, mapping VARCHAR)""")
        # Amount of work: rows x date columns of each table (for the estimate)
        for table, info in self.tables.items():
            nt = len(self.time_specs(table, info)) if info["source"] else 3
            info["_units"] = sum(f.get("rows", 0) for f in info["files"]) * nt
        units_total = sum(i["_units"] for i in self.tables.values())
        self.tl_units = units_total
        r = self.rates
        self.log.set_remaining(units_total * r["tl_s_per_unit"]
                               + units_total * r["rows_per_unit"] * r["final_s_per_row"])
        for table, info in sorted(self.tables.items()):
            self.log.advance(0, f"timeline <- raw.{table}")
            try:
                self._timeline_table(con, table, info)
            finally:
                self.log.advance(info["_units"] * r["tl_s_per_unit"], f"timeline <- raw.{table}")
        self.log.set_phase("Sorting and finalizing")
        con.execute("""CREATE TABLE timeline AS
            SELECT row_number() OVER (ORDER BY ts, src_file, src_row) AS tl_id, *,
                   src_file || '#' || src_row AS ref
            FROM _tl ORDER BY ts, src_file, src_row""")
        con.execute("DROP TABLE _tl")

    def _timeline_table(self, con, table, info):
        src = info["source"]
        cols = info["columns"]
        files = info["files"]
        if src is None:
            if not self.auto:
                info["timeline"] = {"status": "raw only (--no-auto)"}
                return
            times = self.detect_auto_times(con, table, cols)
            guess = {"path": [c for c in cols if not c.startswith("_") and re.search(r"(?i)path|file|url|executable|program", c)][:3],
                     "description": [c for c in cols if not c.startswith("_") and q(c) not in {t["ts"] for t in times}][:4]}
            src = {"id": table, "artifact": f"{files[0]['job']} (undescribed)", "category": "unclassified",
                   "tool": files[0]["job"], "times": times, "path": guess["path"] or None,
                   "description": guess["description"] or None}
            info["auto_source"] = src
            mapping = "auto"
        else:
            mapping = "validated"
        times = self.time_specs(table, {**info, "source": src})
        if not times:
            info["timeline"] = {"status": "no timestamp (raw table only)", "note": (src or {}).get("note")}
            return
        try:
            n, out = self.insert_timeline(con, table, src, cols, times, mapping, files)
            info["timeline"] = {"status": mapping, "rows": n, "out_of_range": out, "times": [t["desc"] if "desc" in t else t.get("desc_sql") for t in times]}
            self.log(f"  timeline <- raw.{table}: {n:,} rows ({mapping})".replace(",", " ")
                     + (f", {out} out-of-range timestamps ignored" if out else ""))
        except duckdb.Error as e:
            msg = str(e).splitlines()[0][:500]
            info["timeline"] = {"status": "error", "error": msg}
            self.report["errors"].append(f"timeline raw.{table} ({src.get('id')}): {msg}")
            self.log(f"  timeline <- raw.{table}: ERROR {msg}")

    def common_exprs(self, src: dict, cols: list[str], files: list[dict]):
        job_ev = self.job_single_input(files[0]["job"]) if files else None
        path = self.expr(src.get("path"), cols, "path")
        desc = self.expr(src.get("description"), cols, "concat")
        user = self.expr(src.get("user"), cols, "coalesce")
        host = self.expr(src.get("host"), cols, "coalesce")
        ev = self.expr(src.get("evidence"), cols, "path")
        ev = f"coalesce({ev}, {lit(job_ev)})" if ev else lit(job_ev)
        user = f"coalesce({user + ', ' if user else ''}user_from_path({ev}), user_from_path({path or 'NULL'}))"
        where = src.get("where") or "TRUE"
        # exclude: [{"column": ..., "regex": ...}] -> rows left out of the timeline (if the column exists)
        for ex in src.get("exclude", []):
            if ex.get("column") in cols:
                where = f"({where}) AND NOT regexp_matches(coalesce({q(ex['column'])}, ''), {lit(ex['regex'])})"
        return path or "NULL", desc or "NULL", user, host or "NULL", ev, where

    def insert_timeline(self, con, table, src, cols, times, mapping, files):
        path, desc, user, host, ev, where = self.common_exprs(src, cols, files)
        structs = []
        shift, suffix = "", ""
        if src.get("local_time"):
            if self.tz_bias is None:
                raise duckdb.InvalidInputException(
                    "timestamps in local time and time zone of the machine unknown (TimeZoneInformation\\ActiveTimeBias missing)")
            shift = f" + INTERVAL ({int(self.tz_bias)}) MINUTE"
            suffix = f" [local time converted to UTC, ActiveTimeBias={self.tz_bias} min]"
        for i, t in enumerate(times):
            d = t.get("desc_sql") or lit(t.get("desc", t["ts"]))
            if suffix:
                d = f"{d} || {lit(suffix)}"
            structs.append(f"{{'v': ts_parse({t['ts']}){shift}, 'd': {d}, 'o': {i}}}")
        base = f"""
            SELECT _src_file, _src_row, {host} AS host, {user} AS user_name, {path} AS path,
                   {desc} AS description, {ev} AS evidence, unnest([{', '.join(structs)}]) AS s
            FROM raw.{q(table)} WHERE {where}"""
        rng = f"s.v >= TIMESTAMP {lit(self.min_ts)} AND s.v <= TIMESTAMP {lit(self.max_ts)}"
        out = con.execute(f"SELECT count(*) FROM ({base}) WHERE s.v IS NOT NULL AND NOT ({rng})").fetchone()[0]
        before = con.execute("SELECT count(*) FROM _tl").fetchone()[0]
        con.execute(f"""
            INSERT INTO _tl
            SELECT s.v, string_agg(s.d, ' ; ' ORDER BY s.o), {lit(src.get('artifact'))}, {lit(src.get('category'))},
                   {lit(src.get('tool'))}, any_value(host), any_value(user_name), any_value(path),
                   any_value(description), any_value(evidence), {lit(table)}, _src_file, _src_row,
                   {lit(src.get('id'))}, {lit(mapping)}
            FROM ({base}) WHERE s.v IS NOT NULL AND {rng}
            GROUP BY s.v, _src_file, _src_row""")
        n = con.execute("SELECT count(*) FROM _tl").fetchone()[0] - before
        return n, out

    # -- detections --------------------------------------------------------------------
    def build_detections(self, con):
        con.execute("""CREATE TABLE _det (ts TIMESTAMP, engine VARCHAR, rule_title VARCHAR, rule_id VARCHAR, level VARCHAR,
            computer VARCHAR, channel VARCHAR, event_id VARCHAR, record_id VARCHAR, details VARCHAR, tactics VARCHAR,
            evidence VARCHAR, src_table VARCHAR, src_file VARCHAR, src_row BIGINT)""")
        for table, info in sorted(self.tables.items()):
            src = info["source"] or {}
            det = src.get("detection")
            if not det:
                continue
            cols = info["columns"]
            e = {k: (self.expr(det.get(k), cols, "path" if k == "evidence" else "coalesce") or "NULL")
                 for k in ("ts", "rule_title", "rule_id", "level", "computer", "channel", "event_id", "record_id",
                           "details", "tactics", "evidence")}
            try:
                con.execute(f"""
                    INSERT INTO _det SELECT ts_parse({e['ts']}), {lit(det.get('engine', src.get('tool')))},
                        {e['rule_title']}, {e['rule_id']}, level_norm({e['level']}), {e['computer']}, {e['channel']},
                        CAST({e['event_id']} AS VARCHAR), CAST({e['record_id']} AS VARCHAR), CAST({e['details']} AS VARCHAR),
                        CAST({e['tactics']} AS VARCHAR), {e['evidence']}, {lit(table)}, _src_file, _src_row
                    FROM raw.{q(table)} WHERE {src.get('where') or 'TRUE'}""")
                n = con.execute(f"SELECT count(*) FROM _det WHERE src_table = {lit(table)}").fetchone()[0]
                info["detections"] = n
                self.log(f"  detections <- raw.{table}: {n:,}".replace(",", " "))
            except duckdb.Error as ex:
                msg = str(ex).splitlines()[0][:500]
                info["detections_error"] = msg
                self.report["errors"].append(f"detections raw.{table}: {msg}")
                self.log(f"  detections <- raw.{table}: ERROR {msg}")
        con.execute("""CREATE TABLE detections AS
            SELECT row_number() OVER (ORDER BY ts, src_file, src_row) AS det_id, *, src_file || '#' || src_row AS ref
            FROM _det ORDER BY ts, src_file, src_row""")
        con.execute("DROP TABLE _det")
        con.execute("""CREATE VIEW timeline_all AS
            SELECT ts, ts_desc, artifact, category, tool, host, user_name, path, description, evidence,
                   src_table, src_file, src_row, ref, mapping FROM timeline
            UNION ALL
            SELECT ts, 'Detection (' || level || ')', 'Detection ' || engine, 'detection', engine, computer, NULL,
                   NULL, rule_title || coalesce(' | ' || details, ''), evidence, src_table, src_file, src_row, ref,
                   'validated' FROM detections""")

    # -- hash lists --------------------------------------------------------------------
    HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
    # Hash columns: SHA1 of Amcache, Defender hashes, Prefetch...
    HASH_COLUMN_RX = r"(?i).*(sha1|sha-1|sha256|sha_256|md5|hash).*"
    # Text columns that embed "MD5=...,SHA256=..." (Sysmon EventID 1/6/7/15/23/26 in EvtxECmd's Payload,
    # Details / ExtraFieldInfo of Hayabusa and Zircolite, Chainsaw document...)
    EMBEDDED_HASH_COLUMN_RX = r"(?i)payload(data\d*)?|details|extrafieldinfo|extrafields|document|hashes|event_?data"
    EMBEDDED_HASH_RX = r"(?i)(?:^|[^A-Za-z0-9])(?:MD5|SHA1|SHA256)=([0-9A-Fa-f]{32,64})"

    def hashset_files(self) -> list[Path]:
        """Offline lists: local\\hashsets\\ (VM-wide) and <case>\\hashsets\\ (case-specific).
        .txt / .csv files: one hash per line, optionally followed by ; or , and a label.
        The file name gives the nature of the list: known_bad*, known_good* (e.g. NSRL extract)."""
        out = []
        for d in (LOCAL_DIR / "hashsets", self.case / "hashsets"):
            if d.is_dir():
                out += sorted(p for p in d.iterdir() if p.suffix.lower() in (".txt", ".csv") and p.is_file()
                              and not p.stem.lower().startswith(("lisezmoi", "readme")))
        return out

    def build_hashsets(self, con):
        con.execute("CREATE TABLE hashset (hash VARCHAR, algo VARCHAR, list VARCHAR, label VARCHAR, source_file VARCHAR)")
        rows, files = [], self.hashset_files()
        for p in files:
            name = p.stem.lower()
            kind = "known_bad" if name.startswith(("known_bad", "bad", "ioc", "malware")) else \
                   "known_good" if name.startswith(("known_good", "good", "nsrl")) else "watch"
            for line in p.read_text(encoding="utf-8-sig", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = re.split(r"[;,\t]", line, 1)
                h = parts[0].strip().strip('"').lower()
                label = parts[1].strip().strip('"') if len(parts) > 1 else None
                if re.fullmatch(r"[0-9a-f]+", h) and len(h) in self.HASH_LEN:
                    rows.append((h, self.HASH_LEN[len(h)], kind, label, str(p)))
        if rows:
            con.executemany("INSERT INTO hashset VALUES (?,?,?,?,?)", rows)
        selects = []
        for table, info in sorted(self.tables.items()):
            for c in info["columns"]:
                if c.startswith("_"):
                    continue
                ref = f"_src_file || '#' || _src_row AS ref FROM raw.{q(table)}"
                if re.fullmatch(self.HASH_COLUMN_RX, c):
                    # Amcache: "0000" identifier + SHA1
                    v = f"lower(regexp_replace(trim({q(c)}), '^0000([0-9a-fA-F]{{40}})$', '\\1'))"
                    selects.append(f"SELECT {v} AS hash, {lit(table)} AS src_table, {lit(c)} AS src_column, {ref} "
                                   f"WHERE length(trim({q(c)})) BETWEEN 32 AND 68")
                elif re.fullmatch(self.EMBEDDED_HASH_COLUMN_RX, c):
                    v = f"lower(unnest(regexp_extract_all({q(c)}, {lit(self.EMBEDDED_HASH_RX)}, 1)))"
                    selects.append(f"SELECT {v} AS hash, {lit(table)} AS src_table, {lit(c)} AS src_column, {ref} "
                                   f"WHERE regexp_matches({q(c)}, {lit(self.EMBEDDED_HASH_RX)})")
        if selects and rows:
            con.execute(f"""CREATE TABLE hash_hits AS
                SELECT h.list, h.algo, v.hash, h.label, v.src_table, v.src_column, v.ref, h.source_file
                FROM ({' UNION ALL '.join(selects)}) v JOIN hashset h ON h.hash = v.hash
                ORDER BY CASE h.list WHEN 'known_bad' THEN 0 WHEN 'watch' THEN 1 ELSE 2 END, v.hash, v.ref""")
        else:
            con.execute("""CREATE TABLE hash_hits (list VARCHAR, algo VARCHAR, hash VARCHAR, label VARCHAR, src_table VARCHAR,
                           src_column VARCHAR, ref VARCHAR, source_file VARCHAR)""")
        n = con.execute("SELECT list, count(*), count(DISTINCT hash) FROM hash_hits GROUP BY 1").fetchall()
        self.report["hashsets"] = {"files": [str(p) for p in files], "hashes": len(rows), "hash_columns": len(selects),
                                   "hits": {k: {"rows": a, "distinct": b} for k, a, b in n}}
        self.log(f"  hash lists: {len(rows)} hash(es) in {len(files)} file(s), {len(selects)} column(s) compared; "
                 + (", ".join(f"{k}: {b} hash(es) found" for k, a, b in n) or "no match"))

    # -- metadata, report --------------------------------------------------------------
    def write_sources(self, con):
        con.execute("""CREATE TABLE sources (src_file VARCHAR, job VARCHAR, bytes BIGINT, sha256 VARCHAR, status VARCHAR,
            reason VARCHAR, raw_table VARCHAR, rows BIGINT, rejected_rows BIGINT, mapping VARCHAR, source_id VARCHAR)""")
        rows = []
        for f in self.files:
            outputs = (self.jobs.get(f["job"]) or {}).get("_outputs", {})
            o = outputs.get(f["rel"]) or {}
            digest = o.get("sha256")
            if not digest and f.get("status") in (LOADED, EMPTY) and f["bytes"] < (64 << 20):
                digest = sha256(f["path"])
            rows.append((f["rel"], f["job"], f["bytes"], digest, f.get("status"), f.get("reason"),
                         ("raw." + f["table"]) if f.get("status") in (LOADED, EMPTY) and "stage" in f else None,
                         f.get("rows"), f.get("rejects"), f.get("mapping"),
                         (f.get("source") or {}).get("id")))
        con.executemany("INSERT INTO sources VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)

    def write_meta(self, con, started: str):
        try:      # version of the deployed pipeline (written by 02_Install-Tools.ps1: git commit of the repository)
            pv = json.loads((PIPE / "VERSION.json").read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            pv = {}
        try:      # collection integrity check (inventory.py)
            integ = json.loads((self.case / "inventory" / "inventory.json").read_text(encoding="utf-8"))["summary"].get("integrity")
        except (OSError, ValueError, KeyError):
            integ = None
        try:      # re-check after parsing (orchestrator.py)
            after = json.loads((self.parsed / "run_summary.json").read_text(encoding="utf-8-sig")).get("integrity_after_parsing")
        except (OSError, ValueError):
            after = None
        if integ and after is not None:
            integ = {**integ, "changed_during_parsing": after.get("changed_during_parsing", [])}
        meta = {
            "pipeline_version": pv.get("label") or "unknown (no VERSION.json: pipeline not deployed by 02_Install-Tools.ps1)",
            "collection_integrity": json.dumps(integ, ensure_ascii=False) if integ else "not checked",
            "case": str(self.case), "normalized_at_utc": started, "normalize_version": VERSION,
            "case_root_in_outputs": self.case_root, "map_file": str(self.map_path), "map_version": str(self.mapping.get("version")),
            "map_sha256": sha256(self.map_path), "duckdb_version": duckdb.__version__,
            "timeline_min_ts": self.min_ts, "timeline_max_ts": self.max_ts,
            "timezone": "UTC (every timeline/detections date)",
            "machine_active_time_bias_min": str(self.tz_bias),
            "ref_format": "<output relative to parsed>#<record number>: CSV data line (header excluded) or JSONL line",
        }
        con.execute("CREATE TABLE meta (key VARCHAR, value VARCHAR)")
        con.executemany("INSERT INTO meta VALUES (?, ?)", list(meta.items()))
        return meta

    def proposals(self, generated: str):
        """Outputs without a validated mapping -> normalize_proposals.json (merged by table)."""
        new = []
        for table, info in sorted(self.tables.items()):
            if info["source"] is None and info.get("auto_source"):
                a = info["auto_source"]
                new.append({
                    "table": table, "glob": [proposal_glob(info["files"][0]["rel"])],
                    "detected_columns": info["columns"],
                    "proposed": {"id": table, "artifact": None, "category": None, "tool": info["files"][0]["job"],
                                 "times": [{"ts": t["ts"], "desc": t["desc"].replace(" (auto, not validated)", "")} for t in a["times"]],
                                 "path": a.get("path"), "description": a.get("description")},
                    "case": str(self.case), "date": generated, "status": PROPOSED,
                    "justification": "Output present in parsed\\ but missing from normalize_map.json; date columns "
                                     "detected automatically. To be checked (meaning of each date, time zone) before validation.",
                })
        try:
            existing = json.loads(PROPOSALS.read_text(encoding="utf-8")) if PROPOSALS.exists() else []
        except ValueError:
            existing = []
        by_table = {p.get("table"): p for p in existing if isinstance(p, dict)}
        # Proposals now covered by a validated mapping: marked "integrated"
        changed = False
        for prop in by_table.values():
            if prop.get("status") == PROPOSED and any(
                    f.get("mapping") == "validated" and glob_match(f["rel"], prop.get("glob", [])) for f in self.files):
                prop["status"] = INTEGRATED
                prop["integrated"] = f"normalize_map.json v{self.mapping.get('version')} ({generated})"
                changed = True
        if not new and not changed:
            return 0
        for p in new:
            old = by_table.get(p["table"])
            if old and old.get("status") != PROPOSED:
                continue                       # already handled by the analyst: do not overwrite
            by_table[p["table"]] = p
        try:
            PROPOSALS.parent.mkdir(parents=True, exist_ok=True)
            PROPOSALS.write_text(json.dumps(list(by_table.values()), ensure_ascii=False, indent=1), encoding="utf-8")
        except OSError as e:
            self.report["warnings"].append(f"Cannot write {PROPOSALS}: {e}")
        return len(new)

    def write_report(self, con, out_dir: Path, meta: dict, n_prop: int):
        tl = con.execute("SELECT count(*), min(ts), max(ts) FROM timeline").fetchone()
        det = con.execute("SELECT level, count(*) FROM detections GROUP BY 1 ORDER BY 2 DESC").fetchall()
        per_art = con.execute("""SELECT artifact, tool, mapping, count(*), min(ts), max(ts) FROM timeline
                                 GROUP BY ALL ORDER BY 4 DESC""").fetchall()
        tables = {}
        for t, info in sorted(self.tables.items()):
            tables[t] = {"files": [f["rel"] for f in info["files"]], "rows": sum(f.get("rows", 0) for f in info["files"]),
                         "mapping": "validated" if info["source"] else ("auto" if self.auto else "raw"),
                         "source_id": (info["source"] or {}).get("id"), "timeline": info.get("timeline"),
                         "detections": info.get("detections")}
        unmapped = [t for t, v in tables.items() if v["mapping"] != "validated"]
        files = [{k: (str(v) if isinstance(v, Path) else v) for k, v in f.items() if k not in ("source", "stage")} for f in self.files]
        rep = {"meta": meta, "timeline": {"rows": tl[0], "min": str(tl[1]), "max": str(tl[2])},
               "detections": {lvl: n for lvl, n in det}, "tables": tables, "unmapped_tables": unmapped,
               "proposals_written": n_prop, "files": files, **self.report}
        (out_dir / "normalize_report.json").write_text(json.dumps(rep, ensure_ascii=False, indent=1, default=str), encoding="utf-8")

        L = [f"# Normalization: {self.case.name}", "",
             f"- Database: `{self.db_path}`", f"- Date (UTC): {meta['normalized_at_utc']}",
             f"- Mapping table: `{self.map_path.name}` v{meta['map_version']} (sha256 {meta['map_sha256'][:16]}…)",
             f"- Timeline: **{tl[0]:,}** rows, from {tl[1]} to {tl[2]} (UTC)".replace(",", " "),
             "- Detections: " + (", ".join(f"{lvl} {n}" for lvl, n in det) or "none"), ""]
        if self.report["errors"]:
            L += ["## Errors", ""] + [f"- {e}" for e in self.report["errors"]] + [""]
        hs = self.report.get("hashsets") or {}
        L += ["## Hash lists", "",
              (f"{hs.get('hashes', 0)} hash(es) loaded from {len(hs.get('files', []))} file(s) "
               f"(`local\\hashsets\\`, `<case>\\hashsets\\`), {hs.get('hash_columns', 0)} hash column(s) compared. "
               + ("Matches (table `hash_hits`): " + ", ".join(f"{k} {v['distinct']}" for k, v in hs["hits"].items())
                  if hs.get("hits") else "No match.")), ""]
        if unmapped:
            L += ["## Outputs without a validated mapping", "",
                  "Loaded as raw tables; their dates (when detected) are in the timeline with `mapping = 'auto'`.",
                  f"Proposals written to `{PROPOSALS}`.", ""]
            L += [f"- raw.{t} ({tables[t]['rows']} rows): {', '.join(tables[t]['files'])}" for t in unmapped] + [""]
        L += ["## Timeline per artifact", "", "| Artifact | Tool | Mapping | Rows | From | To |", "|---|---|---|---:|---|---|"]
        L += [f"| {a} | {t} | {m} | {n} | {mi} | {ma} |" for a, t, m, n, mi, ma in per_art] + [""]
        L += ["## Files", "", "| Output | Status | Table | Rows | Rejects | Note |", "|---|---|---|---:|---:|---|"]
        for f in self.files:
            L.append(f"| {f['rel']} | {f.get('status')} | {('raw.' + f['table']) if 'stage' in f else ''} | "
                     f"{f.get('rows', '')} | {f.get('rejects') or ''} | {f.get('reason') or ''} |")
        (out_dir / "normalize_report.md").write_text("\n".join(L) + "\n", encoding="utf-8")

    # -- run ---------------------------------------------------------------------------
    def run(self, threads: int | None, memory_limit: str | None):
        started = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None).replace(microsecond=0).isoformat() + "Z"
        out_dir = self.db_path.parent
        out_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.db_path.with_suffix(".duckdb.tmp")
        for p in (tmp, Path(str(tmp) + ".wal")):
            if p.exists():
                p.unlink()
        self.log(f"Case: {self.case}")
        self.log(f"Mappings: {self.map_path}")
        self.discover()
        n_load = sum(1 for f in self.files if f.get("status") is None)
        self.log(f"{len(self.files)} files in parsed\\: {n_load} to load, "
                 f"{sum(1 for f in self.files if f.get('status') == IGNORED)} ignored, "
                 f"{sum(1 for f in self.files if f.get('status') == EMPTY)} empty")
        mb = sum(f["bytes"] for f in self.files if f.get("status") is None) / 1e6
        r = self.rates
        est_units = mb * r["units_per_mb"]
        self.log.set_remaining(mb * r["load_s_per_mb"] + est_units * r["tl_s_per_unit"]
                               + est_units * r["rows_per_unit"] * r["final_s_per_row"])
        self.log(f"Volume: {mb:,.0f} MB; estimated duration ~{fmt_duration(self.log.total)}".replace(",", " "))
        marks = {}
        con = duckdb.connect(str(tmp))
        try:
            try:
                con.execute("SET TimeZone = 'UTC'")
            except duckdb.Error:
                self.report["warnings"].append("ICU extension unavailable: UTC time zone not set explicitly.")
            if threads:
                con.execute(f"SET threads = {int(threads)}")
            if memory_limit:
                con.execute(f"SET memory_limit = {lit(memory_limit)}")
            con.execute(f"SET temp_directory = {lit(str(out_dir / '_duckdb_tmp'))}")
            create_macros(con, self.case_root)
            self.load_jobs(con)
            self.log("Loading raw tables")
            self.log.set_phase("Loading")
            marks["t_load"] = time.time()
            self.load_raw(con)
            marks["t_tl"] = time.time()
            self.detect_tz_bias(con)
            self.log("Building the timeline")
            self.log.set_phase("Timeline")
            self.build_timeline(con)
            marks["t_final"] = time.time()
            self.log("Building detections")
            self.log.set_phase("Detections and report")
            tl_rows = con.execute("SELECT count(*) FROM timeline").fetchone()[0]
            self.log.set_remaining(tl_rows * r["final_s_per_row"] * 0.5)
            self.build_detections(con)
            self.build_hashsets(con)
            self.write_sources(con)
            meta = self.write_meta(con, started)
            con.execute("""CREATE VIEW artifact_summary AS
                SELECT artifact, category, tool, mapping, count(*) AS rows, min(ts) AS first_ts, max(ts) AS last_ts
                FROM timeline GROUP BY ALL ORDER BY rows DESC""")
            n_prop = self.proposals(started)
            self.write_report(con, out_dir, meta, n_prop)
            con.execute("CHECKPOINT")
            marks["t_end"] = time.time()
        finally:
            con.close()
            self.log.finish()
        if {"t_load", "t_tl", "t_final", "t_end"} <= marks.keys() and mb > 0:
            tl_rows = json.loads((out_dir / "normalize_report.json").read_text(encoding="utf-8"))["timeline"]["rows"]
            entry = {"case": str(self.case), "date": started, "mb": round(mb, 1), "units": self.tl_units,
                     "timeline_rows": tl_rows,
                     "load_s_per_mb": (marks["t_tl"] - marks["t_load"]) / mb,
                     "units_per_mb": self.tl_units / mb if self.tl_units else None}
            if self.tl_units:
                entry["tl_s_per_unit"] = (marks["t_final"] - marks["t_tl"]) / self.tl_units
                entry["rows_per_unit"] = tl_rows / self.tl_units
            if tl_rows:
                entry["final_s_per_row"] = (marks["t_end"] - marks["t_final"]) / tl_rows
            entry["total_s"] = round(marks["t_end"] - marks["t_load"], 1)
            self.history.add(entry)
        if self.db_path.exists():
            self.db_path.unlink()
        os.replace(tmp, self.db_path)
        import shutil
        for d in (out_dir / "_tmp", out_dir / "_duckdb_tmp"):
            shutil.rmtree(d, ignore_errors=True)
        tl_info = json.loads((out_dir / "normalize_report.json").read_text(encoding="utf-8"))["timeline"]
        self.log(f"Done: {self.db_path}  (timeline {tl_info['rows']:,} rows)".replace(",", " "))
        self.log(f"Report: {out_dir / 'normalize_report.md'}")
        if self.report["errors"]:
            self.log(f"{len(self.report['errors'])} error(s): see the report.")
        return 1 if self.report["errors"] else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("case", type=Path, help="case folder (contains parsed\\)")
    ap.add_argument("--map", type=Path, default=DEFAULT_MAP, help="mapping table (default: normalize_map.json)")
    ap.add_argument("--db", type=Path, help="output database (default: <case>\\db\\case.duckdb)")
    ap.add_argument("--no-auto", action="store_true",
                    help="do not put the automatically detected dates of undescribed outputs in the timeline")
    ap.add_argument("--case-root", help="case path as it appears in the outputs (default: run_summary.json)")
    ap.add_argument("--no-live", action="store_true", help="text progress (one line every 10 s) instead of the bar")
    ap.add_argument("--threads", type=int, help="number of DuckDB threads")
    ap.add_argument("--memory-limit", help="DuckDB memory limit (e.g. 8GB)")
    args = ap.parse_args(argv)
    case = args.case.resolve()
    if not (case / "parsed").is_dir():
        ap.error(f"{case}\\parsed not found: run orchestrator.py first")
    db = args.db or (case / "db" / "case.duckdb")
    log = Progress(live=not args.no_live)
    return Normalizer(case, args.map.resolve(), db.resolve(), not args.no_auto, log, args.case_root).run(args.threads, args.memory_limit)


if __name__ == "__main__":
    sys.exit(main())
