#!/usr/bin/env python3
"""
Sleuthline - step 4: analysis agent. Queries the DuckDB database of a case (normalize.py)
following PLAYBOOK.md, records evidence-backed findings, then produces a Word report.

  python analyze.py "C:\\Sleuthline\\cases\\<case>"              full analysis + report
  python analyze.py <case> --steps 3,4 --force                    replay some steps
  python analyze.py <case> --ask "Where does setup.exe come from?"   one-off question
  python analyze.py <case> --report-only                          regenerate the report
  python analyze.py <case> --profile ollama                       another model (config\\llm_config.json)

Case files (<case>\\analysis\\):
  guidance.txt          context, questions, IOCs, instructions (created from a template if missing)
  findings.json         analysis state: findings, timeline, IOCs, answers (resumable)
  transcript.jsonl      complete trace of the exchanges with the model and of the executed queries
  report_<case>_<date>.docx, iocs.csv, key_timeline.csv, incident_timeline.csv

Guarantees:
  - database opened read-only, file access disabled in DuckDB;
  - every finding, event and IOC must cite references (ref) that exist in the database,
    otherwise the tool refuses to record it; an answer needs references unless it is "undetermined";
  - the confidence is checked by the program (guards.py): a critical/high finding stays "confirmed"
    only with 2 independent sources, and automatically mapped outputs cannot confirm on their own;
  - evidence content reaches the model inside <untrusted_evidence> blocks it cannot close, and text
    that looks like instructions addressed to an AI is flagged and reported, never followed.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import re
import shutil
import sys
import threading
import time
from pathlib import Path

try:
    import duckdb
except ImportError:  # pragma: no cover
    sys.exit("duckdb is not installed in this Python environment.")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
PIPE = Path(__file__).resolve().parents[1]      # <root>\pipeline (1_inventory, 2_parsing, 3_normalize, 4_analysis, config, docs, local)
CONFIG_DIR = PIPE / "config"                       # validated files (source: <repository>\pipeline\config)
LOCAL_DIR = PIPE / "local"                         # files specific to this VM (never overwritten by deployment)
from llm import LLMError, make_provider  # noqa: E402
import guards  # noqa: E402

VERSION = "1.2"
PLAYBOOK = CONFIG_DIR / "PLAYBOOK.md"
GUIDANCE_TEMPLATE = CONFIG_DIR / "guidance_template.txt"
CONFIG = CONFIG_DIR / "llm_config.json"
KEYS_FILE = CONFIG_DIR / "api_keys.txt"
DEFAULT_LIMITS = {"max_tool_calls_per_step": 40, "max_result_chars": 15000, "max_rows": 200,
                  "keep_full_results": 12, "query_timeout_s": 120, "max_billed_tokens_per_run": 0}
SEVERITIES = ["critical", "high", "medium", "low", "info"]
CONFIDENCES = ["confirmed", "probable", "possible"]
UNDETERMINED = "undetermined"
DONE, RUNNING = "done", "running"
LANGUAGES = {"en": "English", "fr": "French", "de": "German", "nl": "Dutch", "es": "Spanish", "it": "Italian",
             "pt": "Portuguese"}

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def num(n) -> str:
    return f"{int(n or 0):,}"


def fmt_duration(sec: float) -> str:
    sec = max(0, int(sec))
    m, s = divmod(sec, 60)
    h, m = divmod(m, 60)
    return f"{h} h {m:02d} min" if h else (f"{m} min {s:02d} s" if m else f"{s} s")


class Log:
    def __init__(self):
        self.t0 = time.time()

    def __call__(self, msg=""):
        print(f"[{fmt_duration(time.time() - self.t0):>12}] {msg}", flush=True)


# ------------------------------------------------------------------------------------------
# Configuration, playbook, guidance
# ------------------------------------------------------------------------------------------
def load_config(path: Path, profile: str | None):
    if not path.exists():
        raise SystemExit(f"Configuration not found: {path}")
    cfg = json.loads(path.read_text(encoding="utf-8"))
    name = profile or cfg.get("active")
    profiles = cfg.get("profiles", {})
    if name not in profiles:
        raise SystemExit(f"Profile '{name}' missing from {path} (profiles: {', '.join(profiles)})")
    limits = {**DEFAULT_LIMITS, **cfg.get("limits", {}), "evidence_policy": guards.load_policy(cfg.get("evidence_policy"))}
    lang = str(cfg.get("report_language") or "en").strip()
    return name, {**profiles[name], "_keys_file": str(KEYS_FILE), "_report_language": lang}, limits


def language_name(code: str) -> str:
    return LANGUAGES.get(str(code).lower(), str(code))


def parse_playbook(path: Path):
    text = path.read_text(encoding="utf-8")
    parts = re.split(r"(?m)^## ", text)
    rules, steps = "", []
    for part in parts[1:]:
        title, _, body = part.partition("\n")
        title = title.strip()
        m = re.match(r"(?i)step\s+(\d+)\s*[:\-—]\s*(.+)", title)
        if m:
            steps.append({"num": int(m.group(1)), "title": m.group(2).strip(), "body": body.strip()})
        elif title.lower().startswith("rules"):
            rules = body.strip()
    if not steps:
        raise SystemExit(f"No step (\"## Step N: title\") in {path}")
    return rules, steps


# Guidance sections
GUIDANCE_SECTIONS = {"context": "context", "period": "period", "questions": "questions", "ioc": "ioc", "iocs": "ioc",
                     "suspects": "suspects", "exclusions": "exclusions", "instructions": "instructions"}
PERIOD_KEYS = {"start": "start", "end": "end"}


def parse_guidance(path: Path) -> dict:
    g = {"context": "", "period": {}, "questions": [], "iocs": [], "suspects": [], "exclusions": [], "instructions": ""}
    if not path.exists():
        return g
    section = None
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^\[([^\]]+)\]$", line)
        if m:
            name = m.group(1).strip().lower()
            section = GUIDANCE_SECTIONS.get(name, name)
            continue
        if section == "context":
            g["context"] += line + "\n"
        elif section == "instructions":
            g["instructions"] += line + "\n"
        elif section == "period":
            k, _, v = line.partition("=")
            if v.strip():
                g["period"][PERIOD_KEYS.get(k.strip().lower(), k.strip().lower())] = v.strip()
        elif section == "questions":
            # Questions: bulleted lines (-, *, •), numbered lines (1. / 1) / Q1.) or lines ending with "?".
            # Other lines (e.g. "Happy Hunting!") go to the context.
            m = re.match(r"^(?:[-*•]|(?:Q\s*)?\d+\s*[.)\-:])\s*(.+)$", line, re.I)
            if m:
                g["questions"].append(m.group(1).strip())
            elif line.endswith("?"):
                g["questions"].append(line)
            else:
                g["context"] += line + "\n"
        elif section == "ioc":
            body, _, comment = line.partition("#")
            k, sep, v = body.partition("=")
            if sep and v.strip():
                g["iocs"].append({"type": k.strip().lower(), "value": v.strip(), "comment": comment.strip()})
            elif body.strip():
                g["iocs"].append({"type": "text", "value": body.strip(), "comment": comment.strip()})
        elif section in ("suspects", "exclusions"):
            g[section].append(line.lstrip("-*• ").strip())
    return g


def guidance_text(g: dict) -> str:
    out = []
    if g["context"].strip():
        out.append("Context provided by the analyst:\n" + g["context"].strip())
    if g["period"]:
        out.append("Period of interest (UTC): " + ", ".join(f"{k} = {v}" for k, v in g["period"].items()))
    if g["questions"]:
        out.append("Questions to answer (answer_question):\n" + "\n".join(f"  Q{i}. {q}" for i, q in enumerate(g["questions"], 1)))
    if g["iocs"]:
        out.append("Provided IOCs:\n" + "\n".join(f"  - {i['type']} = {i['value']}" + (f"  ({i['comment']})" if i["comment"] else "") for i in g["iocs"]))
    if g["suspects"]:
        out.append("Suspected items:\n" + "\n".join(f"  - {s}" for s in g["suspects"]))
    if g["exclusions"]:
        out.append("To be considered legitimate / ignored:\n" + "\n".join(f"  - {s}" for s in g["exclusions"]))
    if g["instructions"].strip():
        out.append("Analyst instructions:\n" + g["instructions"].strip())
    return "\n\n".join(out) or "(no guidance provided: full analysis without preconceptions)"


# ------------------------------------------------------------------------------------------
# Case database (read-only)
# ------------------------------------------------------------------------------------------
# Defense in depth: the database is opened read-only and file access is disabled.
FORBIDDEN = re.compile(r"(?is)\b(copy|attach|detach|install|load|export|import|pragma|checkpoint|vacuum)\b|^\s*(set|reset|use|call)\b")
FILE_FUNCS = re.compile(r"(?i)\b(read_\w+|glob|sniff_csv|\w+_scan|query_table|query)\s*\(")
ALLOWED_START = re.compile(r"(?is)^\s*(select|with|describe|show|summarize|from|explain)\b")


def strip_sql_comments(sql: str) -> str:
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    return re.sub(r"--[^\n]*", " ", sql)


def strip_strings(sql: str) -> str:
    return re.sub(r"'(?:[^']|'')*'", "''", sql)


class CaseDB:
    def __init__(self, path: Path, limits: dict):
        self.path = path
        self.limits = limits
        self.con = duckdb.connect(str(path), read_only=True)
        try:
            self.con.execute("SET TimeZone = 'UTC'")
        except duckdb.Error:
            pass                            # ICU extension missing: columns are already in UTC
        # Mandatory safeguards: without them, a query from the model could read files.
        for stmt in ("SET enable_external_access = false", "SET lock_configuration = true"):
            try:
                self.con.execute(stmt)
            except duckdb.Error as e:
                raise SystemExit(f"Cannot apply \"{stmt}\" to the database ({e}): analysis stopped for safety.")
        self.lock = threading.Lock()
        self.raw_tables = {r[0] for r in self.con.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'raw'").fetchall()}
        self.src_to_table = dict(self.con.execute(
            "SELECT src_file, raw_table FROM sources WHERE raw_table IS NOT NULL").fetchall())

    # -- queries -------------------------------------------------------------------------
    def check_sql(self, sql: str):
        s = strip_strings(strip_sql_comments(sql)).strip().rstrip(";").strip()
        if ";" in s:
            return "One query at a time."
        if not ALLOWED_START.match(s):
            return "Only read queries are allowed (SELECT, WITH, DESCRIBE, SHOW, SUMMARIZE)."
        m = FORBIDDEN.search(s)
        if m:
            return f"Forbidden keyword: {(m.group(1) or m.group(2)).upper()} (read-only database)."
        m = FILE_FUNCS.search(s)
        if m and not m.group(1).lower().startswith(("regexp_", "list_", "array_")):
            return f"Forbidden function: {m.group(1)} (file access disabled)."
        return None

    def run(self, sql: str, params=None, max_rows: int | None = None):
        timeout = self.limits["query_timeout_s"]
        timer = threading.Timer(timeout, self.con.interrupt)
        with self.lock:
            timer.start()
            try:
                cur = self.con.execute(sql, params or [])
                cols = [d[0] for d in cur.description] if cur.description else []
                rows = cur.fetchmany((max_rows or self.limits["max_rows"]) + 1)
            finally:
                timer.cancel()
        return cols, rows

    def query_text(self, sql: str, max_rows: int | None = None) -> str:
        err = self.check_sql(sql)
        if err:
            return "ERROR: " + err
        max_rows = min(int(max_rows or self.limits["max_rows"]), 1000)
        t0 = time.time()
        try:
            cols, rows = self.run(sql, max_rows=max_rows)
        except duckdb.InterruptException:
            return f"ERROR: query interrupted after {self.limits['query_timeout_s']} s: add filters or a LIMIT."
        except duckdb.Error as e:
            return "SQL ERROR: " + str(e).splitlines()[0][:800]
        more = len(rows) > max_rows
        rows = rows[:max_rows]
        return format_table(cols, rows, self.limits["max_result_chars"],
                            footer=(f"(at least {max_rows + 1} rows: result truncated to {max_rows}, refine the query)" if more
                                    else f"({len(rows)} row(s), {time.time() - t0:.1f} s)"))

    # -- evidence ------------------------------------------------------------------------
    def resolve_ref(self, ref: str):
        ref = str(ref).strip()
        for table in ("timeline", "detections"):
            cols, rows = self.run(f"SELECT * FROM {table} WHERE ref = ? ORDER BY ts LIMIT 1", [ref], 1)
            if rows:
                d = dict(zip(cols, rows[0]))
                return {"ref": ref, "ts": str(d.get("ts")), "artifact": d.get("artifact") or f"Detection {d.get('engine')}",
                        "tool": d.get("tool") or d.get("engine"),
                        "description": d.get("description") or (d.get("rule_title", "") + " | " + str(d.get("details") or "")),
                        "evidence": d.get("evidence"), "path": d.get("path"), "user": d.get("user_name"),
                        "ts_desc": d.get("ts_desc") or d.get("level"),
                        "mapping": d.get("mapping") or ("detection" if table == "detections" else None)}
        src, sep, row = ref.rpartition("#")
        if not sep or not row.isdigit():
            return None
        table = self.src_to_table.get(src)
        if not table:
            return None
        schema, _, name = table.partition(".")
        cols, rows = self.run(f'SELECT * FROM {schema}."{name}" WHERE _src_file = ? AND _src_row = ? LIMIT 1', [src, int(row)], 1)
        if not rows:
            return None
        d = {k: v for k, v in zip(cols, rows[0]) if v not in (None, "") and not k.startswith("_")}
        tl = self.run("SELECT ts, ts_desc, artifact, tool, description, evidence, path, user_name, mapping FROM timeline "
                      "WHERE src_file = ? AND src_row = ? ORDER BY ts LIMIT 1", [src, int(row)], 1)[1]
        base = {"ref": ref, "raw": json.dumps(d, ensure_ascii=False, default=str)[:1500], "table": table}
        if tl:
            ts, tsd, art, tool, desc, ev, path, user, mapping = tl[0]
            base.update(ts=str(ts), ts_desc=tsd, artifact=art, tool=tool, description=desc, evidence=ev, path=path, user=user,
                        mapping=mapping)
        else:
            base.update(ts=None, artifact=table, tool=None, description=base["raw"][:400], evidence=None, path=None, user=None,
                        mapping="raw")
        return base

    def get_evidence_text(self, refs: list) -> str:
        out = []
        for r in refs[:30]:
            res = self.resolve_ref(r)
            if not res:
                out.append(f"- {r}: NOT FOUND")
                continue
            line = f"- {r} | {res.get('ts')} | {res.get('artifact')} | {res.get('ts_desc') or ''}\n  {res.get('description') or ''}\n  evidence: {res.get('evidence') or '?'}"
            src, sep, row = r.rpartition("#")
            table = self.src_to_table.get(src)
            if table and row.isdigit():
                schema, _, name = table.partition(".")
                cols, rows = self.run(f'SELECT * FROM {schema}."{name}" WHERE _src_file = ? AND _src_row = ? LIMIT 1', [src, int(row)], 1)
                if rows:
                    d = {k: v for k, v in zip(cols, rows[0]) if v not in (None, "")}
                    line += "\n  raw record: " + json.dumps(d, ensure_ascii=False, default=str)[:3000]
            out.append(line)
        return "\n".join(out)[: self.limits["max_result_chars"]]

    # -- overview for the prompt ---------------------------------------------------------
    def overview(self) -> str:
        parts = []
        meta = dict(self.run("SELECT key, value FROM meta", max_rows=100)[1])
        parts.append("Metadata: " + json.dumps({k: meta.get(k) for k in (
            "case", "normalized_at_utc", "machine_active_time_bias_min", "timezone", "ref_format", "map_version")}, ensure_ascii=False))
        cols, rows = self.run("SELECT * FROM artifact_summary", max_rows=300)
        parts.append("Timeline coverage (artifact_summary):\n" + format_table(cols, rows, 12000))
        cols, rows = self.run("SELECT engine, level, count(*) AS n FROM detections GROUP BY ALL ORDER BY engine, n DESC", max_rows=100)
        parts.append("Detections per engine and level:\n" + format_table(cols, rows, 3000))
        if self.con.execute("SELECT count(*) FROM information_schema.tables WHERE table_name = 'hash_hits'").fetchone()[0]:
            cols, rows = self.run("SELECT list, algo, hash, any_value(label) AS label, count(*) AS occurrences, "
                                  "string_agg(DISTINCT src_table, ', ') AS tables, min(ref) AS example_ref "
                                  "FROM hash_hits GROUP BY ALL ORDER BY list, occurrences DESC", max_rows=100)
            n_hs = self.run("SELECT count(*) FROM hashset", max_rows=1)[1][0][0]
            parts.append(f"Offline hash lists ({n_hs} hashes loaded; table hash_hits):\n"
                         + (format_table(cols, rows, 4000) if rows else "no match in the database"))
        cols, rows = self.run("SELECT dir AS job, status, title FROM jobs WHERE status <> 'ok' ORDER BY 1", max_rows=100)
        if rows:
            parts.append("Parsing jobs not 'ok' (incomplete sources):\n" + format_table(cols, rows, 3000))
        lines = []
        for t in sorted(self.raw_tables):
            c = self.run(f'SELECT count(*) FROM raw."{t}"', max_rows=1)[1][0][0]
            cols = [r[0] for r in self.run(f'DESCRIBE raw."{t}"', max_rows=500)[1]]
            shown = [x for x in cols if not x.startswith("_")]
            lines.append(f"raw.{t} ({c} rows): " + ", ".join(shown[:40]) + (" ..." if len(shown) > 40 else ""))
        parts.append("Raw tables (text columns; _src_file, _src_row always present):\n" + "\n".join(lines))
        parts.append("Main tables:\n"
                     "timeline(tl_id, ts TIMESTAMP UTC, ts_desc, artifact, category, tool, host, user_name, path, description, evidence, "
                     "src_table, src_file, src_row, source_id, mapping, ref)\n"
                     "detections(det_id, ts, engine, rule_title, rule_id, level, computer, channel, event_id, record_id, details, tactics, "
                     "evidence, src_table, src_file, src_row, ref)\n"
                     "hash_hits(list known_bad/known_good/watch, algo, hash, label, src_table, src_column, ref, source_file), hashset\n"
                     "timeline_all (view timeline + detections), artifact_summary, sources, jobs, meta")
        return "\n\n".join(parts)


def format_table(cols, rows, max_chars: int, footer: str = "") -> str:
    def cell(v):
        s = "" if v is None else str(v)
        s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
        return s if len(s) <= 400 else s[:400] + "…"
    lines = ["\t".join(cols)]
    total = len(lines[0])
    for r in rows:
        line = "\t".join(cell(v) for v in r)
        if total + len(line) > max_chars:
            lines.append(f"… (output truncated to {max_chars} characters: reduce the columns or the number of rows)")
            break
        lines.append(line)
        total += len(line) + 1
    if footer:
        lines.append(footer)
    return "\n".join(lines)


# ------------------------------------------------------------------------------------------
# Analysis state (findings.json)
# ------------------------------------------------------------------------------------------
class State:
    def __init__(self, path: Path):
        self.path = path
        if path.exists():
            self.d = json.loads(path.read_text(encoding="utf-8"))
            self.d.setdefault("injection_alerts", [])
        else:
            self.d = {"version": VERSION, "created": now_utc(), "steps": {}, "findings": [], "timeline_events": [],
                      "iocs": [], "answers": [], "summary": {}, "recommendations": {}, "notes": [], "ioc_sweep": None, "injection_alerts": [],
                      "usage": {"input_tokens": 0, "output_tokens": 0, "calls": 0}, "runs": []}

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.d, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
        tmp.replace(self.path)

    def next_id(self, prefix: str, key: str) -> str:
        # Highest existing number + 1 (not len + 1): after a step purge, no duplicate identifier
        nums = [int(m.group(1)) for x in self.d[key] if (m := re.match(rf"{prefix}-(\d+)$", str(x.get("id", ""))))]
        return f"{prefix}-{max(nums, default=0) + 1:03d}"

    def purge_step(self, step) -> int:
        """Removes what a step produced during a previous run (--force replay, or resuming an
        interrupted step): otherwise findings, events and IOCs would be duplicated."""
        n = 0
        for key in ("findings", "timeline_events", "iocs", "notes", "answers", "injection_alerts"):
            self.d.setdefault(key, [])
            keep = [x for x in self.d[key] if str(x.get("step")) != str(step)]
            n += len(self.d[key]) - len(keep)
            self.d[key] = keep
        return n

    def compact(self) -> str:
        """Summary of the state sent to the model at the start of each step."""
        out = []
        for num_, s in sorted(self.d["steps"].items(), key=lambda x: int(x[0])):
            if s.get("summary"):
                out.append(f"Step {num_} ({s.get('title')}): {s['summary'][:1500]}")
        if self.d["findings"]:
            out.append("Recorded findings:\n" + "\n".join(
                f"  {f['id']} [{f['severity']}/{f['confidence']}] {f['title']} ({f.get('first_ts') or '?'} → {f.get('last_ts') or '?'}) "
                f"refs: {', '.join(e['ref'] for e in f['evidence'][:4])}" for f in self.d["findings"]))
        if self.d["timeline_events"]:
            out.append(f"Timeline events already recorded: {len(self.d['timeline_events'])}" + "\n" + "\n".join(
                f"  {e['ts']} {e['title']}" for e in sorted(self.d["timeline_events"], key=lambda e: e["ts"] or "")[-60:]))
        if self.d["iocs"]:
            out.append("Recorded IOCs:\n" + "\n".join(f"  {i['type']} = {i['value']}" for i in self.d["iocs"]))
        return "\n\n".join(out) or "(no finding so far)"


# ------------------------------------------------------------------------------------------
# Tools exposed to the model
# ------------------------------------------------------------------------------------------
DATA_TOOLS = {"sql_query", "describe_table", "search", "timeline_window", "get_evidence"}   # results = case data
REFS = {"type": "array", "items": {"type": "string"}, "description": "evidence references (ref column, or <_src_file>#<_src_row>)"}
TOOLS = [
    {"name": "sql_query", "description": "Runs a read-only DuckDB SQL query on the case database (one query, with LIMIT). Returns a text table.",
     "parameters": {"type": "object", "properties": {"sql": {"type": "string"}, "max_rows": {"type": "integer"}}, "required": ["sql"]}},
    {"name": "describe_table", "description": "Columns of a table (e.g. raw.evtx, timeline) and 3 sample rows.",
     "parameters": {"type": "object", "properties": {"table": {"type": "string"}}, "required": ["table"]}},
    {"name": "search", "description": "Case-insensitive full-text search in the timeline (path, description, user_name) and the detections, optionally within a UTC time window.",
     "parameters": {"type": "object", "properties": {"text": {"type": "string"}, "start": {"type": "string"}, "end": {"type": "string"},
                                                    "artifact_like": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["text"]}},
    {"name": "timeline_window", "description": "Timeline events (and detections) between two UTC instants, optionally filtered (text, category).",
     "parameters": {"type": "object", "properties": {"start": {"type": "string"}, "end": {"type": "string"}, "contains": {"type": "string"},
                                                    "category": {"type": "string"}, "exclude_artifacts": {"type": "array", "items": {"type": "string"}},
                                                    "limit": {"type": "integer"}}, "required": ["start", "end"]}},
    {"name": "get_evidence", "description": "Full detail (raw record) of evidence references.",
     "parameters": {"type": "object", "properties": {"refs": REFS}, "required": ["refs"]}},
    {"name": "add_finding", "description": "Records an evidence-backed finding (refused if a reference does not exist).",
     "parameters": {"type": "object", "properties": {
         "title": {"type": "string"}, "severity": {"type": "string", "enum": SEVERITIES},
         "confidence": {"type": "string", "enum": CONFIDENCES},
         "category": {"type": "string", "description": "e.g. execution, persistence, initial access, context, anti-forensics"},
         "mitre": {"type": "array", "items": {"type": "string"}, "description": "ATT&CK techniques, e.g. T1059.001"},
         "description": {"type": "string", "description": "observed facts, very detailed (paths, hashes, EventIDs, accounts, UTC times)"},
         "analysis": {"type": "string", "description": "interpretation, correlations, hypotheses and their level of certainty"},
         "refs": REFS}, "required": ["title", "severity", "confidence", "description", "refs"]}},
    {"name": "add_timeline_event", "description": "Adds a key event to the incident timeline.",
     "parameters": {"type": "object", "properties": {
         "ts": {"type": "string", "description": "UTC timestamp YYYY-MM-DD HH:MM:SS"}, "title": {"type": "string"},
         "phase": {"type": "string"}, "mitre": {"type": "array", "items": {"type": "string"}},
         "description": {"type": "string"}, "refs": REFS}, "required": ["ts", "title", "description", "refs"]}},
    {"name": "add_ioc", "description": "Records an indicator of compromise with its context and evidence.",
     "parameters": {"type": "object", "properties": {
         "type": {"type": "string", "description": "sha1, sha256, md5, file, path, ip, domain, url, user, sid, registry, service, task, command"},
         "value": {"type": "string"}, "context": {"type": "string"}, "refs": REFS}, "required": ["type", "value", "context", "refs"]}},
    {"name": "add_evidence", "description": "Adds corroborating references to a finding already recorded; its confidence is re-assessed "
                                    "(restores the declared confidence once the evidence policy is met).",
     "parameters": {"type": "object", "properties": {"finding_id": {"type": "string"}, "refs": REFS}, "required": ["finding_id", "refs"]}},
    {"name": "answer_question", "description": "Answers a question of the guidance (or asked with --ask). refs are mandatory unless "
                                       "confidence = undetermined.",
     "parameters": {"type": "object", "properties": {"question": {"type": "string"}, "answer": {"type": "string"},
                                                    "confidence": {"type": "string", "enum": CONFIDENCES + [UNDETERMINED]},
                                                    "refs": REFS}, "required": ["question", "answer", "confidence"]}},
    {"name": "set_summary", "description": "Report summary.",
     "parameters": {"type": "object", "properties": {"executive_summary": {"type": "string"}, "technical_summary": {"type": "string"},
                                                    "limitations": {"type": "string"}, "verdict": {"type": "string"}},
                    "required": ["executive_summary", "technical_summary", "limitations"]}},
    {"name": "set_recommendations", "description": "Recommendations, per category (lists of strings).",
     "parameters": {"type": "object", "properties": {k: {"type": "array", "items": {"type": "string"}} for k in
                                                    ("immediate", "remediation", "hardening", "detection", "further_investigation")}}},
    {"name": "note", "description": "Working note (leads ruled out, false positives): appears in the report appendix.",
     "parameters": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
    {"name": "step_complete", "description": "Ends the current step with a technical summary.",
     "parameters": {"type": "object", "properties": {"summary": {"type": "string"},
                                                    "gaps": {"type": "string", "description": "what could not be verified and why"}},
                    "required": ["summary"]}},
]


def norm_ts(s: str | None) -> str | None:
    if not s:
        return None
    s = str(s).strip().replace("T", " ").rstrip("Z")
    return s[:26]


class Agent:
    def __init__(self, case: Path, db: CaseDB, state: State, provider, limits: dict, guidance: dict, rules: str, log: Log,
                 transcript: Path, language: str = "en"):
        self.case, self.db, self.state, self.provider, self.limits = case, db, state, provider, limits
        self.guidance, self.rules, self.log, self.transcript = guidance, rules, log, transcript
        self.language = language_name(language)
        self.policy = limits.get("evidence_policy") or guards.load_policy(None)
        self.untrusted = guards.Untrusted()
        self.current_step = None
        self.step_done = None
        self.run_billed = 0.0           # billed tokens (input equivalent) since launch: budget

    # -- trace -----------------------------------------------------------------------------
    def trace(self, kind: str, **data):
        with self.transcript.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": now_utc(), "step": self.current_step, "kind": kind, **data}, ensure_ascii=False, default=str) + "\n")

    # -- evidence validation ---------------------------------------------------------------
    def resolve_all(self, refs):
        if not isinstance(refs, list) or not refs:
            return None, "at least one evidence reference (refs) is required"
        resolved, missing = [], []
        for r in refs[:50]:
            x = self.db.resolve_ref(r)
            (resolved.append(x) if x else missing.append(str(r)))
        if missing:
            return None, ("references not found in the database: " + ", ".join(missing[:10]) +
                          ". Use the ref column of timeline/detections, or <_src_file>#<_src_row> of a raw table.")
        return resolved, None

    # -- tools -----------------------------------------------------------------------------
    def dispatch(self, name: str, a: dict) -> str:
        try:
            fn = getattr(self, "t_" + name)
        except AttributeError:
            return f"ERROR: unknown tool \"{name}\"."
        try:
            return fn(**{k: v for k, v in (a or {}).items() if not k.startswith("_")})
        except TypeError as e:
            return f"ERROR: invalid parameters for {name}: {e}"
        except duckdb.Error as e:
            return "SQL ERROR: " + str(e).splitlines()[0][:800]

    def t_sql_query(self, sql, max_rows=None):
        return self.db.query_text(sql, max_rows)

    def t_describe_table(self, table):
        t = table.strip()
        if not re.fullmatch(r"(raw\.)?\"?[A-Za-z0-9_]+\"?", t):
            return "ERROR: invalid table name."
        cols = self.db.query_text(f"DESCRIBE {t}", 300)
        sample = self.db.query_text(f"SELECT * FROM {t} LIMIT 3", 3)
        return cols + "\n\nSample:\n" + sample

    def t_search(self, text, start=None, end=None, artifact_like=None, limit=100):
        limit = min(int(limit or 100), 500)
        cond, params = ["(path ILIKE ? OR description ILIKE ? OR user_name ILIKE ?)"], [f"%{text}%"] * 3
        if start:
            cond.append("ts >= ?"); params.append(norm_ts(start))
        if end:
            cond.append("ts <= ?"); params.append(norm_ts(end))
        if artifact_like:
            cond.append("artifact ILIKE ?"); params.append(f"%{artifact_like}%")
        cols, rows = self.db.run("SELECT ts, artifact, ts_desc, user_name, path, description, ref FROM timeline_all WHERE "
                                 + " AND ".join(cond) + f" ORDER BY ts LIMIT {limit + 1}", params, limit + 1)
        n = self.db.run("SELECT count(*) FROM timeline_all WHERE " + " AND ".join(cond), params, 1)[1][0][0]
        return format_table(cols, rows[:limit], self.limits["max_result_chars"], footer=f"({n} occurrence(s) in total, {min(n, limit)} shown)")

    def t_timeline_window(self, start, end, contains=None, category=None, exclude_artifacts=None, limit=200):
        limit = min(int(limit or 200), 1000)
        cond, params = ["ts BETWEEN ? AND ?"], [norm_ts(start), norm_ts(end)]
        if contains:
            cond.append("(path ILIKE ? OR description ILIKE ?)"); params += [f"%{contains}%"] * 2
        if category:
            cond.append("category ILIKE ?"); params.append(f"%{category}%")
        for x in exclude_artifacts or []:
            cond.append("artifact NOT ILIKE ?"); params.append(f"%{x}%")
        where = " AND ".join(cond)
        n = self.db.run(f"SELECT count(*) FROM timeline_all WHERE {where}", params, 1)[1][0][0]
        cols, rows = self.db.run(f"SELECT ts, artifact, ts_desc, user_name, path, description, ref FROM timeline_all WHERE {where} "
                                 f"ORDER BY ts LIMIT {limit}", params, limit)
        hint = "" if n <= limit else ": too many events, narrow the window or filter (contains, category, exclude_artifacts)"
        return format_table(cols, rows, self.limits["max_result_chars"], footer=f"({n} event(s) in the window, {len(rows)} shown{hint})")

    def t_get_evidence(self, refs):
        return self.db.get_evidence_text(refs if isinstance(refs, list) else [refs])

    def t_add_finding(self, title, severity, confidence, description, refs, category="", mitre=None, analysis=""):
        if severity not in SEVERITIES:
            return f"ERROR: severity must be one of {SEVERITIES}"
        if confidence not in CONFIDENCES:
            return f"ERROR: confidence must be one of {CONFIDENCES}"
        ev, err = self.resolve_all(refs)
        if err:
            return "REFUSED: " + err
        f = {"id": self.state.next_id("F", "findings"), "step": self.current_step, "title": title, "severity": severity,
             "confidence_declared": confidence, "category": category, "mitre": mitre or [], "description": description,
             "analysis": analysis, "evidence": ev, "created": now_utc()}
        msg = self.apply_policy(f)
        self.state.d["findings"].append(f)
        self.state.save()
        self.log(f"      + finding {f['id']} [{severity}/{f['confidence']}] {title}")
        return f"OK: finding {f['id']} recorded with {len(ev)} verified piece(s) of evidence." + msg

    def apply_policy(self, f: dict) -> str:
        """Computes the retained confidence of a finding from its evidence (guards.assess)."""
        tss = sorted(e["ts"] for e in f["evidence"] if e.get("ts") and e["ts"] != "None")
        f["first_ts"], f["last_ts"] = (tss[0], tss[-1]) if tss else (None, None)
        f["confidence"], f["confidence_notes"], f["sources"] = guards.assess(
            f["confidence_declared"], f["evidence"], self.policy, f["severity"])
        if f["confidence_notes"]:
            self.log(f"        confidence lowered to {f['confidence']}: {'; '.join(f['confidence_notes'])}")
            return (f" WARNING: confidence recorded as '{f['confidence']}' instead of '{f['confidence_declared']}': "
                    + "; ".join(f["confidence_notes"]) + ". Add corroborating evidence with add_evidence if it exists.")
        return ""

    def t_add_evidence(self, finding_id, refs):
        f = next((x for x in self.state.d["findings"] if x["id"] == str(finding_id).strip()), None)
        if not f:
            return f"ERROR: unknown finding {finding_id}."
        ev, err = self.resolve_all(refs)
        if err:
            return "REFUSED: " + err
        known = {e["ref"] for e in f["evidence"]}
        added = [e for e in ev if e["ref"] not in known]
        f["evidence"] += added
        f.setdefault("confidence_declared", f.get("confidence"))
        msg = self.apply_policy(f)
        self.state.save()
        return f"OK: {len(added)} reference(s) added to {f['id']}, confidence {f['confidence']}." + msg

    def t_add_timeline_event(self, ts, title, description, refs, phase="", mitre=None):
        ev, err = self.resolve_all(refs)
        if err:
            return "REFUSED: " + err
        e = {"id": self.state.next_id("T", "timeline_events"), "step": self.current_step, "ts": norm_ts(ts), "title": title,
             "phase": phase, "mitre": mitre or [], "description": description, "evidence": ev}
        self.state.d["timeline_events"].append(e)
        self.state.save()
        return f"OK: event {e['id']} added to the timeline."

    def t_add_ioc(self, type, value, context, refs):
        ev, err = self.resolve_all(refs)
        if err:
            return "REFUSED: " + err
        key = (type.lower(), value.strip().lower())
        for i in self.state.d["iocs"]:
            if (i["type"].lower(), i["value"].strip().lower()) == key:
                i["evidence"] += [x for x in ev if x["ref"] not in {y["ref"] for y in i["evidence"]}]
                i["context"] = i["context"] if context in i["context"] else i["context"] + "; " + context
                self.state.save()
                return f"OK: IOC {i['id']} already known, evidence merged."
        tss = sorted(x["ts"] for x in ev if x.get("ts") and x["ts"] != "None")
        i = {"id": self.state.next_id("I", "iocs"), "type": type, "value": value.strip(), "context": context, "evidence": ev,
             "first_seen": tss[0] if tss else None, "last_seen": tss[-1] if tss else None, "step": self.current_step}
        self.state.d["iocs"].append(i)
        self.state.save()
        return f"OK: IOC {i['id']} recorded."

    def t_answer_question(self, question, answer, confidence, refs=None):
        if confidence not in CONFIDENCES + [UNDETERMINED]:
            return f"ERROR: confidence must be one of {CONFIDENCES + [UNDETERMINED]}"
        ev = []
        if refs or confidence != UNDETERMINED:
            ev, err = self.resolve_all(refs)
            if err:
                return ("REFUSED: " + err + (f". An answer with confidence '{confidence}' must cite its evidence; "
                                             f"use '{UNDETERMINED}' if the database does not allow to answer."))
        retained, notes, sources = (guards.assess(confidence, ev, self.policy) if confidence != UNDETERMINED
                                    else (confidence, [], []))
        self.state.d["answers"] = [x for x in self.state.d["answers"] if x["question"] != question]
        self.state.d["answers"].append({"question": question, "answer": answer, "confidence": retained,
                                        "confidence_declared": confidence, "confidence_notes": notes, "sources": sources,
                                        "evidence": ev, "step": self.current_step, "created": now_utc()})
        self.state.save()
        return "OK: answer recorded." + (f" WARNING: confidence recorded as '{retained}': {'; '.join(notes)}." if notes else "")

    def t_set_summary(self, executive_summary, technical_summary, limitations, verdict=""):
        self.state.d["summary"] = {"executive_summary": executive_summary, "technical_summary": technical_summary,
                                   "limitations": limitations, "verdict": verdict}
        self.state.save()
        return "OK: summary recorded."

    def t_set_recommendations(self, **kw):
        self.state.d["recommendations"] = {k: v for k, v in kw.items() if isinstance(v, list)}
        self.state.save()
        return "OK: recommendations recorded."

    def t_note(self, text):
        self.state.d["notes"].append({"step": self.current_step, "text": text, "ts": now_utc()})
        self.state.save()
        return "OK"

    def t_step_complete(self, summary, gaps=""):
        self.step_done = {"summary": summary, "gaps": gaps}
        return "OK: step completed."

    # -- deterministic sweep of the guidance IOCs ----------------------------------------------
    def ioc_sweep(self):
        iocs = self.guidance["iocs"]
        if not iocs:
            return None
        self.log(f"Sweeping {len(iocs)} IOC(s) across the whole database")
        results = []
        for ioc in iocs:
            v = ioc["value"]
            hits = []
            n_tl = self.db.run("SELECT count(*) FROM timeline_all WHERE path ILIKE ? OR description ILIKE ?", [f"%{v}%"] * 2, 1)[1][0][0]
            sample = self.db.run("SELECT ts, artifact, ref FROM timeline_all WHERE path ILIKE ? OR description ILIKE ? ORDER BY ts LIMIT 15",
                                 [f"%{v}%"] * 2, 15)[1]
            for t in sorted(self.db.raw_tables):
                cols = [r[0] for r in self.db.run(f'DESCRIBE raw."{t}"', max_rows=500)[1] if not r[0].startswith("_")]
                if not cols:
                    continue
                cond = " OR ".join(f'"{c}" ILIKE ?' for c in cols)
                try:
                    c = self.db.run(f'SELECT count(*) FROM raw."{t}" WHERE {cond}', [f"%{v}%"] * len(cols), 1)[1][0][0]
                    if c:
                        refs = [r[0] for r in self.db.run(f"SELECT _src_file || '#' || _src_row FROM raw.\"{t}\" WHERE {cond} LIMIT 5",
                                                          [f"%{v}%"] * len(cols), 5)[1]]
                        hits.append({"table": f"raw.{t}", "count": c, "refs": refs})
                except duckdb.Error:
                    continue
            results.append({**ioc, "timeline_hits": n_tl, "timeline_sample": [[str(a), b, c] for a, b, c in sample], "raw_hits": hits})
            self.log(f"  {ioc['type']} = {v}: {n_tl} timeline event(s), {sum(h['count'] for h in hits)} raw row(s)")
        self.state.d["ioc_sweep"] = {"date": now_utc(), "results": results}
        self.state.save()
        return results

    def ioc_sweep_text(self) -> str:
        sw = self.state.d.get("ioc_sweep")
        if not sw:
            return ""
        lines = ["Result of the automatic sweep of the provided IOCs (to exploit and verify):"]
        for r in sw["results"]:
            lines.append(f"- {r['type']} = {r['value']}: {r['timeline_hits']} event(s) in the timeline; raw tables: "
                         + (", ".join(f"{h['table']} ({h['count']}, e.g. {', '.join(h['refs'][:3])})" for h in r["raw_hits"]) or "none"))
            for ts, art, ref in r["timeline_sample"][:8]:
                lines.append(f"    {ts} {art} {ref}")
        return "\n".join(lines)

    # -- prompts ---------------------------------------------------------------------------
    def system_prompt(self, overview: str) -> str:
        return f"""You are a senior DFIR analyst (incident response, Windows forensics). You analyze the DuckDB database of a case, built from a KAPE collection parsed by recognized tools (EZTools, Hayabusa, Chainsaw, Zircolite, Dissect, plaso, etc.).
You work only with the tools provided. Write every finding, event, answer, summary and recommendation in {self.language}, in a very technical and precise way.

{self.untrusted.policy_text()}

{guards.evidence_policy_text(self.policy)}

METHOD RULES:
{self.rules}

ANALYST GUIDANCE FOR THIS CASE:
{guidance_text(self.guidance)}

DATABASE STRUCTURE:
{overview}
"""

    def step_prompt(self, step: dict, total: int) -> str:
        sweep = self.ioc_sweep_text()
        if sweep:
            sweep = self.untrusted.wrap(sweep, "ioc_sweep")[0]
        return f"""STEP {step['num']} / {total}: {step['title']}

{step['body']}

ANALYSIS STATE (previous steps):
{self.state.compact()}

{sweep}

Instructions: explore the database with the tools, pivot, corroborate. Record each finding (add_finding), the key events (add_timeline_event) and the IOCs (add_ioc) as soon as they are established, with their references. Do not duplicate a finding already recorded: complement it with a new one if the contribution is significant. Finish with step_complete."""

    # -- step loop -------------------------------------------------------------------------
    def compact_messages(self, messages: list[dict]) -> list[dict]:
        keep = self.limits["keep_full_results"]
        tool_idx = [i for i, m in enumerate(messages) if m["role"] == "tool"]
        # Truncation in batches of 8: the beginning of the conversation only changes once every 8 results,
        # which preserves the provider cache between two calls (otherwise everything is billed again every turn)
        n_old = max(0, len(tool_idx) - keep)
        n_old -= n_old % 8
        old = set(tool_idx[:n_old])
        out = []
        for i, m in enumerate(messages):
            if i in old and len(m["content"]) > 600:
                c = m["content"][:500]
                if c.startswith(self.untrusted.open[:-1]):      # keep the block closed
                    c += "…\n" + self.untrusted.close
                out.append({**m, "content": c + "\n[… old result truncated to save context: run the query again if needed]"})
            else:
                out.append(m)
        return out

    def run_conversation(self, system: str, first_user: str, label: str, final_tool: str = "step_complete"):
        messages = [{"role": "user", "content": first_user}]
        calls, nudges, forced = 0, 0, False
        usage = {"input_tokens": 0, "output_tokens": 0, "calls": 0, "cache_read_tokens": 0, "cache_write_tokens": 0}
        self.step_done = None
        t0 = time.time()
        while True:
            try:
                rep = self.provider.chat(system, self.compact_messages(messages), TOOLS)
            except LLMError as e:
                self.trace("error", error=str(e))
                raise
            delta = {"input_tokens": rep.input_tokens, "output_tokens": rep.output_tokens, "calls": 1,
                     "cache_read_tokens": rep.cache_read_tokens, "cache_write_tokens": rep.cache_write_tokens}
            for k, v in delta.items():          # immediate accumulation: nothing lost if the step is interrupted
                usage[k] += v
                self.state.d["usage"][k] = self.state.d["usage"].get(k, 0) + v
            self.run_billed += rep.billed_input() + 5 * rep.output_tokens     # output ~5x the input price
            self.trace("assistant", text=rep.text, tool_calls=rep.tool_calls,
                       usage=[rep.input_tokens, rep.output_tokens, rep.cache_read_tokens, rep.cache_write_tokens],
                       stop=rep.stop_reason)
            budget = self.limits.get("max_billed_tokens_per_run") or 0
            if budget and self.run_billed > budget:
                self.state.save()
                raise LLMError(f"run budget reached ({num(self.run_billed)} input-equivalent tokens > "
                               f"limits.max_billed_tokens_per_run = {num(budget)}): run again to continue, or raise the limit")
            messages.append({"role": "assistant", "content": rep.text, "tool_calls": rep.tool_calls})
            if not rep.tool_calls:
                nudges += 1
                if nudges > 3:
                    self.log(f"    the model no longer answers with tool calls: end of {label}")
                    if rep.text and final_tool == "step_complete":
                        self.step_done = {"summary": rep.text, "gaps": "step ended without step_complete"}
                    break
                messages.append({"role": "user", "content": f"Continue with the tools. Finish with {final_tool}."})
                continue
            for tc in rep.tool_calls:
                calls += 1
                if tc["name"] != "step_complete":
                    self.log(f"    [{calls:>2}] {tc['name']} {self.short_args(tc)}")
                result = self.dispatch(tc["name"], tc.get("args") or {})
                if result.startswith(("REFUSED", "ERROR", "SQL ERROR")):
                    self.log(f"         -> {result[:160]}")
                elif tc["name"] in DATA_TOOLS:
                    result = self.guard_result(tc, result)
                self.trace("tool", name=tc["name"], args=tc.get("args"), result=result[:20000])
                messages.append({"role": "tool", "tool_call_id": tc["id"], "name": tc["name"], "content": result})
            if self.step_done is not None:
                break
            if calls >= self.limits["max_tool_calls_per_step"]:
                if forced:
                    self.step_done = {"summary": "(call limit reached)", "gaps": "tool call limit reached"}
                    break
                forced = True
                messages.append({"role": "user", "content": "Tool call limit reached for this step: record what is established "
                                                            f"then call {final_tool} immediately."})
        return usage, calls, time.time() - t0

    def guard_result(self, tc: dict, result: str) -> str:
        """Encloses case data in an untrusted block; text addressed to an AI is flagged and kept for the report."""
        wrapped, hits = self.untrusted.wrap(result, tc["name"])
        if hits:
            alerts = self.state.d.setdefault("injection_alerts", [])
            known = {a.get("match", "").lower() for a in alerts}
            for h in hits:
                if h["match"].lower() not in known:
                    known.add(h["match"].lower())
                    alerts.append({"step": self.current_step, "tool": tc["name"], "query": self.short_args(tc),
                                   "match": h["match"][:200], "excerpt": h["excerpt"][:400],
                                   "refs": re.findall(r"[\w./-]+#\d+", h["excerpt"])[:5], "ts": now_utc()})
                    self.log(f"         [!] text addressed to an AI found in the evidence: {h['excerpt'][:120]}")
            self.trace("injection_alert", name=tc["name"], hits=hits)
            self.state.save()
        return wrapped

    @staticmethod
    def short_args(tc) -> str:
        a = tc.get("args") or {}
        s = a.get("sql") or a.get("text") or a.get("title") or a.get("table") or (f"{a.get('start')} → {a.get('end')}" if a.get("start") else "") \
            or ", ".join(a.get("refs", [])[:3]) or a.get("value") or a.get("question") or ""
        s = re.sub(r"\s+", " ", str(s))
        return s[:110] + ("…" if len(s) > 110 else "")


# ------------------------------------------------------------------------------------------
# Exports
# ------------------------------------------------------------------------------------------
def export_csv(case: Path, out: Path, state: State, db: CaseDB, guidance: dict, log: Log):
    with (out / "iocs.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["id", "type", "value", "context", "first seen (UTC)", "last seen (UTC)", "references"])
        for i in state.d["iocs"]:
            w.writerow([i["id"], i["type"], i["value"], i["context"], i.get("first_seen"), i.get("last_seen"),
                        " ".join(e["ref"] for e in i["evidence"])])
    with (out / "key_timeline.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["timestamp (UTC)", "id", "event", "phase", "MITRE", "description", "references", "original evidence"])
        for e in sorted(state.d["timeline_events"], key=lambda e: e["ts"] or ""):
            w.writerow([e["ts"], e["id"], e["title"], e.get("phase"), " ".join(e.get("mitre", [])), e["description"],
                        " ".join(x["ref"] for x in e["evidence"]), " | ".join(sorted({str(x.get("evidence")) for x in e["evidence"]}))])
    # Complete timeline of the incident window (period of the guidance, otherwise key events ± 1 h)
    start, end = guidance["period"].get("start"), guidance["period"].get("end")
    keys = sorted(e["ts"] for e in state.d["timeline_events"] if e.get("ts"))
    if not (start and end) and keys:
        s = dt.datetime.fromisoformat(keys[0][:19]) - dt.timedelta(hours=1)
        e = dt.datetime.fromisoformat(keys[-1][:19]) + dt.timedelta(hours=1)
        start, end = start or s.isoformat(sep=" "), end or e.isoformat(sep=" ")
    state.d["incident_window"] = {"start": start, "end": end}
    if start and end:
        cols, rows = db.run("SELECT ts, ts_desc, artifact, tool, user_name, path, description, evidence, ref, mapping FROM timeline_all "
                            "WHERE ts BETWEEN ? AND ? ORDER BY ts LIMIT 500000", [norm_ts(start), norm_ts(end)], 500000)
        with (out / "incident_timeline.csv").open("w", encoding="utf-8-sig", newline="") as fh:
            w = csv.writer(fh, delimiter=";")
            w.writerow(cols)
            w.writerows(rows)
        state.d["incident_window"]["rows"] = len(rows)
        state.d["incident_window"]["truncated"] = len(rows) >= 500000
        log(f"incident_timeline.csv: {num(len(rows))} events ({start} → {end})"
            + (": TRUNCATED to 500,000 rows (set [PERIOD] in guidance.txt)" if len(rows) >= 500000 else ""))


# ------------------------------------------------------------------------------------------
# Main program
# ------------------------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("case", type=Path)
    ap.add_argument("--profile", help="profile of llm_config.json (default: 'active')")
    ap.add_argument("--config", type=Path, default=CONFIG)
    ap.add_argument("--playbook", type=Path, default=PLAYBOOK)
    ap.add_argument("--steps", help="steps to run, e.g. 1,2,5-7 (default: all)")
    ap.add_argument("--force", action="store_true", help="replay steps already done")
    ap.add_argument("--reset", action="store_true", help="start from scratch (findings.json archived)")
    ap.add_argument("--ask", help="one-off question (answer added to the report)")
    ap.add_argument("--report-only", action="store_true", help="regenerate the report without calling the model")
    ap.add_argument("--no-report", action="store_true")
    args = ap.parse_args(argv)

    log = Log()
    case = args.case.resolve()
    db_path = case / "db" / "case.duckdb"
    if not db_path.exists():
        ap.error(f"{db_path} not found: run normalize.py first")
    out = case / "analysis"
    out.mkdir(exist_ok=True)
    guidance_path = out / "guidance.txt"
    if not guidance_path.exists() and GUIDANCE_TEMPLATE.exists():
        shutil.copy2(GUIDANCE_TEMPLATE, guidance_path)
        log(f"Guidance file created: {guidance_path} (to complete if needed: questions, IOCs, context)")
    guidance = parse_guidance(guidance_path)
    state_path = out / "findings.json"
    if args.reset and state_path.exists():
        state_path.rename(out / f"findings_{dt.datetime.now():%Y%m%d_%H%M%S}.json")
    state = State(state_path)
    profile_name, pcfg, limits = load_config(args.config, args.profile)
    db = CaseDB(db_path, limits)
    rules, steps = parse_playbook(args.playbook)

    if not args.report_only:
        provider = make_provider(pcfg)
        if pcfg.get("api_key_env") and not provider.api_key():
            env = pcfg["api_key_env"]
            log(f"API key missing for profile \"{profile_name}\": fill in the line \"{env} = ...\" in "
                f"<repository>\\pipeline\\config\\api_keys.txt, then redeploy "
                f"(.\\install\\02_Install-Tools.ps1 -Only Pipeline). File read: {KEYS_FILE}")
            return 2
        log(f"Case: {case}")
        log(f"Model: {provider.describe()} (profile {profile_name}) ; report language: {language_name(pcfg['_report_language'])}")
        if pcfg.get("provider") != "mock" and not pcfg.get("base_url", "").startswith(("http://localhost", "http://127.0.0.1")):
            log("Warning: the data queried by the model is sent to its API (external provider).")
        run = {"started": now_utc(), "profile": profile_name, "provider": pcfg.get("provider"), "model": pcfg.get("model"),
               "playbook_sha256": hashlib.sha256(args.playbook.read_bytes()).hexdigest(),
               "guidance_sha256": hashlib.sha256(guidance_path.read_bytes()).hexdigest() if guidance_path.exists() else None}
        agent = Agent(case, db, state, provider, limits, guidance, rules, log, out / "transcript.jsonl",
                      language=pcfg["_report_language"])
        overview = db.overview()
        system = agent.system_prompt(overview)
        try:
            if args.ask:
                agent.current_step = "question"
                log(f"Question: {args.ask}")
                prompt = (f"ANALYST QUESTION: {args.ask}\n\nANALYSIS STATE:\n{state.compact()}\n\n"
                          "Answer based on the database: explore, then record the answer with answer_question (with refs), "
                          "add new findings/IOCs if needed, then call step_complete.")
                u, n, d = agent.run_conversation(system, prompt, "the question")
                ans = next((a for a in reversed(state.d["answers"]) if a["question"] == args.ask), None)
                print("\n" + "=" * 80 + "\nANSWER:\n" + (ans["answer"] if ans else (agent.step_done or {}).get("summary", "(no answer)")) + "\n" + "=" * 80)
            else:
                if guidance["iocs"] and (args.force or not state.d.get("ioc_sweep")):
                    agent.ioc_sweep()
                sel = select_steps(args.steps, steps)
                todo = [s for s in steps if s["num"] in sel and (args.force or state.d["steps"].get(str(s["num"]), {}).get("status") != DONE)]
                durations = []
                for k, step in enumerate(todo, 1):
                    agent.current_step = step["num"]
                    eta = (f"; ~{fmt_duration(sum(durations) / len(durations) * (len(todo) - k + 1))} left" if durations else "")
                    log(f"Step {step['num']}/{len(steps)}: {step['title']}  [{k}/{len(todo)}{eta}]")
                    purged = state.purge_step(step["num"])
                    if purged:
                        log(f"  {purged} item(s) from a previous run of this step removed (replay)")
                    st = state.d["steps"][str(step["num"])] = {}
                    st.update(title=step["title"], status=RUNNING, started=now_utc())
                    state.save()
                    nf = len(state.d["findings"])
                    u, n, d = agent.run_conversation(system, agent.step_prompt(step, len(steps)), f"step {step['num']}")
                    durations.append(d)
                    st.update(status=DONE, ended=now_utc(), duration_s=round(d, 1), tool_calls=n, usage=u,
                              summary=(agent.step_done or {}).get("summary", ""), gaps=(agent.step_done or {}).get("gaps", ""))
                    state.save()
                    log(f"  done in {fmt_duration(d)}: {n} tool calls, {len(state.d['findings']) - nf} finding(s), "
                        f"tokens {num(u['input_tokens'])} in / {num(u['output_tokens'])} out")
        except LLMError as e:
            log(f"MODEL ERROR: {e}")
            log("The state is saved: run the same command again to resume at the unfinished steps.")
            state.save()
            return 2
        except KeyboardInterrupt:
            log("Interrupted: the state is saved, run again to resume.")
            state.save()
            return 130
        run.update(ended=now_utc(), usage=dict(state.d["usage"]))
        state.d["runs"].append(run)
        state.save()
        tu = state.d["usage"]
        log(f"Total tokens: {num(tu['input_tokens'])} in (of which {num(tu.get('cache_read_tokens'))} read from cache) / "
            f"{num(tu['output_tokens'])} out, {tu['calls']} model calls")

    if args.no_report:
        return 0
    export_csv(case, out, state, db, guidance, log)
    state.save()
    from report_docx import build_report
    path = build_report(case, out, state.d, db, guidance, steps, pcfg, log)
    log(f"Report: {path}")
    return 0


def select_steps(spec: str | None, steps: list[dict]) -> set[int]:
    if not spec:
        return {s["num"] for s in steps}
    sel = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            sel |= set(range(int(a), int(b) + 1))
        elif part:
            sel.add(int(part))
    return sel


if __name__ == "__main__":
    sys.exit(main())
