#!/usr/bin/env python3
"""
Sleuthline - case database of a multi-host case (1.2).

A multi-host case has one folder per host in <case>\\hosts\\, each processed like a single-host case
(inventory, parsing, normalization into hosts\\<host>\\db\\case.duckdb, with the time zone of that
host), and optionally captures of the whole case in <case>\\pcap\\ (normalized into
<case>\\db\\network.duckdb). This script merges them into <case>\\db\\case.duckdb, the database
used by the analysis and the report. No tool output is read again.

  - common tables (timeline, detections, hash_hits, sources, jobs, coverage, conservation): union of
    the hosts with a host_id column; references become <host>:<output>#<record>;
  - raw tables: one schema per host (raw_<host>.<table>, _src_file prefixed the same way) and a view
    raw.<table> = union of the hosts, with a _host column;
  - meta: the hosts (real name, sources, time zone, integrity, SHA-256 of their database);
  - conservation: rows of every host table = rows of the case table for that host (check host_to_case).

  python merge.py C:\\Sleuthline\\cases\\case01
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path

import duckdb

VERSION = "1.0"
NETWORK_UNIT = "network"           # host id of the case-level captures (<case>\pcap\)
HOST_RX = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")
COMMON = ["timeline", "detections", "hash_hits", "sources", "jobs", "coverage", "conservation"]   # entities: rebuilt


def q(ident: str) -> str:
    return '"' + str(ident).replace('"', '""') + '"'


def lit(value) -> str:
    return "NULL" if value is None else "'" + str(value).replace("'", "''") + "'"


def slug(host: str) -> str:
    return re.sub(r"[^a-z0-9_]", "_", host.lower())


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def host_dirs(case: Path) -> list[Path]:
    d = case / "hosts"
    return sorted(p for p in d.iterdir() if p.is_dir()) if d.is_dir() else []


def units(case: Path) -> list[tuple[str, Path]]:
    """(host id, database) of every unit of the case: each host, then the case-level captures if any."""
    out = []
    for h in host_dirs(case):
        if not HOST_RX.fullmatch(h.name):
            raise SystemExit(f"Host folder name not allowed: {h.name} (letters, digits, - and _ only)")
        if h.name.lower() == NETWORK_UNIT:
            raise SystemExit(f"\"{NETWORK_UNIT}\" is reserved for the captures of the case (<case>\\pcap\\): rename hosts\\{h.name}")
        db = h / "db" / "case.duckdb"
        if not db.exists():
            raise SystemExit(f"Database of host {h.name} not found: {db} (run normalize for this host)")
        out.append((h.name, db))
    if len({slug(u) for u, _ in out}) != len(out):
        raise SystemExit("Two host folders differ only by case or punctuation: rename one of them")
    net = case / "db" / "network.duckdb"
    if net.exists():
        out.append((NETWORK_UNIT, net))
    return out


class Merger:
    def __init__(self, case: Path, log=print):
        self.case = case
        self.log = log
        self.units = units(case)
        if not self.units:
            raise SystemExit(f"No host in {case / 'hosts'}: not a multi-host case")

    # -- helpers ---------------------------------------------------------------------------
    def tables(self, con, alias: str, schema: str) -> list[str]:
        return [r[0] for r in con.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_catalog = ? AND table_schema = ? "
            "AND table_type = 'BASE TABLE' ORDER BY 1", [alias, schema]).fetchall()]

    def columns(self, con, alias: str, schema: str, table: str) -> list[str]:
        return [r[0] for r in con.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_catalog = ? AND table_schema = ? "
            "AND table_name = ? ORDER BY ordinal_position", [alias, schema, table]).fetchall()]

    def meta(self, con, alias: str) -> dict:
        try:
            return dict(con.execute(f"SELECT key, value FROM {alias}.main.meta").fetchall())
        except duckdb.Error:
            return {}

    def real_name(self, con, alias: str) -> str | None:
        """Host name read in the artifacts: most frequent timeline host, else COMPUTERNAME of the memory image."""
        for sql in (f"SELECT host FROM {alias}.main.timeline WHERE host IS NOT NULL AND host <> '' "
                    f"GROUP BY 1 ORDER BY count(*) DESC LIMIT 1",
                    f"SELECT \"Value\" FROM {alias}.raw.vol_envars WHERE \"Variable\" = 'COMPUTERNAME' AND \"Value\" IS NOT NULL "
                    f"GROUP BY 1 ORDER BY count(*) DESC LIMIT 1"):
            try:
                r = con.execute(sql).fetchone()
                if r and r[0]:
                    return str(r[0])
            except duckdb.Error:
                continue
        return None

    # -- merge ----------------------------------------------------------------------------
    def run(self) -> Path:
        out = self.case / "db" / "case.duckdb"
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_suffix(".merging.duckdb")
        if tmp.exists():
            tmp.unlink()
        started = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        con = duckdb.connect(str(tmp))
        try:
            aliases = {}
            for u, path in self.units:
                alias = "u_" + slug(u)
                con.execute(f"ATTACH {lit(str(path))} AS {alias} (READ_ONLY)")
                aliases[u] = alias
                self.log(f"  {u}: {path}")
            checks = []
            raw_by_table: dict[str, list[str]] = {}
            # Raw tables: one schema per host, _src_file prefixed
            for u, alias in aliases.items():
                schema = "raw_" + slug(u)
                con.execute(f"CREATE SCHEMA {schema}")
                for t in self.tables(con, alias, "raw"):
                    cols = self.columns(con, alias, "raw", t)
                    sel = (f"SELECT * REPLACE ({lit(u + ':')} || _src_file AS _src_file) FROM {alias}.raw.{q(t)}"
                           if "_src_file" in cols else f"SELECT * FROM {alias}.raw.{q(t)}")
                    con.execute(f"CREATE TABLE {schema}.{q(t)} AS {sel}")
                    raw_by_table.setdefault(t, []).append(u)
                    n_in = con.execute(f"SELECT count(*) FROM {alias}.raw.{q(t)}").fetchone()[0]
                    n_out = con.execute(f"SELECT count(*) FROM {schema}.{q(t)}").fetchone()[0]
                    checks.append((u, f"raw.{t}", n_in, n_out))
            con.execute("CREATE SCHEMA raw")
            for t, us in sorted(raw_by_table.items()):
                parts = [f"SELECT {lit(u)} AS _host, * FROM raw_{slug(u)}.{q(t)}" for u in us]
                con.execute(f"CREATE VIEW raw.{q(t)} AS " + " UNION ALL BY NAME ".join(parts))
            # Common tables
            for t in COMMON:
                parts = []
                for u, alias in aliases.items():
                    if t not in self.tables(con, alias, "main"):
                        continue
                    cols = self.columns(con, alias, "main", t)
                    rep = []
                    for c in ("src_file", "ref"):
                        if c in cols:
                            rep.append(f"{lit(u + ':')} || {q(c)} AS {q(c)}")
                    if t == "sources" and "raw_table" in cols:
                        rep.append(f"CASE WHEN raw_table IS NULL THEN NULL ELSE 'raw_{slug(u)}.' || split_part(raw_table, '.', 2) END AS raw_table")
                    excl = [c for c in ("tl_id", "det_id") if c in cols]
                    sel = "SELECT " + (f"* EXCLUDE ({', '.join(excl)})" if excl else "*")
                    if rep:
                        sel += " REPLACE (" + ", ".join(rep) + ")"
                    parts.append(f"{sel}, {lit(u)} AS host_id FROM {alias}.main.{q(t)}")
                    n_in = con.execute(f"SELECT count(*) FROM {alias}.main.{q(t)}").fetchone()[0]
                    checks.append((u, t, n_in, None))
                if not parts:
                    continue
                union = " UNION ALL BY NAME ".join(parts)
                if t == "timeline":
                    con.execute(f"CREATE TABLE timeline AS SELECT row_number() OVER (ORDER BY ts, src_file, src_row) AS tl_id, * "
                                f"FROM ({union}) ORDER BY ts, src_file, src_row")
                elif t == "detections":
                    con.execute(f"CREATE TABLE detections AS SELECT row_number() OVER (ORDER BY ts, src_file, src_row) AS det_id, * "
                                f"FROM ({union}) ORDER BY ts, src_file, src_row")
                else:
                    con.execute(f"CREATE TABLE {q(t)} AS {union}")
            for t, ddl in (("detections", "CREATE TABLE detections (det_id BIGINT, ts TIMESTAMP, engine VARCHAR, rule_title VARCHAR, "
                                          "rule_id VARCHAR, level VARCHAR, computer VARCHAR, channel VARCHAR, event_id VARCHAR, "
                                          "record_id VARCHAR, details VARCHAR, tactics VARCHAR, evidence VARCHAR, src_table VARCHAR, "
                                          "src_file VARCHAR, src_row BIGINT, ref VARCHAR, host_id VARCHAR)"),
                           ("conservation", "CREATE TABLE conservation (src_file VARCHAR, \"check\" VARCHAR, expected BIGINT, "
                                            "actual BIGINT, status VARCHAR, note VARCHAR, host_id VARCHAR)")):
                if not con.execute("SELECT count(*) FROM information_schema.tables WHERE table_catalog = current_database() "
                                   "AND table_schema = 'main' AND table_name = ?", [t]).fetchone()[0]:
                    con.execute(ddl)
            # hashset: the same lists are usually loaded for every host
            hs = [f"SELECT * FROM {a}.main.hashset" for a in aliases.values() if "hashset" in self.tables(con, a, "main")]
            if hs:
                con.execute("CREATE TABLE hashset AS SELECT DISTINCT * FROM (" + " UNION ALL BY NAME ".join(hs) + ")")
            # Views (same as normalize.py, with host_id)
            con.execute("""CREATE VIEW timeline_all AS
                SELECT ts, ts_desc, artifact, category, tool, host, user_name, path, description, evidence,
                       src_table, src_file, src_row, ref, mapping, host_id FROM timeline
                UNION ALL
                SELECT ts, 'Detection (' || level || ')', 'Detection ' || engine, 'detection', engine, computer, NULL,
                       NULL, rule_title || coalesce(' | ' || details, ''), evidence, src_table, src_file, src_row, ref,
                       'validated', host_id FROM detections""")
            con.execute("""CREATE VIEW artifact_summary AS
                SELECT host_id, artifact, category, tool, mapping, count(*) AS rows, min(ts) AS first_ts, max(ts) AS last_ts
                FROM timeline GROUP BY ALL ORDER BY rows DESC""")
            # Entity graph of the whole case (2.0a): one entity for the same file / hash / IP on every host
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            import entities
            entities.build(con, multi=True, log=self.log)
            # Conservation of the merge
            rows = []
            for u, t, n_in, n_out in checks:
                if n_out is None:
                    n_out = con.execute(f"SELECT count(*) FROM {q(t)} WHERE host_id = ?", [u]).fetchone()[0]
                rows.append((f"{u}:{t}", "host_to_case", n_in, n_out, "ok" if n_in == n_out else "fail",
                             "" if n_in == n_out else "rows lost or added by the merge", u))
            con.executemany("INSERT INTO conservation VALUES (?,?,?,?,?,?,?)", rows)
            fails = [r for r in rows if r[4] != "ok"]
            # Meta
            hosts, metas = [], {}
            for u, path in self.units:
                m = self.meta(con, aliases[u])
                metas[u] = m
                try:
                    src = json.loads(m.get("sources") or "")
                except ValueError:
                    src = None
                try:
                    integ = json.loads(m.get("collection_integrity") or "")
                except ValueError:
                    integ = None
                hosts.append({"id": u, "kind": "network" if u == NETWORK_UNIT else "host",
                              "name": None if u == NETWORK_UNIT else self.real_name(con, aliases[u]),
                              "sources": src, "active_time_bias_min": m.get("machine_active_time_bias_min"),
                              "collection_integrity": integ, "pipeline_version": m.get("pipeline_version"),
                              "normalized_at_utc": m.get("normalized_at_utc"), "database": str(path), "db_sha256": sha256(path),
                              "timeline_rows": con.execute("SELECT count(*) FROM timeline WHERE host_id = ?", [u]).fetchone()[0]})
            combined = {"disk": {"present": False, "files": 0}, "memory": {"present": False, "images": []},
                        "network": {"present": False, "captures": []}}
            for h in hosts:
                s = h["sources"] or {}
                for k in combined:
                    v = s.get(k) or {}
                    if v.get("present"):
                        combined[k]["present"] = True
                        if k == "disk":
                            combined[k]["files"] += int(v.get("files") or 0)
                        elif k == "memory":
                            combined[k]["images"] += v.get("images") or []
                        else:
                            combined[k]["captures"] += v.get("captures") or []
            first = metas[self.units[0][0]]
            tl = con.execute("SELECT min(ts), max(ts), count(*) FROM timeline").fetchone()
            meta = {
                "multi_host": "true", "hosts": json.dumps(hosts, ensure_ascii=False),
                "sources": json.dumps(combined, ensure_ascii=False),
                "case": str(self.case), "merged_at_utc": started, "merge_version": VERSION,
                "normalized_at_utc": ", ".join(f"{h['id']}={h['normalized_at_utc']}" for h in hosts),
                "normalize_version": first.get("normalize_version"), "pipeline_version": first.get("pipeline_version"),
                "map_file": first.get("map_file"), "map_version": first.get("map_version"), "map_sha256": first.get("map_sha256"),
                "duckdb_version": duckdb.__version__,
                "timeline_min_ts": str(tl[0]), "timeline_max_ts": str(tl[1]),
                "timezone": "UTC (every timeline/detections date; local-time sources converted with the time zone of their host)",
                "machine_active_time_bias_min": ", ".join(f"{h['id']}={h['active_time_bias_min']}" for h in hosts
                                                          if h["kind"] == "host"),
                "collection_integrity": "per host: see hosts",
                "ref_format": "<host>:<output relative to the parsed folder of the host>#<record number>",
            }
            con.execute("CREATE TABLE meta (key VARCHAR, value VARCHAR)")
            con.executemany("INSERT INTO meta VALUES (?, ?)", list(meta.items()))
            con.execute("CHECKPOINT")
        finally:
            con.close()
        if out.exists():
            out.unlink()
        os.replace(tmp, out)
        self.write_report(out, hosts, rows, tl)
        self.log(f"Done: {out}  (timeline {tl[2]:,} rows, {len([h for h in hosts if h['kind'] == 'host'])} host(s)".replace(",", " ")
                 + (", case-level captures" if any(h["kind"] == "network" for h in hosts) else "") + ")")
        if fails:
            self.log(f"{len(fails)} conservation failure(s) in the merge: see {out.parent / 'merge_report.md'}")
        return out

    def write_report(self, out: Path, hosts: list[dict], rows: list, tl) -> None:
        md = ["# Merge of the hosts", "", f"- Case database: `{out}`", f"- Timeline: {tl[2]:,} rows, {tl[0]} to {tl[1]} (UTC)", "",
              "| Host | Real name | Sources | Time bias (min) | Timeline rows | Database SHA-256 |", "|---|---|---|---|---|---|"]
        for h in hosts:
            s = h["sources"] or {}
            have = ", ".join(k for k in ("disk", "memory", "network") if (s.get(k) or {}).get("present")) or "?"
            md.append(f"| {h['id']} | {h['name'] or ''} | {have} | {h['active_time_bias_min'] or ''} | {h['timeline_rows']:,} | "
                      f"`{h['db_sha256'][:16]}…` |")
        bad = [r for r in rows if r[4] != "ok"]
        md += ["", "## Conservation", "", f"{len(rows) - len(bad)} check(s) ok, {len(bad)} failure(s)."]
        md += [f"- **{r[0]}**: expected {r[2]}, got {r[3]}" for r in bad]
        (out.parent / "merge_report.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("case", type=Path, help="multi-host case folder (contains hosts\\)")
    args = ap.parse_args(argv)
    case = args.case.resolve()
    print(f"Merging the hosts of {case}")
    Merger(case).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
