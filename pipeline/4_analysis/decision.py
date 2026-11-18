"""
Sleuthline 2.0b - decision graph: leads, decision rules and the queue of investigation tasks.

After the triage steps of the playbook, the analysis is driven by leads:
  - the agent opens leads with add_lead (a question worth a deeper look, with its seeds);
  - the program opens leads with the decision rules (config\\decision_rules.json) from what was recorded
    (findings, IOCs) and from the data itself (timeline patterns);
  - the scheduler runs each lead as a focused task (a short conversation of the agent), highest priority
    first, within bounds (depth, number of tasks, run budget); a task can open new leads.
A bound never drops a lead silently: the leads not investigated keep their reason and are listed in the report.

State in findings.json:  leads = [{id, question, reason, priority, source, origin, host, depth, refs, entities,
                                    status (open / done / not_investigated / duplicate), outcome, summary, task_key, ...}]
                         rule_hits = ["<rule id>|<origin>", ...]   (a rule fires once per origin)
"""
from __future__ import annotations

import json
import re
from pathlib import Path

PRIORITY = {"high": 3, "medium": 2, "low": 1}
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
OUTCOMES = ("confirmed", "refuted", "inconclusive")
DEFAULT_BOUNDS = {"max_tasks": 30, "max_lead_depth": 3, "max_tool_calls_per_task": 15, "max_tool_calls_per_triage_step": 30}


def load_rules(path: Path) -> list[dict]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    rules = []
    for r in data.get("rules", []):
        if r.get("kind") not in ("finding", "timeline", "ioc") or not r.get("id") or not r.get("question"):
            raise SystemExit(f"{path}: invalid rule {r.get('id')!r} (id, kind = finding / timeline / ioc, question)")
        for rx in r.get("regex_all", []) + ([r["regex"]] if r.get("regex") else []):
            try:
                re.compile(rx)
            except re.error as e:
                raise SystemExit(f"{path}: rule {r['id']}: invalid regular expression ({e})")
        rules.append(r)
    return rules


def norm_question(q: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(q).lower()).strip()


def fill(template: str, **kw) -> str:
    out = template
    for k, v in kw.items():
        out = out.replace("{" + k + "}", str(v))
    return out


class Leads:
    """Leads of the analysis state (state.d['leads'])."""

    def __init__(self, state):
        self.state = state
        self.d = state.d
        self.d.setdefault("leads", [])
        self.d.setdefault("rule_hits", [])

    @property
    def all(self) -> list[dict]:
        return self.d["leads"]

    def next_id(self) -> str:
        nums = [int(m.group(1)) for x in self.all if (m := re.match(r"L-(\d+)$", str(x.get("id", ""))))]
        return f"L-{max(nums, default=0) + 1:03d}"

    def add(self, question: str, reason: str, priority: str, source: str, origin: str | None, depth: int,
            refs=None, entities=None, host: str | None = None, now: str | None = None) -> tuple[dict, bool]:
        """(lead, created). A lead with the same question (normalized) as an open or investigated one is a duplicate."""
        key = norm_question(question)
        for x in self.all:
            if norm_question(x["question"]) == key and x["status"] != "duplicate":
                return x, False
        lead = {"id": self.next_id(), "question": str(question).strip(), "reason": str(reason or "").strip(),
                "priority": priority if priority in PRIORITY else "medium", "source": source, "origin": origin,
                "host": host or None, "depth": int(depth), "refs": list(refs or [])[:20], "entities": list(entities or [])[:10],
                "status": "open", "created": now}
        self.all.append(lead)
        return lead, True

    def open(self) -> list[dict]:
        return [x for x in self.all if x["status"] == "open"]

    def order_key(self, lead: dict, findings: dict) -> tuple:
        sev = SEV_RANK.get((findings.get(lead.get("origin")) or {}).get("severity"), 0)
        return (-PRIORITY.get(lead["priority"], 2), -sev, lead["depth"], lead["id"])


# ------------------------------------------------------------------------------------------
# Decision rules
# ------------------------------------------------------------------------------------------
def finding_text(f: dict) -> str:
    return " | ".join(str(x) for x in (f.get("title"), f.get("description"), f.get("analysis"), f.get("category"),
                                         " ".join(f.get("mitre") or [])) if x)


def evaluate_rules(rules: list[dict], state, db, leads: Leads, depth: int, now: str, data_rules: bool = False,
                   log=print) -> list[dict]:
    """Opens the leads of the rules that fire. Finding / IOC rules: on findings and IOCs not yet evaluated by the
    rule. Timeline rules (data_rules=True, once after the triage): on the whole database."""
    created = []
    hits = set(state.d["rule_hits"])
    cited = {e["ref"] for f in state.d["findings"] for e in f.get("evidence", [])}
    for r in rules:
        prio = r.get("priority", "medium")
        if r["kind"] == "finding":
            min_sev = SEV_RANK.get(r.get("min_severity", "low"), 1)
            for f in state.d["findings"]:
                key = f"{r['id']}|{f['id']}"
                if key in hits or SEV_RANK.get(f.get("severity"), 0) < min_sev:
                    continue
                text = finding_text(f)
                if all(re.search(rx, text) for rx in r.get("regex_all", [])):
                    hits.add(key)
                    hosts = f.get("hosts") or []
                    lead, new = leads.add(
                        fill(r["question"], finding_id=f["id"], finding_title=f["title"], hosts=", ".join(hosts) or "?"),
                        f"rule {r['id']} on {f['id']}", prio, f"rule:{r['id']}", f["id"], depth,
                        refs=[e["ref"] for e in f.get("evidence", [])][:8],
                        host=hosts[0] if len(hosts) == 1 else None, now=now)
                    if new:
                        created.append(lead)
        elif r["kind"] == "ioc":
            if not db.has_table("entity_refs"):
                continue
            types = {t.lower() for t in r.get("types", [])}
            for i in state.d["iocs"]:
                key = f"{r['id']}|{i['id']}"
                if i["type"].lower() not in types or key in hits:
                    continue
                refs = [x[0] for x in db.run(
                    "SELECT DISTINCT r.ref FROM entity_refs r JOIN entities e ON e.entity_id = r.entity_id "
                    "WHERE NOT e.common AND (e.norm = lower(?) OR e.value = ?) LIMIT 500", [i["value"], i["value"]], 500)[1]]
                extra = [x for x in refs if x not in cited]
                if not extra:
                    continue
                hits.add(key)
                hosts = sorted({x.split(":", 1)[0] for x in extra if ":" in x.split("/")[0]}) if db.multi else []
                lead, new = leads.add(
                    fill(r["question"], ioc_type=i["type"], ioc_value=i["value"], extra=len(extra), hosts=", ".join(hosts) or "-"),
                    f"rule {r['id']} on {i['id']}", prio, f"rule:{r['id']}", i["id"], depth, refs=extra[:10], now=now)
                if new:
                    created.append(lead)
        elif r["kind"] == "timeline" and data_rules:
            key = f"{r['id']}|data"
            if key in hits:
                continue
            hits.add(key)                      # evaluated once, fired or not
            cols, rows = db.run("SELECT ref FROM timeline_all WHERE description IS NOT NULL AND regexp_matches(description, ?) "
                                "ORDER BY ts LIMIT 500", [r["regex"]], 500)
            refs = [x[0] for x in rows]
            if len(refs) < int(r.get("min_count", 1)) or all(x in cited for x in refs):
                continue
            lead, new = leads.add(fill(r["question"], count=f"{len(refs)}{'+' if len(refs) >= 500 else ''}",
                                       sample_refs=", ".join(refs[:4])),
                                  f"rule {r['id']} on the data", prio, f"rule:{r['id']}", None, depth, refs=refs[:10], now=now)
            if new:
                created.append(lead)
    state.d["rule_hits"] = sorted(hits)
    for x in created:
        log(f"  + lead {x['id']} [{x['priority']}] ({x['source']}) {x['question'][:110]}")
    return created
