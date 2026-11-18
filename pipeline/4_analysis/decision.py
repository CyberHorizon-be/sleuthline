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


# ------------------------------------------------------------------------------------------
# Hypotheses and counter-evidence (2.0c)
# ------------------------------------------------------------------------------------------
RELATIONS = ("supports", "contradicts", "context")
CONF_ORDER = {"confirmed": 3, "probable": 2, "possible": 1}


class Hypotheses:
    """Hypotheses of the analysis state (state.d['hypotheses']): statements about the attack, linked to findings."""

    def __init__(self, state):
        self.state = state
        self.d = state.d
        self.d.setdefault("hypotheses", [])

    @property
    def all(self) -> list[dict]:
        return self.d["hypotheses"]

    def get(self, hid: str) -> dict | None:
        return next((h for h in self.all if h["id"] == str(hid).strip()), None)

    def next_id(self) -> str:
        nums = [int(m.group(1)) for h in self.all if (m := re.match(r"H-(\d+)$", h["id"]))]
        return f"H-{max(nums, default=0) + 1:03d}"

    def add(self, statement: str, tactic: str, step, now: str) -> tuple[dict, bool]:
        key = norm_question(statement)
        for h in self.all:
            if norm_question(h["statement"]) == key:
                return h, False
        h = {"id": self.next_id(), "statement": str(statement).strip(), "tactic": str(tactic or "").strip(),
             "links": [], "step": step, "created": now, "status": "open", "confidence": "possible", "reasons": []}
        self.all.append(h)
        return h, True

    @staticmethod
    def link(h: dict, finding_id: str, relation: str, note: str = "") -> bool:
        for x in h["links"]:
            if x["finding"] == finding_id and x["relation"] == relation:
                return False
        h["links"].append({"finding": finding_id, "relation": relation, "note": str(note or "").strip()})
        return True


def evaluate_hypothesis(h: dict, findings: dict, leads: dict, policy: dict, independent_sources) -> dict:
    """Status and retained confidence of a hypothesis, enforced by the program (like the evidence policy):
      refuted    : a contradicting finding is confirmed;
      contested  : its challenge task established a contradiction not (yet) confirmed by a finding;
      open       : no supporting finding;
      supported  : confirmed only with >= min_independent_sources independent sources among the supporting findings,
                   no unresolved contradiction, and - when a supporting finding is critical / high - its challenge task
                   run without finding a contradiction (outcome refuted); probable otherwise."""
    sup = [findings[x["finding"]] for x in h["links"] if x["relation"] == "supports" and x["finding"] in findings]
    con = [findings[x["finding"]] for x in h["links"] if x["relation"] == "contradicts" and x["finding"] in findings]
    ch = leads.get(h.get("challenge_lead") or "")
    sources = independent_sources([e for f in sup for e in f.get("evidence", [])])
    needs_challenge = any(f.get("severity") in policy.get("corroboration_severities", []) for f in sup)
    reasons = []
    hosts = sorted({x for f in sup for x in (f.get("hosts") or [])})
    tss = sorted(t for f in sup for t in (f.get("first_ts"), f.get("last_ts")) if t)
    if any(f.get("confidence") == "confirmed" for f in con):
        status, conf = "refuted", "confirmed"
        reasons.append("contradicted by confirmed finding(s) " + ", ".join(f["id"] for f in con if f.get("confidence") == "confirmed"))
    elif ch and ch.get("status") == "done" and ch.get("outcome") == "confirmed":
        status, conf = "contested", "possible"
        reasons.append(f"its challenge task {ch['id']} established a contradiction: {str(ch.get('summary') or '')[:300]}")
    elif not sup:
        status, conf = "open", "possible"
        reasons.append("no supporting finding")
    else:
        status = "supported"
        ok_sources = len(sources) >= int(policy.get("min_independent_sources", 2))
        unresolved = [f["id"] for f in con]
        challenged = (not needs_challenge) or (ch is not None and ch.get("status") == "done" and ch.get("outcome") == "refuted")
        if ok_sources and not unresolved and challenged:
            conf = "confirmed"
        else:
            conf = "probable"
            if not ok_sources:
                reasons.append(f"{len(sources)} independent source(s) among the supporting findings "
                               f"({policy.get('min_independent_sources', 2)} required)")
            if unresolved:
                reasons.append("unresolved contradicting finding(s) " + ", ".join(unresolved))
            if not challenged:
                reasons.append("challenge " + (f"{ch['id']} {ch.get('outcome') or ch.get('status')}" if ch else "not run")
                               + " (a contradiction search with outcome refuted is required)")
    h.update(status=status, confidence=conf, reasons=reasons, sources=sources, hosts=hosts,
             first_ts=tss[0] if tss else None, last_ts=tss[-1] if tss else None)
    return h


def challenge_question(h: dict) -> str:
    return (f"CHALLENGE of {h['id']}: \"{h['statement']}\". What would contradict it: another explanation, a legitimate use "
            "(administrator, software update, backup, the responder's own tools), the same activity before the incident "
            "window, another source host or account, a clock offset that reverses the order of events? Look for it in the "
            "data. Outcome: confirmed = a contradiction IS established (record it as a finding and link it with "
            "link_hypothesis, relation contradicts); refuted = you looked for it and there is none (say what you checked); "
            "inconclusive = the data cannot tell.")
