#!/usr/bin/env python3
"""
Sleuthline - compares two analyses of the same evidence (findings.json): another version of the pipeline, of the
playbook or of the decision rules, another model, --classic against the decision graph, or the same run twice
(consistency). Replay = analyze <case> --reset with the other setting, then this comparison.

Findings are matched on their evidence (shared references), then on their title. The report lists the findings
lost (in A, not in B), the new ones, the severity / confidence changes, and the hypotheses, leads and model usage
of each run.

  python compare_runs.py <A\\findings.json> <B\\findings.json> [--names A B] [--out compare.md]
"""
from __future__ import annotations

import argparse
import difflib
import json
import sys
from collections import Counter
from pathlib import Path

SEV = ["critical", "high", "medium", "low", "info"]


def load(p: Path) -> dict:
    d = json.loads(p.read_text(encoding="utf-8"))
    d.setdefault("findings", [])
    return d


def refs(f: dict) -> set:
    # host prefix removed: a single-host run and the same host in a multi-host run cite the same records
    return {str(e.get("ref", "")).split(":", 1)[-1] if ":" in str(e.get("ref", "")).split("/")[0] else str(e.get("ref", ""))
            for e in f.get("evidence", [])}


def match(a: list[dict], b: list[dict]) -> list[tuple[dict, dict | None, str]]:
    """(finding of A, its match in B or None, how). Greedy, most severe findings of A first."""
    free = list(b)
    out = []
    for f in sorted(a, key=lambda x: (SEV.index(x.get("severity")) if x.get("severity") in SEV else 9, x["id"])):
        best, score, how = None, 0.0, ""
        ra = refs(f)
        for g in free:
            rb = refs(g)
            shared = len(ra & rb) / max(1, min(len(ra), len(rb))) if ra and rb else 0.0
            title = difflib.SequenceMatcher(None, f.get("title", "").lower(), g.get("title", "").lower()).ratio()
            s = shared + 0.5 * title if shared else (title if title >= 0.6 else 0.0)
            if s > score:
                best, score, how = g, s, ("evidence" if shared else "title")
        if best is not None:
            free.remove(best)
        out.append((f, best, how))
    return out


def usage(d: dict) -> str:
    u = d.get("usage") or {}
    tin = int(u.get("input_tokens", 0)) + int(u.get("cache_read_tokens", 0)) + int(u.get("cache_write_tokens", 0))
    return f"{u.get('calls', 0)} model calls, {tin:,} input tokens (cache included), {int(u.get('output_tokens', 0)):,} output tokens"


def compare(a: dict, b: dict, na: str = "A", nb: str = "B") -> str:
    pairs = match(a["findings"], b["findings"])
    matched_b = {id(g) for _, g, _ in pairs if g}
    lost = [f for f, g, _ in pairs if g is None]
    new = [g for g in b["findings"] if id(g) not in matched_b]
    changed = [(f, g) for f, g, _ in pairs if g and (f.get("severity") != g.get("severity") or f.get("confidence") != g.get("confidence"))]
    md = [f"# Comparison of two analyses: {na} vs {nb}", ""]
    md += ["| | " + na + " | " + nb + " |", "|---|---|---|"]
    for s in SEV:
        ca = sum(1 for f in a["findings"] if f.get("severity") == s)
        cb = sum(1 for f in b["findings"] if f.get("severity") == s)
        md.append(f"| {s} findings | {ca} | {cb} |")
    md.append(f"| total findings | {len(a['findings'])} | {len(b['findings'])} |")
    for k in ("timeline_events", "iocs", "hypotheses", "leads"):
        md.append(f"| {k.replace('_', ' ')} | {len(a.get(k) or [])} | {len(b.get(k) or [])} |")
    md.append(f"| model usage | {usage(a)} | {usage(b)} |")
    md += ["", f"**Matched findings:** {len(pairs) - len(lost)} of {len(a['findings'])} ({sum(1 for *_, h in pairs if h == 'evidence')} "
           f"on their evidence, {sum(1 for *_, h in pairs if h == 'title')} on their title)."]
    sev_lost = [f for f in lost if f.get("severity") in ("critical", "high")]
    md += ["", f"## Findings of {na} not found in {nb} ({len(lost)}, of which {len(sev_lost)} critical / high)", ""]
    md += [f"- **{f['id']}** [{f.get('severity')}/{f.get('confidence')}] {f.get('title')}" for f in lost] or ["- none"]
    md += ["", f"## New findings in {nb} ({len(new)})", ""]
    md += [f"- **{g['id']}** [{g.get('severity')}/{g.get('confidence')}] {g.get('title')}"
           + (f" (step {g.get('step')})" if g.get("step") else "") for g in new] or ["- none"]
    md += ["", f"## Severity or confidence changed ({len(changed)})", ""]
    md += [f"- {f['id']} -> {g['id']}: {f.get('severity')}/{f.get('confidence')} -> {g.get('severity')}/{g.get('confidence')}: "
           f"{g.get('title')}" for f, g in changed] or ["- none"]
    for name, d in ((na, a), (nb, b)):
        if d.get("hypotheses"):
            md += ["", f"## Hypotheses of {name}", ""]
            md += [f"- {h['id']} [{h.get('status')}/{h.get('confidence')}] {h.get('statement')}" for h in d["hypotheses"]]
        if d.get("leads"):
            st = Counter(x.get("status") for x in d["leads"])
            oc = Counter(x.get("outcome") for x in d["leads"] if x.get("status") == "done")
            md += ["", f"## Leads of {name}", "", f"- {len(d['leads'])} lead(s): " + ", ".join(f"{v} {k}" for k, v in st.items())
                   + "; outcomes: " + (", ".join(f"{v} {k}" for k, v in oc.items()) or "none")]
    return "\n".join(md) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("a", type=Path)
    ap.add_argument("b", type=Path)
    ap.add_argument("--names", nargs=2, default=None, metavar=("A", "B"))
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)
    na, nb = args.names or (args.a.parent.parent.name + "/" + args.a.parent.name, args.b.parent.parent.name + "/" + args.b.parent.name)
    md = compare(load(args.a), load(args.b), na, nb)
    if args.out:
        args.out.write_text(md, encoding="utf-8")
        print(f"Comparison written: {args.out}")
    else:
        sys.stdout.write(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
