#!/usr/bin/env python3
"""
Sleuthline - samples the parsing outputs of a case: for each file of <case>\\parsed\\,
header + first lines + line count + detected encoding/delimiter.

Used to write and check the DuckDB loaders (normalization) and lets the agent
discover the structure of the outputs without loading hundreds of MB.

  python sample_outputs.py "C:\\Sleuthline\\cases\\test02 - SANS"
  -> <case>\\parsed\\_samples\\samples.json  (+ one readable .txt per file)
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

TEXT_EXT = {".csv", ".json", ".jsonl", ".txt", ".log", ".tsv"}
MAX_LINES = 8
MAX_LINE_LEN = 4000


def detect_encoding(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    try:
        raw.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        return "cp1252"


def count_lines(path: Path) -> int:
    n = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 22), b""):
            n += chunk.count(b"\n")
    return n


def sample(path: Path) -> dict:
    raw = path.open("rb").read(1 << 16)
    enc = detect_encoding(raw)
    text = raw.decode(enc, errors="replace")
    lines = [l[:MAX_LINE_LEN] for l in text.splitlines()[:MAX_LINES]]
    info = {"file": str(path), "bytes": path.stat().st_size, "encoding": enc, "lines": count_lines(path),
            "head": lines}
    if path.suffix.lower() in (".csv", ".tsv", ".txt") and lines:
        try:
            dialect = csv.Sniffer().sniff("\n".join(lines[:5]), delimiters=",;|\t")
            info["delimiter"] = dialect.delimiter
            info["columns"] = next(csv.reader([lines[0]], delimiter=dialect.delimiter))
        except csv.Error:
            pass
    if path.suffix.lower() in (".jsonl", ".json") and lines:
        try:
            first = json.loads(lines[0])
            if isinstance(first, dict):
                info["keys"] = list(first.keys())
        except ValueError:
            info["json_note"] = "first line is not JSON (JSON array or multi-line JSON)"
    return info


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("case", type=Path)
    args = ap.parse_args(argv)
    parsed = args.case / "parsed"
    out = parsed / "_samples"
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for f in sorted(parsed.rglob("*")):
        if not f.is_file() or "_samples" in f.parts or f.name.startswith("_") or f.suffix.lower() not in TEXT_EXT:
            continue
        try:
            s = sample(f)
        except OSError as e:
            s = {"file": str(f), "error": str(e)}
        s["rel"] = str(f.relative_to(parsed))
        results.append(s)
        txt = out / (s["rel"].replace("\\", "__").replace("/", "__") + ".txt")
        txt.write_text(json.dumps({k: v for k, v in s.items() if k != "head"}, ensure_ascii=False, indent=1)
                       + "\n\n" + "\n".join(s.get("head", [])), encoding="utf-8")
    (out / "samples.json").write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{len(results)} files sampled -> {out / 'samples.json'}")


if __name__ == "__main__":
    main()
