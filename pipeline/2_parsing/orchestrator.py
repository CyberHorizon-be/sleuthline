#!/usr/bin/env python3
"""
Sleuthline - step 2: parsing orchestrator for a KAPE collection.

Reads the inventory (inventory.py), the tool manifest and the parser registry,
then runs each tool on the artifacts present:

  <case>\\parsed\\<job>\\              raw tool outputs (CSV / JSON / JSONL)
  <case>\\parsed\\<job>\\_run.log       full console output of the tool
  <case>\\parsed\\<job>\\_status.json   job state (used for resuming)
  <case>\\parsed\\jobs.jsonl            log of every execution (traceability)
  <case>\\parsed\\run_summary.json / .md   summary

Principles:
  - read-only on the collection: no tool writes into the evidence folder
    (outputs in parsed\\, Dissect cache disabled, working copies in parsed\\,
    read-only attribute set on the collection files);
  - a job only runs if its artifacts are present and its tool installed;
  - every execution is traced: exact command, tool version, duration,
    return code, input files and SHA-256 of the outputs;
  - resume: a job that already succeeded is not run again (unless --force).

Usage:
  python orchestrator.py C:\\Sleuthline\\cases\\test01
  python orchestrator.py C:\\Sleuthline\\cases\\test01 --list
  python orchestrator.py C:\\Sleuthline\\cases\\test01 --only hayabusa,mftecmd_mft --force
  python orchestrator.py C:\\Sleuthline\\cases\\test01 --dry-run
  python orchestrator.py C:\\Sleuthline\\cases\\test01 --memory D:\\dumps\\host.raw

Memory: a memory image placed in <case>\\memory\\ (or given with --memory) is analyzed with
Volatility 3 by the "volatility" job (memory.py).
Network: the captures placed in <case>\\pcap\\ (or given with --pcap) are analyzed with Suricata by
the "suricata" job (network.py).
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
from collections import defaultdict
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import memory  # noqa: E402
import network  # noqa: E402
PIPE = HERE.parent                                   # <root>\pipeline
ROOT = PIPE.parent                                   # installation root (default C:\Sleuthline)
DEFAULT_MANIFEST = ROOT / "tools" / "tools-manifest.json"
DEFAULT_TIMEOUT = 2 * 3600          # seconds per command
# RECmd batch complementing the Kroll batch (keys missing from Kroll_Batch.reb), versioned with the pipeline
COMPLEMENT_BATCH = PIPE / "config" / "recmd" / "Sleuthline_Complement.reb"

# Dissect plugins that are run. Plugins that extract secrets (browser passwords,
# LSA secrets, SAM hashes, DPAPI keys, product keys) are EXCLUDED by default:
# they do not serve the analysis and the tool is meant to be public.
DISSECT_PLUGINS = [
    # browsers (IE / legacy Edge through WebCacheV01.dat, and the others for correlation)
    "iexplore.history", "iexplore.downloads", "browser.history", "browser.downloads", "browser.extensions",
    # persistence
    "tasks", "runkeys", "services", "cim.consumerbindings", "startupinfo", "msoffice.startup",
    "clsid.user", "appinit",                    # COM hijacking (HKCU\Software\Classes\CLSID), AppInit_DLLs
    "thumbcache.thumbcache", "sevenzip",        # thumbnails (files viewed), 7-Zip history
    # execution / activity
    "powershell_history", "bam", "userassist", "muicache", "mru.run", "mru.opensave", "mru.lastvisited",
    "mru.recentdocs", "mru.mstsc", "mru.networkdrive", "recentfilecache", "activitiescache",
    "windowsnotepad.tabs",                      # Windows 11 Notepad tabs (TabState, including unsaved ones)
    # Defender and logs
    "defender.mplog", "defender.mpcmdrun", "defender.quarantine", "defender.exclusions",
    "schedlgu", "pfro", "wer", "firewall.logs", "firewall.rules", "notifications.wpndatabase",
    # devices, network, system
    "usb", "network_history", "applications", "trusteddocs", "recyclebin",
    # Windows Search index (complements SIDR, another ESE implementation)
    "search",
    # remote access
    "remoteaccess.logs", "remoteaccess.incoming", "remoteaccess.filetransfer",
]
DISSECT_EXCLUDED_SENSITIVE = [
    "browser.passwords", "*.passwords", "lsa.secrets", "sam", "credential.*", "credhist.*",
    "defaultpassword.*", "winlogon.*", "dpapi.*", "productkey", "license", "browser.cookies",
]


# --------------------------------------------------------------------------
# Context: inventory, manifest, paths
# --------------------------------------------------------------------------
class Context:
    def __init__(self, case: Path, inventory: dict, manifest: dict, out: Path, memory_images: list[Path] | None = None,
                 captures: list[Path] | None = None):
        self.case = case
        self.out = out
        self.root = Path(inventory["summary"]["collection_root"])
        self.files_by_art: dict[str, list[dict]] = defaultdict(list)
        for f in inventory["files"]:
            self.files_by_art[f["artifact"]].append(f)
        # Memory image (outside the KAPE collection): pseudo-artifact "memory_image", absolute path
        self.memory_images = [Path(p) for p in (memory_images or [])]
        for img in self.memory_images:
            self.files_by_art["memory_image"].append({"rel_path": str(img), "size": img.stat().st_size,
                                                      "artifact": "memory_image", "original_path": str(img)})
        # Network captures (outside the KAPE collection): pseudo-artifact "pcap", absolute paths
        self.captures = [Path(p) for p in (captures or [])]
        for cap in self.captures:
            self.files_by_art["pcap"].append({"rel_path": str(cap), "size": cap.stat().st_size,
                                              "artifact": "pcap", "original_path": str(cap)})
        self.exe: dict[str, str] = {}
        self.tool_of: dict[str, dict] = {}
        for tool in manifest.get("tools", []):
            if not str(tool.get("status", "")).startswith(("OK", "WARN")):
                continue
            for key, path in (tool.get("executables") or {}).items():
                if key == "python":
                    # each Python tool has its own venv: python_<tool> (e.g. python_bitsparser, python_odlpy)
                    key = "python_" + re.sub(r"[^a-z0-9]", "", tool["name"].split()[0].lower())
                self.exe[key] = path
                self.tool_of[key] = {"name": tool["name"], "version": tool.get("version")}
        # "native": internal parsing (j_native), run by the orchestrator's Python
        self.exe["native"] = sys.executable
        self.tool_of["native"] = {"name": "orchestrator.py (internal)", "version": f"Python {sys.version.split()[0]}"}
        if COMPLEMENT_BATCH.is_file():
            self.exe["RECmd_ComplementBatch"] = str(COMPLEMENT_BATCH)
            self.tool_of["RECmd_ComplementBatch"] = {"name": r"Sleuthline_Complement.reb (pipeline\config\recmd)",
                                                     "version": "sha256 " + sha256(COMPLEMENT_BATCH)[:16]}

    # Files of an artifact (absolute paths in the collection)
    def paths(self, artifact: str) -> list[Path]:
        # rel_path uses Windows separators (backslash): explicit, portable split
        return [self.root.joinpath(*f["rel_path"].split("\\")) for f in self.files_by_art.get(artifact, [])]

    def records(self, artifact: str) -> list[dict]:
        return self.files_by_art.get(artifact, [])

    def first(self, artifact: str, name_rx: str | None = None) -> Path | None:
        for p in self.paths(artifact):
            if name_rx is None or re.search(name_rx, p.name, re.IGNORECASE):
                return p
        return None

    def parents(self, artifact: str, name_rx: str | None = None) -> list[Path]:
        # Windows is case-insensitive: winevt\logs and winevt\Logs (both present in KAPE
        # CopyLogs) are the SAME folder; without this deduplication a tool would process
        # the same logs twice (duplicate detections).
        return dedupe([p.parent for p in self.paths(artifact)
                       if not name_rx or re.search(name_rx, p.name, re.IGNORECASE)])

    def volumes(self) -> list[Path]:
        return [p for p in self.root.iterdir() if p.is_dir() and re.fullmatch(r"[A-Za-z]", p.name)]

    def has(self, key: str) -> bool:
        return bool(self.exe.get(key)) and Path(self.exe[key]).exists()


@dataclass
class Step:
    cmd: list[str]
    cwd: Path | None = None
    stdout_file: Path | None = None   # if set, stdout is written to this file (tool output)
    timeout: int = DEFAULT_TIMEOUT
    label: str = ""
    ok_codes: tuple = (0,)
    func: Callable[[], str] | None = None   # internal step (working copy...) instead of a command
    stall_timeout: int | None = None        # stop if nothing is written to watch_dir for N seconds
    watch_dir: Path | None = None           # watched folder (default: job folder)
    optional: bool = False                  # a failure only downgrades the job to "warning"


@dataclass
class Job:
    id: str
    title: str
    artifacts: list[str]              # at least one must be present
    tools: list[str]                  # manifest executable keys, all required
    build: Callable[[Context, Path], list[Step]]
    inputs: Callable[[Context], list[Path]] = None
    note: str = ""
    # Patterns signalling a failure or data loss DESPITE a 0 return code
    # (e.g. SIDR "failed with error", SBECmd "Data may be missing")
    warn_patterns: list[str] = field(default_factory=list)
    # Real progress (0..1) read from the tool outputs while it runs, when possible
    progress: Callable[[Context, Path], float | None] | None = None
    # Steps after the first serial_first ones run `parallel` at a time (Volatility plugins)
    parallel: int = 1
    serial_first: int = 0


def dedupe(paths) -> list[Path]:
    """Unique paths, case-insensitive (like Windows)."""
    seen, out = set(), []
    for p in paths:
        k = str(p).lower()
        if k not in seen:
            seen.add(k)
            out.append(p)
    return out


def user_of(path: Path) -> str:
    parts = [x.lower() for x in path.parts]
    if "users" in parts and parts.index("users") + 1 < len(parts):
        return path.parts[parts.index("users") + 1]
    return "system"


def safe(s: str) -> str:
    return re.sub(r"[^\w.-]+", "_", s).strip("_")[:80]


# --------------------------------------------------------------------------
# Job definitions (syntax checked against <root>\tools\_help\)
# --------------------------------------------------------------------------
def _evtx_dirs(c: Context) -> list[Path]:
    return c.parents("evtx", r"\.evtx$")


def _ez(key: str, *args) -> Callable:
    def build(c: Context, out: Path) -> list[Step]:
        return [Step([c.exe[key], *[a(c, out) if callable(a) else a for a in args]])]
    return build


def j_mft(c, out):
    return [Step([c.exe["MFTECmd"], "-f", str(c.first("ntfs_mft")), "--csv", str(out), "--csvf", "mft.csv"])]


def j_usnjrnl(c, out):
    cmd = [c.exe["MFTECmd"], "-f", str(c.first("ntfs_usnjrnl")), "--csv", str(out), "--csvf", "usnjrnl.csv"]
    mft = c.first("ntfs_mft")
    if mft:
        cmd[3:3] = ["-m", str(mft)]     # parent path resolution
    return [Step(cmd)]


def j_boot(c, out):
    return [Step([c.exe["MFTECmd"], "-f", str(c.first("ntfs_boot")), "--csv", str(out), "--csvf", "boot.csv"])]


def j_sds(c, out):
    return [Step([c.exe["MFTECmd"], "-f", str(c.first("ntfs_sds")), "--csv", str(out), "--csvf", "sds.csv"])]


def j_logfile(c, out):
    # AutoIt application: parameters documented in the README of jschicht/LogFileParser
    # Watchdog: if it writes nothing for 15 min (infinite loop seen on test01,
    # "chunk 9 of 1 ... 900 %"), it is stopped and its partial outputs are kept.
    return [Step([c.exe["LogFileParser"], f"/LogFileFile:{c.first('ntfs_logfile')}", f"/OutputPath:{out}"],
                 cwd=Path(c.exe["LogFileParser"]).parent, timeout=3 * 3600, stall_timeout=15 * 60, watch_dir=out)]


def p_logfile(c: Context, out: Path) -> float | None:
    """LogFileParser writes one line per processed page in LogFile_RCRD.csv (1st column =
    page offset): offset / size of the $LogFile = real progress."""
    lf = c.first("ntfs_logfile")
    rcrd = next(out.glob("LogFile_*/LogFile_RCRD.csv"), None)
    if not lf or not rcrd:
        return None
    try:
        size = lf.stat().st_size
        with rcrd.open("rb") as fh:
            fh.seek(max(0, rcrd.stat().st_size - 4096))
            last = [l for l in fh.read().decode("ascii", "replace").splitlines() if l.startswith("0x")]
        return min(int(last[-1].split("|")[0], 16) / size, 1.0) if last and size else None
    except (OSError, ValueError, IndexError):
        return None


def j_evtxecmd(c, out):
    return [Step([c.exe["EvtxECmd"], "-d", str(d), "--csv", str(out), "--csvf", f"evtxecmd_{i}.csv"],
                 cwd=Path(c.exe["EvtxECmd"]).parent) for i, d in enumerate(_evtx_dirs(c))]


def j_hayabusa(c, out):
    exe = c.exe["hayabusa"]
    # Maximum coverage: ALL rules (deprecated, noisy, unsupported included), no channel filter
    # (neither on rules -A nor on EVTX files -a), all levels (-m informational), and recovery
    # of records from EVTX slack space (-x). Super-verbose profile: Details + ExtraFieldInfo = all fields.
    return [Step([exe, "dfir-timeline", "-d", str(d), "-t", "JSONL", "-o", str(out / f"hayabusa_{i}.jsonl"),
                  "-p", "super-verbose", "-A", "-a", "-D", "-n", "-u", "-x", "-m", "informational",
                  "-w", "-U", "-C", "-q", "-K"], cwd=Path(exe).parent, label=f"dfir-timeline {d.name}")
            for i, d in enumerate(_evtx_dirs(c))]


def j_chainsaw(c, out):
    exe = c.exe["chainsaw"]
    sigma = Path(c.exe["sigma_rules_dir"])
    if (sigma / "rules" / "windows").is_dir():
        sigma = sigma / "rules" / "windows"
    steps = []
    for i, d in enumerate(_evtx_dirs(c)):
        cmd = [exe, "hunt", str(d), "-s", str(sigma), "--mapping", c.exe["chainsaw_mapping"],
               "--jsonl", "-o", str(out / f"chainsaw_{i}.jsonl"), "-q", "--skip-errors"]
        if c.exe.get("chainsaw_rules"):
            cmd[3:3] = ["-r", c.exe["chainsaw_rules"]]
        steps.append(Step(cmd, cwd=Path(exe).parent))
    return steps


def j_zircolite(c, out):
    exe = c.exe["zircolite"]
    rules = Path(c.exe.get("zircolite_rules") or Path(exe).parent / "rules")
    ruleset = rules / "rules_windows_merged.json"           # generic + Sysmon rules
    if not ruleset.exists():
        ruleset = rules / "rules_windows_generic.json"
    return [Step([exe, "--evtx", str(d), "--ruleset", str(ruleset), "-o", str(out / f"zircolite_{i}.json"),
                  "--timeline", str(out / f"zircolite_timeline_{i}.jsonl"), "-l", str(out / f"zircolite_{i}.log"), "-q"],
                 cwd=Path(exe).parent) for i, d in enumerate(_evtx_dirs(c))]


def j_pecmd(c, out):
    return [Step([c.exe["PECmd"], "-d", str(d), "-q", "--mp", "--csv", str(out), "--csvf", f"prefetch_{i}.csv"])
            for i, d in enumerate(c.parents("prefetch"))]


def j_amcache(c, out):
    return [Step([c.exe["AmcacheParser"], "-f", str(c.first("amcache")), "-i", "--mp", "--csv", str(out)])]


def j_shimcache(c, out):
    return [Step([c.exe["AppCompatCacheParser"], "-f", str(c.first("reg_system")), "--csv", str(out), "--csvf", "shimcache.csv"])]


def j_recentfilecache(c, out):
    return [Step([c.exe["RecentFileCacheParser"], "-f", str(c.first("recentfilecache")), "--csv", str(out)])]


def j_recmd(c, out):
    exe = c.exe["RECmd"]
    return [Step([exe, "-d", str(v), "--bn", c.exe["RECmd_KrollBatch"], "--nl", "--csv", str(out),
                  "--csvf", f"recmd_kroll_{v.name}.csv"], cwd=Path(exe).parent) for v in c.volumes()]


def j_recmd_complement(c, out):
    exe = c.exe["RECmd"]
    return [Step([exe, "-d", str(v), "--bn", c.exe["RECmd_ComplementBatch"], "--nl", "--csv", str(out),
                  "--csvf", f"recmd_complement_{v.name}.csv"], cwd=Path(exe).parent) for v in c.volumes()]


def j_sbecmd(c, out):
    # NO --nl: SBECmd would then ignore the transaction logs ("Data may be missing")
    return [Step([c.exe["SBECmd"], "-d", str(v / "Users"), "--csv", str(out)])
            for v in c.volumes() if (v / "Users").is_dir()]


def j_lecmd(c, out):
    return [Step([c.exe["LECmd"], "-d", str(v), "-q", "--mp", "--csv", str(out), "--csvf", f"lnk_{v.name}.csv"]) for v in c.volumes()]


def j_jlecmd(c, out):
    return [Step([c.exe["JLECmd"], "-d", str(v), "-q", "--mp", "--csv", str(out)]) for v in c.volumes()]


def j_rbcmd(c, out):
    roots = []
    for p in c.paths("recyclebin_i"):
        rb = next((a for a in p.parents if a.name.lower() == "$recycle.bin"), None)
        if rb:
            roots.append(rb)
    roots = dedupe(roots)
    return [Step([c.exe["RBCmd"], "-d", str(rb), "-q", "--csv", str(out), "--csvf", f"recyclebin_{i}.csv"]) for i, rb in enumerate(roots)]


def j_srum(c, out):
    # SRUDB.dat is almost always dirty in a live collection: SrumECmd then rejects the database
    # (return code 0, no output). Working copy + esentutl /r (SRU*.log journals), as SrumECmd
    # itself recommends; the original evidence is not modified.
    db = c.first("srum", r"^SRUDB\.dat$")
    work = out / "_work" / "sru"
    steps = ese_working_copy(db, work)
    cmd = [c.exe["SrumECmd"], "-f", str(work / db.name), "--csv", str(out)]
    sw = c.first("reg_software")
    if sw:
        cmd[3:3] = ["-r", str(sw)]
    steps.append(Step(cmd, label="SrumECmd (replayed copy)"))
    return steps


SQLITE_MAGIC = b"SQLite format 3\x00"
SQLITE_SIDECARS = ("-wal", "-shm", "-journal")
# Chromium cache folders: large and of no interest to Hindsight / SQLECmd
CHROMIUM_CACHE_DIRS = {"cache", "code cache", "gpucache", "dawncache", "grshadercache", "shadercache", "cachestorage",
                       "scriptcache", "component_crx_cache", "crashpad"}


def is_sqlite(p: Path) -> bool:
    try:
        with p.open("rb") as fh:
            return fh.read(16) == SQLITE_MAGIC
    except OSError:
        return False


def working_copy(c: Context, files: list[Path], work: Path, label: str) -> Step:
    """Working copy of collection files (same relative tree under work\\, e.g.
    work\\C\\Users\\...), before handing them to a tool that would open them for writing.

    SQLite writes to the database and its -wal / -shm files as soon as it opens it (journal
    replay, checkpoint): seen on test02, where WxTCmd had modified ActivitiesCache.db in the
    collection. Side files (-wal, -shm, -journal) are copied with their database so that their
    content (recent transactions) is read. Paths of the copy are mapped back to the original
    paths by normalize.py (orig_path macro: ...\\_work\\C\\... -> C:\\...)."""
    def copy() -> str:
        seen, lines = set(), []
        for f in files:
            for p in [f] + [f.with_name(f.name + s) for s in SQLITE_SIDECARS]:
                k = str(p).lower()
                if k in seen or not p.is_file():
                    continue
                seen.add(k)
                dst = work / p.relative_to(c.root)
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, dst)
                os.chmod(dst, stat.S_IREAD | stat.S_IWRITE)      # only the copy becomes writable
                lines.append(f"copied: {p.relative_to(c.root)} ({p.stat().st_size} B)")
        return "\n".join(lines) + f"\n{len(lines)} file(s) copied\n"
    return Step([], label=label, func=copy)


def j_wxtcmd(c, out):
    # Output stored under the original path of the database folder (wxtcmd\C\Users\<u>\...\<account>\): WxTCmd
    # does not write the source database in its CSV, normalize.py derives the evidence from it (evidence column).
    steps = []
    work = out / "_work"
    for p in c.paths("timeline"):
        if p.name.lower() == "activitiescache.db":
            steps.append(working_copy(c, [p], work, f"working copy {user_of(p)}"))
            o = out / p.parent.relative_to(c.root)
            steps.append(Step([c.exe["WxTCmd"], "-f", str(work / p.relative_to(c.root)), "--csv", str(o)]))
    return steps


def j_sumecmd(c, out):
    return [Step([c.exe["SumECmd"], "-d", str(d), "--csv", str(out)]) for d in c.parents("sum_ual")]


def j_sqlecmd(c, out):
    # SQLECmd opens databases in place: it works on a copy of the SQLite databases of the collection only
    exe = c.exe["SQLECmd"]
    work = out / "_work"
    dbs = [p for v in c.volumes() for p in v.rglob("*") if p.is_file() and not p.name.lower().endswith(SQLITE_SIDECARS)
           and not CHROMIUM_CACHE_DIRS & {x.lower() for x in p.parts} and is_sqlite(p)]
    if not dbs:
        return []
    return [working_copy(c, dbs, work, f"working copy of {len(dbs)} SQLite database(s)"),
            Step([exe, "-d", str(work), "--csv", str(out)], cwd=Path(exe).parent)]


ESENTUTL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "esentutl.exe"
ESE_LOG_RX = re.compile(r"^([A-Za-z0-9]{3})[0-9A-Fa-f]*\.(log|jtx)$", re.IGNORECASE)


def ese_working_copy(db: Path, work: Path) -> list[Step]:
    """Working copy of an ESE database (database + logs + checkpoint) then replay of the
    logs with esentutl /r (built into Windows) ON THE COPY.

    A database copied live is dirty (Dirty Shutdown): some parsers fail or lose data.
    The original evidence is never modified; a failed replay is not blocking (the parser
    is attempted anyway). No "esentutl /p" (destructive repair, blocking dialog box).
    """
    src = db.parent

    def copy() -> str:
        work.mkdir(parents=True, exist_ok=True)
        lines = []
        for f in sorted(src.iterdir()):
            if f.is_file():
                dst = work / f.name
                shutil.copy2(f, dst)
                # Evidence is often read-only (good practice) and copy2 keeps that attribute:
                # ESE then cannot replay the logs (JET_errFileAccessDenied). The COPY is made
                # writable; the original is never modified.
                os.chmod(dst, stat.S_IREAD | stat.S_IWRITE)
                lines.append(f"copied: {f.name} ({f.stat().st_size} B, sha256 {sha256(f)[:16]}...)")
        return "\n".join(lines) + "\n"

    steps = [Step([], label=f"working copy of {src}", func=copy)]
    bases = sorted({m.group(1) for f in src.iterdir() if f.is_file() and (m := ESE_LOG_RX.match(f.name))
                    and not f.name.lower().startswith(("edbtmp", "tmp"))})
    if ESENTUTL.exists():
        for base in bases:
            # relative paths (cwd = copy): no spaces in the /l /s /d options
            steps.append(Step([str(ESENTUTL), "/r", base, "/l.", "/s.", "/d.", "/i", "/o"], cwd=work,
                              label=f"esentutl /r {base} (log replay on the copy)", optional=True, timeout=1800))
    return steps


def j_sidr(c, out):
    steps = []
    for i, d in enumerate(c.parents("search_index", r"^Windows\.(edb|db)$")):
        db = next((p for p in d.iterdir() if p.name.lower() in ("windows.edb", "windows.db")), None)
        if db and db.suffix.lower() == ".edb":
            work = out / "_work" / f"search_{i}"
            steps += ese_working_copy(db, work)
            steps.append(Step([c.exe["sidr"], "-f", "csv", "-o", str(out), str(work)], label="sidr (replayed copy)"))
        elif db:
            # Windows.db (Windows 11) is a SQLite database: working copy, as for ESE
            work = out / "_work"
            steps.append(working_copy(c, [p for p in d.iterdir() if p.is_file()], work, f"working copy of {d.name}"))
            steps.append(Step([c.exe["sidr"], "-f", "csv", "-o", str(out), str(work / d.relative_to(c.root))],
                              label="sidr (working copy)"))
    return steps


def j_bits(c, out):
    return [Step([c.exe["python_bitsparser"], c.exe["BitsParser"], "-i", str(d), "-o", str(out / f"bits_{i}.json"), "--carvedb"])
            for i, d in enumerate(c.parents("bits"))]


def j_bmc(c, out):
    return [Step([c.exe["python_bmctools"], c.exe["bmc-tools"], "-s", str(d), "-d", str(out / safe(user_of(d))), "-k"])
            for d in c.parents("rdp_cache")]


def j_hindsight(c, out):
    roots = []
    for p in c.paths("chromium"):
        ud = next((a for a in p.parents if a.name.lower() == "user data"), None)
        if ud:
            roots.append(ud)
    roots = dedupe(roots)
    steps = []
    work = out / "_work"
    for ud in roots:
        name = safe(f"{user_of(ud)}_{ud.parent.name}")
        tmp = out / "_tmp"
        # Hindsight only copies databases when they are locked: working copy of the profile (caches excluded)
        files = [p for p in ud.rglob("*") if p.is_file()
                 and not CHROMIUM_CACHE_DIRS & {x.lower() for x in p.relative_to(ud).parts[:-1]}]
        steps.append(working_copy(c, files, work, f"working copy {name}"))
        steps.append(Step([c.exe["hindsight"], "-i", str(work / ud.relative_to(c.root)), "-o", str(out / f"hindsight_{name}"),
                           "-f", "jsonl", "-l", str(out / f"hindsight_{name}.log"), "--temp_dir", str(tmp)]))
    return steps


def j_odl(c, out):
    folders = []
    for p in c.paths("onedrive"):
        if re.search(r"\.(odl|odlgz|odlsent|aodl)$", p.name, re.IGNORECASE):
            folders.append(p.parent)
    folders = dedupe(folders)
    return [Step([c.exe["python_odlpy"], c.exe["odl"], "-o", str(out / f"odl_{safe(user_of(f))}_{safe(f.name)}.csv"), str(f)])
            for f in folders]


def read_text_auto(p: Path) -> str:
    """Text of a Windows file: UTF-16 (BOM or null bytes, as in .rdp files and some logs) or UTF-8 / ANSI."""
    data = p.read_bytes()
    if data[:2] in (b"\xff\xfe", b"\xfe\xff") or (len(data) > 1 and data[1:2] == b"\x00"):
        return data.decode("utf-16", errors="replace").lstrip("\ufeff")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


WLAN_NS = re.compile(r"^\{[^}]*\}")
WLAN_SECRET_TAGS = {"keymaterial", "sharedkey"}       # Wi-Fi key (DPAPI-encrypted): never extracted


def parse_wlan_profile(text: str) -> dict:
    """Wi-Fi profile (Wlansvc\\Profiles\\Interfaces\\{adapter}\\{profile}.xml, WLANProfile v1 schema): name, SSID,
    connection type and mode, authentication, encryption. The key (sharedKey / keyMaterial) is not read."""
    import xml.etree.ElementTree as ET
    rec: dict = {}
    for el in ET.fromstring(text.encode("utf-8")).iter():
        tag = WLAN_NS.sub("", el.tag)
        if tag.lower() in WLAN_SECRET_TAGS:
            continue
        val = (el.text or "").strip()
        if not val:
            continue
        if tag == "name" and "name" not in rec:
            rec["name"] = val                      # first <name>: profile name
        elif tag == "name":
            rec.setdefault("ssid", val)            # SSIDConfig\SSID\name
        elif tag == "hex":
            rec.setdefault("ssid_hex", val)
        elif tag in ("connectionType", "connectionMode", "authentication", "encryption", "useOneX",
                     "nonBroadcast", "autoSwitch", "randomizationSeed", "MacRandomization"):
            rec.setdefault(tag, val)
    return rec


RDP_SECRET_KEYS = re.compile(r"password|psw", re.IGNORECASE)   # "password 51:b:": DPAPI-encrypted password, excluded


def parse_rdp_file(text: str) -> dict:
    """Remote Desktop connection file (.rdp, lines "key:type:value"): every setting except passwords.
    full address / username / gatewayhostname / remoteapplicationprogram in dedicated columns."""
    settings = {}
    for line in text.splitlines():
        parts = line.strip().split(":", 2)
        if len(parts) == 3 and parts[1] in ("s", "i", "b") and not RDP_SECRET_KEYS.search(parts[0]):
            settings[parts[0].strip().lower()] = parts[2]
    rec = {k.replace(" ", "_"): settings.get(k) for k in ("full address", "alternate full address", "username",
                                                            "gatewayhostname", "remoteapplicationprogram")}
    rec["settings"] = settings
    return rec


# setupact.log / setuperr.log: "2023-11-09 18:58:09, Info                  CONX   message"
PANTHER_LINE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\s*(\w+)\s+(?:\[[^\]]*\]\s*)?(?:([A-Z][A-Za-z0-9]{1,15})\s{2,})?(.*)$")


def parse_panther_log(text: str):
    """Windows setup / upgrade log (Panther): one record per timestamped line (LOCAL time of the
    machine); following lines without a timestamp are appended to the message."""
    cur = None
    for n, line in enumerate(text.splitlines(), 1):
        m = PANTHER_LINE.match(line)
        if m:
            if cur:
                yield cur
            cur = {"line": n, "ts_local": m.group(1), "level": m.group(2), "component": m.group(3),
                   "message": m.group(4).strip()}
        elif cur and line.strip() and len(cur["message"]) < 4000:
            cur["message"] += " " + line.strip()
    if cur:
        yield cur


def j_native(c, out):
    """Artifacts with no format to decode (registry: parser "native", type "trivial"): Startup folders,
    hosts file, Wi-Fi profiles, .rdp files, Panther logs.
    Startup: one record per file, original timestamps recorded by KAPE (CopyLog) and SHA-256.
    hosts: one line per active entry (address, names), comments and blank lines excluded.
    Wi-Fi / .rdp: one record per file (settings, secrets excluded) + CopyLog timestamps.
    Panther: one record per timestamped line."""
    def file_meta(r: dict, p: Path) -> dict:
        return {"original_path": r.get("original_path"), "user": r.get("user"), "sha256": sha256(p),
                "created_utc": r.get("created_utc"), "modified_utc": r.get("modified_utc")}

    def per_file(artifact: str, name_rx: str, parse, dest: str, what: str) -> Callable[[], str]:
        def run() -> str:
            n, errors = 0, []
            with (out / dest).open("w", encoding="utf-8") as fh:
                for r in c.records(artifact):
                    p = c.root.joinpath(*r["rel_path"].split("\\"))
                    if not re.search(name_rx, p.name, re.IGNORECASE):
                        continue
                    try:
                        rec = parse(read_text_auto(p))
                    except Exception as e:                      # truncated file / invalid XML: reported, not blocking
                        errors.append(f"{r.get('original_path')}: {e}")
                        continue
                    fh.write(json.dumps({**file_meta(r, p), **rec}, ensure_ascii=False) + "\n")
                    n += 1
            return f"{n} {what}\n" + "".join(f"Read error: {e}\n" for e in errors)
        return run

    def panther() -> str:
        n = 0
        with (out / "panther.jsonl").open("w", encoding="utf-8") as fh:
            for r in c.records("panther"):
                p = c.root.joinpath(*r["rel_path"].split("\\"))
                for rec in parse_panther_log(read_text_auto(p)):
                    fh.write(json.dumps({"original_path": r.get("original_path"), **rec}, ensure_ascii=False) + "\n")
                    n += 1
        return f"{n} timestamped line(s) in {len(c.records('panther'))} Panther log(s)\n"

    def startup() -> str:
        recs = c.records("startup")
        with (out / "startup.jsonl").open("w", encoding="utf-8") as fh:
            for r in recs:
                p = c.root.joinpath(*r["rel_path"].split("\\"))
                fh.write(json.dumps({"original_path": r.get("original_path"), "user": r.get("user"), "size": r.get("size"),
                                     "sha256": sha256(p) if p.is_file() else None, "sha1_kape": r.get("sha1"),
                                     "created_utc": r.get("created_utc"), "modified_utc": r.get("modified_utc"),
                                     "accessed_utc": r.get("accessed_utc"), "rel_path": r["rel_path"]},
                                    ensure_ascii=False) + "\n")
        return f"{len(recs)} file(s) in Startup folders\n"

    def hosts() -> str:
        n = 0
        with (out / "hosts.jsonl").open("w", encoding="utf-8") as fh:
            for r in c.records("hosts"):
                if not re.search(r"\\hosts$", r["rel_path"], re.IGNORECASE):
                    continue
                p = c.root.joinpath(*r["rel_path"].split("\\"))
                for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    entry = line.split("#", 1)[0].split()
                    if len(entry) >= 2:
                        n += 1
                        fh.write(json.dumps({"original_path": r.get("original_path"), "line": i, "address": entry[0],
                                             "names": " ".join(entry[1:]), "raw": line.strip(),
                                             "modified_utc": r.get("modified_utc")}, ensure_ascii=False) + "\n")
        return f"{n} active entry(ies) in hosts\n"

    steps = []
    if c.records("startup"):
        steps.append(Step([], label="Startup folders", func=startup))
    if c.records("hosts"):
        steps.append(Step([], label="hosts file", func=hosts))
    if c.records("wifi_profiles"):
        steps.append(Step([], label="Wi-Fi profiles", func=per_file("wifi_profiles", r"\.xml$", parse_wlan_profile,
                                                                    "wifi_profiles.jsonl", "Wi-Fi profile(s)")))
    if c.records("rdp_files"):
        steps.append(Step([], label=".rdp files", func=per_file("rdp_files", r"\.rdp$", parse_rdp_file,
                                                                "rdp_files.jsonl", ".rdp file(s)")))
    if c.records("panther"):
        steps.append(Step([], label="Panther logs", func=panther))
    return steps


def _plaso(parsers: str, sources: list[Path], name: str) -> Callable:
    def build(c: Context, out: Path) -> list[Step]:
        steps = []
        for i, src in enumerate(sources(c)):
            storage = out / f"{name}_{i}.plaso"
            if storage.exists():
                storage.unlink()            # log2timeline would append to the existing storage
            steps.append(Step([c.exe["log2timeline"], "--parsers", parsers, "--storage-file", str(storage),
                               "-u", "--status_view", "none", "--logfile", str(out / f"{name}_{i}_log2timeline.log.gz"),
                               str(src)], cwd=out))
            steps.append(Step([c.exe["psort"], "-o", "json_line", "-w", str(out / f"{name}_{i}.jsonl"), "-u",
                               "--logfile", str(out / f"{name}_{i}_psort.log.gz"), str(storage)], cwd=out))
        return steps
    return build


def j_dissect(c, out):
    tq = c.exe["dissect"]
    return [Step([tq, "-q", "--no-cache", "-L", "kape", "-f", plugin, "-j", str(c.root)],
                 stdout_file=out / f"{plugin}.jsonl", label=plugin, timeout=3600) for plugin in DISSECT_PLUGINS]


def j_volatility(c, out):
    """Volatility 3 on the memory image: SHA-256 of the image, windows.info (identifies the kernel and
    downloads its symbols), then the plugins of memory.PLUGINS in parallel."""
    image = c.memory_images[0]
    vol = c.exe["vol"]
    voldir = ROOT / "tools" / "volatility"
    symbols, cache = voldir / "symbols", voldir / "cache"
    for d in (symbols, cache):
        d.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    steps = [Step([], label="SHA-256 of the memory image",
                  func=lambda: memory.hash_image(image, out / "memory_image.jsonl"), timeout=memory.PLUGIN_TIMEOUT)]
    for p in memory.PLUGINS:
        cmd = memory.vol_command(vol, image, p.name, symbols, cache)
        steps.append(Step(cmd, label=p.name, timeout=memory.PLUGIN_TIMEOUT,
                          func=(lambda cmd=cmd, name=p.name: memory.run_plugin(cmd, out / f"{name}.jsonl", env=env))))
    return steps


def j_suricata(c, out):
    """Suricata on the network captures: SHA-256 of the captures, configuration for an offline
    analysis (from the suricata.yaml shipped with Suricata), then one Suricata run per capture."""
    exe = c.exe["suricata"]
    install = Path(exe).parent
    default_yaml = Path(c.exe["suricata_yaml"]) if c.exe.get("suricata_yaml") else network.find_config_file(install, "suricata.yaml")
    rules = Path(c.exe["suricata_rules"]) if c.exe.get("suricata_rules") else None
    config = out / "_suricata.yaml"
    env = dict(os.environ, PYTHONUTF8="1")
    steps = [Step([], label="SHA-256 of the captures",
                  func=lambda: network.hash_captures(c.captures, out / "pcap_files.jsonl"), timeout=network.RUN_TIMEOUT)]
    if not default_yaml or not Path(default_yaml).is_file():
        def no_config():
            raise RuntimeError(f"suricata.yaml not found next to {exe}")
        steps.append(Step([], label="Suricata configuration", func=no_config))
    else:
        steps.append(Step([], label="Suricata configuration (offline analysis)",
                          func=lambda: network.write_config(Path(default_yaml), config, rules, install)))
    for cap in c.captures:
        d = out / network.capture_dir_name(cap, c.captures)
        cmd = network.suricata_command(exe, cap, config, d / "raw")
        steps.append(Step(cmd, label=cap.name, timeout=network.RUN_TIMEOUT,
                          func=(lambda cmd=cmd, d=d, cap=cap: network.run_capture(cmd, d / "raw", d, cap.name, env=env))))
    return steps


JOBS: list[Job] = [
    # --- File system
    Job("mftecmd_mft", "MFTECmd - $MFT", ["ntfs_mft"], ["MFTECmd"], j_mft),
    Job("mftecmd_usnjrnl", "MFTECmd - $UsnJrnl:$J", ["ntfs_usnjrnl"], ["MFTECmd"], j_usnjrnl),
    Job("mftecmd_boot", "MFTECmd - $Boot", ["ntfs_boot"], ["MFTECmd"], j_boot),
    Job("mftecmd_sds", "MFTECmd - $Secure:$SDS", ["ntfs_sds"], ["MFTECmd"], j_sds),
    Job("logfileparser", "LogFileParser - $LogFile", ["ntfs_logfile"], ["LogFileParser"], j_logfile, progress=p_logfile,
        note="AutoIt application (GUI if parameters are invalid): stopped after the timeout if it hangs"),
    # --- Event logs
    Job("evtxecmd", "EvtxECmd - EVTX (maps)", ["evtx"], ["EvtxECmd"], j_evtxecmd),
    Job("hayabusa", "Hayabusa - detections (all rules)", ["evtx"], ["hayabusa"], j_hayabusa,
        note="All rules (deprecated/noisy/unsupported), no channel filter, recovered records (-x)"),
    Job("chainsaw", "Chainsaw - Sigma detections + Chainsaw rules", ["evtx"], ["chainsaw", "chainsaw_mapping", "sigma_rules_dir"], j_chainsaw),
    Job("zircolite", "Zircolite - Sigma detections", ["evtx"], ["zircolite"], j_zircolite),
    # --- Execution
    Job("pecmd", "PECmd - Prefetch", ["prefetch"], ["PECmd"], j_pecmd),
    Job("amcacheparser", "AmcacheParser - Amcache.hve", ["amcache"], ["AmcacheParser"], j_amcache),
    Job("appcompatcache", "AppCompatCacheParser - ShimCache", ["reg_system"], ["AppCompatCacheParser"], j_shimcache),
    Job("recentfilecache", "RecentFileCacheParser", ["recentfilecache"], ["RecentFileCacheParser"], j_recentfilecache),
    Job("srumecmd", "SrumECmd - SRUM", ["srum"], ["SrumECmd"], j_srum,
        warn_patterns=[r"Error processing file", r"database is dirty"],
        note="Database copied and logs replayed (esentutl /r) before parsing"),
    Job("sumecmd", "SumECmd - User Access Logging", ["sum_ual"], ["SumECmd"], j_sumecmd),
    # --- Registry
    Job("recmd_kroll", "RECmd - Kroll batch (all hives)", ["reg_system", "reg_software", "reg_ntuser", "reg_usrclass"],
        ["RECmd", "RECmd_KrollBatch"], j_recmd),
    Job("recmd_complement", "RECmd - complementary batch (EMDMgmt, Active Setup, Print Monitors, BootExecute, PCA)",
        ["reg_system", "reg_software", "reg_ntuser"], ["RECmd", "RECmd_ComplementBatch"], j_recmd_complement,
        note=r"Keys missing from Kroll_Batch.reb: pipeline\config\recmd\Sleuthline_Complement.reb"),
    Job("sbecmd", "SBECmd - ShellBags", ["reg_usrclass", "reg_ntuser"], ["SBECmd"], j_sbecmd,
        warn_patterns=[r"Hive is dirty and the transaction logs should be reviewed"]),
    # --- User activity
    Job("lecmd", "LECmd - LNK files", ["lnk"], ["LECmd"], j_lecmd),
    Job("jlecmd", "JLECmd - Jump Lists", ["jumplists"], ["JLECmd"], j_jlecmd),
    Job("rbcmd", "RBCmd - Recycle Bin ($I)", ["recyclebin_i"], ["RBCmd"], j_rbcmd),
    Job("wxtcmd", "WxTCmd - Windows Timeline", ["timeline"], ["WxTCmd"], j_wxtcmd),
    Job("sidr", "SIDR - Windows Search index", ["search_index"], ["sidr"], j_sidr,
        warn_patterns=[r"failed with error", r"database state is not clean"],
        note="Database copied and logs replayed (esentutl /r) before parsing; see also dissect/search.jsonl"),
    Job("sqlecmd", "SQLECmd - SQLite databases (browsers, notifications...)", ["firefox", "chromium", "notifications", "timeline"],
        ["SQLECmd"], j_sqlecmd),
    # --- Browsers / cloud
    Job("hindsight", "Hindsight - Chromium browsers", ["chromium"], ["hindsight"], j_hindsight),
    Job("odl", "odl.py - OneDrive logs", ["onedrive"], ["odl", "python_odlpy"], j_odl,
        warn_patterns=[r"Strings will not be decoded"],
        note="Without general.keystore / ObfuscationStringMap.txt in the collection, strings stay obfuscated"),
    # --- Persistence / remote access
    Job("bitsparser", "BitsParser - BITS jobs", ["bits"], ["BitsParser", "python_bitsparser"], j_bits),
    Job("bmc_tools", "bmc-tools - RDP bitmap cache", ["rdp_cache"], ["bmc-tools", "python_bmctools"], j_bmc),
    # --- plaso (parsers with no installed equivalent)
    Job("plaso_setupapi", "plaso - setupapi.dev.log (USB)", ["setupapi"], ["log2timeline", "psort"],
        _plaso("text/setupapi", lambda c: c.paths("setupapi"), "setupapi")),
    Job("plaso_pca", "plaso - Program Compatibility Assistant", ["pca"], ["log2timeline", "psort"],
        _plaso("winpca_db0,winpca_dic", lambda c: c.parents("pca"), "pca")),
    # --- Internal parsing ("native" in the registry): files with no format to decode
    Job("native", "Internal - Startup, hosts, Wi-Fi profiles, .rdp files, Panther logs",
        ["startup", "hosts", "wifi_profiles", "rdp_files", "panther"], ["native"], j_native,
        warn_patterns=[r"^Read error"]),
    # --- Dissect (WebCache, tasks, Defender, WMI, PowerShell, WER, registry...)
    Job("dissect", "Dissect - Windows plugins (no secrets)", ["evtx", "reg_system", "reg_software"], ["dissect"], j_dissect,
        note="Sensitive plugins excluded: " + ", ".join(DISSECT_EXCLUDED_SENSITIVE)),
    # --- Memory (image in <case>\memory\ or --memory)
    Job("volatility", f"Volatility 3 - memory image ({len(memory.PLUGINS)} plugins, no secrets, no file extraction)",
        ["memory_image"], ["vol"], j_volatility, parallel=memory.PARALLEL, serial_first=2,
        note="Not run: " + ", ".join(memory.EXCLUDED)),
    # --- Network (captures in <case>\pcap\ or --pcap)
    Job("suricata", "Suricata - network captures (alerts and protocol metadata)", ["pcap"], ["suricata"], j_suricata,
        parallel=1, serial_first=2),
]


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------
_log_lock = threading.Lock()
_print_lock = threading.Lock()
PROGRESS: dict[str, dict] = {}          # running job -> step, total, label, start, estimate
_console = None                          # rich console (live display) when available


def say(msg: str) -> None:
    """Thread-safe console output (lines never interleaved)."""
    with _print_lock:
        if _console is not None:
            _console.print(msg, markup=False, highlight=False)
        else:
            print(msg, flush=True)


class DurationHistory:
    """Durations of previous executions (all cases) to estimate the remaining time.

    Simple model: duration ≈ input volume / throughput, the throughput being the median of
    past executions of this job. Stored in <root>\\logs\\job_durations.jsonl.
    """

    def __init__(self, path: Path):
        self.path = path
        self.rows: dict[str, list[dict]] = defaultdict(list)
        if path.exists():
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    r = json.loads(line)
                    self.rows[r["job"]].append(r)
                except (ValueError, KeyError):
                    continue

    def estimate(self, job: str, input_bytes: int) -> float | None:
        rows = [r for r in self.rows.get(job, []) if r.get("duration_s", 0) > 0][-10:]
        if not rows:
            return None
        if input_bytes > 0 and all(r.get("input_bytes", 0) > 0 for r in rows):
            rates = sorted(r["input_bytes"] / r["duration_s"] for r in rows)
            return input_bytes / rates[len(rates) // 2]
        durs = sorted(r["duration_s"] for r in rows)
        return durs[len(durs) // 2]

    def add(self, job: str, input_bytes: int, duration: float, case: str) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with _log_lock, self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"job": job, "input_bytes": input_bytes, "duration_s": duration,
                                     "case": case, "date": utcnow()}) + "\n")
        except OSError:
            pass


HISTORY: DurationHistory | None = None


def dir_size(path: Path) -> int:
    total = 0
    try:
        for f in path.rglob("*"):
            try:
                if f.is_file():
                    total += f.stat().st_size
            except OSError:
                continue
    except OSError:
        pass
    return total


def fmt_dur(sec: float) -> str:
    sec = int(sec)
    return f"{sec // 3600}h{(sec % 3600) // 60:02d}" if sec >= 3600 else f"{sec // 60}m{sec % 60:02d}s"


# Silent failure patterns common to every tool
GENERIC_WARN_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"Unhandled exception",
    r"Data may be missing",
]


def rm_tree(path: Path) -> None:
    """Robust removal of a results folder: on Windows, rmtree fails on read-only files
    (e.g. copies of evidence); the attribute is removed and the operation retried."""
    def _retry(func, p, _exc):
        try:
            os.chmod(p, stat.S_IREAD | stat.S_IWRITE)
            func(p)
        except OSError:
            pass
    if path.exists():
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=_retry)
        else:
            shutil.rmtree(path, onerror=_retry)


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_watched(step: Step, env) -> tuple[str, int | None, str]:
    """Runs a command while watching the activity of its outputs.

    If nothing is written to watch_dir for stall_timeout seconds, the tool is considered
    stuck (infinite loop, invisible dialog box...) and stopped; its partial outputs are
    kept. Returns (text, return code, state)."""
    import time
    watch = step.watch_dir or step.cwd
    out_file = (step.cwd or Path.cwd()) / f"_step_{os.getpid()}_{threading.get_ident()}.out"
    state = "done"
    with out_file.open("wb") as so:
        p = subprocess.Popen(step.cmd, cwd=step.cwd, stdout=so, stderr=subprocess.STDOUT, env=env,
                             stdin=subprocess.DEVNULL)
        t0 = last_change = time.monotonic()
        last_size = -1
        while p.poll() is None:
            time.sleep(5)
            now = time.monotonic()
            size = dir_size(watch) if watch else 0
            if size != last_size:
                last_size, last_change = size, now
            if now - last_change > step.stall_timeout:
                state = "stalled"
            elif now - t0 > step.timeout:
                state = "timeout"
            if state != "done":
                p.kill()
                p.wait()
                break
    text = out_file.read_bytes().decode("utf-8", "replace")
    out_file.unlink(missing_ok=True)
    return text, p.returncode, state


def run_step(step: Step, log, env) -> dict:
    started = dt.datetime.now(dt.timezone.utc)
    shown = (f"{step.label}: {subprocess.list2cmdline(step.cmd)}" if step.cmd else step.label) if step.func \
        else subprocess.list2cmdline(step.cmd)
    log.write(f"\n$ {shown}\n  (cwd={step.cwd or ''})\n")
    log.flush()
    rec = {"label": step.label, "cmd": step.cmd, "cwd": str(step.cwd) if step.cwd else None,
           "started_utc": started.isoformat(timespec="seconds"), "optional": step.optional}
    text = ""
    try:
        if step.func:
            text = step.func() or ""
            log.write(text)
            rec["returncode"] = 0
            rec["status"] = "ok"
        elif step.stall_timeout and not step.stdout_file:
            text, rc, state = run_watched(step, env)
            log.write(text)
            rec["returncode"] = rc
            if state == "stalled":
                rec["status"] = "stalled"
                log.write(f"\n!! Nothing written for {step.stall_timeout} s: tool considered stuck and stopped "
                          f"(partial outputs kept)\n")
            elif state == "timeout":
                rec["status"] = "timeout"
                log.write(f"\n!! Timeout ({step.timeout} s): command stopped\n")
            else:
                rec["status"] = "ok" if rc in step.ok_codes else "failed"
        elif step.stdout_file:
            step.stdout_file.parent.mkdir(parents=True, exist_ok=True)
            with step.stdout_file.open("wb") as so:
                p = subprocess.run(step.cmd, cwd=step.cwd, stdout=so, stderr=subprocess.PIPE,
                                   timeout=step.timeout, env=env, stdin=subprocess.DEVNULL)
            text = p.stderr.decode("utf-8", "replace")
            log.write(text)
        else:
            p = subprocess.run(step.cmd, cwd=step.cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=step.timeout, env=env, stdin=subprocess.DEVNULL)
            text = p.stdout.decode("utf-8", "replace")
            log.write(text)
        if not step.func and "status" not in rec:
            rec["returncode"] = p.returncode
            rec["status"] = "ok" if p.returncode in step.ok_codes else "failed"
    except subprocess.TimeoutExpired:
        rec["returncode"] = None
        rec["status"] = "timeout"
        log.write(f"\n!! Timeout ({step.timeout} s): command stopped\n")
    except Exception as e:                      # OSError (launch) or error in an internal step
        rec["returncode"] = None
        rec["status"] = "failed"
        log.write(f"\n!! Failure: {e}\n")
    if step.optional and rec["status"] != "ok":
        rec["status"] = "warning"
    rec["_text"] = text
    rec["duration_s"] = round((dt.datetime.now(dt.timezone.utc) - started).total_seconds(), 1)
    log.write(f"\n-> {rec['status']} (code {rec['returncode']}, {rec['duration_s']} s)\n")
    log.flush()
    return rec


def run_steps(job: Job, steps: list[Step], log, env) -> list[dict]:
    """Runs the steps of a job in order. A job with serial_first > 0 runs its first serial_first steps,
    then the others only if those succeeded, `parallel` at a time when parallel > 1 (each step then logs
    into a buffer copied to _run.log when it ends, so that the log is not interleaved)."""
    recs: list[dict] = []
    n_serial = job.serial_first or len(steps)
    for i, st in enumerate(steps[:n_serial], 1):
        PROGRESS[job.id].update(step=i, label=st.label or (Path(st.cmd[0]).stem if st.cmd else ""))
        recs.append(run_step(st, log, env))
    rest = steps[n_serial:]
    if not rest:
        return recs
    if any(r["status"] not in ("ok", "warning") for r in recs):
        log.write(f"\n!! A preliminary step failed: the {len(rest)} other step(s) are not run\n")
        for st in rest:
            recs.append({"label": st.label, "cmd": st.cmd, "status": "skipped", "returncode": None, "duration_s": 0,
                         "_text": "", "note": "not run: a preliminary step failed"})
        return recs
    if job.parallel <= 1:
        for i, st in enumerate(rest, n_serial + 1):
            PROGRESS[job.id].update(step=i, label=st.label or (Path(st.cmd[0]).stem if st.cmd else ""))
            recs.append(run_step(st, log, env))
        return recs

    def one(st: Step):
        buf = io.StringIO()
        rec = run_step(st, buf, env)
        return rec, buf.getvalue()

    done = 0
    results: dict[int, dict] = {}
    with ThreadPoolExecutor(max_workers=job.parallel) as pool:
        futs = {pool.submit(one, st): k for k, st in enumerate(rest)}
        for fut in as_completed(futs):
            rec, text = fut.result()
            results[futs[fut]] = rec
            done += 1
            log.write(text)
            log.flush()
            PROGRESS[job.id].update(step=n_serial + done, label=rec.get("label") or "")
    recs.extend(results[k] for k in range(len(rest)))
    return recs


def run_job(job: Job, ctx: Context, force: bool, dry_run: bool) -> dict:
    out = ctx.out / job.id
    status_file = out / "_status.json"
    base = {"job": job.id, "title": job.title, "tools": {k: ctx.tool_of.get(k) for k in job.tools}}

    present = [a for a in job.artifacts if ctx.files_by_art.get(a)]
    if not present:
        return {**base, "status": "no_input"}
    missing = [k for k in job.tools if not ctx.has(k)]
    if missing:
        return {**base, "status": "tool_missing", "missing": missing}
    if status_file.exists() and not force:
        prev = json.loads(status_file.read_text(encoding="utf-8"))
        if prev.get("status") in ("ok", "partial", "warning"):
            return {**prev, "status": prev["status"], "skipped": "already run (--force to run again)"}

    if out.exists() and not dry_run:
        rm_tree(out)
    out.mkdir(parents=True, exist_ok=True) if not dry_run else None
    steps = job.build(ctx, out)
    if not steps:
        return {**base, "status": "no_input", "note": "no usable input for this job"}
    if dry_run:
        return {**base, "status": "dry_run", "steps": [subprocess.list2cmdline(s.cmd) for s in steps]}

    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    inputs = sorted({f["rel_path"] for a in present for f in ctx.records(a)})
    input_bytes = sum(int(f.get("size") or 0) for a in present for f in ctx.records(a))
    eta = HISTORY.estimate(job.id, input_bytes) if HISTORY else None
    started = utcnow()
    t0 = dt.datetime.now().timestamp()
    PROGRESS[job.id] = {"title": job.title, "step": 0, "total": len(steps), "label": "", "start": t0,
                        "eta": eta, "out": out, "input_bytes": input_bytes, "job": job}
    # Default working folder: some tools (WxTCmd, SQLECmd) drop DLLs (SQLite.Interop.dll) into
    # the current folder; they thus stay in _tmp, which is deleted afterwards.
    tmp_cwd = out / "_tmp"
    tmp_cwd.mkdir(parents=True, exist_ok=True)
    for st in steps:
        if st.cwd is None and not st.func:
            st.cwd = tmp_cwd
    step_recs = []
    try:
        with (out / "_run.log").open("w", encoding="utf-8", errors="replace") as log:
            log.write(f"# {job.title}\n# job={job.id} start={started}\n")
            step_recs = run_steps(job, steps, log, env)
    finally:
        PROGRESS.pop(job.id, None)

    outputs = []
    for f in sorted(out.rglob("*")):
        if f.is_file() and not f.name.startswith("_") and "_tmp" not in f.parts and "_work" not in f.parts:
            outputs.append({"file": str(f.relative_to(ctx.out)), "bytes": f.stat().st_size, "sha256": sha256(f)})
    for scratch in (out / "_tmp", out / "_work"):      # temporary copies (never kept)
        rm_tree(scratch)

    # Silent failures: return code 0 but an error / data-loss message
    patterns = [re.compile(p, re.IGNORECASE) for p in GENERIC_WARN_PATTERNS + job.warn_patterns]
    warnings = []
    for srec in step_recs:
        text = srec.pop("_text", "") or ""
        hits = [ln.strip() for ln in text.splitlines() if any(p.search(ln) for p in patterns)]
        if hits and srec["status"] == "ok":
            srec["status"] = "warning"
        if hits:
            srec["warnings"] = hits[:20]
            warnings.extend(hits[:20])
    for srec in step_recs:
        if srec["status"] == "stalled":
            warnings.append("Tool stuck (nothing written during the watch delay): stopped, partial outputs")
    oks = sum(1 for s in step_recs if s["status"] in ("ok", "warning"))
    status = "ok" if oks == len(step_recs) else ("partial" if oks else "failed")
    if status == "failed" and outputs and any(s["status"] == "stalled" for s in step_recs):
        status = "partial"        # stuck midway: incomplete but usable results
    if status == "ok" and any(s["status"] == "warning" for s in step_recs):
        status = "warning"
    if status not in ("failed",) and not outputs:
        status = "empty"          # the tool ran without producing any file
    rec = {**base, "status": status, "started_utc": started, "ended_utc": utcnow(),
           "duration_s": round(sum(s["duration_s"] for s in step_recs), 1),
           "steps": step_recs, "inputs": inputs, "outputs": outputs, "note": job.note,
           "warnings": warnings[:50]}
    status_file.write_text(json.dumps(rec, ensure_ascii=False, indent=1), encoding="utf-8")
    if HISTORY and status in ("ok", "warning", "partial"):
        HISTORY.add(job.id, input_bytes, rec["duration_s"], str(ctx.case))
    return rec


def protect_collection(ctx: Context) -> int:
    """Read-only attribute on every file of the collection (defense in depth: a tool trying to
    write to evidence fails instead of modifying it). Only the attribute changes.
    To delete a case folder later: attrib -r /s /d <case>\\* (or remove the attribute in Explorer)."""
    n = 0
    paths = [ctx.root.joinpath(*r["rel_path"].split("\\")) for art, recs in ctx.files_by_art.items()
             if art not in ("memory_image", "pcap") for r in recs] + list(ctx.memory_images) + list(ctx.captures)
    for p in paths:
        try:
            if os.access(p, os.W_OK):
                os.chmod(p, stat.S_IREAD)
                n += 1
        except OSError:
            continue
    return n


def recheck_integrity(ctx: Context, inventory: dict) -> dict | None:
    """Recomputes the SHA-1 after parsing: a file matching the inventory that no longer does was
    modified during parsing (evidence tampering, to be reported)."""
    sys.path.insert(0, str(PIPE / "1_inventory"))
    try:
        from inventory import verify_integrity
    except ImportError:
        return None
    before = {f["rel_path"]: f.get("integrity") for f in inventory["files"]}
    recs = [dict(f) for f in inventory["files"]]
    res = verify_integrity(ctx.root, recs)
    changed = [f["original_path"] for f in recs if f.get("integrity") == "different" and before.get(f["rel_path"]) == "ok"]
    res["changed_during_parsing"] = changed
    return res


def load_inventory(case: Path, manifest: Path) -> dict:
    inv_file = case / "inventory" / "inventory.json"
    if not inv_file.exists():
        print("[i] No inventory: running inventory.py")
        subprocess.run([sys.executable, str(PIPE / "1_inventory" / "inventory.py"), str(case), "--manifest", str(manifest)],
                       check=True)
    return json.loads(inv_file.read_text(encoding="utf-8"))


def write_summary(ctx: Context, results: list[dict], integrity: dict | None = None) -> None:
    order = {"failed": 0, "timeout": 0, "stalled": 0, "partial": 1, "warning": 2, "empty": 2, "tool_missing": 3, "ok": 4, "no_input": 5, "dry_run": 6}
    results = sorted(results, key=lambda r: (order.get(r["status"], 9), r["job"]))
    counts = defaultdict(int)
    for r in results:
        counts[r["status"]] += 1
    summary = {"case": str(ctx.case), "collection_root": str(ctx.root), "generated_at": utcnow(),
               "counts": dict(counts), "integrity_after_parsing": integrity, "jobs": results}
    (ctx.out / "run_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")

    icon = {"ok": "✅", "partial": "⚠️", "warning": "⚠️", "empty": "⚠️", "failed": "❌", "timeout": "❌", "tool_missing": "✗",
            "no_input": "—", "dry_run": "·"}
    md = ["# Collection parsing", "", f"- Collection: `{ctx.root}`", f"- Generated: {summary['generated_at']}",
          "- " + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))]
    if integrity:
        ch = integrity["changed_during_parsing"]
        md.append("- Collection integrity after parsing: "
                  + (f"**{len(ch)} file(s) modified during parsing**: " + ", ".join(f"`{p}`" for p in ch[:10]) if ch
                     else "no file modified by parsing"))
    md += ["",
           "| | Job | Status | Duration | Outputs | Note |", "|---|---|---|---:|---:|---|"]
    for r in results:
        note = r.get("skipped") or r.get("note") or ", ".join(r.get("missing", []))
        fails = [s.get("label") or "" for s in r.get("steps", []) if s.get("status") != "ok"]
        if fails and r["status"] == "partial":
            note = f"failures: {', '.join(f for f in fails if f) or len(fails)}"
        if r["status"] == "warning" and r.get("warnings"):
            note = "warning: " + r["warnings"][0][:120].replace("|", "/")
        md.append(f"| {icon.get(r['status'], '?')} | {r['title']} | {r['status']} | {r.get('duration_s', '')} | "
                  f"{len(r.get('outputs', []))} | {note} |")
    md += ["", "Details of each execution: `parsed\\<job>\\_run.log` and `parsed\\jobs.jsonl`."]
    (ctx.out / "run_summary.md").write_text("\n".join(md), encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("case", type=Path, help="Case folder (containing the collection and inventory\\)")
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--out", type=Path, help="Output folder (default: <case>\\parsed)")
    ap.add_argument("--only", help="Comma-separated list of jobs to run")
    ap.add_argument("--skip", help="Comma-separated list of jobs to skip")
    ap.add_argument("--workers", type=int, default=3, help="Parallel jobs (default: 3)")
    ap.add_argument("--force", action="store_true", help="Run again jobs that already succeeded")
    ap.add_argument("--dry-run", action="store_true", help="Show the commands without running them")
    ap.add_argument("--list", action="store_true", help="List the jobs and whether they apply")
    ap.add_argument("--no-live", action="store_true", help="No live display (text progress every 30 s)")
    ap.add_argument("--no-verify", action="store_true", help="Do not re-check the SHA-1 of the collection after parsing")
    ap.add_argument("--memory", type=Path, action="append",
                    help="Memory image of the machine (default: the image found in <case>\\memory\\)")
    ap.add_argument("--pcap", type=Path, action="append",
                    help="Network capture (repeatable; default: the captures found in <case>\\pcap\\)")
    args = ap.parse_args(argv)

    manifest = json.loads(args.manifest.read_text(encoding="utf-8-sig")) if args.manifest.exists() else {"tools": []}
    inventory = load_inventory(args.case, args.manifest)
    out = args.out or (args.case / "parsed")
    out.mkdir(parents=True, exist_ok=True)
    images = memory.find_images(args.case, args.memory)
    missing_img = [str(p) for p in images if not p.is_file()]
    if missing_img:
        raise SystemExit(f"Memory image not found: {', '.join(missing_img)}")
    if len(images) > 1:
        raise SystemExit("Several memory images: " + ", ".join(p.name for p in images)
                         + ". Keep one per case, or choose it with --memory <path>.")
    captures = network.find_captures(args.case, args.pcap)
    missing_cap = [str(p) for p in captures if not p.is_file()]
    if missing_cap:
        raise SystemExit(f"Network capture not found: {', '.join(missing_cap)}")
    ctx = Context(args.case, inventory, manifest, out, images, captures)
    if images:
        print(f"Memory image: {images[0]} ({images[0].stat().st_size / 1e9:.1f} GB)")
    if captures:
        print(f"Network captures: {len(captures)} file(s), {sum(p.stat().st_size for p in captures) / 1e9:.2f} GB")

    jobs = JOBS
    if args.only:
        wanted = {j.strip() for j in args.only.split(",")}
        unknown = wanted - {j.id for j in JOBS}
        if unknown:
            raise SystemExit(f"Unknown jobs: {', '.join(sorted(unknown))}")
        jobs = [j for j in JOBS if j.id in wanted]
    if args.skip:
        skip = {j.strip() for j in args.skip.split(",")}
        jobs = [j for j in jobs if j.id not in skip]

    if args.list:
        for j in jobs:
            present = [a for a in j.artifacts if ctx.files_by_art.get(a)]
            missing = [k for k in j.tools if not ctx.has(k)]
            state = "tool missing: " + ", ".join(missing) if missing else ("applicable" if present else "no input")
            print(f"{j.id:<18} {state:<40} {j.title}")
        return 0

    results = []
    print(f"Collection: {ctx.root}\nOutputs   : {out}\n")
    if not args.dry_run:
        n = protect_collection(ctx)
        if n:
            print(f"[i] {n} collection file(s) set to read-only (evidence protection)\n")
    global HISTORY, _console
    HISTORY = DurationHistory(args.manifest.parent.parent / "logs" / "job_durations.jsonl")
    applicable = [j for j in jobs if any(ctx.files_by_art.get(a) for a in j.artifacts) and all(ctx.has(k) for k in j.tools)]
    t_start = dt.datetime.now().timestamp()

    def run_tracked(job: Job):
        if job in applicable and not args.dry_run and (args.force or not (out / job.id / "_status.json").exists()):
            say(f"  [started     ] {job.id}")
        return run_job(job, ctx, args.force, args.dry_run)

    def bar(frac: float | None, width: int = 18) -> str:
        if frac is None:
            return "▒" * width                               # unknown duration: no estimate
        n = int(round(max(0.0, min(frac, 1.0)) * width))
        return "█" * n + "░" * (width - n)

    def snapshot() -> list[dict]:
        now = dt.datetime.now().timestamp()
        rows = []
        for jid, p in list(PROGRESS.items()):
            el = now - p["start"]
            real = p["job"].progress(ctx, p["out"]) if p["job"].progress else None
            if real is not None and real > 0:
                # measured progress: remaining time extrapolated from the observed pace
                frac, remain = real, el * (1 - real) / real
            elif p["eta"]:
                frac = min(el / p["eta"], 0.99)
                remain = max(p["eta"] - el, 0)
            elif p["total"] > 1:
                frac, remain = (p["step"] - 1) / p["total"], None
            else:
                frac, remain = None, None
            rows.append({"job": jid, "title": p["title"], "frac": frac, "step": p["step"], "total": p["total"],
                         "label": p["label"], "mb": dir_size(p["out"]) / 1e6, "elapsed": el, "remain": remain})
        return sorted(rows, key=lambda r: -r["elapsed"])

    def header(done: int) -> str:
        return (f"Jobs: {done}/{len(applicable)} done · {len(PROGRESS)} running · "
                f"elapsed {fmt_dur(dt.datetime.now().timestamp() - t_start)}")

    def render(done: int):
        from rich.table import Table
        t = Table(title=header(done), title_justify="left", expand=False, show_lines=False, box=None, padding=(0, 1))
        for col, kw in (("Job", {}), ("Artifact / tool", {"max_width": 42, "overflow": "ellipsis"}),
                        ("Progress", {}), ("%", {"justify": "right"}), ("Step", {"max_width": 30, "overflow": "ellipsis"}),
                        ("Written", {"justify": "right"}), ("Elapsed", {"justify": "right"}), ("Remaining (est.)", {"justify": "right"})):
            t.add_column(col, **kw)
        for r in snapshot():
            pct = f"{r['frac'] * 100:.0f}%" if r["frac"] is not None else "?"
            t.add_row(r["job"], r["title"], bar(r["frac"]), pct,
                      f"{r['step']}/{r['total']} {r['label']}", f"{r['mb']:.1f} MB",
                      fmt_dur(r["elapsed"]), fmt_dur(r["remain"]) if r["remain"] is not None else "first run")
        return t

    def text_status(done: int):
        lines = [f"  ... {header(done)}"]
        for r in snapshot():
            pct = f"{r['frac'] * 100:3.0f}%" if r["frac"] is not None else "  ?"
            rest = f"~{fmt_dur(r['remain'])} left" if r["remain"] is not None else "unknown duration"
            lines.append(f"      {r['job']:<16} [{bar(r['frac'])}] {pct}  step {r['step']}/{r['total']}  "
                         f"{r['mb']:.1f} MB  {fmt_dur(r['elapsed'])}  {rest}")
        say("\n".join(lines))

    live = None
    if not args.dry_run and not args.no_live and sys.stdout.isatty():
        try:
            from rich.console import Console
            from rich.live import Live
            _console = Console()
            live = Live(render(0), console=_console, refresh_per_second=1, transient=True)
            live.start()
        except Exception:
            live, _console = None, None

    done_count = 0
    last_text = 0.0
    try:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futures = {pool.submit(run_tracked, j): j for j in jobs}
            pending = set(futures)
            while pending:
                done, pending = wait(pending, timeout=1, return_when=FIRST_COMPLETED)
                for fut in done:
                    j = futures[fut]
                    try:
                        rec = fut.result()
                    except Exception as e:                       # orchestrator error, not a tool error
                        rec = {"job": j.id, "title": j.title, "status": "failed", "error": repr(e)}
                    results.append(rec)
                    if j in applicable:
                        done_count += 1
                    extra = rec.get("skipped") or (", ".join(rec.get("missing", [])) if rec["status"] == "tool_missing" else "")
                    if rec["status"] == "warning" and rec.get("warnings"):
                        extra = "! " + rec["warnings"][0][:90]
                    say(f"  [{rec['status']:<12}] {j.id:<18} {rec.get('duration_s', ''):>8} {extra}")
                    if args.dry_run and rec.get("steps"):
                        for st in rec["steps"]:
                            say(f"      {st}")
                    if not args.dry_run and rec["status"] not in ("no_input", "tool_missing") and not rec.get("skipped"):
                        with _log_lock, (out / "jobs.jsonl").open("a", encoding="utf-8") as jl:
                            jl.write(json.dumps(rec, ensure_ascii=False) + "\n")
                if live is not None:
                    live.update(render(done_count))
                elif not args.dry_run and PROGRESS and dt.datetime.now().timestamp() - last_text >= 30:
                    last_text = dt.datetime.now().timestamp()
                    text_status(done_count)
    finally:
        if live is not None:
            live.stop()
            _console = None

    if not args.dry_run:
        # Summary of the COMPLETE state of the parsed\ folder (not only the jobs of this run)
        current = {r["job"]: r for r in results}
        full = []
        for j in JOBS:
            if j.id in current:
                full.append(current[j.id])
            elif (out / j.id / "_status.json").exists():
                full.append(json.loads((out / j.id / "_status.json").read_text(encoding="utf-8")))
        integ = recheck_integrity(ctx, inventory) if not args.no_verify else None
        write_summary(ctx, full, integ)
        if integ and integ["changed_during_parsing"]:
            print(f"\n[!] EVIDENCE TAMPERING: {len(integ['changed_during_parsing'])} collection file(s) modified "
                  f"during parsing: {', '.join(integ['changed_during_parsing'][:5])}")
        print(f"\nSummary: {out / 'run_summary.md'}")
    failed = [r for r in results if r["status"] in ("failed", "timeout")]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
