#!/usr/bin/env python3
"""
Sleuthline - step 1: inventory of a KAPE collection and coverage report.

Walks a KAPE collection (Targets only, e.g. !SANS_Triage), classifies every file
by artifact type, determines which installed parser handles it (from
<root>\\tools\\tools-manifest.json) and writes:

  <out>\\inventory.json   one record per file (original path, size, KAPE SHA-1,
                          timestamps, artifact, user, integrity check)
  <out>\\coverage.json    per-artifact summary (presence, parsers, status)
  <out>\\coverage.md      the same report, human-readable
  <out>\\gaps.json        what no registered tool handles (see docs\\POLICY_parsers.md)

Standard library only. Read-only on the collection.

Usage:
  python inventory.py C:\\Sleuthline\\cases\\test01
  python inventory.py C:\\Sleuthline\\cases\\test01\\raw --out C:\\Sleuthline\\cases\\test01\\inventory
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import ntpath
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
PIPE = Path(__file__).resolve().parents[1]      # <root>\pipeline (1_inventory, 2_parsing, 3_normalize, 4_analysis, config, docs, local)
ROOT = PIPE.parent                                 # installation root (default C:\Sleuthline)
DEFAULT_MANIFEST = ROOT / "tools" / "tools-manifest.json"
CONFIG_DIR = PIPE / "config"                       # validated files (source: <repository>\pipeline\config)
LOCAL_DIR = PIPE / "local"                         # files specific to this VM (never overwritten by deployment)
DEFAULT_REGISTRY = CONFIG_DIR / "parser_registry.json"   # VALIDATED decisions
POLICY_FILE = "docs\\POLICY_parsers.md"

# Coverage statuses
COVERED, NOT_COVERED, CONTEXT, ABSENT = "COVERED", "NOT COVERED", "CONTEXT", "ABSENT"


# --------------------------------------------------------------------------
# Artifact catalog
#   id        : stable identifier (reused by the orchestrator and the DuckDB database)
#   parsers   : "executables" keys of the manifest (or "native" = internal Python parsing)
#   expected  : expected in a !SANS_Triage collection of a Windows 10/11 workstation
#   regex     : applied to the normalized original path (backslashes, no volume letter)
# Order matters: the first matching rule wins.
# --------------------------------------------------------------------------
@dataclass
class Artifact:
    id: str
    label: str
    category: str
    regex: str
    parsers: list[str]
    expected: bool = True
    note: str = ""
    context: bool = False      # raw content, no parsing expected (context only)
    rx: re.Pattern = field(init=False, repr=False)

    def __post_init__(self):
        self.rx = re.compile(self.regex, re.IGNORECASE)


CATALOG: list[Artifact] = [
    # --- NTFS file system
    Artifact("ntfs_mft", "$MFT", "File system", r"^\\\$MFT$", ["MFTECmd"]),
    Artifact("ntfs_usnjrnl", "$UsnJrnl:$J", "File system", r"^\\\$Extend\\\$UsnJrnl.*\$J$|^\\\$Extend\\\$J$", ["MFTECmd"]),
    Artifact("ntfs_logfile", "$LogFile", "File system", r"^\\\$LogFile$", ["LogFileParser", "MFTECmd"]),
    Artifact("ntfs_boot", "$Boot", "File system", r"^\\\$Boot$", ["MFTECmd"]),
    Artifact("ntfs_sds", "$Secure:$SDS", "File system", r"^\\\$Secure_\$SDS$|^\\\$Secure:\$SDS$", ["MFTECmd"]),
    Artifact("ntfs_other", "Other NTFS metadata", "File system", r"^\\\$Extend\\", [], expected=False,
             note="$UsnJrnl:$Max, $TxfLog...: context only", context=True),
    # --- Event logs
    Artifact("evtx", "Event logs (EVTX)", "Logs", r"\.evtx$",
             ["hayabusa", "chainsaw", "zircolite", "EvtxECmd"]),
    # --- Execution
    Artifact("prefetch", "Prefetch", "Execution", r"\\Windows\\Prefetch\\[^\\]+\.pf$", ["PECmd"]),
    Artifact("amcache", "Amcache.hve", "Execution", r"\\AppCompat\\Programs\\Amcache\.hve$", ["AmcacheParser"]),
    Artifact("amcache_logs", "Amcache (transaction logs)", "Execution", r"\\AppCompat\\Programs\\Amcache\.hve\.LOG\d$", ["AmcacheParser"], expected=False),
    Artifact("recentfilecache", "RecentFileCache.bcf", "Execution", r"RecentFileCache\.bcf$", ["RecentFileCacheParser"], expected=False,
             note="Windows 7 / 2008 R2 only"),
    Artifact("srum", "SRUM (SRUDB.dat)", "Execution", r"\\System32\\SRU\\SRUDB\.dat$", ["SrumECmd"]),
    Artifact("srum_logs", "SRUM (ESE logs)", "Execution", r"\\System32\\SRU\\", ["SrumECmd"], expected=False,
             note="ESE side files, used for SRUDB.dat consistency"),
    Artifact("sum_ual", "User Access Logging (SUM)", "Execution", r"\\LogFiles\\Sum\\.*\.mdb$", ["SumECmd"], expected=False,
             note="Windows Server only"),
    Artifact("pca", "Program Compatibility Assistant", "Execution", r"\\appcompat\\pca\\", ["native"], expected=False,
             note="Windows 11 22H2+"),
    # --- Registry
    Artifact("reg_system", "SYSTEM hive", "Registry", r"\\System32\\config\\SYSTEM$", ["RECmd", "AppCompatCacheParser"]),
    Artifact("reg_software", "SOFTWARE hive", "Registry", r"\\System32\\config\\SOFTWARE$", ["RECmd"]),
    Artifact("reg_sam", "SAM hive", "Registry", r"\\System32\\config\\SAM$", ["RECmd"]),
    Artifact("reg_security", "SECURITY hive", "Registry", r"\\System32\\config\\SECURITY$", ["RECmd"]),
    Artifact("reg_default", "DEFAULT hive", "Registry", r"\\System32\\config\\DEFAULT$", ["RECmd"]),
    Artifact("reg_regback", "RegBack hives (backups)", "Registry", r"\\System32\\config\\RegBack\\", ["RECmd"], expected=False),
    Artifact("reg_ntuser", "NTUSER.DAT", "Registry", r"\\NTUSER\.DAT$", ["RECmd"]),
    Artifact("reg_usrclass", "UsrClass.dat (ShellBags)", "Registry", r"\\UsrClass\.dat$", ["RECmd", "SBECmd"]),
    Artifact("reg_txlogs", "Registry transaction logs", "Registry", r"(\\System32\\config\\[^\\]+|NTUSER\.DAT|UsrClass\.dat)\.LOG\d?$", ["RECmd"], expected=False,
             note="Replayed by RECmd for dirty hives"),
    # --- User activity
    Artifact("lnk", "LNK files (Recent)", "User activity", r"\.lnk$", ["LECmd"]),
    Artifact("jumplists", "Jump Lists", "User activity", r"\.(automaticDestinations|customDestinations)-ms$", ["JLECmd"]),
    # Before browser caches: a .rdp received by e-mail / downloaded (INetCache, Content.Outlook) is classified here
    Artifact("rdp_files", "RDP connection files (.rdp, Default.rdp)", "Remote access", r"^\\Users\\[^\\]+\\.*\.rdp$",
             ["native"], expected=False,
             note="Default.rdp (last mstsc connection) and received or downloaded .rdp files; passwords excluded"),
    Artifact("notepad_tabs", "Windows 11 Notepad tabs (TabState)", "User activity",
             r"\\Packages\\Microsoft\.WindowsNotepad_[^\\]+\\LocalState\\TabState\\", ["dissect"], expected=False,
             note="Tab content, including never-saved tabs; Windows 11"),
    Artifact("recyclebin_i", "Recycle Bin ($I)", "User activity", r"\\\$Recycle\.Bin\\[^\\]+\\\$I[^\\]*$", ["RBCmd"]),
    Artifact("recyclebin_r", "Recycle Bin ($R, deleted content)", "User activity", r"\\\$Recycle\.Bin\\[^\\]+\\\$R[^\\]*$", ["native"], expected=False,
             note="Content of deleted files: hash and type, to correlate with $I"),
    Artifact("timeline", "Windows Timeline (ActivitiesCache.db)", "User activity", r"\\ConnectedDevicesPlatform\\.*\\ActivitiesCache\.db(-wal|-shm)?$", ["WxTCmd"]),
    Artifact("search_index", "Windows Search index", "User activity", r"\\Search\\Data\\Applications\\Windows\\Windows\.(edb|db)$", ["sidr"]),
    Artifact("search_index_logs", "Windows Search index (side files)", "User activity", r"\\Search\\Data\\Applications\\Windows\\", ["sidr"], expected=False),
    Artifact("thumbcache", "Thumbcache (thumbnails)", "User activity", r"\\Microsoft\\Windows\\Explorer\\(thumb|icon)cache_[^\\]*\.db$",
             ["dissect"], expected=False, note="Images viewed in Explorer (including deleted files); KAPE target ThumbCache"),
    Artifact("ps_history", "PowerShell history (PSReadLine)", "User activity", r"\\PSReadLine\\[^\\]*_history\.txt$", ["native"]),
    Artifact("notifications", "Notifications (wpndatabase.db)", "User activity", r"\\Notifications\\wpndatabase\.db$", ["SQLECmd"], expected=False),
    # --- Browsers
    Artifact("chromium", "Chromium browsers (Chrome / Edge / Brave)", "Browsers",
             r"\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser)\\User Data\\", ["hindsight", "SQLECmd"]),
    Artifact("firefox", "Firefox", "Browsers", r"\\Mozilla\\Firefox\\Profiles\\", ["SQLECmd"]),
    Artifact("webcache", "WebCache (IE / legacy Edge, ESE)", "Browsers", r"\\Microsoft\\Windows\\WebCache\\", [], expected=False,
             note="ESE database WebCacheV01.dat: IE / legacy Edge history and downloads"),
    Artifact("edge_legacy", "Legacy Edge (UWP): cache and data", "Browsers", r"\\Packages\\Microsoft\.MicrosoftEdge_8wekyb3d8bbwe\\", [], expected=False,
             note="Raw cache files; history is in WebCacheV01.dat", context=True),
    Artifact("ie_cache", "Internet Explorer cache / INetCache", "Browsers", r"\\Microsoft\\(Windows\\(INetCache|History|Explorer)|Internet Explorer)\\", [], expected=False,
             note="Raw content, context only", context=True),
    # --- Persistence
    Artifact("sched_tasks", "Scheduled tasks (XML)", "Persistence", r"\\System32\\Tasks\\", ["native"]),
    Artifact("wmi_repo", "WMI repository (OBJECTS.DATA)", "Persistence", r"\\wbem\\Repository\\(OBJECTS\.DATA|INDEX\.BTR|MAPPING\d\.MAP)$", ["PyWMIPersistenceFinder"]),
    Artifact("startup", "Startup folders", "Persistence", r"\\Start Menu\\Programs\\Startup\\", ["native"], expected=False),
    Artifact("bits", "BITS jobs (qmgr)", "Persistence", r"\\Network\\Downloader\\qmgr.*\.(db|dat)$", ["BitsParser"]),
    # --- Remote access
    Artifact("rdp_cache", "RDP bitmap cache", "Remote access", r"\\Terminal Server Client\\Cache\\", ["bmc-tools"], expected=False,
             note="Only present if the host opened outbound RDP sessions"),
    Artifact("remote_access", "Remote access tools (AnyDesk, TeamViewer, Splashtop, RustDesk)", "Remote access",
             r"\\(AnyDesk|TeamViewer|Splashtop[^\\]*|RustDesk)\\", ["dissect"], expected=False,
             note="Connection and transfer logs (ad.trace, connection_trace.txt, Connections_incoming.txt...); "
                  "collection: KAPE target RemoteAdmin in addition to !SANS_Triage"),
    Artifact("remote_access_other", "Other remote access tools / RMM (ScreenConnect, Atera, Kaseya...)", "Remote access",
             r"\\(ScreenConnect[^\\]*|ConnectWiseControl|ATERA Networks|Kaseya|NinjaRMMAgent|LogMeIn[^\\]*|Action1)\\", [],
             expected=False, context=True,
             note="No recognized parser: raw files; activity via EVTX (Application), $MFT, Prefetch, services"),
    # --- Text logs
    Artifact("setupapi", "setupapi.dev.log (USB devices)", "Logs", r"\\INF\\setupapi\..*\.log$", ["native"]),
    Artifact("panther", "Windows setup logs (Panther)", "Logs",
             r"\\Windows\\Panther\\(UnattendGC\\)?setup(act|err)\.log$|\\\$Windows\.~BT\\Sources\\Panther\\setup(act|err)\.log$",
             ["native"], expected=False, note="Windows installation and upgrades (dates, versions, migration)"),
    Artifact("panther_other", "Panther (other files)", "Logs", r"\\Panther\\", [], expected=False, context=True,
             note="unattend.xml may contain passwords: not parsed (secrets excluded); context only"),
    Artifact("wifi_profiles", "Wi-Fi profiles (Wlansvc)", "Network", r"\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\.*\.xml$",
             ["native"], expected=False, note="SSID, authentication, encryption; Wi-Fi key not extracted"),
    Artifact("defender", "Windows Defender logs", "Logs", r"\\Windows Defender\\(Support|Scans\\History)\\|\\Temp\\MpCmdRun\.log$", ["native"], expected=False),
    Artifact("onedrive_db", "OneDrive (SyncEngineDatabase.db)", "Cloud",
             r"\\AppData\\Local\\Microsoft\\OneDrive\\settings\\[^\\]+\\SyncEngineDatabase\.db(-wal|-shm|-journal)?$", [],
             expected=False, note="Synchronized tree (files, folders, dates); no parser installed: "
                                  "OneDriveExplorer proposed (see parser_registry.json)"),
    Artifact("onedrive", "OneDrive (ODL logs and settings)", "Cloud", r"\\AppData\\Local\\Microsoft\\OneDrive\\(logs|settings)\\", [], expected=False,
             note="Cloud synchronization / exfiltration (.odl/.odlgz/.aodl logs)"),
    Artifact("dpapi", "DPAPI master keys", "Credentials", r"\\AppData\\Roaming\\Microsoft\\Protect\\", [], expected=False, context=True,
             note="Needed to decrypt user secrets; not parsed"),
    Artifact("etw", "ETW traces / diagnostics (.etl, WDI)", "Logs",
             r"\.etl(\.\d+)?$|\\System32\\WDI\\|\\LogFiles\\WMI\\RtBackup\\", [], expected=False, context=True,
             note="SleepStudy, WDI, DeliveryOptimization, WMI autologgers: specialized ETW parsing not planned"),
    Artifact("wer", "Error reports (WER)", "Logs", r"\\WER\\.*\.wer$", ["native"], expected=False),
    Artifact("hosts", "hosts file", "Configuration", r"\\drivers\\etc\\", ["native"], expected=False),
    Artifact("desktop_ini", "desktop.ini", "Miscellaneous", r"\\desktop\.ini$", [], expected=False, note="No analytical value", context=True),
]

USER_RX = re.compile(r"^\\Users\\([^\\]+)\\", re.IGNORECASE)
SERVICE_PROFILE_RX = re.compile(r"\\ServiceProfiles\\([^\\]+)\\", re.IGNORECASE)


# --------------------------------------------------------------------------
# Reading the collection
# --------------------------------------------------------------------------
def find_collection_root(path: Path) -> Path:
    """Accepts the case folder or its raw\\ subfolder and returns the KAPE root."""
    for candidate in (path, path / "raw"):
        if candidate.is_dir() and (list(candidate.glob("*_CopyLog.csv")) or _volume_dirs(candidate)):
            return candidate
    raise SystemExit(f"No KAPE collection found in {path} (neither *_CopyLog.csv nor a volume folder)")


def _volume_dirs(root: Path) -> list[Path]:
    return [p for p in root.iterdir() if p.is_dir() and re.fullmatch(r"[A-Za-z]", p.name)]


def load_copylog(root: Path) -> dict[str, dict]:
    """Indexes the KAPE CopyLogs by path relative to the KAPE output (lower case).

    DestinationFile holds the absolute path on the collection machine
    (e.g. C:\\kape_output\\C\\Windows\\..., or ...\\LongFileNames\\<guid>.js):
    the common output folder is removed to get the relative path.
    """
    rows = []
    for log in sorted(root.glob("*_CopyLog.csv")):
        with log.open(encoding="utf-8-sig", newline="") as fh:
            rows.extend(r for r in csv.DictReader(fh) if r.get("DestinationFile"))
    if not rows:
        return {}
    try:
        base = ntpath.commonpath([r["DestinationFile"] for r in rows])
    except ValueError:
        base = ""
    # If every copy comes from a single volume, the common path includes that volume (...\<case>\C):
    # walk up to the folder whose relative paths really exist in the collection.
    sample = rows[:: max(1, len(rows) // 50)]
    for _ in range(3):
        if not base:
            break
        hits = sum(1 for r in sample if r["DestinationFile"].lower().startswith(base.lower())
                   and (root / r["DestinationFile"][len(base):].lstrip("\\").replace("\\", os.sep)).exists())
        if hits >= len(sample) / 2:
            break
        base = ntpath.dirname(base)
    index: dict[str, dict] = {}
    for r in rows:
        dest = r["DestinationFile"]
        rel = dest[len(base):].lstrip("\\") if base and dest.lower().startswith(base.lower()) else dest
        index[rel.lower()] = r
    return index


def load_long_names(root: Path) -> dict[str, str]:
    """LongFileNames\\<guid>.<ext> -> original path (files with paths > 260 characters)."""
    mapping: dict[str, str] = {}
    lfn = root / "LongFileNames"
    if not lfn.is_dir():
        return mapping
    for info in lfn.glob("*_OriginalPathInfo.txt"):
        guid = info.name[: -len("_OriginalPathInfo.txt")]
        original = info.read_text(encoding="utf-8-sig", errors="replace").strip()
        for f in lfn.iterdir():
            if f.name.startswith(guid) and not f.name.endswith("_OriginalPathInfo.txt"):
                mapping[str(f.relative_to(root))] = original
    return mapping


def iter_files(root: Path):
    """(path relative to the collection, original path 'C\\...') for every file."""
    long_names = load_long_names(root)
    for vol in _volume_dirs(root):
        for dirpath, _dirs, files in os.walk(vol):
            for name in files:
                full = Path(dirpath) / name
                rel = str(full.relative_to(root)).replace("/", "\\")
                yield full, rel, rel
    for rel, original in long_names.items():
        yield root / rel, rel.replace("/", "\\"), original.replace("/", "\\")


def sha1_file(path: Path) -> str | None:
    h = hashlib.sha1()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 22), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def modified_after_copy(path: Path, copied_utc: str | None, tolerance_s: int = 120) -> bool:
    """Modification time of the copy later than the KAPE copy time (CopiedTimestamp, UTC):
    the file was rewritten after collection (e.g. SQLite database opened for writing by a tool)."""
    if not copied_utc:
        return False
    try:
        copied = dt.datetime.fromisoformat(copied_utc.strip()[:26]).replace(tzinfo=dt.timezone.utc)
        mtime = dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc)
    except (OSError, ValueError):
        return False
    return (mtime - copied).total_seconds() > tolerance_s


def verify_integrity(root: Path, records: list[dict]) -> dict:
    """Recomputes the SHA-1 of every collected file and compares it with the one recorded by KAPE at copy
    time (CopyLog, SourceFileSha1): shows that the collection has not changed since acquisition."""
    t0 = dt.datetime.now()
    ok = mismatch = missing = no_ref = live = 0
    examples, live_examples = [], []
    for r in records:
        ref = (r.get("sha1") or "").strip().lower()
        if not ref:
            no_ref += 1
            r["integrity"] = "no_reference"
            continue
        path = root.joinpath(*r["rel_path"].split("\\"))
        actual = sha1_file(path)
        if actual is None:
            missing += 1
            r["integrity"] = "missing"
        elif actual == ref:
            ok += 1
            r["integrity"] = "ok"
        elif r.get("kape_deferred") and not modified_after_copy(path, r.get("copied_utc")):
            # Deferred raw copy (locked file, e.g. $MFT, $LogFile): KAPE hashes the live source at a different
            # moment than the copy; a difference is expected when the file changes constantly.
            live += 1
            r["integrity"] = "different_raw_live_copy"
            live_examples.append(r["original_path"])
        else:
            mismatch += 1
            r["integrity"] = "different"
            examples.append(r["original_path"])
    verdict = "INTACT" if not mismatch and not missing else "ANOMALIES"
    return {"verdict": verdict, "ok": ok, "mismatch": mismatch, "missing": missing, "no_reference": no_ref,
            "live_copy_mismatch": live, "live_copy_examples": live_examples[:50],
            "mismatch_examples": examples[:50], "checked_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
            "duration_s": round((dt.datetime.now() - t0).total_seconds(), 1),
            "method": "SHA-1 recomputed vs SourceFileSha1 of the KAPE *_CopyLog.csv"}


def classify(origin_no_volume: str) -> Artifact | None:
    for art in CATALOG:
        if art.rx.search(origin_no_volume):
            return art
    return None


def owner_of(origin_no_volume: str) -> str | None:
    m = USER_RX.match(origin_no_volume)
    if m:
        return m.group(1)
    m = SERVICE_PROFILE_RX.search(origin_no_volume)
    return f"service:{m.group(1)}" if m else None


# --------------------------------------------------------------------------
# Tool manifest
# --------------------------------------------------------------------------
def load_parsers(manifest_path: Path) -> dict[str, dict]:
    """Executable key -> {tool, status, version, path}."""
    parsers: dict[str, dict] = {
        "native": {"tool": "orchestrator", "status": "OK", "version": "-", "path": "(internal Python parsing)"}
    }
    if not manifest_path.is_file():
        print(f"[!] Manifest not found: {manifest_path} (parser status unknown)", file=sys.stderr)
        return parsers
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    for tool in manifest.get("tools", []):
        for key, path in (tool.get("executables") or {}).items():
            parsers[key] = {"tool": tool["name"], "status": tool["status"], "version": tool.get("version"), "path": path}
    return parsers


def check_registry_keys(parsers: dict) -> list[str]:
    """Parser keys of the catalog/registry missing from the manifest (configuration error)."""
    unknown = sorted({k for a in CATALOG for k in a.parsers if k not in parsers})
    for k in unknown:
        users = [a.id for a in CATALOG if k in a.parsers]
        print(f"[!] Parser key '{k}' unknown to the manifest (artifacts: {', '.join(users)}): "
              f"check parser_registry.json", file=sys.stderr)
    return unknown


def parser_ok(info: dict | None) -> bool:
    return bool(info) and str(info.get("status", "")).startswith(("OK", "WARN"))


def apply_registry(registry_path: Path) -> dict:
    """The parser registry is authoritative: it replaces the catalog's default parsers.

    A decision taken by applying POLICY_parsers.md (new tool chosen for an artifact)
    therefore takes effect without editing this script.
    """
    if not registry_path.is_file():
        print(f"[!] Parser registry not found: {registry_path} (default catalog used)", file=sys.stderr)
        return {}
    registry = json.loads(registry_path.read_text(encoding="utf-8-sig"))
    entries = registry.get("artifacts", {})
    for art in CATALOG:
        e = entries.get(art.id)
        if e is not None:
            art.parsers = list(e.get("parsers") or [])
    return entries


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------
def build(root: Path, manifest_path: Path, verify: bool = True):
    copylog = load_copylog(root)
    parsers = load_parsers(manifest_path)
    if manifest_path.is_file():
        check_registry_keys(parsers)

    records = []
    for full, rel, origin in iter_files(root):
        origin_nv = origin[1:] if re.match(r"^[A-Za-z]\\", origin) else origin  # strip the volume letter
        art = classify(origin_nv)
        meta = copylog.get(rel.lower(), {})
        try:
            size = full.stat().st_size
        except OSError:
            size = int(meta.get("FileSize") or 0)
        records.append({
            "rel_path": rel,
            "original_path": meta.get("SourceFile") or (origin[0] + ":" + origin_nv),
            "artifact": art.id if art else "unclassified",
            "user": owner_of(origin_nv),
            "size": size,
            "sha1": meta.get("SourceFileSha1"),
            "kape_deferred": (meta.get("DeferredCopy") or "").lower() == "true" or None,
            "copied_utc": meta.get("CopiedTimestamp"),
            "created_utc": meta.get("CreatedOnUtc"),
            "modified_utc": meta.get("ModifiedOnUtc"),
            "accessed_utc": meta.get("LastAccessedOnUtc"),
        })

    integrity = verify_integrity(root, records) if verify and copylog else None

    by_art: dict[str, list] = defaultdict(list)
    for r in records:
        by_art[r["artifact"]].append(r)

    coverage = []
    for art in CATALOG:
        files = by_art.get(art.id, [])
        if not files and not art.expected:
            continue
        p_status = [{"key": k, **(parsers.get(k) or {"tool": None, "status": "ABSENT"})} for k in art.parsers]
        usable = [p for p in p_status if parser_ok(p)]
        if not files:
            status = ABSENT          # expected but not in the collection
        elif art.context:
            status = CONTEXT         # kept as is, no parser needed
        elif usable:
            status = COVERED
        else:
            status = NOT_COVERED     # present but no usable parser
        coverage.append({
            "artifact": art.id, "label": art.label, "category": art.category,
            "files": len(files), "bytes": sum(f["size"] for f in files),
            "users": sorted({f["user"] for f in files if f["user"]}),
            "parsers": p_status, "status": status, "note": art.note,
        })

    unclassified = by_art.get("unclassified", [])
    gaps = build_gaps(coverage, unclassified)
    summary = {
        "collection_root": str(root),
        "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "manifest": str(manifest_path),
        "files_total": len(records),
        "bytes_total": sum(r["size"] for r in records),
        "copylog_entries": len(copylog),
        "users": sorted({r["user"] for r in records if r["user"] and not r["user"].startswith("service:")}),
        "kape_copy_window": _copy_window(copylog),
        "status_counts": {s: sum(1 for c in coverage if c["status"] == s) for s in (COVERED, NOT_COVERED, CONTEXT, ABSENT)},
        "unclassified_files": len(unclassified),
        "gaps": len(gaps["items"]),
        "integrity": integrity,
    }
    return records, coverage, unclassified, summary, gaps


def build_gaps(coverage: list, unclassified: list) -> dict:
    """Everything no registered tool handles: to be submitted to POLICY_parsers.md."""
    items = []
    for c in coverage:
        if c["status"] == NOT_COVERED:
            reason = "no registered parser" if not c["parsers"] else "registered parser(s) not installed or failing"
            items.append({"kind": "artifact_not_covered", "artifact": c["artifact"], "label": c["label"],
                          "files": c["files"], "parsers": [p["key"] for p in c["parsers"]], "reason": reason})
    groups: dict[str, list] = defaultdict(list)
    for r in unclassified:
        ext = Path(r["original_path"]).suffix.lower() or "(no extension)"
        folder = "\\".join(r["original_path"].split("\\")[:-1])
        groups[(folder, ext)].append(r)
    for (folder, ext), rs in sorted(groups.items(), key=lambda x: -len(x[1])):
        items.append({"kind": "unknown_files", "folder": folder, "extension": ext, "files": len(rs),
                      "examples": [r["original_path"] for r in rs[:3]]})
    return {
        "policy": POLICY_FILE,
        "action": ("For each item: apply the procedure in POLICY_parsers.md (look for an existing tool before "
                   "writing any custom parser), record the proposal in local\\registry_proposals.json and submit "
                   "it to the analyst - never install anything automatically. Validated decisions go into the "
                   "repository (install script + pipeline\\config\\parser_registry.json)."),
        "items": items,
    }


def _copy_window(copylog: dict) -> list[str] | None:
    ts = sorted(r["CopiedTimestamp"] for r in copylog.values() if r.get("CopiedTimestamp"))
    return [ts[0], ts[-1]] if ts else None


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def render_md(coverage, unclassified, summary, gaps=None) -> str:
    icon = {COVERED: "✅", NOT_COVERED: "⚠️", CONTEXT: "ℹ️", ABSENT: "—"}
    out = [
        "# Collection inventory and coverage",
        "",
        f"- Collection: `{summary['collection_root']}`",
        f"- Files: {summary['files_total']} ({human(summary['bytes_total'])})",
        f"- Users: {', '.join(summary['users']) or '-'}",
    ]
    if summary["kape_copy_window"]:
        out.append(f"- KAPE copy: {summary['kape_copy_window'][0]} → {summary['kape_copy_window'][1]} (UTC)")
    integ = summary.get("integrity")
    if integ:
        out.append(f"- Integrity (KAPE SHA-1): **{integ['verdict']}**: {integ['ok']} matching, {integ['mismatch']} different, "
                   f"{integ['missing']} missing, {integ['no_reference']} without hash, "
                   f"{integ.get('live_copy_mismatch', 0)} expected difference(s) on raw live copies")
        out += [f"  - different: `{p}`" for p in integ["mismatch_examples"][:10]]
        out += [f"  - raw live copy (expected difference): `{p}`" for p in integ.get("live_copy_examples", [])[:10]]
    else:
        out.append("- Integrity: not checked (no KAPE CopyLog, or --no-verify)")
    sc = summary["status_counts"]
    out += [f"- Artifacts: {sc[COVERED]} covered, {sc[NOT_COVERED]} not covered, "
            f"{sc[CONTEXT]} context only, {sc[ABSENT]} expected but absent", ""]

    cats: dict[str, list] = defaultdict(list)
    for c in coverage:
        cats[c["category"]].append(c)
    for cat, items in cats.items():
        out += [f"## {cat}", "", "| | Artifact | Files | Size | Parsers | Note |", "|---|---|---:|---:|---|---|"]
        for c in items:
            ps = ", ".join(
                f"{p['key']}{'' if parser_ok(p) else ' ✗'}" for p in c["parsers"]
            ) or "none"
            users = f" ({', '.join(c['users'])})" if c["users"] else ""
            out.append(f"| {icon[c['status']]} | {c['label']}{users} | {c['files']} | {human(c['bytes'])} | {ps} | {c['note']} |")
        out.append("")

    if unclassified:
        out += ["## Unclassified files", ""]
        groups: dict[str, int] = defaultdict(int)
        for r in unclassified:
            groups["\\".join(r["rel_path"].split("\\")[:6])] += 1
        for g, n in sorted(groups.items(), key=lambda x: -x[1])[:30]:
            out.append(f"- {n} × `{g}`")
        out.append("")
    if gaps and gaps["items"]:
        out += ["## Gaps to handle", "",
                f"{len(gaps['items'])} item(s) in `gaps.json`. Rule: **{POLICY_FILE}** "
                "(look for an existing tool before writing a parser, record the proposal in "
                "`local\\registry_proposals.json`, install nothing without validation).", ""]
        for g in gaps["items"]:
            if g["kind"] == "artifact_not_covered":
                out.append(f"- Artifact not covered: **{g['label']}** ({g['files']} files) - {g['reason']}")
            else:
                out.append(f"- Unknown files: {g['files']} × `{g['extension']}` in `{g['folder']}`")
        out.append("")
    out.append("Legend: ✅ present and parser available · ⚠️ present without a usable parser · ℹ️ context (no parsing) · — expected but absent · ✗ parser missing")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("case", type=Path, help="KAPE collection folder (or case folder containing raw\\)")
    ap.add_argument("--manifest", type=Path, default=Path(DEFAULT_MANIFEST))
    ap.add_argument("--out", type=Path, help="Output folder (default: <case>\\inventory)")
    ap.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY, help="Parser registry (parser_registry.json)")
    ap.add_argument("--no-verify", action="store_true", help="Do not recompute the SHA-1 of the collection (integrity)")
    args = ap.parse_args(argv)

    root = find_collection_root(args.case)
    out = args.out or (args.case / "inventory")
    out.mkdir(parents=True, exist_ok=True)

    apply_registry(args.registry)
    records, coverage, unclassified, summary, gaps = build(root, args.manifest, verify=not args.no_verify)
    (out / "inventory.json").write_text(json.dumps({"summary": summary, "files": records}, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "coverage.json").write_text(json.dumps({"summary": summary, "artifacts": coverage}, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "gaps.json").write_text(json.dumps(gaps, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "coverage.md").write_text(render_md(coverage, unclassified, summary, gaps), encoding="utf-8")

    sc = summary["status_counts"]
    print(f"{summary['files_total']} files | {sc[COVERED]} artifacts covered, "
          f"{sc[NOT_COVERED]} not covered, {sc[CONTEXT]} context, {sc[ABSENT]} absent | {summary['unclassified_files']} unclassified | {summary['gaps']} gap(s) -> gaps.json")
    integ = summary["integrity"]
    if integ:
        print(f"Collection integrity: {integ['verdict']} ({integ['ok']} matching, {integ['mismatch']} different, "
              f"{integ['missing']} missing, {integ['no_reference']} without KAPE hash, {integ['duration_s']} s)")
    print(f"Report: {out / 'coverage.md'}")


if __name__ == "__main__":
    main()
