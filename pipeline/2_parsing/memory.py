"""
Sleuthline - memory analysis with Volatility 3 (job "volatility" of the orchestrator).

Input : one memory image of the analyzed machine, in <case>\\memory\\ (.raw .mem .vmem .dmp .img
        .bin .lime) or given with `orchestrator.py <case> --memory <path>`.
Output: <case>\\parsed\\volatility\\
          memory_image.jsonl    path, size and SHA-256 of the image (computed before anything else)
          <plugin>.jsonl        one file per Volatility plugin (e.g. windows.pslist.PsList.jsonl),
                                one JSON object per row; tree outputs (pstree...) are flattened
                                with a TreeDepth column.

Principles (same as the disk side):
  - the image is never modified: read-only attribute, Volatility only reads it;
  - recognized tool only: Volatility 3, run plugin by plugin, every command traced in jobs.jsonl;
  - no secret extraction: hashdump, lsadump, cachedump, truecrypt are never run;
  - no file extraction: dumpfiles, pedump, memmap --dump are never run (tables only).

windows.info runs first (it identifies the kernel and downloads its symbols from the Microsoft
symbol server: internet access needed at the first analysis of a given Windows build); the other
plugins then run in parallel.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

MEMORY_EXT = {".raw", ".mem", ".vmem", ".dmp", ".img", ".bin", ".lime"}
PLUGIN_TIMEOUT = 3600          # seconds per plugin (handles, filescan, mftscan can be long)
PARALLEL = 3                   # Volatility processes run at the same time after windows.info


@dataclass
class VolPlugin:
    name: str                              # Volatility plugin, e.g. windows.pslist.PsList
    table: str                             # DuckDB table: raw.<table>
    artifact: str                          # label in the timeline
    category: str
    times: list = field(default_factory=list)          # [(column, description)]
    path: list = field(default_factory=list)            # columns used as "path" in the timeline
    description: list = field(default_factory=list)     # columns concatenated as "description"


def P(name, table, artifact, category, times=(), path=(), description=()):
    return VolPlugin(name, table, artifact, category, list(times), list(path), list(description))


# Plugins run, in this order (windows.info first). Plugins that extract secrets or files, that need
# parameters (strings, vadregexscan, yarascan, pe_symbols) or that duplicate another one are not run.
PLUGINS: list[VolPlugin] = [
    P("windows.info.Info", "vol_info", "Memory: system information", "system",
      description=["Variable", "Value"]),
    # --- processes
    P("windows.pslist.PsList", "vol_pslist", "Memory: process list (pslist)", "execution",
      [("CreateTime", "process created (memory, pslist)"), ("ExitTime", "process exited (memory, pslist)")],
      ["ImageFileName"], ["PID", "PPID", "ImageFileName", "SessionId", "Threads", "Handles"]),
    P("windows.psscan.PsScan", "vol_psscan", "Memory: process scan (psscan)", "execution",
      [("CreateTime", "process created (memory, psscan)"), ("ExitTime", "process exited (memory, psscan)")],
      ["ImageFileName"], ["PID", "PPID", "ImageFileName", "SessionId"]),
    P("windows.pstree.PsTree", "vol_pstree", "Memory: process tree", "execution",
      path=["Path", "ImageFileName"], description=["PID", "PPID", "Cmd"]),
    P("windows.malware.psxview.PsXView", "vol_psxview", "Memory: hidden process check (psxview)", "anti-forensics",
      path=["Name"], description=["PID", "pslist", "psscan", "thrdscan", "csrss"]),
    P("windows.cmdline.CmdLine", "vol_cmdline", "Memory: command lines", "execution",
      path=["Process"], description=["PID", "Args"]),
    P("windows.envars.Envars", "vol_envars", "Memory: environment variables", "system"),
    P("windows.getsids.GetSIDs", "vol_getsids", "Memory: process SIDs", "accounts"),
    P("windows.privileges.Privs", "vol_privileges", "Memory: process privileges", "accounts"),
    P("windows.sessions.Sessions", "vol_sessions", "Memory: logon sessions", "accounts",
      [("Create Time", "process in session (memory)")], ["Process"], ["Session ID", "Session Type", "Process ID", "User Name"]),
    P("windows.joblinks.JobLinks", "vol_joblinks", "Memory: job objects", "execution"),
    P("windows.verinfo.VerInfo", "vol_verinfo", "Memory: PE version information", "execution"),
    # --- DLLs, modules, drivers, kernel
    P("windows.dlllist.DllList", "vol_dlllist", "Memory: loaded DLLs", "execution",
      [("LoadTime", "DLL loaded (memory)")], ["Path", "Name"], ["PID", "Process"]),
    P("windows.malware.ldrmodules.LdrModules", "vol_ldrmodules", "Memory: unlinked DLLs (ldrmodules)", "anti-forensics"),
    P("windows.modules.Modules", "vol_modules", "Memory: kernel modules", "system"),
    P("windows.modscan.ModScan", "vol_modscan", "Memory: kernel module scan", "system"),
    P("windows.unloadedmodules.UnloadedModules", "vol_unloadedmodules", "Memory: unloaded kernel modules", "system",
      [("Time", "kernel module unloaded (memory)")], ["Name"], ["StartAddress"]),
    P("windows.driverscan.DriverScan", "vol_driverscan", "Memory: driver scan", "system"),
    P("windows.malware.drivermodule.DriverModule", "vol_drivermodule", "Memory: drivers without module (rootkit check)", "anti-forensics"),
    P("windows.driverirp.DriverIrp", "vol_driverirp", "Memory: driver IRP hooks", "anti-forensics"),
    P("windows.devicetree.DeviceTree", "vol_devicetree", "Memory: device tree", "system"),
    P("windows.ssdt.SSDT", "vol_ssdt", "Memory: system call table (SSDT)", "anti-forensics"),
    P("windows.callbacks.Callbacks", "vol_callbacks", "Memory: kernel callbacks", "anti-forensics"),
    P("windows.timers.Timers", "vol_timers", "Memory: kernel timers", "system"),
    # --- handles, objects, files, network
    P("windows.handles.Handles", "vol_handles", "Memory: handles", "system"),
    P("windows.mutantscan.MutantScan", "vol_mutantscan", "Memory: mutexes", "execution"),
    P("windows.symlinkscan.SymlinkScan", "vol_symlinkscan", "Memory: symbolic links", "system",
      [("CreateTime", "symbolic link created (memory)")], ["To Name"], ["From Name"]),
    P("windows.filescan.FileScan", "vol_filescan", "Memory: file objects", "file system"),
    P("windows.mftscan.MFTScan", "vol_mftscan", "Memory: MFT records in memory", "file system",
      [("Created", "file created (memory, MFT record)"), ("Modified", "file modified (memory, MFT record)")],
      ["Filename"], ["Record Number", "Attribute Type", "MFT Type"]),
    P("windows.mftscan.ADS", "vol_ads", "Memory: alternate data streams (MFT records)", "file system",
      path=["Filename"], description=["ADS Filename", "Hexdump"]),
    P("windows.netscan.NetScan", "vol_netscan", "Memory: network connections (netscan)", "network",
      [("Created", "network endpoint created (memory)")], ["Owner"],
      ["Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID"]),
    P("windows.netstat.NetStat", "vol_netstat", "Memory: network connections (netstat)", "network",
      [("Created", "network endpoint created (memory, netstat)")], ["Owner"],
      ["Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID"]),
    # --- injection, hollowing, hooks, rootkits
    P("windows.malware.malfind.Malfind", "vol_malfind", "Memory: injected code (malfind)", "anti-forensics"),
    P("windows.malware.hollowprocesses.HollowProcesses", "vol_hollowprocesses", "Memory: process hollowing", "anti-forensics"),
    P("windows.malware.processghosting.ProcessGhosting", "vol_processghosting", "Memory: process ghosting", "anti-forensics"),
    P("windows.malware.pebmasquerade.PebMasquerade", "vol_pebmasquerade", "Memory: PEB masquerading", "anti-forensics"),
    P("windows.malware.suspicious_threads.SuspiciousThreads", "vol_suspicious_threads", "Memory: suspicious threads", "anti-forensics"),
    P("windows.suspended_threads.SuspendedThreads", "vol_suspended_threads", "Memory: suspended threads", "anti-forensics"),
    P("windows.orphan_kernel_threads.Threads", "vol_orphan_kernel_threads", "Memory: orphan kernel threads", "anti-forensics"),
    P("windows.malware.svcdiff.SvcDiff", "vol_svcdiff", "Memory: hidden services (svcdiff)", "persistence"),
    P("windows.malware.direct_system_calls.DirectSystemCalls", "vol_direct_system_calls", "Memory: direct system calls (EDR evasion)", "anti-forensics"),
    P("windows.malware.indirect_system_calls.IndirectSystemCalls", "vol_indirect_system_calls", "Memory: indirect system calls (EDR evasion)", "anti-forensics"),
    P("windows.malware.unhooked_system_calls.UnhookedSystemCalls", "vol_unhooked_system_calls", "Memory: hooked system calls", "anti-forensics"),
    P("windows.malware.skeleton_key_check.Skeleton_Key_Check", "vol_skeleton_key", "Memory: Skeleton Key check", "accounts"),
    P("windows.etwpatch.EtwPatch", "vol_etwpatch", "Memory: ETW patching", "anti-forensics"),
    P("windows.debugregisters.DebugRegisters", "vol_debugregisters", "Memory: debug registers", "anti-forensics"),
    # --- services, registry, consoles
    P("windows.svcscan.SvcScan", "vol_svcscan", "Memory: services (svcscan)", "persistence",
      path=["Binary", "Binary (Registry)"], description=["Name", "Display", "State", "Start", "PID"]),
    P("windows.svclist.SvcList", "vol_svclist", "Memory: services (svclist)", "persistence"),
    P("windows.getservicesids.GetServiceSIDs", "vol_getservicesids", "Memory: service SIDs", "persistence"),
    P("windows.registry.hivelist.HiveList", "vol_hivelist", "Memory: registry hives", "system"),
    P("windows.registry.userassist.UserAssist", "vol_userassist", "Memory: UserAssist", "execution",
      [("Last Updated", "UserAssist: last run (memory)")], ["Name"], ["Hive Name", "Count", "Focus Count"]),
    P("windows.registry.scheduled_tasks.ScheduledTasks", "vol_scheduled_tasks", "Memory: scheduled tasks (registry)", "persistence",
      [("Creation Time", "scheduled task created (memory)"), ("Last Run Time", "scheduled task last run (memory)")],
      ["Action"], ["Task Name", "Action Arguments", "Principal ID", "Enabled"]),
    P("windows.registry.amcache.Amcache", "vol_amcache", "Memory: Amcache", "execution",
      [("LastModifyTime", "Amcache: last modification (memory)"), ("InstallTime", "Amcache: install (memory)")],
      ["Path"], ["EntryType", "Company", "ProductName", "SHA1"]),
    P("windows.shimcachemem.ShimcacheMem", "vol_shimcachemem", "Memory: ShimCache", "execution",
      [("Last Modified", "ShimCache: file modified (memory)")], ["File Path"], ["Order", "Exec Flag"]),
    P("windows.registry.certificates.Certificates", "vol_certificates", "Memory: registry certificates", "system"),
    P("windows.registry.getcellroutine.GetCellRoutine", "vol_getcellroutine", "Memory: registry hooks (GetCellRoutine)", "anti-forensics"),
    P("windows.cmdscan.CmdScan", "vol_cmdscan", "Memory: console command history (cmdscan)", "execution"),
    P("windows.consoles.Consoles", "vol_consoles", "Memory: console buffers (consoles)", "execution"),
]
INFO_PLUGIN = PLUGINS[0].name
# Never run (secrets, file extraction): listed for the tests and the documentation
EXCLUDED = ["windows.hashdump.Hashdump", "windows.lsadump.Lsadump", "windows.cachedump.Cachedump",
            "windows.truecrypt.Passphrase", "windows.dumpfiles.DumpFiles", "windows.pedump.PEDump"]


# --------------------------------------------------------------------------
# Memory image
# --------------------------------------------------------------------------
def find_images(case: Path, given: list[Path] | None = None) -> list[Path]:
    """Memory images of the case: --memory paths, otherwise the files of <case>\\memory\\."""
    if given:
        return [Path(p) for p in given]
    folder = case / "memory"
    if not folder.is_dir():
        return []
    return sorted(p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in MEMORY_EXT)


def hash_image(image: Path, out_file: Path) -> str:
    h = hashlib.sha256()
    with image.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    rec = {"image": str(image), "name": image.name, "bytes": image.stat().st_size, "sha256": h.hexdigest().upper()}
    out_file.write_text(json.dumps(rec, ensure_ascii=False) + "\n", encoding="utf-8")
    return f"{image.name}: {rec['bytes']} bytes, SHA-256 {rec['sha256']}\n"


# --------------------------------------------------------------------------
# Running Volatility
# --------------------------------------------------------------------------
def flatten(rows: list, depth: int = 0):
    """Volatility JSON renderer output (tree: "__children") -> flat rows with TreeDepth."""
    for row in rows:
        children = row.pop("__children", None) or []
        yield {"TreeDepth": depth, **row}
        yield from flatten(children, depth + 1)


def vol_command(vol: str, image: Path, plugin: str, symbols: Path | None = None, cache: Path | None = None) -> list[str]:
    cmd = [sys.executable, vol] if vol.lower().endswith(".py") else [vol]
    cmd += ["-q", "-r", "json"]
    if symbols:
        cmd += ["-s", str(symbols)]
    if cache:
        cmd += ["--cache-path", str(cache)]
    return cmd + ["-f", str(image), plugin]


def run_plugin(cmd: list[str], out_file: Path, timeout: int = PLUGIN_TIMEOUT, env: dict | None = None) -> str:
    """Runs one plugin, writes its flattened rows as JSONL. Returns the stderr text (log)."""
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=env,
                       stdin=subprocess.DEVNULL)
    err = p.stderr.decode("utf-8", "replace")
    text = p.stdout.decode("utf-8", "replace").strip()
    if p.returncode != 0:      # Volatility prints its requirement errors on stdout
        raise RuntimeError(f"Volatility exit code {p.returncode}: {(text[-600:] + ' ' + err.strip()[-400:]).strip()}")
    try:
        rows = json.loads(text) if text else []
    except ValueError as e:
        raise RuntimeError(f"unreadable Volatility output ({e}): {text[:300]}")
    n = 0
    with out_file.open("w", encoding="utf-8") as fh:
        for row in flatten(rows if isinstance(rows, list) else [rows]):
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
            n += 1
    return f"{n} row(s) -> {out_file.name}\n" + err


def normalize_map_entries() -> list[dict]:
    """normalize_map.json entries of the Volatility outputs (kept in sync by the tests)."""
    out = [{"id": "vol_image", "glob": ["volatility/memory_image.jsonl"], "artifact": "Memory image", "category": "system",
            "tool": "Sleuthline", "times": [], "description": ["name", "sha256"],
            "note": "Path, size and SHA-256 of the memory image, computed before the analysis."}]
    for p in PLUGINS:
        e = {"id": p.table, "glob": [f"volatility/{p.name}.jsonl"], "artifact": p.artifact, "category": p.category,
             "tool": "Volatility 3", "times": [{"ts": f'"{c}"', "desc": d} for c, d in p.times]}
        if p.path:
            e["path"] = p.path
        if p.description:
            e["description"] = p.description
        out.append(e)
    return out
