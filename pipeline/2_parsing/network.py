"""
Sleuthline - network capture analysis with Suricata (job "suricata" of the orchestrator).

Input : packet captures of the case, in <case>\\pcap\\ (.pcap .pcapng .cap) or given with
        `orchestrator.py <case> --pcap <file>` (repeatable).
Output: <case>\\parsed\\suricata\\
          pcap_files.jsonl              name, size and SHA-256 of every capture (computed first)
          <capture>\\raw\\eve.jsonl      Suricata EVE output, as produced (kept, hashed)
          <capture>\\eve_<type>.jsonl    the same events split by event_type (alert, flow, dns, http,
                                        tls, fileinfo, anomaly, smb, ...), nested fields flattened
                                        (alert.signature -> alert_signature) and the capture name
                                        added (pcap_file)

Suricata reads the capture offline (-r), with the configuration shipped with Suricata, adjusted
for an offline analysis: only the EVE output, file hashes (MD5, SHA-1, SHA-256), community-id,
checksum validation disabled (captures often hold offloaded checksums), and the rules installed by
suricata-update (ET Open). Without rules, the protocol metadata is still produced (no alert).
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

PCAP_EXT = {".pcap", ".pcapng", ".cap"}
RUN_TIMEOUT = 4 * 3600
# event_type -> file; the others go to eve_other.jsonl
# Columns always present (NULL if absent from the event), so that the mappings can rely on them
BASE_FIELDS = ["pcap_file", "timestamp", "event_type", "src_ip", "src_port", "dest_ip", "dest_port", "proto",
               "app_proto", "community_id", "flow_id"]
TYPE_FIELDS = {"alert": ["alert_signature", "alert_signature_id", "alert_severity", "alert_category",
                         "alert_metadata_mitre_tactic_name", "alert_metadata_mitre_technique_id"],
               "flow": ["flow_start", "flow_end", "flow_state", "flow_bytes_toserver", "flow_bytes_toclient"]}
EVENT_TYPES = ["alert", "anomaly", "flow", "dns", "http", "tls", "fileinfo", "smb", "rdp", "ssh", "smtp", "ftp",
               "dhcp", "krb5", "dcerpc", "quic", "netflow"]


# --------------------------------------------------------------------------
# Captures
# --------------------------------------------------------------------------
def find_captures(case: Path, given: list[Path] | None = None) -> list[Path]:
    """Captures of the case: --pcap paths, otherwise the files of <case>\\pcap\\ (sub-folders included)."""
    if given:
        return [Path(p) for p in given]
    folder = case / "pcap"
    if not folder.is_dir():
        return []
    return sorted(p for p in folder.rglob("*") if p.is_file() and p.suffix.lower() in PCAP_EXT)


def hash_captures(captures: list[Path], out_file: Path) -> str:
    lines = []
    with out_file.open("w", encoding="utf-8") as fh:
        for c in captures:
            h = hashlib.sha256()
            with c.open("rb") as f:
                for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
                    h.update(chunk)
            rec = {"file": str(c), "name": c.name, "bytes": c.stat().st_size, "sha256": h.hexdigest().upper()}
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            lines.append(f"{c.name}: {rec['bytes']} bytes, SHA-256 {rec['sha256']}")
    return "\n".join(lines) + "\n"


def capture_dir_name(capture: Path, all_captures: list[Path]) -> str:
    """Output folder of a capture: its file name (made unique if two captures share a name)."""
    stem = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in capture.name)
    same = [c for c in all_captures if c.name == capture.name]
    return stem if len(same) == 1 else f"{stem}_{same.index(capture) + 1}"


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
def find_config_file(install_dir: Path, name: str) -> Path | None:
    hits = sorted(install_dir.rglob(name))
    return hits[0] if hits else None


def write_config(default_yaml: Path, out_yaml: Path, rules_file: Path | None, install_dir: Path | None = None) -> str:
    """Configuration for an offline analysis, derived from the suricata.yaml shipped with Suricata."""
    import yaml        # PyYAML (orchestrator environment)
    text = default_yaml.read_text(encoding="utf-8", errors="replace")
    cfg = yaml.safe_load(text)
    notes = []
    # Outputs: only EVE, as JSON lines, with file hashes and community-id
    eve = None
    for o in cfg.get("outputs") or []:
        name = next(iter(o)) if isinstance(o, dict) else o
        conf = o.get(name) if isinstance(o, dict) else None
        if name == "eve-log" and eve is None:
            eve = conf if isinstance(conf, dict) else {}
            o[name] = eve
        elif isinstance(conf, dict):
            conf["enabled"] = False
    if eve is None:
        eve = {}
        cfg.setdefault("outputs", []).insert(0, {"eve-log": eve})
    eve.update({"enabled": True, "filetype": "regular", "filename": "eve.jsonl", "append": False, "community-id": True})
    types = eve.get("types") or []
    names = [next(iter(t)) if isinstance(t, dict) else t for t in types]
    for i, n in enumerate(names):
        if n == "files":
            conf = types[i]["files"] if isinstance(types[i], dict) and isinstance(types[i]["files"], dict) else {}
            conf.update({"force-magic": True, "force-hash": ["md5", "sha1", "sha256"]})
            types[i] = {"files": conf}
        elif n == "alert":
            conf = types[i]["alert"] if isinstance(types[i], dict) and isinstance(types[i]["alert"], dict) else {}
            conf.update({"payload-printable": True, "metadata": True})
            types[i] = {"alert": conf}
    for wanted in ("alert", "anomaly", "flow", "dns", "http", "tls", "files"):
        if wanted not in names:
            types.append(wanted)
    eve["types"] = types
    # Offline analysis: no checksum validation, no unix socket, no file extraction
    cfg.setdefault("pcap-file", {})
    if isinstance(cfg["pcap-file"], dict):
        cfg["pcap-file"]["checksum-checks"] = "no"
    if isinstance(cfg.get("unix-command"), dict):
        cfg["unix-command"]["enabled"] = False
    # Rules
    if rules_file and rules_file.is_file():
        cfg["default-rule-path"] = str(rules_file.parent)
        cfg["rule-files"] = [rules_file.name]
        notes.append(f"rules: {rules_file}")
    else:
        cfg["rule-files"] = []
        notes.append("no rule file: protocol metadata only, no alert")
    # Reference files shipped with Suricata (paths of the installation)
    if install_dir:
        for key, name in (("classification-file", "classification.config"),
                          ("reference-config-file", "reference.config"),
                          ("threshold-file", "threshold.config")):
            f = find_config_file(install_dir, name)
            if f:
                cfg[key] = str(f)
            elif key == "threshold-file":
                # not shipped with the Windows MSI: an empty file avoids Suricata's warning (no thresholding)
                empty = out_yaml.parent / "threshold.config"
                empty.write_text("# empty: no alert thresholding (file not shipped with this Suricata build)\n",
                                 encoding="utf-8")
                cfg[key] = str(empty)
            else:
                cfg.pop(key, None)
    out_yaml.write_text("%YAML 1.1\n---\n" + yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return "; ".join(notes) + "\n"


# --------------------------------------------------------------------------
# Running Suricata
# --------------------------------------------------------------------------
def suricata_command(exe: str, capture: Path, config: Path, log_dir: Path) -> list[str]:
    cmd = [sys.executable, exe] if exe.lower().endswith(".py") else [exe]      # .py: test double
    return cmd + ["-r", str(capture), "-c", str(config), "-l", str(log_dir), "-k", "none"]


def flatten(obj, prefix: str = "", out: dict | None = None) -> dict:
    """Nested EVE fields -> flat columns (alert.signature -> alert_signature); lists kept as JSON."""
    out = {} if out is None else out
    for k, v in obj.items():
        key = f"{prefix}_{k}" if prefix else str(k)
        if isinstance(v, dict):
            flatten(v, key, out)
        elif isinstance(v, list):
            out[key] = json.dumps(v, ensure_ascii=False)
        else:
            out[key] = v
    return out


def split_eve(eve: Path, out_dir: Path, capture_name: str) -> dict:
    """Splits eve.jsonl by event_type into eve_<type>.jsonl (flattened). Returns the counts."""
    handles, counts = {}, {}
    try:
        with eve.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                et = ev.get("event_type") or "other"
                if et == "stats":
                    continue
                name = et if et in EVENT_TYPES else "other"
                if name not in handles:
                    handles[name] = (out_dir / f"eve_{name}.jsonl").open("w", encoding="utf-8")
                flat = flatten(ev)
                row = {k: None for k in BASE_FIELDS + TYPE_FIELDS.get(name, [])}
                row.update(flat)
                row["pcap_file"] = capture_name
                handles[name].write(json.dumps(row, ensure_ascii=False) + "\n")
                counts[name] = counts.get(name, 0) + 1
    finally:
        for h in handles.values():
            h.close()
    return counts


def run_capture(cmd: list[str], log_dir: Path, out_dir: Path, capture_name: str, timeout: int = RUN_TIMEOUT,
                env: dict | None = None) -> str:
    log_dir.mkdir(parents=True, exist_ok=True)
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=env,
                       stdin=subprocess.DEVNULL)
    text = p.stdout.decode("utf-8", "replace")
    if p.returncode != 0:
        if p.returncode in (-1073741515, 3221225781):     # 0xC0000135: DLL not found (Windows)
            text += "\nSuricata cannot start: a DLL is missing (Npcap / wpcap.dll). Install Npcap, see the README.\n"
        raise RuntimeError(f"Suricata exit code {p.returncode}: {text.strip()[-800:]}")
    eve = log_dir / "eve.jsonl"
    if not eve.is_file():
        raise RuntimeError(f"Suricata produced no eve.jsonl: {text.strip()[-500:]}")
    counts = split_eve(eve, out_dir, capture_name)
    return text + rules_summary(log_dir / "suricata.log") + "\nEvents: " + ", ".join(
        f"{k}={v}" for k, v in sorted(counts.items())) + "\n"


def rules_summary(log: Path) -> str:
    """'52825 rules successfully loaded, 9 rules failed' from suricata.log, with the keywords the build
    does not support (e.g. file.magic in the Windows build): the alerts of those rules cannot fire."""
    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    m = re.search(r"(\d+) rules successfully loaded, (\d+) rules failed", text)
    if not m:
        return ""
    out = f"\nRules: {m.group(1)} loaded, {m.group(2)} failed"
    kw = sorted(set(re.findall(r"unknown rule keyword '([^']+)'", text)))
    if int(m.group(2)) and kw:
        out += f" (keywords not supported by this Suricata build: {', '.join(kw)})"
    return out + "\n"


# --------------------------------------------------------------------------
# Normalization entries
# --------------------------------------------------------------------------
SKIP_RULE = {"glob": "suricata/*/raw/*", "reason": "raw Suricata output (eve.jsonl, suricata.log): loaded split by event type"}

def _ep():
    """src:port -> dest:port (base fields, always present)."""
    return ("concat_ws(' ', \"proto\", \"src_ip\" || coalesce(':' || \"src_port\", ''), '->', "
            "\"dest_ip\" || coalesce(':' || \"dest_port\", ''))")


def normalize_map_entries() -> list[dict]:
    """normalize_map.json entries of the Suricata outputs (kept in sync by the tests). SQL expressions
    only use the columns always present (BASE_FIELDS, TYPE_FIELDS); the other columns are given as lists,
    of which only those present are used."""
    ev = ["pcap_file"]
    base = {"tool": "Suricata", "evidence": ev}
    return [
        {"id": "pcap_files", "glob": ["suricata/pcap_files.jsonl"], "artifact": "Network captures", "category": "network",
         "tool": "Sleuthline", "times": [], "description": ["name", "sha256"],
         "note": "Name, size and SHA-256 of every capture, computed before the analysis."},
        {"id": "suricata_alert", "glob": ["suricata/*/eve_alert.jsonl"], "artifact": "Suricata", "category": "detection",
         "tool": "Suricata", "times": [],
         "detection": {"engine": "Suricata", "ts": "\"timestamp\"", "rule_title": ["alert_signature"],
                       "rule_id": ["alert_signature_id"],
                       "level": "CASE CAST(\"alert_severity\" AS VARCHAR) WHEN '1' THEN 'high' WHEN '2' THEN 'medium' "
                                "WHEN '3' THEN 'low' ELSE 'informational' END",
                       "computer": ["dest_ip"], "channel": ["app_proto", "proto"], "event_id": ["alert_signature_id"],
                       "record_id": ["flow_id"],
                       "details": f"concat_ws(' | ', {_ep()}, nullif(\"alert_category\", ''), \"community_id\", \"pcap_file\")",
                       "tactics": "concat_ws(' ', \"alert_metadata_mitre_tactic_name\", \"alert_metadata_mitre_technique_id\")",
                       "evidence": ev},
         "note": "Severity 1 = high, 2 = medium, 3 = low (ET Open). The HTTP / DNS / TLS context of the alert is in raw.suricata_alert."},
        {**base, "id": "suricata_flow", "glob": ["suricata/*/eve_flow.jsonl"], "artifact": "Network flows (Suricata)",
         "category": "network",
         "times": [{"ts": "\"flow_start\"", "desc": "network flow: start"}, {"ts": "\"flow_end\"", "desc": "network flow: end"}],
         "path": ["dest_ip"],
         "description": f"concat_ws(' ', {_ep()}, \"app_proto\", 'state=' || \"flow_state\", "
                        "'bytes=' || \"flow_bytes_toserver\" || '/' || \"flow_bytes_toclient\")"},
        {**base, "id": "suricata_dns", "glob": ["suricata/*/eve_dns.jsonl"], "artifact": "DNS (Suricata)", "category": "network",
         "times": [{"ts": "\"timestamp\"", "desc": "DNS query / answer"}],
         "path": ["dns_rrname", "dns_queries", "dns_query"],
         "description": ["dns_type", "dns_rrtype", "dns_rcode", "src_ip", "dest_ip", "dns_answers", "dns_grouped_A",
                         "dns_grouped_CNAME"]},
        {**base, "id": "suricata_http", "glob": ["suricata/*/eve_http.jsonl"], "artifact": "HTTP (Suricata)", "category": "network",
         "times": [{"ts": "\"timestamp\"", "desc": "HTTP request"}],
         "path": ["http_url", "http_hostname"],
         "description": ["http_hostname", "http_http_port", "http_http_method", "http_status", "http_http_user_agent",
                         "http_http_content_type", "http_length", "src_ip", "dest_ip"]},
        {**base, "id": "suricata_tls", "glob": ["suricata/*/eve_tls.jsonl"], "artifact": "TLS (Suricata)", "category": "network",
         "times": [{"ts": "\"timestamp\"", "desc": "TLS handshake"}],
         "path": ["tls_sni", "dest_ip"],
         "description": ["tls_sni", "dest_ip", "dest_port", "tls_version", "tls_subject", "tls_issuerdn", "tls_ja3_hash",
                         "tls_ja3s_hash", "tls_ja4"]},
        {**base, "id": "suricata_fileinfo", "glob": ["suricata/*/eve_fileinfo.jsonl"], "artifact": "Files transferred (Suricata)",
         "category": "network",
         "times": [{"ts": "\"timestamp\"", "desc": "file transferred over the network"}],
         "path": ["fileinfo_filename"],
         "description": ["app_proto", "http_hostname", "src_ip", "dest_ip", "fileinfo_size", "fileinfo_magic",
                         "fileinfo_sha256", "fileinfo_md5", "fileinfo_state"]},
        {**base, "id": "suricata_anomaly", "glob": ["suricata/*/eve_anomaly.jsonl"], "artifact": "Network anomalies (Suricata)",
         "category": "network",
         "times": [{"ts": "\"timestamp\"", "desc": "protocol anomaly"}],
         "description": ["anomaly_type", "anomaly_event", "anomaly_layer", "src_ip", "dest_ip", "app_proto"]},
        {**base, "id": "suricata_other", "glob": ["suricata/*/eve_*.jsonl"], "artifact": "Network events (Suricata)",
         "category": "network", "table_per_file": True,
         "times": [{"ts": "\"timestamp\"", "desc": "network event"}],
         "description": f"concat_ws(' ', \"event_type\", {_ep()}, \"app_proto\")",
         "note": "SMB, RDP, SSH, SMTP, FTP, DHCP, Kerberos, DCERPC, QUIC...: one table per event type."},
    ]
