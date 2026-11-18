"""
Sleuthline 2.0a - entity graph of a case.

Links every file, hash, IP address, URL, domain, account, SID and host to the records where it appears.
Deterministic (no model): extracted from the unified timeline and the detections (timeline_all view,
which already carries the mapped path, account, host and description of every source: disk, memory,
network) and from the hash matches (hash_hits).

  entity_refs(entity_id, type, norm, value, ref, ts, host, host_id, artifact, role)
  entities(entity_id, type, norm, value, refs, records, artifacts, hosts, first_ts, last_ts, common)

entity_id = 'E' + 12 hex of md5(type:norm): the same entity has the same id in every database of a case
(host databases and the merged case database). Normalization makes one entity of the forms an analyst
considers the same: `F:\\Windows\\System32\\X.exe`, `C:\\Windows\\System32\\x.exe`,
`\\Device\\HarddiskVolume3\\Windows\\System32\\x.exe` and `%SystemRoot%\\System32\\x.exe` -> `\\windows\\system32\\x.exe`
(the drive letter of a mounted image is not meaningful).

Co-occurrence edges are not stored: they are computed on demand from entity_refs (same record, or same
host within a time window). `common` flags the entities seen everywhere (svchost.exe, SYSTEM, 127.0.0.1...)
so that pivots skip them by default.
"""
from __future__ import annotations

import re

VERSION = "1.0"
TYPES = ("file", "filename", "hash", "ip", "url", "domain", "account", "sid", "host")
# File names worth pivoting on by name alone (Prefetch, detections, command lines): executables, scripts, archives
NAME_EXT = r"exe|dll|sys|scr|com|cpl|msi|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|lnk|jar|zip|7z|rar|iso|img|vhd|vhdx"
# Always common, whatever their count
COMMON = {("account", "system"), ("account", "local service"), ("account", "network service"), ("sid", "s-1-5-18"),
          ("sid", "s-1-5-19"), ("sid", "s-1-5-20"), ("ip", "127.0.0.1"), ("ip", "0.0.0.0"), ("ip", "255.255.255.255"),
          ("account", "-"), ("account", "n/a"), ("ip", "::1"), ("ip", "::")}
COMMON_MIN_REFS = 500            # an entity with more refs than this and than COMMON_SHARE of all refs is common
COMMON_SHARE = 0.005

# --- normalization (SQL macros, mirrored in Python for the agent tools) --------------------------------------
_PATH_SQL = r"""lower(regexp_replace(regexp_replace(regexp_replace(regexp_replace(replace(trim({x}), '/', '\'),
    '^\\\\\?\\', ''), '^(\\Device\\HarddiskVolume\d+|\\\?\?\\[A-Za-z]:|[A-Za-z]:|%systemdrive%)', '', 'i'),
    '^%(systemroot|windir)%', '\\Windows', 'i'), '\\+', '\\', 'g'))"""
IP_RX = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"
# IPv6: full (8 groups) or compressed (with ::); filtered after extraction so that times (12:30:45) and MAC addresses
# (aa:bb:cc:dd:ee:ff) are not taken for addresses
IP6_RX = r"(?i)(?:^|[^0-9a-f:.])((?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{0,4}::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{0,4})(?:[^0-9a-f:.]|$)"


def norm_path(p: str) -> str:
    p = str(p).strip().replace("/", "\\")
    p = re.sub(r"^\\\\\?\\", "", p)
    p = re.sub(r"(?i)^(\\Device\\HarddiskVolume\d+|\\\?\?\\[A-Za-z]:|[A-Za-z]:|%systemdrive%)", "", p)
    p = re.sub(r"(?i)^%(systemroot|windir)%", r"\\Windows", p)
    return re.sub(r"\\+", r"\\", p).lower()


def norm_value(etype: str, value: str) -> str:
    v = str(value).strip()
    if etype == "file":
        return norm_path(v)
    if etype == "host":
        return v.lower().split(".")[0]
    return v.lower()


def guess_type(value: str) -> list[str]:
    """Possible types of a value typed by the agent (pivot tool)."""
    v = str(value).strip()
    if re.fullmatch(r"(?i)[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", v):
        return ["hash"]
    if re.fullmatch(IP_RX, v) or (":" in v and re.fullmatch(r"(?i)[0-9a-f:]+", v) and ("::" in v or v.count(":") == 7)):
        return ["ip"]
    if re.match(r"(?i)https?://", v):
        return ["url"]
    if re.fullmatch(r"(?i)S-1-\d+(-\d+)+", v):
        return ["sid"]
    if "\\" in v or "/" in v:
        return ["file"]
    if re.search(rf"(?i)\.({NAME_EXT})$", v):
        return ["filename", "domain"]
    if "." in v:
        return ["domain", "host"]
    return ["account", "host"]


def entity_id_sql(t: str, n: str) -> str:
    return f"'E' || substr(md5({t} || ':' || {n}), 1, 12)"


def build(con, multi: bool = False, log=print) -> dict:
    """Builds entity_refs and entities from timeline_all and hash_hits of an open database (normalize.py,
    merge.py). multi: the database is a merged multi-host case (timeline_all has host_id)."""
    hid = "host_id" if multi else "CAST(NULL AS VARCHAR)"
    src = (f"SELECT ref, ts, host, {hid} AS host_id, artifact, path, user_name, description FROM timeline_all "
           "WHERE ref IS NOT NULL")
    con.execute(f"CREATE OR REPLACE TEMP TABLE _src AS {src}")
    parts = [
        # files: full paths (path column), normalized without the drive / volume
        f"""SELECT 'file' AS type, {_PATH_SQL.format(x='path')} AS norm, path AS value, ref, ts, host, host_id, artifact,
                   'path' AS role FROM _src
            WHERE path IS NOT NULL AND regexp_matches(path, '^([A-Za-z]:\\\\|\\\\|%[A-Za-z]+%\\\\)')
              AND regexp_matches(path, '\\.[A-Za-z0-9]{{1,5}}$')""",
        # full paths of executables / scripts / archives quoted in the description (command lines, 4688, 7045, Sysmon...)
        f"""SELECT 'file', {_PATH_SQL.format(x='p')}, p, ref, ts, host, host_id, artifact, 'path' FROM
              (SELECT unnest(regexp_extract_all(description,
                      '(?i)((?:[A-Za-z]:|%[A-Za-z]+%|\\\\Device\\\\HarddiskVolume\\d+)\\\\[^\\s"''|<>*?:]+\\.(?:{NAME_EXT}))(?:[^A-Za-z0-9_]|$)', 1)) AS p,
                      ref, ts, host, host_id, artifact FROM _src WHERE description IS NOT NULL)""",
        # file names of executables / scripts / archives: from the path and from the description
        f"""SELECT 'filename', lower(regexp_extract(path, '([^\\\\/]+)$', 1)), regexp_extract(path, '([^\\\\/]+)$', 1),
                   ref, ts, host, host_id, artifact, 'name' FROM _src
            WHERE path IS NOT NULL AND regexp_matches(path, '(?i)\\.({NAME_EXT})$')""",
        f"""SELECT 'filename', lower(n), n, ref, ts, host, host_id, artifact, 'name' FROM
              (SELECT unnest(regexp_extract_all(description, '(?i)([A-Za-z0-9_$~.-]+\\.(?:{NAME_EXT}))(?:[^A-Za-z0-9_]|$)', 1)) AS n,
                      ref, ts, host, host_id, artifact FROM _src WHERE description IS NOT NULL)
            WHERE length(n) BETWEEN 5 AND 120 AND NOT starts_with(n, '.')""",
        # hashes labelled as such in the description (SHA1=..., fileinfo_sha256=..., MD5: ...)
        """SELECT 'hash', lower(h), h, ref, ts, host, host_id, artifact, 'hash' FROM
             (SELECT unnest(regexp_extract_all(description,
                     '(?i)(?:md5|sha-?1|sha-?256|hash(?:es)?)[^0-9a-f]{0,12}([0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?:[^0-9a-f]|$)', 1)) AS h,
                     ref, ts, host, host_id, artifact FROM _src WHERE description IS NOT NULL)""",
        # IPv4 addresses: in the description, and as the whole path (network sources map the remote address there)
        f"""SELECT 'ip', ip, ip, ref, ts, host, host_id, artifact, 'ip' FROM
             (SELECT unnest(regexp_extract_all(description, '(?:^|[^0-9A-Za-z.])({IP_RX})(?:[^0-9.]|$)', 1)) AS ip,
                     ref, ts, host, host_id, artifact FROM _src WHERE description IS NOT NULL)""",
        f"""SELECT 'ip', path, path, ref, ts, host, host_id, artifact, 'ip' FROM _src
            WHERE path IS NOT NULL AND regexp_full_match(path, '{IP_RX}')""",
        f"""SELECT 'ip', lower(ip), ip, ref, ts, host, host_id, artifact, 'ip' FROM
             (SELECT unnest(regexp_extract_all(description, '{IP6_RX}', 1)) AS ip,
                     ref, ts, host, host_id, artifact FROM _src WHERE description IS NOT NULL AND contains(description, ':'))
            WHERE length(ip) >= 3 AND ip <> '::' AND regexp_matches(ip, '[0-9a-fA-F]')
              AND (contains(ip, '::') OR length(ip) - length(replace(ip, ':', '')) = 7)
              AND NOT regexp_full_match(ip, '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')""",
        # URLs and their domain
        """SELECT 'url', lower(u), u, ref, ts, host, host_id, artifact, 'url' FROM
             (SELECT unnest(regexp_extract_all(description, '(?i)(https?://[^\\s"''<>|]+)', 1)) AS u,
                     ref, ts, host, host_id, artifact FROM _src WHERE description IS NOT NULL)""",
        """SELECT 'domain', lower(d), d, ref, ts, host, host_id, artifact, 'domain' FROM
             (SELECT regexp_extract(u, '(?i)^https?://([^/:?#]+)', 1) AS d, ref, ts, host, host_id, artifact FROM
               (SELECT unnest(regexp_extract_all(description, '(?i)(https?://[^\\s"''<>|]+)', 1)) AS u,
                       ref, ts, host, host_id, artifact FROM _src WHERE description IS NOT NULL))
            WHERE d <> '' AND NOT regexp_full_match(d, '[0-9.]+')""",
        # accounts and SIDs: account column, SIDs in the description
        """SELECT CASE WHEN regexp_full_match(user_name, '(?i)S-1-\\d+(-\\d+)+') THEN 'sid' ELSE 'account' END,
                  lower(trim(user_name)), user_name, ref, ts, host, host_id, artifact, 'account' FROM _src
            WHERE user_name IS NOT NULL AND trim(user_name) <> ''""",
        """SELECT 'sid', lower(s), s, ref, ts, host, host_id, artifact, 'sid' FROM
             (SELECT unnest(regexp_extract_all(description, '(?i)(S-1-5-21-\\d+-\\d+-\\d+-\\d+)', 1)) AS s,
                     ref, ts, host, host_id, artifact FROM _src WHERE description IS NOT NULL)""",
        # host names found in the records (computer name of the event, of the memory image...)
        """SELECT 'host', lower(split_part(trim(host), '.', 1)), host, ref, ts, host, host_id, artifact, 'host' FROM _src
            WHERE host IS NOT NULL AND trim(host) <> '' AND NOT regexp_full_match(trim(host), '[0-9.:]+')""",
    ]
    has_hits = con.execute("SELECT count(*) FROM information_schema.tables WHERE table_name = 'hash_hits' "
                           "AND table_schema = 'main' AND table_catalog = current_database()").fetchone()[0]
    if has_hits:
        hits_host = "host_id" if multi else "CAST(NULL AS VARCHAR)"
        parts.append(f"""SELECT 'hash', lower(h.hash), h.hash, h.ref, t.ts, t.host, {('h.' + hits_host) if multi else hits_host},
                                coalesce(t.artifact, h.src_table), 'hash' FROM hash_hits h
                         LEFT JOIN (SELECT ref, any_value(ts) AS ts, any_value(host) AS host, any_value(artifact) AS artifact
                                    FROM _src GROUP BY ref) t ON t.ref = h.ref
                         WHERE h.ref IS NOT NULL AND h.hash IS NOT NULL""")
    union = " UNION ALL ".join(f"({p})" for p in parts)
    con.execute("DROP TABLE IF EXISTS entity_refs")
    con.execute(f"""CREATE TABLE entity_refs AS
        SELECT DISTINCT {entity_id_sql('type', 'norm')} AS entity_id, type, norm, value, ref, ts, host, host_id, artifact, role
        FROM ({union}) WHERE norm IS NOT NULL AND norm <> ''""")
    total = con.execute("SELECT count(*) FROM entity_refs").fetchone()[0]
    threshold = max(COMMON_MIN_REFS, int(total * COMMON_SHARE))
    common_list = " OR ".join(f"(type = '{t}' AND norm = '{n}')" for t, n in sorted(COMMON))
    con.execute("DROP TABLE IF EXISTS entities")
    con.execute(f"""CREATE TABLE entities AS
        SELECT entity_id, type, norm, mode(value) AS value, count(*) AS refs, count(DISTINCT ref) AS records,
               count(DISTINCT artifact) AS artifacts,
               string_agg(DISTINCT coalesce(host_id, lower(split_part(host, '.', 1))), ', ' ORDER BY coalesce(host_id, lower(split_part(host, '.', 1)))) AS hosts,
               min(ts) AS first_ts, max(ts) AS last_ts,
               (count(*) > {threshold} OR {common_list}) AS common
        FROM entity_refs GROUP BY entity_id, type, norm""")
    con.execute("DROP TABLE _src")
    stats = dict(con.execute("SELECT type, count(*) FROM entities GROUP BY 1 ORDER BY 1").fetchall())
    n_common = con.execute("SELECT count(*) FROM entities WHERE common").fetchone()[0]
    log(f"  entities: {sum(stats.values()):,} ({', '.join(f'{k} {v:,}' for k, v in stats.items())}), "
        f"{total:,} references, {n_common} common".replace(",", " "))
    return {"entities": stats, "references": total, "common": n_common, "common_threshold": threshold}
