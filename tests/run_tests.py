#!/usr/bin/env python3
"""
Sleuthline tests (standard library + duckdb + python-docx, already present in the orchestrator venv).

  <root>\\venvs\\orchestrator\\Scripts\\python.exe tests\\run_tests.py                       fast tests (~10 s)
  ... run_tests.py --regression "C:\\Sleuthline\\cases\\test01"                             + regression on a real case
  ... run_tests.py --regression "C:\\Sleuthline\\cases\\test01" --update-golden             (re)records the reference

Fast tests: SQL safeguards of the agent, guidance (and French section names of the first version), identifiers
and step replay, migration of an older findings.json, DuckDB macros (dates, paths), hash extraction from the EVTX,
inventory (classification, CopyLog, integrity), internal parsers, payload sent to the Anthropic provider, and a
complete end-to-end analysis with the "mock" provider on a small synthetic database (verified evidence, refusal of
non-existent references, Word report).

Regression: normalizes the case (from its parsed\\ folder) into a temporary database and compares, artifact per
artifact, the number of timeline rows and detections with tests\\golden\\<case>.json.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIPE = ROOT / "pipeline"
for sub in ("1_inventory", "2_parsing", "3_normalize", "4_analysis"):
    sys.path.insert(0, str(PIPE / sub))

import duckdb  # noqa: E402

import analyze  # noqa: E402
import inventory  # noqa: E402
import llm  # noqa: E402
import normalize  # noqa: E402
import orchestrator  # noqa: E402

GOLDEN = Path(__file__).resolve().parent / "golden"


# ------------------------------------------------------------------------------------------
# Agent: safeguards and state
# ------------------------------------------------------------------------------------------
class TestSqlGuard(unittest.TestCase):
    def setUp(self):
        self.db = analyze.CaseDB.__new__(analyze.CaseDB)        # check_sql needs no connection

    def test_reads_allowed(self):
        for sql in ("SELECT * FROM timeline LIMIT 5", "with x as (select 1) select * from x",
                    "DESCRIBE raw.evtx", "SELECT 'copy; attach' AS text"):
            self.assertIsNone(self.db.check_sql(sql), sql)

    def test_writes_and_files_refused(self):
        for sql in ("COPY timeline TO 'x.csv'", "ATTACH 'x.db'", "SELECT * FROM read_csv('C:/x.csv')",
                    "INSERT INTO meta VALUES (1, 2)", "SET enable_external_access = true",
                    "SELECT 1; DROP TABLE timeline", "SELECT * FROM glob('C:/*')", "PRAGMA database_list"):
            self.assertIsNotNone(self.db.check_sql(sql), sql)


class TestGuidance(unittest.TestCase):
    def parse(self, text):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "guidance.txt"
            p.write_text(text, encoding="utf-8")
            return analyze.parse_guidance(p)

    def test_numbered_questions_and_context(self):
        g = self.parse("[CONTEXT]\nEDR alert\n[QUESTIONS]\n1. Which executable?\n- Which IP?\nWho got in?\n"
                       "Happy Hunting!\n[IOC]\nip = 10.0.0.12  # server\nevil.exe\n[PERIOD]\nstart = 2023-11-10 10:00\n")
        self.assertEqual(g["questions"], ["Which executable?", "Which IP?", "Who got in?"])
        self.assertIn("Happy Hunting!", g["context"])
        self.assertEqual(g["iocs"][0], {"type": "ip", "value": "10.0.0.12", "comment": "server"})
        self.assertEqual(g["iocs"][1]["type"], "text")
        self.assertEqual(g["period"], {"start": "2023-11-10 10:00"})

    def test_legacy_french_sections(self):
        """guidance.txt files of the first (French) version are still read."""
        g = self.parse("[CONTEXTE]\nAlerte EDR\n[PERIODE]\ndebut = 2023-11-10 10:00\nfin = 2023-11-10 12:00\n"
                       "[CONSIGNES]\nPrioriser le réseau\n")
        self.assertIn("Alerte EDR", g["context"])
        self.assertEqual(g["period"], {"start": "2023-11-10 10:00", "end": "2023-11-10 12:00"})
        self.assertIn("Prioriser", g["instructions"])

    def test_select_steps(self):
        steps = [{"num": n} for n in range(1, 13)]
        self.assertEqual(analyze.select_steps("1,3-5", steps), {1, 3, 4, 5})
        self.assertEqual(analyze.select_steps(None, steps), set(range(1, 13)))

    def test_playbook_titles(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "PLAYBOOK.md"
            p.write_text("# P\n\n## Rules\n\nr\n\n## Step 1: One\n\na\n\n## Étape 2 : Deux\n\nb\n", encoding="utf-8")
            rules, steps = analyze.parse_playbook(p)
        self.assertEqual(rules, "r")
        self.assertEqual([(s["num"], s["title"]) for s in steps], [(1, "One"), (2, "Deux")])


class TestState(unittest.TestCase):
    def test_purge_and_identifiers(self):
        with tempfile.TemporaryDirectory() as d:
            st = analyze.State(Path(d) / "findings.json")
            st.d["findings"] = [{"id": "F-001", "step": 1}, {"id": "F-002", "step": 3}, {"id": "F-003", "step": 4}]
            st.d["iocs"] = [{"id": "I-001", "step": 3}]
            self.assertEqual(st.purge_step(3), 2)
            self.assertEqual([f["id"] for f in st.d["findings"]], ["F-001", "F-003"])
            # no collision with F-003 after purging F-002
            self.assertEqual(st.next_id("F", "findings"), "F-004")
            self.assertEqual(st.next_id("I", "iocs"), "I-001")

    def test_legacy_findings_migrated(self):
        """findings.json written by the first (French) version: values converted on load."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "findings.json"
            p.write_text(json.dumps({"steps": {"1": {"status": "terminée"}}, "findings": [{"id": "F-001", "confidence": "confirmé"}],
                                     "answers": [{"question": "q", "confidence": "indéterminé"}]}), encoding="utf-8")
            st = analyze.State(p)
        self.assertEqual(st.d["steps"]["1"]["status"], analyze.DONE)
        self.assertEqual(st.d["findings"][0]["confidence"], "confirmed")
        self.assertEqual(st.d["answers"][0]["confidence"], analyze.UNDETERMINED)


# ------------------------------------------------------------------------------------------
# Normalization
# ------------------------------------------------------------------------------------------
class TestNormalizeMacros(unittest.TestCase):
    def setUp(self):
        self.con = duckdb.connect()
        self.con.execute("SET TimeZone = 'UTC'")
        normalize.create_macros(self.con, r"C:\Sleuthline\cases\test01")

    def one(self, sql):
        return self.con.execute(sql).fetchone()[0]

    def test_ts_parse(self):
        self.assertEqual(str(self.one("SELECT ts_parse('2023-11-10 11:03:09.1234567')")), "2023-11-10 11:03:09.123456")
        self.assertEqual(str(self.one("SELECT ts_parse('2023-11-10T12:03:09+01:00')")), "2023-11-10 11:03:09")
        self.assertIsNone(self.one("SELECT ts_parse('0')"))
        self.assertIsNone(self.one("SELECT ts_parse('not a date')"))

    def test_orig_path(self):
        self.assertEqual(self.one(r"SELECT orig_path('C:\Sleuthline\cases\test01\C\Windows\System32\cmd.exe')"),
                         r"C:\Windows\System32\cmd.exe")
        # orchestrator working copy (SQLECmd, WxTCmd, Hindsight...)
        self.assertEqual(self.one(r"SELECT orig_path('C:\Sleuthline\cases\test01\parsed\sqlecmd\_work\C\Users\bob\History')"),
                         r"C:\Users\bob\History")
        self.assertEqual(self.one(r"SELECT user_from_path('C:\Users\bob\Desktop\x.txt')"), "bob")

    def test_table_names(self):
        self.assertEqual(normalize.auto_table_name("recmd_kroll/20261018172202_RECmd_Batch_Kroll_Output.csv"),
                         "recmd_kroll_recmd_batch_kroll_output")
        self.assertEqual(normalize.proposal_glob("sqlecmd/20261018_Chrome_History.csv"), "sqlecmd/*_Chrome_History.csv")

    def test_embedded_hashes(self):
        """Hashes embedded in the EVTX (Sysmon Hashes field): extracted for hash_hits, IMPHASH excluded."""
        payload = ('{"EventData":{"Data":[{"@Name":"Hashes","#text":"MD5=DED9E58DD95A88A4BEE89B74A65F05F1,'
                   'SHA256=ABBF7B5F7A059348A17DCD8BCD464767125F54B4F8691F0F810AC1819C6CF931,IMPHASH=ADD361A4F3939AF38D11873F1D74BDED"}]}}')
        rx = normalize.Normalizer.EMBEDDED_HASH_RX
        got = self.one(f"SELECT regexp_extract_all({normalize.lit(payload)}, {normalize.lit(rx)}, 1)")
        self.assertEqual([h.lower() for h in got], ["ded9e58dd95a88a4bee89b74a65f05f1",
                                                     "abbf7b5f7a059348a17dcd8bcd464767125f54b4f8691f0f810ac1819c6cf931"])
        import re
        self.assertRegex("Payload", normalize.Normalizer.EMBEDDED_HASH_COLUMN_RX)
        self.assertIsNone(re.fullmatch(normalize.Normalizer.EMBEDDED_HASH_COLUMN_RX, "Description"))


# ------------------------------------------------------------------------------------------
# Inventory
# ------------------------------------------------------------------------------------------
class TestInventory(unittest.TestCase):
    def test_classification(self):
        cases = {r"\Windows\Prefetch\CMD.EXE-1234.pf": "prefetch",
                 r"\ProgramData\AnyDesk\ad_svc.trace": "remote_access",
                 r"\Program Files (x86)\ScreenConnect Client (abc)\user.config": "remote_access_other",
                 r"\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk": "lnk",
                 r"\Windows\System32\drivers\etc\hosts": "hosts",
                 r"\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{A1}\{B2}.xml": "wifi_profiles",
                 r"\Users\bob\Documents\Default.rdp": "rdp_files",
                 # .rdp received through Outlook: classified as an RDP file, not as IE cache
                 r"\Users\bob\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\X1\vpn.rdp": "rdp_files",
                 r"\Windows\Panther\setupact.log": "panther",
                 r"\Windows\Panther\UnattendGC\setuperr.log": "panther",
                 r"\Windows\Panther\unattend.xml": "panther_other",
                 r"\Users\bob\AppData\Local\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState\x.bin": "notepad_tabs",
                 r"\Users\bob\AppData\Local\Microsoft\OneDrive\settings\Personal\SyncEngineDatabase.db": "onedrive_db",
                 r"\Users\bob\AppData\Local\Microsoft\OneDrive\settings\Personal\general.keystore": "onedrive"}
        for path, art in cases.items():
            self.assertEqual(inventory.classify(path).id, art, path)

    def test_registry_consistent(self):
        """Every artifact of the catalog has an entry in parser_registry.json, and vice versa."""
        reg = json.loads((PIPE / "config" / "parser_registry.json").read_text(encoding="utf-8"))["artifacts"]
        self.assertEqual(sorted(a.id for a in inventory.CATALOG), sorted(reg))

    def _collection(self, d: Path, single_volume: bool):
        """Mini KAPE collection: C\\a.txt (matching), C\\b.txt (modified), C\\$MFT (raw live copy)."""
        import hashlib
        root = d / "case"
        (root / "C").mkdir(parents=True)
        files = {"a.txt": b"alpha", "b.txt": b"bravo", "$MFT": b"mft"}
        for n, data in files.items():
            (root / "C" / n).write_bytes(data)
        dest = r"C:\Sleuthline\cases\case" if single_volume else r"C:\kape_output"
        rows = ["CopiedTimestamp,SourceFile,DestinationFile,FileSize,SourceFileSha1,DeferredCopy,CreatedOnUtc,ModifiedOnUtc,LastAccessedOnUtc,CopyDuration"]
        for n, data in files.items():
            sha = hashlib.sha1(b"other" if n != "a.txt" else data).hexdigest().upper()
            rows.append(f"2099-01-01 00:00:00.0000000,C:\\{n},{dest}\\C\\{n},{len(data)},{sha},{n == '$MFT'},,,,00:00:00")
        if not single_volume:     # second root folder: the common path is the KAPE output folder
            (root / "LongFileNames").mkdir()
            rows.append(rf"2099-01-01 00:00:00.0000000,C:\long,{dest}\LongFileNames\x.bin,1,,False,,,,00:00:00")
        (root / "2099-01-01T000000_CopyLog.csv").write_text("\n".join(rows), encoding="utf-8")
        return root

    def test_copylog_and_integrity(self):
        for single in (True, False):            # a single volume: the common path includes "\C" (fixed bug)
            with tempfile.TemporaryDirectory() as d:
                root = self._collection(Path(d), single)
                idx = inventory.load_copylog(root)
                self.assertIn(r"c\a.txt", idx, f"single_volume={single}")
                recs = [{"rel_path": rf"C\{n}", "original_path": rf"C:\{n}", "sha1": idx[rf"c\{n.lower()}"]["SourceFileSha1"],
                         "kape_deferred": n == "$MFT", "copied_utc": "2099-01-01 00:00:00"} for n in ("a.txt", "b.txt", "$MFT")]
                res = inventory.verify_integrity(root, recs)
                self.assertEqual((res["ok"], res["mismatch"], res["live_copy_mismatch"]), (1, 1, 1))
                self.assertEqual(res["verdict"], "ANOMALIES")

    def test_modified_after_copy(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x"
            p.write_bytes(b"x")
            self.assertTrue(inventory.modified_after_copy(p, "2000-01-01 00:00:00.0000000"))
            self.assertFalse(inventory.modified_after_copy(p, "2999-01-01 00:00:00"))


# ------------------------------------------------------------------------------------------
# Internal parsing ("native" job): Wi-Fi profiles, .rdp files, Panther logs
# ------------------------------------------------------------------------------------------
WLAN_XML = """<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>Office-5G</name>
  <SSIDConfig><SSID><hex>4F66666963652D3547</hex><name>Office-5G</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType><connectionMode>auto</connectionMode>
  <MSM><security>
    <authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption><useOneX>false</useOneX></authEncryption>
    <sharedKey><keyType>passPhrase</keyType><protected>true</protected><keyMaterial>01000000D08C9DDF0115D1118C7A</keyMaterial></sharedKey>
  </security></MSM>
</WLANProfile>"""

RDP_TEXT = ("screen mode id:i:2\r\nfull address:s:10.0.0.12:3389\r\nusername:s:CORP\\admin\r\n"
            "gatewayhostname:s:rdg.example.com\r\npassword 51:b:01000000D08C9DDF\r\ndrivestoredirect:s:*\r\n")

PANTHER_TEXT = ("2023-11-09 18:58:09, Info                  CONX   Windows setup started\n"
                "2023-11-09 18:58:10, Error      [0x08038d] MIG    Migration failed\n"
                "    rest of the message on the next line\n"
                "noise line without timestamp before the end\n")


class TestNativeParsers(unittest.TestCase):
    def test_wlan_without_key(self):
        rec = orchestrator.parse_wlan_profile(WLAN_XML)
        self.assertEqual((rec["name"], rec["ssid"], rec["authentication"], rec["encryption"], rec["connectionMode"]),
                         ("Office-5G", "Office-5G", "WPA2PSK", "AES", "auto"))
        self.assertNotIn("01000000D08C9DDF", json.dumps(rec))          # keyMaterial never extracted

    def test_rdp_without_password(self):
        p = Path(tempfile.mkdtemp()) / "Default.rdp"
        try:
            p.write_bytes(b"\xff\xfe" + RDP_TEXT.encode("utf-16-le"))   # format written by mstsc
            rec = orchestrator.parse_rdp_file(orchestrator.read_text_auto(p))
        finally:
            shutil.rmtree(p.parent, ignore_errors=True)
        self.assertEqual((rec["full_address"], rec["username"], rec["gatewayhostname"]),
                         ("10.0.0.12:3389", "CORP\\admin", "rdg.example.com"))
        self.assertEqual(rec["settings"]["drivestoredirect"], "*")
        self.assertNotIn("01000000D08C9DDF", json.dumps(rec))          # "password 51:b" excluded

    def test_panther(self):
        recs = list(orchestrator.parse_panther_log(PANTHER_TEXT))
        self.assertEqual(len(recs), 2)
        self.assertEqual((recs[0]["ts_local"], recs[0]["level"], recs[0]["component"]), ("2023-11-09 18:58:09", "Info", "CONX"))
        self.assertEqual((recs[1]["level"], recs[1]["component"], recs[1]["line"]), ("Error", "MIG", 2))
        self.assertIn("rest of the message", recs[1]["message"])

    def test_native_job(self):
        """"native" job end to end on a mini collection: JSONL outputs and CopyLog timestamps kept."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "raw"
            files = {r"C\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{A}\{B}.xml": ("wifi_profiles", WLAN_XML.encode()),
                     r"C\Users\bob\Documents\Default.rdp": ("rdp_files", b"\xff\xfe" + RDP_TEXT.encode("utf-16-le")),
                     r"C\Windows\Panther\setupact.log": ("panther", PANTHER_TEXT.encode())}
            recs = []
            for rel, (art, data) in files.items():
                p = root.joinpath(*rel.split("\\"))
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(data)
                recs.append({"rel_path": rel, "original_path": "C:" + rel[1:], "artifact": art, "user": "bob" if "bob" in rel else None,
                             "size": len(data), "created_utc": "2023-11-01 10:00:00", "modified_utc": "2023-11-09 18:00:00"})
            inv = {"summary": {"collection_root": str(root)}, "files": recs}
            out = Path(d) / "parsed" / "native"
            out.mkdir(parents=True)
            ctx = orchestrator.Context(Path(d), inv, {"tools": []}, out.parent)
            for st in orchestrator.j_native(ctx, out):
                st.func()
            wifi = [json.loads(l) for l in (out / "wifi_profiles.jsonl").read_text(encoding="utf-8").splitlines()]
            rdp = [json.loads(l) for l in (out / "rdp_files.jsonl").read_text(encoding="utf-8").splitlines()]
            pan = (out / "panther.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual((wifi[0]["ssid"], wifi[0]["created_utc"]), ("Office-5G", "2023-11-01 10:00:00"))
        self.assertEqual((rdp[0]["full_address"], rdp[0]["user"]), ("10.0.0.12:3389", "bob"))
        self.assertEqual(len(pan), 2)

    def test_jobs_and_mappings_declared(self):
        """New artifacts: one job (or one Dissect plugin) and one normalization mapping each."""
        jobs_art = {a for j in orchestrator.JOBS for a in j.artifacts}
        for art in ("wifi_profiles", "rdp_files", "panther"):
            self.assertIn(art, jobs_art)
        for plugin in ("windowsnotepad.tabs", "clsid.user", "appinit", "thumbcache.thumbcache", "sevenzip"):
            self.assertIn(plugin, orchestrator.DISSECT_PLUGINS)
        self.assertTrue(orchestrator.COMPLEMENT_BATCH.is_file())
        sources = json.loads((PIPE / "config" / "normalize_map.json").read_text(encoding="utf-8"))["sources"]
        ids = [s["id"] for s in sources]
        for sid in ("registry_complement", "reg_usbstor", "native_wifi", "native_rdp", "native_panther", "dissect_windowsnotepad_tabs",
                    "dissect_clsid_user", "dissect_appinit", "dissect_thumbcache", "dissect_sevenzip"):
            self.assertIn(sid, ids)
        # First match wins: the dedicated Dissect entries must come before the catch-all one
        for sid in ("dissect_clsid_user", "dissect_appinit", "dissect_thumbcache", "dissect_sevenzip"):
            self.assertLess(ids.index(sid), ids.index("dissect_other"))

    def test_wxtcmd_evidence(self):
        """WxTCmd does not write the source database: evidence rebuilt from the output folder."""
        src = next(s for s in json.loads((PIPE / "config" / "normalize_map.json").read_text(encoding="utf-8"))["sources"]
                   if s["id"] == "wxt_activity")
        con = duckdb.connect()
        f = "wxtcmd/C/Users/bob/AppData/Local/ConnectedDevicesPlatform/L.bob/20261018_bob_Activity.csv"
        ev, user = con.execute(f"SELECT {src['evidence']}, {src['user']} FROM (SELECT '{f}' AS _src_file)").fetchone()
        self.assertEqual(ev, r"C:\Users\bob\AppData\Local\ConnectedDevicesPlatform\L.bob\ActivitiesCache.db")
        self.assertEqual(user, "bob")


# ------------------------------------------------------------------------------------------
# Anthropic provider: payload (no network)
# ------------------------------------------------------------------------------------------
class TestAnthropicPayload(unittest.TestCase):
    def test_cache_and_tool_result(self):
        captured = {}

        def fake_http(url, payload, headers, timeout, retries=6):
            captured.update(payload)
            return {"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn",
                    "usage": {"input_tokens": 10, "cache_read_input_tokens": 90, "cache_creation_input_tokens": 0, "output_tokens": 5}}
        old = llm._http_json
        llm._http_json = fake_http
        try:
            p = llm.AnthropicProvider({"provider": "anthropic", "model": "m", "api_key": "k"})
            msgs = [{"role": "user", "content": "go"},
                    {"role": "assistant", "content": "", "tool_calls": [{"id": "t1", "name": "sql_query", "args": {"sql": "SELECT 1"}}]},
                    {"role": "tool", "tool_call_id": "t1", "name": "sql_query", "content": "1"}]
            rep = p.chat("system", msgs, analyze.TOOLS)
        finally:
            llm._http_json = old
        self.assertEqual(captured["system"][0]["cache_control"], {"type": "ephemeral"})
        last = captured["messages"][-1]["content"][-1]
        self.assertEqual(last["type"], "tool_result")
        self.assertEqual(last["cache_control"], {"type": "ephemeral"})
        # only one cache breakpoint in the messages (the API accepts at most 4 in total)
        marks = sum(1 for m in captured["messages"] for b in m["content"] if isinstance(b, dict) and "cache_control" in b)
        self.assertEqual(marks, 1)
        self.assertEqual((rep.input_tokens, rep.cache_read_tokens), (100, 90))
        self.assertAlmostEqual(rep.billed_input(), 10 + 9.0)


# ------------------------------------------------------------------------------------------
# End-to-end analysis (mock provider, synthetic database)
# ------------------------------------------------------------------------------------------
def build_synthetic_case(case: Path):
    (case / "db").mkdir(parents=True)
    con = duckdb.connect(str(case / "db" / "case.duckdb"))
    con.execute("CREATE SCHEMA raw")
    con.execute("""CREATE TABLE raw.prefetch AS SELECT * FROM (VALUES
        ('prefetch/p.csv', 1, 'EVIL.EXE', '2023-11-10 11:03:09'),
        ('prefetch/p.csv', 2, 'CMD.EXE',  '2023-11-10 11:04:00')) t(_src_file, _src_row, ExecutableName, LastRun)""")
    con.execute("""CREATE TABLE timeline AS SELECT row_number() OVER () AS tl_id, CAST(LastRun AS TIMESTAMP) AS ts,
        'last execution' AS ts_desc, 'Prefetch' AS artifact, 'execution' AS category, 'PECmd' AS tool, 'PC1' AS host,
        'bob' AS user_name, 'C:\\Users\\bob\\' || ExecutableName AS path, ExecutableName AS description,
        'C:\\Windows\\Prefetch\\x.pf' AS evidence, 'prefetch' AS src_table, _src_file AS src_file, _src_row AS src_row,
        'prefetch' AS source_id, 'validated' AS mapping, _src_file || '#' || _src_row AS ref FROM raw.prefetch""")
    con.execute("""CREATE TABLE detections (det_id BIGINT, ts TIMESTAMP, engine VARCHAR, rule_title VARCHAR, rule_id VARCHAR,
        level VARCHAR, computer VARCHAR, channel VARCHAR, event_id VARCHAR, record_id VARCHAR, details VARCHAR, tactics VARCHAR,
        evidence VARCHAR, src_table VARCHAR, src_file VARCHAR, src_row BIGINT, ref VARCHAR)""")
    con.execute("""CREATE VIEW timeline_all AS SELECT ts, ts_desc, artifact, category, tool, host, user_name, path, description,
        evidence, src_table, src_file, src_row, ref, mapping FROM timeline""")
    con.execute("CREATE VIEW artifact_summary AS SELECT artifact, category, tool, mapping, count(*) AS rows, min(ts) AS first_ts, "
                "max(ts) AS last_ts FROM timeline GROUP BY ALL")
    con.execute("CREATE TABLE sources AS SELECT 'prefetch/p.csv' AS src_file, 'pecmd' AS job, 0 AS bytes, NULL AS sha256, "
                "'loaded' AS status, NULL AS reason, 'raw.prefetch' AS raw_table, 2 AS rows, 0 AS rejected_rows, "
                "'validated' AS mapping, 'prefetch' AS source_id")
    con.execute("CREATE TABLE jobs (job VARCHAR, dir VARCHAR, title VARCHAR, status VARCHAR, started_utc VARCHAR, ended_utc VARCHAR, "
                "duration_s DOUBLE, tools VARCHAR, inputs VARCHAR, warnings VARCHAR, note VARCHAR)")
    con.execute("CREATE TABLE meta (key VARCHAR, value VARCHAR)")
    con.execute("INSERT INTO meta VALUES ('normalize_version', 'test'), ('map_version', 'test'), ('map_sha256', 'x')")
    con.execute("CREATE TABLE hashset (hash VARCHAR, algo VARCHAR, list VARCHAR, label VARCHAR, source_file VARCHAR)")
    con.execute("CREATE TABLE hash_hits (list VARCHAR, algo VARCHAR, hash VARCHAR, label VARCHAR, src_table VARCHAR, "
                "src_column VARCHAR, ref VARCHAR, source_file VARCHAR)")
    con.close()


class TestAgentEndToEnd(unittest.TestCase):
    def test_mock_analysis(self):
        with tempfile.TemporaryDirectory() as d:
            case = Path(d) / "case"
            build_synthetic_case(case)
            script = [
                {"tool_calls": [{"name": "sql_query", "args": {"sql": "SELECT ref, description FROM timeline LIMIT 5"}}]},
                {"tool_calls": [{"name": "add_finding", "args": {"title": "Non-existent ref", "severity": "high",
                                                                 "confidence": "confirmed", "description": "x", "refs": ["nope#1"]}}]},
                {"tool_calls": [{"name": "add_finding", "args": {"title": "Execution of EVIL.EXE", "severity": "critical",
                                                                 "confidence": "confirmed", "description": "Prefetch",
                                                                 "refs": ["prefetch/p.csv#1"]}},
                                {"name": "add_ioc", "args": {"type": "file", "value": "EVIL.EXE", "context": "malicious",
                                                             "refs": ["prefetch/p.csv#1"]}},
                                {"name": "step_complete", "args": {"summary": "done"}}]},
            ]
            (Path(d) / "script.json").write_text(json.dumps(script), encoding="utf-8")
            cfg = {"active": "mock", "report_language": "fr",
                   "profiles": {"mock": {"provider": "mock", "model": "mock", "script": str(Path(d) / "script.json")}}}
            (Path(d) / "cfg.json").write_text(json.dumps(cfg), encoding="utf-8")
            pb = Path(d) / "PLAYBOOK.md"
            pb.write_text("# P\n\n## Rules\n\n1. Facts.\n\n## Step 1: Execution\n\nLook.\n\n## Step 2: Summary\n\nSummarize.\n",
                          encoding="utf-8")
            argv = [str(case), "--config", str(Path(d) / "cfg.json"), "--playbook", str(pb)]
            self.assertEqual(analyze.main(argv), 0)
            st = json.loads((case / "analysis" / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual([f["title"] for f in st["findings"]], ["Execution of EVIL.EXE"])   # the non-existent ref is refused
            self.assertEqual(st["findings"][0]["evidence"][0]["artifact"], "Prefetch")
            self.assertEqual(len(st["iocs"]), 1)
            self.assertEqual(st["steps"]["1"]["status"], analyze.DONE)
            self.assertTrue(list((case / "analysis").glob("report_*.docx")))
            self.assertTrue((case / "analysis" / "key_timeline.csv").exists())
            refused = [json.loads(l) for l in (case / "analysis" / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertTrue(any(str(r.get("result", "")).startswith("REFUSED") for r in refused))
            # Replay of step 1: the items of the first run are removed, not duplicated
            (Path(d) / "script.json").write_text(json.dumps(script[2:]), encoding="utf-8")
            self.assertEqual(analyze.main(argv + ["--steps", "1", "--force", "--no-report"]), 0)
            st = json.loads((case / "analysis" / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(len(st["findings"]), 1)
            self.assertEqual(len(st["iocs"]), 1)

    def test_report_language_in_prompt(self):
        agent = analyze.Agent.__new__(analyze.Agent)
        agent.language, agent.rules, agent.guidance = analyze.language_name("fr"), "r", analyze.parse_guidance(Path("/nonexistent"))
        self.assertIn("in French", agent.system_prompt("overview"))


# ------------------------------------------------------------------------------------------
# Regression on a real case
# ------------------------------------------------------------------------------------------
def snapshot(db: Path) -> dict:
    con = duckdb.connect(str(db), read_only=True)
    try:
        tl = {f"{a} | {t}": n for a, t, n in con.execute(
            "SELECT artifact, tool, count(*) FROM timeline GROUP BY ALL ORDER BY 1, 2").fetchall()}
        det = {f"{e} | {lv}": n for e, lv, n in con.execute(
            "SELECT engine, level, count(*) FROM detections GROUP BY ALL ORDER BY 1, 2").fetchall()}
        raw = {t: con.execute(f'SELECT count(*) FROM raw."{t}"').fetchone()[0] for (t,) in con.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'raw' ORDER BY 1").fetchall()}
    finally:
        con.close()
    return {"timeline": tl, "detections": det, "raw_tables": raw}


def regression(case: Path, update: bool) -> int:
    case = case.resolve()
    tmp = Path(tempfile.mkdtemp(prefix="sleuthline_reg_"))
    try:
        db = tmp / "case.duckdb"
        # Temporary database: the case files (db\, local\normalize_proposals.json) are not modified
        normalize.PROPOSALS = tmp / "normalize_proposals.json"
        normalize.RateHistory.add = lambda self, entry: None
        log = normalize.Progress(live=False)
        rc = normalize.Normalizer(case, normalize.DEFAULT_MAP, db, True, log).run(None, None)
        snap = snapshot(db)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    GOLDEN.mkdir(exist_ok=True)
    gold = GOLDEN / (normalize.sanitize(case.name) + ".json")
    if update or not gold.exists():
        gold.write_text(json.dumps(snap, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"Reference recorded: {gold}")
        return 0
    ref = json.loads(gold.read_text(encoding="utf-8"))
    diffs = []
    for part in ("timeline", "detections", "raw_tables"):
        for k in sorted(set(ref[part]) | set(snap[part])):
            if ref[part].get(k) != snap[part].get(k):
                diffs.append(f"{part}: {k}: reference {ref[part].get(k)} -> got {snap[part].get(k)}")
    print(f"Regression {case.name}: " + ("compliant" if not diffs else f"{len(diffs)} difference(s)"))
    for x in diffs[:100]:
        print("  " + x)
    if rc:
        print(f"  (normalize.py reported errors: code {rc})")
    return 1 if diffs else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--regression", type=Path, action="append", help="real case to normalize and compare with tests\\golden")
    ap.add_argument("--update-golden", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args, rest = ap.parse_known_args()
    os.environ.setdefault("PYTHONUTF8", "1")
    result = unittest.main(argv=[sys.argv[0]] + rest, exit=False, verbosity=2 if args.verbose else 1).result
    code = 0 if result.wasSuccessful() else 1
    for c in args.regression or []:
        code |= regression(c, args.update_golden)
    sys.exit(code)
