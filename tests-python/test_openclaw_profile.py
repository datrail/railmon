"""RC-516: OpenClaw's harness profile fills the harness fields.

The shipped profile (tools/scan/gke/harness/profiles/openclaw.json and its
hooks, openclaw.py), loaded as production loads it, read against an agent laid
out from fixtures OpenClaw 2026.9.2 wrote itself (fixtures/openclaw/README.md).
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "tools" / "scan"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "openclaw"


def load(name: str, path: Path):
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


sys.path.insert(0, str(SCAN))
reader = load("harness_reader", SCAN / "gke" / "harness" / "reader.py")
harness_sources = load("gke_harness_sources", SCAN / "gke" / "harness" / "harness_sources.py")
pod_mode = load("gke_pod_mode", SCAN / "gke" / "pod_mode.py")
import evidence_bundle  # noqa: E402
import scan_agent_environment as scanner  # noqa: E402

PROFILES = reader.load_profiles()
OPENCLAW = next(p for p in PROFILES if p["harness"] == "openclaw")
hooks = sys.modules["harness_profile_openclaw"]
BUILDERS = {"answered": evidence_bundle._answered, "blind": evidence_bundle._blind,
            "absent": evidence_bundle._absent, "failed": evidence_bundle._failed,
            "partial": evidence_bundle._partial}
AGENT = reader.Agent("node /usr/local/bin/openclaw gateway --allow-unconfigured", {"HOME": "/root"})


def write_transcript(path: Path, tool_names: list[str], extra_events: list[str] = ()) -> sqlite3.Connection:
    """agents/<id>/agent/openclaw-agent.sqlite's transcript_events, as OpenClaw
    2026.9 writes it, in WAL mode and not checkpointed (as on a running agent):
    the returned connection holds the -wal open."""
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("pragma journal_mode=wal")
    db.execute("pragma wal_autocheckpoint=0")
    db.execute("create table transcript_events (session_id text, seq integer, event_json text, created_at text)")
    events = [json.dumps({"type": "message", "message": {"role": "user", "content": "price of A?"}})]
    events += [json.dumps({"type": "message", "message": {"role": "assistant", "content": [
        {"type": "toolCall", "name": name, "arguments": {"symbol": "argument-placeholder"}}]}}) for name in tool_names]
    events += list(extra_events)
    db.executemany("insert into transcript_events values ('s1', ?, ?, '')", list(enumerate(events)))
    db.commit()
    return db


class Install(unittest.TestCase):
    """An OpenClaw agent's root, laid out as OpenClaw lays it out."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "agent-root"
        self.state = self.root / "root" / ".openclaw"
        self.install(self.state)
        self.dbs: list[sqlite3.Connection] = []

    def install(self, state: Path, transcripts: list[str] = ("getStockPrice", "getStockPrice", "getStatement")) -> None:
        (state / "state").mkdir(parents=True, exist_ok=True)
        shutil.copy(FIXTURES / "openclaw.json", state / "openclaw.json")
        db = sqlite3.connect(state / "state" / "openclaw.sqlite")
        db.executescript((FIXTURES / "exec_approvals_config.sql").read_text())
        db.close()
        (state / "workspace").mkdir(exist_ok=True)
        (state / "workspace" / "AGENTS.md").write_text("# FinRetail assistant\nprompt-text-placeholder\n")
        (state / "skills" / "stock-lookup").mkdir(parents=True, exist_ok=True)
        (state / "skills" / "stock-lookup" / "SKILL.md").write_text("---\nname: stock-lookup\ndescription: Look up a stock price\n---\n")
        package = self.root / "usr" / "local" / "lib" / "node_modules" / "openclaw"
        (package / "dist").mkdir(parents=True, exist_ok=True)
        (package / "dist" / "build-info.json").write_text(json.dumps({"version": "2026.9.2", "commit": "3928bad9badfcb6c"}))
        self.transcript_db = write_transcript(state / "agents" / "main" / "agent" / "openclaw-agent.sqlite", list(transcripts))
        self.addCleanup(self.transcript_db.close)

    def transcript_db_path(self) -> Path:
        return self.state / "agents" / "main" / "agent" / "openclaw-agent.sqlite"

    def read(self, agent=AGENT, **kwargs):
        return reader.read_harness_fields(OPENCLAW, agent, reader.LocalSources(self.root), **kwargs)


class OpenClawProfileTest(Install):
    def test_the_profile_ships_and_recognizes_openclaw(self):
        self.assertIs(reader.harness_reader_for(PROFILES, AGENT), OPENCLAW)
        self.assertIs(reader.harness_reader_for(PROFILES, reader.Agent("node app.js", {"OPENCLAW_STATE_DIR": "/s"})), OPENCLAW)
        self.assertIsNone(reader.harness_reader_for(PROFILES, reader.Agent("python3 other_agent.py", {"HOME": "/root"})))
        # Started by node from the installed package, with no OPENCLAW_* variable.
        for cmdline in ("node /usr/local/lib/node_modules/openclaw/openclaw.mjs gateway",
                        "node /app/node_modules/openclaw/dist/index.js gateway --profile x"):
            self.assertIs(reader.harness_reader_for(PROFILES, reader.Agent(cmdline, {"HOME": "/root"})), OPENCLAW)
        # A different package whose name starts the same is not OpenClaw.
        self.assertIsNone(reader.harness_reader_for(
            PROFILES, reader.Agent("node /app/node_modules/openclaw-lite/index.js", {"HOME": "/root"})))

    def test_each_harness_field_is_answered_with_its_source_named(self):
        results = self.read()
        config = "$OPENCLAW_DIR/openclaw.json"  # reported as the profile writes it, never expanded
        expected = {
            "harness_identity": ("openclaw/2026.9.2", "/usr/local/lib/node_modules/openclaw/dist/build-info.json"),
            "model_name": ("external/gemini-flash-latest", config),
            "llm_provider": ("google", config),
            "inference_endpoint": ("https://generativelanguage.googleapis.com/v1beta/openai", config),
            "mcp_servers_declared": ({"finretail": {"url": "http://finretail-mcp-server:23004/mcp",
                                                    "transport": "streamable-http"}}, config),
            "tool_allow_deny": ({"deny": ["browser"]}, config),
            "approval_policy": ({"exec": {"host": "gateway", "mode": "ask"},
                                 "host_approvals": {"security": "allowlist", "ask": "on-miss", "ask_fallback": "deny",
                                                    "allowlist_entries": 0, "agent_overrides": 0}},
                                [config, "$OPENCLAW_DIR/state/openclaw.sqlite#exec_approvals_config"]),
            # The bundle's shape: sorted names, a floor, not a count.
            "tool_names": (["getStatement", "getStockPrice"], "$OPENCLAW_DIR/agents/main/agent/openclaw-agent.sqlite"),
            "system_prompt_present": ({"present": True, "files": ["$OPENCLAW_DIR/workspace/AGENTS.md"]},
                                      ["$OPENCLAW_DIR/workspace/AGENTS.md"]),
            "skills_inventory": ([{"name": "stock-lookup", "description": "Look up a stock price",
                                   "path": "$OPENCLAW_DIR/skills/stock-lookup"}], ["$OPENCLAW_DIR/skills"]),
        }
        for field, (value, source) in expected.items():
            result = results[field]
            self.assertEqual((result["status"], result["value"], result["source"]), ("ANSWERED", value, source), field)
        self.assertEqual(results["harness_identity"]["note"], "build 3928bad")

    def test_secrets_and_tool_arguments_never_reach_a_value(self):
        text = json.dumps(self.read(collect_prompt=False))
        for secret in ("fixture-placeholder-not-a-key", "socket-token-placeholder", "raw_json",
                       "argument-placeholder", "prompt-text-placeholder"):
            self.assertNotIn(secret, text)

    def test_the_approvals_query_never_selects_raw_json(self):
        statements: list[str] = []
        real_connect = sqlite3.connect

        def traced(*args, **kwargs):
            db = real_connect(*args, **kwargs)
            db.set_trace_callback(statements.append)
            return db

        with mock.patch.object(hooks.sqlite3, "connect", side_effect=traced):
            self.assertEqual(self.read()["approval_policy"]["status"], "ANSWERED")
        approvals = [s for s in statements if "exec_approvals_config" in s]
        self.assertTrue(approvals)
        self.assertFalse([s for s in approvals if "raw_json" in s or "*" in s])

    def test_a_config_moved_by_openclaw_config_path_is_found(self):
        moved = self.root / "etc" / "openclaw" / "custom.json"
        moved.parent.mkdir(parents=True)
        config = json.loads((FIXTURES / "openclaw.json").read_text())
        config["agents"]["defaults"]["model"]["primary"] = "external/gemini-pro-latest"
        moved.write_text(json.dumps(config))
        agent = reader.Agent("openclaw gateway", {"HOME": "/root", "OPENCLAW_CONFIG_PATH": "/etc/openclaw/custom.json"})
        result = self.read(agent)["model_name"]
        self.assertEqual((result["value"], result["source"]), ("external/gemini-pro-latest", "$OPENCLAW_CONFIG_PATH"))

    def test_a_state_dir_moved_by_openclaw_state_dir_is_used(self):
        shutil.rmtree(self.state)
        self.install(self.root / "srv" / "openclaw-state", transcripts=["searchFunds"])
        agent = reader.Agent("openclaw gateway", {"HOME": "/root", "OPENCLAW_STATE_DIR": "/srv/openclaw-state"})
        results = self.read(agent)
        self.assertEqual(results["model_name"]["source"], "$OPENCLAW_DIR/openclaw.json")
        self.assertEqual(results["tool_names"]["value"], ["searchFunds"])
        self.assertIn("$OPENCLAW_DIR/state/openclaw.sqlite#exec_approvals_config", results["approval_policy"]["source"])
        self.assertEqual(results["system_prompt_present"]["source"], ["$OPENCLAW_DIR/workspace/AGENTS.md"])
        # The folder the variable held is used, never reported.
        self.assertNotIn("/srv/openclaw-state", json.dumps(results))

    def test_profile_dev_and_openclaw_home_pick_the_folder_openclaw_picks(self):
        # As OpenClaw 2026.9.2 resolves it (fixtures/openclaw/README.md): only the
        # agent's own folder is read, never the default one beside it.
        cases = [("openclaw --profile eqform gateway", {}, "root/.openclaw-eqform"),
                 ("openclaw --profile=eqform gateway", {}, "root/.openclaw-eqform"),
                 ("openclaw --dev gateway", {}, "root/.openclaw-dev"),
                 ("openclaw gateway", {"OPENCLAW_HOME": "/srv/h"}, "srv/h/.openclaw"),
                 ("openclaw --profile p gateway", {"OPENCLAW_HOME": "/srv/h"}, "srv/h/.openclaw-p"),
                 ("openclaw --profile p gateway", {"OPENCLAW_STATE_DIR": "/srv/s"}, "srv/s"),
                 # OPENCLAW_PROFILE in the environment alone doesn't move the folder.
                 ("openclaw gateway", {"OPENCLAW_PROFILE": "eqform"}, "root/.openclaw")]
        for cmdline, env, folder in cases:
            with self.subTest(cmdline=cmdline, env=env):
                if folder != "root/.openclaw":
                    self.install(self.root / folder, transcripts=["searchFunds"])
                results = self.read(reader.Agent(cmdline, {"HOME": "/root", **env}))
                expected = ["getStatement", "getStockPrice"] if folder == "root/.openclaw" else ["searchFunds"]
                self.assertEqual(results["tool_names"]["value"], expected)
                self.assertEqual(results["model_name"]["source"], "$OPENCLAW_DIR/openclaw.json")
                self.assertNotIn(folder, json.dumps(results))
                if folder != "root/.openclaw":
                    self.transcript_db.close()
                    shutil.rmtree(self.root / folder)

    def test_a_profile_with_no_folder_reads_nothing_of_the_default_one(self):
        results = self.read(reader.Agent("openclaw --profile other gateway", {"HOME": "/root"}))
        self.assertEqual((results["model_name"]["status"], results["model_name"]["reason"]),
                         ("BLIND", "NO_SOURCE_ACCESS"))
        self.assertNotEqual(results["tool_names"]["status"], "ANSWERED")

    def test_an_agent_in_agents_list_overrides_the_default_model(self):
        config = json.loads((FIXTURES / "openclaw.json").read_text())
        config["agents"]["list"] = [{"id": "main", "model": "external/gemini-pro-latest"}]
        (self.state / "openclaw.json").write_text(json.dumps(config))
        self.assertEqual(self.read()["model_name"]["value"], "external/gemini-pro-latest")

    def test_invalid_json_gives_failed_with_parse_failed(self):
        (self.state / "openclaw.json").write_text("{not json")
        results = self.read()
        for field in ("model_name", "inference_endpoint", "llm_provider", "mcp_servers_declared"):
            self.assertEqual((results[field]["status"], results[field]["reason"]), ("FAILED", "PARSE_FAILED"), field)
        # The installed package still names the harness.
        self.assertEqual(results["harness_identity"]["value"], "openclaw/2026.9.2")

    def test_a_locked_database_gives_approval_policy_partial(self):
        # A database that can't be read whole: tools.exec still answers, the host side is missing.
        (self.state / "state" / "openclaw.sqlite").write_bytes(b"not a database, or one mid-write")
        result = self.read()["approval_policy"]
        self.assertEqual((result["status"], result["reason"]), ("PARTIAL", "NO_SOURCE_ACCESS"))
        self.assertEqual(result["value"], {"exec": {"host": "gateway", "mode": "ask"}})
        self.assertIn("host approvals could not be read", result["note"])

    def test_a_database_over_the_cap_is_size_cap_exceeded(self):
        with mock.patch.object(hooks, "DB_MAX_BYTES", 1024):
            results = self.read()
        approval, tools = results["approval_policy"], results["tool_names"]
        # tools.exec still answers; the host approvals were too large to copy whole.
        self.assertEqual((approval["status"], approval["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))
        self.assertEqual((tools["status"], tools["reason"]), ("FAILED", "SIZE_CAP_EXCEEDED"))
        self.assertIn("larger than 1024 bytes", tools["note"])

    def test_no_declared_policy_is_never_evidence_of_restriction(self):
        config = json.loads((FIXTURES / "openclaw.json").read_text())
        del config["tools"]
        (self.state / "openclaw.json").write_text(json.dumps(config))
        (self.state / "state" / "openclaw.sqlite").unlink()
        results = self.read()
        for field in ("approval_policy", "tool_allow_deny"):
            self.assertEqual((results[field]["status"], results[field]["reason"]), ("BLIND", "GATEWAY_MANAGED"), field)

    def test_no_prompt_text_without_the_flag(self):
        self.assertEqual(self.read()["system_prompt_text"]["reason"], "NOT_COLLECTED_BY_PACK")
        self.assertIn("prompt-text-placeholder", json.dumps(self.read(collect_prompt=True)["system_prompt_text"]))

    def test_the_latest_transcript_writes_in_the_wal_are_counted(self):
        self.transcript_db.execute("insert into transcript_events values ('s1', 99, ?, '')", (json.dumps(
            {"type": "message", "message": {"role": "assistant", "content": [{"type": "toolCall", "name": "buyStock"}]}}),))
        self.transcript_db.commit()
        self.assertIn("buyStock", self.read()["tool_names"]["value"])

    def test_a_bad_transcript_event_gives_partial(self):
        self.transcript_db.execute("insert into transcript_events values ('s1', 99, 'not json', '')")
        self.transcript_db.commit()
        result = self.read()["tool_names"]
        self.assertEqual((result["status"], result["reason"]), ("PARTIAL", "PARSE_FAILED"))

    def test_an_event_over_the_value_cap_fails_only_itself(self):
        # SQLite applies the value cap when it reads a stored value too: an
        # event holding a screenshot must cost only that event, not the
        # database's other tool calls.
        big = json.dumps({"type": "message", "message": {"role": "assistant", "content": [
            {"type": "image", "data": "A" * 2_000_000}, {"type": "toolCall", "name": "takeScreenshot"}]}})
        self.transcript_db.execute("insert into transcript_events values ('s1', 50, ?, '')", (big,))
        self.transcript_db.execute("insert into transcript_events values ('s1', 51, ?, '')", (json.dumps(
            {"type": "message", "message": {"role": "assistant", "content": [{"type": "toolCall", "name": "buyStock"}]}}),))
        self.transcript_db.commit()
        result = self.read()["tool_names"]
        self.assertEqual((result["status"], result["reason"]), ("PARTIAL", "PARSE_FAILED"))
        self.assertEqual(result["value"], ["buyStock", "getStatement", "getStockPrice"])
        self.assertIn(f"1 event(s) larger than {hooks.DB_MAX_VALUE} bytes not read", result["note"])

    def test_content_that_is_not_a_list_is_skipped_not_a_crash(self):
        # The agent writes this database: a stray shape must not stop the scan.
        for content in (5, True, "plain text", {"type": "toolCall", "name": "x"}):
            event = json.dumps({"type": "message", "message": {"role": "assistant", "content": content}})
            self.transcript_db.execute("insert into transcript_events values ('s1', 100, ?, '')", (event,))
        self.transcript_db.commit()
        result = self.read()["tool_names"]
        self.assertEqual((result["status"], result["value"]), ("ANSWERED", ["getStatement", "getStockPrice"]))

    def test_an_unwritable_tmp_fails_the_database_fields_only(self):
        # A read-only or full /tmp in a hardened pod: the copy can't be made.
        with mock.patch.object(hooks.tempfile, "TemporaryDirectory", side_effect=OSError(28, "No space left", "/tmp/x-secret-path")):
            results = self.read()
        for field in ("tool_names", "approval_policy"):
            self.assertEqual((results[field]["status"], results[field]["reason"]), ("FAILED", "PARSE_FAILED"), field)
            self.assertIn("OSError", results[field]["note"])
        self.assertNotIn("x-secret-path", json.dumps(results))
        self.assertEqual(results["model_name"]["status"], "ANSWERED")

    def test_a_view_in_place_of_a_table_is_refused_not_run(self):
        # The agent writes these databases: a view could compute rows without end.
        self.transcript_db.executescript(
            "alter table transcript_events rename to real_events;"
            "create view transcript_events as with recursive n(i) as (select 1 union all select i + 1 from n) "
            "select 's1' as session_id, i as seq, randomblob(1000000) as event_json, '' as x from n;")
        approvals = sqlite3.connect(self.state / "state" / "openclaw.sqlite")
        approvals.executescript("alter table exec_approvals_config rename to real_config;"
                                "create view exec_approvals_config as select * from real_config;")
        approvals.close()
        started = time.monotonic()
        results = self.read()
        self.assertLess(time.monotonic() - started, 5)
        self.assertNotEqual(results["tool_names"]["status"], "ANSWERED")
        self.assertIn("not an ordinary table", results["tool_names"]["note"])
        self.assertNotIn("host_approvals", results["approval_policy"].get("value") or {})
        self.assertIn("not an ordinary table", results["approval_policy"]["note"])

    def test_a_query_is_interrupted_at_its_deadline_and_values_are_capped(self):
        copy = self.state / "state" / "openclaw.sqlite"
        endless = "with recursive n(i) as (select 1 union all select i + 1 from n) select count(*) from n"
        with mock.patch.object(hooks, "DB_SECONDS", 0.2):
            started = time.monotonic()
            with self.assertRaises(sqlite3.OperationalError):
                hooks._query(copy, "exec_approvals_config", endless)
            self.assertLess(time.monotonic() - started, 5)
        with self.assertRaises(sqlite3.Error):  # larger than DB_MAX_VALUE
            hooks._query(copy, "exec_approvals_config", "select randomblob(2000000)")
        with self.assertRaises(sqlite3.Error):  # opened read-only
            hooks._query(copy, "exec_approvals_config", "delete from exec_approvals_config")

    def test_approvals_values_are_short_words_counts_or_flags_only(self):
        approvals = sqlite3.connect(self.state / "state" / "openclaw.sqlite")
        approvals.execute("update exec_approvals_config set default_ask = ?, default_ask_fallback = 'deny' "
                          "where config_key = 'current'", ("a" * 100_000,))
        approvals.commit()
        approvals.close()
        host = self.read()["approval_policy"]["value"]["host_approvals"]
        self.assertNotIn("ask", host)
        self.assertEqual(host["ask_fallback"], "deny")
        # OpenClaw's table is STRICT, but a crafted one need not be.
        self.assertEqual([hooks._summary_value(v) for v in (b"\x00blob", 3.5, None, "on", 4, True)],
                         [None, None, None, "on", 4, True])

    def test_a_checkpointed_database_with_no_wal_is_still_read(self):
        # A cleanly stopped agent: WAL mode in the header, no -wal or -shm beside it.
        self.transcript_db.execute("pragma wal_checkpoint(truncate)")
        self.transcript_db.close()
        approvals = sqlite3.connect(self.state / "state" / "openclaw.sqlite")
        approvals.execute("pragma journal_mode=wal")
        approvals.execute("pragma wal_checkpoint(truncate)")
        approvals.close()
        for wal in [*self.state.rglob("*.sqlite-wal"), *self.state.rglob("*.sqlite-shm")]:
            wal.unlink()
        for db in (self.transcript_db_path(), self.state / "state" / "openclaw.sqlite"):
            self.assertEqual(db.read_bytes()[18:20], b"\x02\x02", db)  # WAL mode in the header
        results = self.read()
        self.assertEqual(results["tool_names"]["status"], "ANSWERED")
        self.assertEqual(results["approval_policy"]["value"]["host_approvals"]["security"], "allowlist")

    def test_a_generated_column_is_refused_and_a_large_table_read_only_up_to_the_budget(self):
        path = self.transcript_db_path()
        self.transcript_db.close()
        path.unlink()
        for leftover in path.parent.glob(path.name + "-*"):
            leftover.unlink()
        generated = sqlite3.connect(path)
        generated.executescript("create table transcript_events (session_id text, seq integer, "
                                "event_json text generated always as (zeroblob(900000)) virtual, created_at text);"
                                "insert into transcript_events (session_id, seq, created_at) values ('s1', 1, '');")
        generated.close()
        result = self.read()["tool_names"]
        self.assertNotEqual(result["status"], "ANSWERED")
        self.assertIn("generated column", result["note"])
        path.unlink()
        self.transcript_db = write_transcript(path, ["getStockPrice", "getStatement", "searchFunds"])
        with mock.patch.object(hooks, "DB_MAX_ROWS", 3):  # the user message, then two calls
            result = self.read()["tool_names"]
        self.assertEqual((result["status"], result["reason"], result["value"]),
                         ("PARTIAL", "SIZE_CAP_EXCEEDED", ["getStatement", "getStockPrice"]))

    def test_no_install_at_all_is_blind(self):
        shutil.rmtree(self.state)
        shutil.rmtree(self.root / "usr")
        results = self.read()
        for field in ("model_name", "harness_identity", "tool_names", "skills_inventory"):
            self.assertEqual((results[field]["status"], results[field]["reason"]), ("BLIND", "NO_SOURCE_ACCESS"), field)


class PodModeTest(Install):
    """The shipped profile through pod mode: the config volume mounted at the
    agent's path in the sidecar, everything else through the agent's root."""

    def test_pod_mode_fills_openclaws_fields_from_the_volume_and_the_agents_root(self):
        volume = self.tmp / "volume"
        shutil.copytree(self.state, volume / "root" / ".openclaw")
        shutil.rmtree(self.state)  # only the package stays in the agent's own root
        volume_path = volume / "root" / ".openclaw"
        subject = {"root": str(self.root), "cmdline": AGENT.cmdline, "env": {"HOME": str(volume / "root")}}
        context = {"mode": "pod", "subject": subject, "config_paths": [str(volume_path)]}
        attributes = pod_mode.harness_attributes(context, BUILDERS)
        self.assertEqual(attributes["model_name"]["value"], "external/gemini-flash-latest")
        self.assertEqual(attributes["model_name"]["method"], "openclaw profile: $OPENCLAW_DIR/openclaw.json")
        self.assertEqual(attributes["harness_identity"]["value"], "openclaw/2026.9.2")
        self.assertEqual(attributes["approval_policy"]["authored_by"], "platform")
        self.assertEqual(attributes["tool_names"]["value"], ["getStatement", "getStockPrice"])
        self.assertNotIn("fixture-placeholder-not-a-key", json.dumps(attributes))
        self.assertNotIn(str(volume), json.dumps(attributes))  # the agent's HOME is never reported

    def test_pod_mode_merges_openclaws_values_in_the_bundles_own_shapes(self):
        # As evidence_bundle.py calls it: the bundle's attributes so far, and the
        # scanner's own shaping functions.
        volume = self.tmp / "volume"
        shutil.copytree(self.state, volume / "root" / ".openclaw")
        subject = {"root": str(self.root), "cmdline": AGENT.cmdline, "env": {"HOME": str(volume / "root")}}
        context = {"mode": "pod", "subject": subject, "config_paths": [str(volume / "root" / ".openclaw")]}
        shapers = {"mcp_inventory_entries": scanner.mcp_inventory_entries, "normalize_skill": scanner.normalize_skill,
                   "merge_skill_lists": scanner.merge_skill_lists, "url_host": scanner.url_host,
                   "redact_url": scanner.redact_url}
        existing = {"tool_names": evidence_bundle._answered(["wireTool"], "observed", authored_by="none")}
        attributes = pod_mode.harness_attributes(context, BUILDERS, existing=existing, shapers=shapers)
        servers = attributes["mcp_servers_declared"]["value"]
        self.assertEqual(servers, scanner.mcp_inventory_entries(
            {"finretail": {"url": "http://finretail-mcp-server:23004/mcp", "transport": "streamable-http"}}, "openclaw profile"))
        self.assertEqual(attributes["skills_inventory"]["value"], [{
            "name": "stock-lookup", "description": "Look up a stock price", "destination_endpoints": [],
            "source_type": "skills_config"}])
        self.assertEqual(attributes["declared_destinations"]["value"],
                         ["finretail-mcp-server", "generativelanguage.googleapis.com"])
        self.assertNotIn("tool_names", attributes)  # AgentSight's wire-observed list stands


if __name__ == "__main__":
    unittest.main()
