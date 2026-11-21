"""RC-545: mcp_servers_observed names each MCP server's tools the agent called,
from its transcripts.

The same transcripts tool_names reads (OpenClaw's transcript_events, with
event_zstd, and Claude Code's JSONL under ~/.claude/projects/), with each
call's tool name matched to an MCP server by the profile's
workspace.transcripts.mcp_tools pattern: OpenClaw names an MCP tool
<server>__<tool>, Claude Code mcp__<server>__<tool>. Names only: no arguments,
and no counts, which grow with every call and would be drift on every scan.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_agent_process as tap  # noqa: E402  (its FakeProc, and the scanner modules it loads)
import test_claude_code_profile as cc  # noqa: E402
import test_transcript_caps as caps  # noqa: E402

reader = caps.reader
OPENCLAW, CLAUDE = caps.OPENCLAW, caps.CLAUDE
hooks = caps.hooks
FINRETAIL_URL = "http://finretail-mcp-server:23004/mcp"


def setUpModule() -> None:
    tap.setUpModule()


def tearDownModule() -> None:
    tap.tearDownModule()


def claude_call(*names: str) -> str:
    """One assistant entry calling each of `names`, with an input that must
    never reach the bundle."""
    return json.dumps({"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": f"toolu_{i}", "name": name, "input": {"symbol": caps.ARGUMENT}}
        for i, name in enumerate(names)]}})


class OpenClawObservedTest(caps.OpenClawInstall):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(hooks, "zstd_decompress", side_effect=caps.fake_decompress)
        patcher.start()
        self.addCleanup(patcher.stop)

    def read(self):
        results = reader.read_harness_fields(OPENCLAW, caps.OPENCLAW_AGENT, reader.LocalSources(self.root))
        return results

    def test_five_calls_to_finretail_from_event_json(self):
        self.table(with_zstd=False)  # 2026.9.2
        for seq in range(5):
            self.db.execute("insert into transcript_events values ('s1', ?, ?, '')",
                            (seq, caps.call("finretail__getStockPrice")))
        self.db.commit()
        observed = self.read()["mcp_servers_observed"]
        self.assertEqual(observed["status"], "ANSWERED")
        self.assertEqual(observed["value"], [{"name": "finretail", "tools_called": ["getStockPrice"]}])
        self.assertEqual(observed["tier"], "observed")
        self.assertNotIn(FINRETAIL_URL, json.dumps(observed))  # the transcript names no address
        self.assertIn("floor", observed["note"])

    def test_compressed_events_count_too(self):
        self.table()  # 2026.10.8
        self.add(1, caps.call("finretail__getStockPrice"))
        self.add(2, None, caps.fake_compress(caps.call("finretail__getStockPrice", pad=2000)))
        self.add(3, None, caps.fake_compress(caps.call("finretail__buyStock", pad=5000)))
        observed = self.read()["mcp_servers_observed"]
        self.assertEqual(observed["value"][0]["tools_called"], ["buyStock", "getStockPrice"])

    def test_built_in_tools_and_undeclared_prefixes_are_not_counted(self):
        self.table()
        self.add(1, caps.call("automations"))
        self.add(2, caps.call("exec"))
        self.add(3, caps.call("other__lookup"))  # no server "other" is declared
        results = self.read()
        self.assertEqual(results["tool_names"]["value"], ["automations", "exec", "other__lookup"])
        observed = results["mcp_servers_observed"]
        self.assertEqual(observed["status"], "ABSENT")
        self.assertIn("no call in the transcripts read named an MCP server", observed["method"])

    def test_no_tool_call_at_all_is_absent_as_tool_names_is(self):
        self.table()
        self.add(1, json.dumps({"type": "message", "message": {"role": "user", "content": "hi"}}))
        results = self.read()
        self.assertEqual(results["tool_names"]["status"], "ABSENT")
        self.assertEqual(results["mcp_servers_observed"]["status"], "ABSENT")

    def test_an_unreadable_event_with_no_mcp_call_is_an_empty_floor(self):
        self.table()
        self.add(1, caps.call("exec"))
        self.add(2, "{not json")
        observed = self.read()["mcp_servers_observed"]
        self.assertEqual((observed["status"], observed["reason"], observed["value"]), ("PARTIAL", "PARSE_FAILED", []))

    def test_an_unreadable_event_gives_partial_parse_failed(self):
        self.table()
        self.add(1, caps.call("finretail__getStockPrice"))
        self.add(2, "{not json")
        self.add(3, None, b"not a frame")
        observed = self.read()["mcp_servers_observed"]
        self.assertEqual((observed["status"], observed["reason"]), ("PARTIAL", "PARSE_FAILED"))
        self.assertEqual(observed["value"][0]["tools_called"], ["getStockPrice"])

    def test_no_transcript_database_is_blind(self):
        shutil.rmtree(self.root / "root" / ".openclaw" / "agents")
        observed = self.read()["mcp_servers_observed"]
        self.assertEqual((observed["status"], observed["reason"]), ("BLIND", "NO_SOURCE_ACCESS"))

    def test_no_argument_reaches_the_value(self):
        self.table()
        self.add(1, caps.call("finretail__getStockPrice"))
        self.assertNotIn(caps.ARGUMENT, json.dumps(self.read()))


@unittest.skipUnless(caps.real_zstd, "needs compression.zstd (Python 3.14+), as CI and the images have")
class OpenClawRealZstdTest(caps.OpenClawInstall):
    def test_real_frames_count(self):
        self.table()
        for seq in range(5):
            self.add(seq, None, caps.real_zstd.compress(caps.call("finretail__getStockPrice", pad=2000).encode()))
        observed = reader.read_harness_fields(OPENCLAW, caps.OPENCLAW_AGENT,
                                              reader.LocalSources(self.root))["mcp_servers_observed"]
        self.assertEqual(observed["value"][0]["tools_called"], ["getStockPrice"])


class ClaudeCodeObservedTest(cc.Install):
    TRANSCRIPT = "/root/.claude/projects/-work/0cf9746c-7773-486a-9058-fb795c31ab97.jsonl"

    def append(self, *lines: str) -> None:
        with self.path(self.TRANSCRIPT).open("a") as handle:
            for line in lines:
                handle.write(line + "\n")

    def test_mcp_prefixed_calls_are_counted_by_server(self):
        self.append(claude_call("mcp__finretail__getStockPrice", "Bash"),
                    claude_call("mcp__finretail__getStockPrice"),
                    claude_call("mcp__finretail__getStatement"))
        observed = self.read()["mcp_servers_observed"]
        self.assertEqual(observed["status"], "ANSWERED")
        self.assertEqual(observed["value"], [{"name": "finretail",
                                              "tools_called": ["getStatement", "getStockPrice"]}])
        self.assertNotIn("not declared", observed["note"])

    def test_a_server_no_config_declares_is_still_counted_and_named_in_the_note(self):
        # mcp__ is Claude Code's prefix for MCP tools only, so a plugin's server
        # (mcp__plugin_<plugin>_<server>__<tool>) still counts, under the name
        # Claude Code spells, which no declared name matches: the note says so.
        self.append(claude_call("mcp__plugin_search_web__query"), claude_call("mcp__finretail__getStockPrice"))
        observed = self.read()["mcp_servers_observed"]
        self.assertIn({"name": "plugin_search_web", "tools_called": ["query"]}, observed["value"])
        self.assertIn("not declared in any MCP config the scan read", observed["note"])
        self.assertIn("plugin_search_web", observed["note"])
        self.assertNotIn("finretail", observed["note"].split("tool names:")[-1])

    def test_a_declared_name_is_matched_as_claude_code_spells_it(self):
        self.edit("/root/.claude.json", lambda d: d["mcpServers"].update(
            {"my.server": {"type": "http", "url": "http://my-server:8080/mcp"}}))
        self.append(claude_call("mcp__my_server__lookup"))
        observed = self.read()["mcp_servers_observed"]
        self.assertIn({"name": "my.server", "tools_called": ["lookup"]}, observed["value"])

    def test_built_in_tools_only_is_absent(self):
        observed = self.read()["mcp_servers_observed"]  # the fixture calls Read and Bash
        self.assertEqual(observed["status"], "ABSENT")

    def test_a_bad_line_gives_partial_parse_failed(self):
        self.append("{not json", claude_call("mcp__finretail__getStockPrice"))
        observed = self.read()["mcp_servers_observed"]
        self.assertEqual((observed["status"], observed["reason"]), ("PARTIAL", "PARSE_FAILED"))
        self.assertEqual(observed["value"][0]["tools_called"], ["getStockPrice"])

    def test_more_transcripts_than_the_cap_is_partial_size_cap_exceeded(self):
        folder = "/root/.claude/projects/-work"
        for i in range(reader.TRANSCRIPT_MAX_FILES + 5):
            self.write(f"{folder}/session-{i:03d}.jsonl", claude_call("mcp__finretail__getStockPrice") + "\n")
        observed = self.read()["mcp_servers_observed"]
        self.assertEqual((observed["status"], observed["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))
        self.assertEqual(observed["value"][0]["name"], "finretail")

    def test_no_argument_reaches_the_value(self):
        self.append(claude_call("mcp__finretail__getStockPrice"))
        self.assertNotIn(caps.ARGUMENT, json.dumps(self.read()))

    def test_more_calls_to_the_same_tools_leave_the_value_unchanged(self):
        # No counts: an agent that keeps calling the same tools reads the same
        # on every scan, so a locked baseline sees no drift.
        self.append(claude_call("mcp__finretail__getStockPrice"))
        before = self.read()["mcp_servers_observed"]["value"]
        self.append(*[claude_call("mcp__finretail__getStockPrice")] * 5)
        self.assertEqual(self.read()["mcp_servers_observed"]["value"], before)

    def test_two_declared_names_one_key_spells_match_the_same_one_every_time(self):
        self.edit("/root/.claude.json", lambda d: d["mcpServers"].update(
            {"my_server": {"type": "http", "url": "http://a:8080/mcp"},
             "my.server": {"type": "http", "url": "http://b:8080/mcp"}}))
        self.append(claude_call("mcp__my_server__lookup"))
        observed = self.read()["mcp_servers_observed"]
        self.assertIn({"name": "my.server", "tools_called": ["lookup"]}, observed["value"])
        self.assertEqual(reader.observed_mcp_servers(["mcp__my_server__lookup"], ["my_server", "my.server"],
                                                     {"pattern": "mcp__{server}__{tool}"}),
                         reader.observed_mcp_servers(["mcp__my_server__lookup"], ["my.server", "my_server"],
                                                     {"pattern": "mcp__{server}__{tool}"}))

    def test_tool_names_are_redacted_as_tool_names_are(self):
        # A tool's name is a value here, as in tool_names: get_token is kept, and
        # a secret written in a name is scrubbed the same way in both fields.
        token = "ghp_" + "a1B2c3D4e5" * 4
        self.append(claude_call("mcp__vault__get_token", "mcp__vault__list_secrets", "mcp__vault__env"),
                    claude_call(f"mcp__vault__{token}", "mcp__vault__lookup password=hunter2"))
        results = self.read()
        observed = results["mcp_servers_observed"]
        tools = next(entry["tools_called"] for entry in observed["value"] if entry["name"] == "vault")
        for name in ("env", "get_token", "list_secrets"):
            self.assertIn(name, tools)
        self.assertNotIn(token, json.dumps(observed))
        self.assertNotIn("hunter2", json.dumps(observed))
        self.assertNotIn("hunter2", json.dumps(results["tool_names"]))

    def test_a_secret_split_across_server_and_tool_is_still_scrubbed(self):
        # An undeclared server is split from its tool at the separator; a name
        # is scrubbed whole first, so "token=" and the value after it are never
        # reported apart, where redaction would no longer see them together.
        self.append(claude_call("mcp__token=__hunter2secret", "mcp__password:__hunter2pass",
                                "mcp__finretail__getStockPrice"))
        results = self.read()
        observed = results["mcp_servers_observed"]
        for secret in ("hunter2secret", "hunter2pass"):
            self.assertNotIn(secret, json.dumps(observed))
            self.assertNotIn(secret, json.dumps(results["tool_names"]))
        self.assertIn({"name": "finretail", "tools_called": ["getStockPrice"]}, observed["value"])


class SharedReaderObservedTest(caps.Transcripts):
    def test_the_shared_reader_counts_with_a_pattern(self):
        profile = json.loads(json.dumps(caps.TOY))
        profile["fields"] = {"mcp_servers_declared": "mcp"}
        profile["sources"] = [{"path": "~/.toy/config.json"}]
        profile["workspace"]["transcripts"]["mcp_tools"] = {"pattern": "{server}.{tool}"}
        self.write("/home/toy/.toy/config.json", json.dumps({"mcp": {"db": {"url": "http://db:1/mcp"}}}), age=0)
        self.write("/home/toy/.toy/sessions/a.jsonl",
                   "\n".join(json.dumps({"call": {"name": n}}) for n in ("db.query", "db.query", "shell")) + "\n", age=0)
        agent = reader.Agent("toyagent serve", {"HOME": "/home/toy"})
        observed = reader.read_harness_fields(profile, agent, reader.LocalSources(self.root))["mcp_servers_observed"]
        self.assertEqual(observed["value"], [{"name": "db", "tools_called": ["query"]}])

    def test_no_mcp_call_is_absent_and_says_where_it_looked(self):
        profile = json.loads(json.dumps(caps.TOY))
        profile["workspace"]["transcripts"]["mcp_tools"] = {"pattern": "{server}.{tool}"}
        self.write("/home/toy/.toy/sessions/a.jsonl", json.dumps({"call": {"name": "shell"}}) + "\n", age=0)
        agent = reader.Agent("toyagent serve", {"HOME": "/home/toy"})
        observed = reader.read_harness_fields(profile, agent, reader.LocalSources(self.root))["mcp_servers_observed"]
        self.assertEqual(observed["status"], "ABSENT")
        self.assertIn("~/.toy/sessions/a.jsonl", observed["method"])
        self.assertNotIn("None", observed["method"])

    def test_a_profile_without_a_pattern_says_so(self):
        self.write("/home/toy/.toy/sessions/a.jsonl", json.dumps({"call": {"name": "x"}}) + "\n", age=0)
        agent = reader.Agent("toyagent serve", {"HOME": "/home/toy"})
        observed = reader.read_harness_fields(caps.TOY, agent, reader.LocalSources(self.root))["mcp_servers_observed"]
        self.assertEqual((observed["status"], observed["reason"]), ("BLIND", "NOT_COLLECTED_BY_PACK"))

    def test_a_bad_pattern_is_refused_when_the_profile_loads(self):
        for pattern in ("{tool}", "{server}{tool}", "{server}__{tool}x", 7):
            profile = json.loads(json.dumps(caps.TOY))
            profile["workspace"]["transcripts"]["mcp_tools"] = {"pattern": pattern}
            with self.subTest(pattern=pattern), self.assertRaises(reader.ProfileError):
                reader.validate_profile(profile)

    def test_a_harness_without_a_profile_is_blind_unknown_harness(self):
        observed = reader.read_harness_fields(None, reader.Agent("hermes run", {"HOME": "/home/toy"}),
                                              reader.LocalSources(self.root))["mcp_servers_observed"]
        self.assertEqual((observed["status"], observed["reason"]), ("BLIND", "UNKNOWN_HARNESS"))


class PodModeBundleTest(unittest.TestCase):
    """A real pod-mode scan, in process, against a fake /proc and an OpenClaw
    config volume, as test_agent_process runs one: the bundle carries the
    field and passes verify_bundle."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fake = tap.FakeProc(self.tmp)
        self.fake.agent_filesystem()
        self.volume = self.tmp / "volume" / ".openclaw"
        self.volume.mkdir(parents=True)
        config = json.loads((caps.FIXTURES / "openclaw" / "openclaw.json").read_text())
        # A port nothing listens on: the MCP probe is refused at once.
        config["mcp"]["servers"]["finretail"]["url"] = "http://127.0.0.1:9/mcp"
        (self.volume / "openclaw.json").write_text(json.dumps(config))
        podinfo = self.tmp / "podinfo"
        podinfo.mkdir()
        (podinfo / "labels").write_text('app="agent-finretail"\npod-template-hash="58cd78b55d"\n')
        self.sidecar_env = {"POD_NAME": "agent-finretail-58cd78b55d-48jcw", "POD_NAMESPACE": "gke-test",
                            "POD_UID": "f3fe5e58-b328-40cb-9b03-1acf558d773d", "NODE_NAME": "node-1",
                            "RAIL_POD_INFO_DIR": str(podinfo), "HOME": str(self.tmp / "sidecar-home")}

    def transcript(self, *names: str) -> None:
        import sqlite3
        path = self.volume / "agents" / "main" / "agent" / "openclaw-agent.sqlite"
        path.parent.mkdir(parents=True)
        db = sqlite3.connect(path)
        db.execute("create table transcript_events (session_id text, seq integer, event_json text, created_at text)")
        db.executemany("insert into transcript_events values ('s1', ?, ?, '')",
                       [(i, caps.call(name)) for i, name in enumerate(names)])
        db.commit()
        db.close()

    def scan(self):
        # The volume is mounted at the same path in the agent and the sidecar.
        shutil.copytree(self.volume, self.fake.container("agent") / self.volume.relative_to("/"))
        env = {**tap.AGENT_ENV, "OPENCLAW_STATE_DIR": str(self.volume)}
        self.fake.process(1, "pause", ["/pause"], env={})
        self.fake.process(7, "agent", ["node", "/usr/local/bin/openclaw", "gateway"], env=env)
        scanner, evidence_bundle = tap.scanner, tap.evidence_bundle
        args = scanner.make_parser().parse_args(["--mode", "pod", "--config-path", str(self.volume),
                                                 "--no-feature-file", "--host-id", "gke-test"])
        clean = {k: v for k, v in os.environ.items()
                 if not k.startswith(("RAIL_", "POD_", "GIT_")) and k != "NODE_NAME"}
        with mock.patch.dict(os.environ, {**clean, **self.sidecar_env}, clear=True), \
                mock.patch.object(tap.agent_process, "PROC_DIR", self.fake.proc), \
                contextlib.redirect_stderr(io.StringIO()):
            context, payload, identity = scanner.scan(args)
            return evidence_bundle.build_verified_bundle(args, context, payload, identity)

    def test_the_bundle_carries_the_servers_the_agent_called(self):
        self.transcript(*["finretail__getStockPrice"] * 5, "automations")
        bundle = self.scan()
        observed = bundle["attributes"]["mcp_servers_observed"]
        self.assertEqual(observed["status"], "ANSWERED")
        self.assertEqual(observed["value"], [{"name": "finretail", "tools_called": ["getStockPrice"]}])
        self.assertEqual((observed["tier"], observed["authored_by"]), ("observed", "subject"))
        self.assertNotIn(caps.ARGUMENT, json.dumps(bundle))

    def test_no_mcp_call_is_absent_in_the_bundle_not_the_placeholder(self):
        self.transcript("automations")
        observed = self.scan()["attributes"]["mcp_servers_observed"]
        self.assertEqual(observed["status"], "ABSENT")
        self.assertIn("named an MCP server", observed["method"])

    def test_no_transcript_replaces_the_agentsight_placeholder(self):
        bundle = self.scan()
        observed = bundle["attributes"]["mcp_servers_observed"]
        self.assertEqual((observed["status"], observed["reason"]), ("BLIND", "NO_SOURCE_ACCESS"))
        self.assertNotIn("AgentSight", observed.get("note", ""))


if __name__ == "__main__":
    unittest.main()
