"""DSC.G2 — the scanner asks a live MCP server what it exposes.

A real loopback HTTP server, not a mock of `probe_mcp_tools`'s internals:
the acceptance criterion is that a real tool the server declares arrives as
its own skill carrying the server's own description, and that failure is
recorded as unreachable rather than skipped. Both are wire-level claims a
mocked prober couldn't verify. Stdlib only, to match the scanner itself.
"""

from __future__ import annotations

import importlib.util
import json
import threading
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "tools" / "scan" / "scan_agent_environment.py"

_spec = importlib.util.spec_from_file_location("scan_agent_environment", SCANNER)
scanner = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(scanner)


class FakeMcpServer:
    """A minimal Streamable HTTP MCP server: `initialize`, then `tools/list`.

    Runs on an ephemeral loopback port in a background thread so tests hit a
    real socket without any external network dependency.
    """

    def __init__(self, tools, *, require_auth=None, session_header=True, page_size=None, refuse_status=401,
                 fail_after_pages=None):
        self.tools = tools
        self.require_auth = require_auth
        self.session_header = session_header
        self.seen_session_ids = []
        self._issued_session_id = "test-session-1"

        tools_by_call = self.tools
        require_auth_ = self.require_auth
        issued_session_id = self._issued_session_id
        send_session_header = self.session_header
        seen = self.seen_session_ids
        cursors = self.seen_cursors = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                seen.append(self.headers.get("Mcp-Session-Id"))
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                if require_auth_ is not None and self.headers.get("Authorization") != require_auth_:
                    self.send_response(refuse_status)
                    self.end_headers()
                    return
                method = body.get("method")
                if method == "initialize":
                    result = {"protocolVersion": scanner.MCP_PROTOCOL_VERSION, "capabilities": {}}
                elif method == "tools/list" and page_size is None:
                    result = {"tools": tools_by_call}
                elif method == "tools/list":
                    # MCP pagination: an opaque cursor, here the next offset.
                    cursor = (body.get("params") or {}).get("cursor")
                    cursors.append(cursor)
                    if fail_after_pages is not None and len(cursors) > fail_after_pages:
                        self.send_response(500)
                        self.end_headers()
                        return
                    start = int(cursor[len("page-"):]) if cursor else 0
                    result = {"tools": tools_by_call[start:start + page_size]}
                    if start + page_size < len(tools_by_call):
                        result["nextCursor"] = f"page-{start + page_size}"
                else:
                    self.send_response(400)
                    self.end_headers()
                    return
                payload = json.dumps({"jsonrpc": "2.0", "id": body.get("id"), "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                if send_session_header:
                    self.send_header("Mcp-Session-Id", issued_session_id)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}/mcp"

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


class ProbeMcpToolsTest(unittest.TestCase):
    def test_every_declared_tool_comes_back(self):
        tools = [
            {"name": "track_package", "description": "Track one package."},
            {"name": "forbidden_tool", "description": "A tool a policy denies."},
        ]
        with FakeMcpServer(tools) as server:
            result = scanner.probe_mcp_tools(server.url, None)
        self.assertEqual(result, tools)

    def test_the_initialize_session_id_is_replayed_on_tools_list(self):
        with FakeMcpServer([{"name": "t", "description": "d"}]) as server:
            scanner.probe_mcp_tools(server.url, None)
        self.assertEqual(server.seen_session_ids, [None, "test-session-1"])

    def test_a_stateless_server_with_no_session_header_still_works(self):
        with FakeMcpServer([{"name": "t", "description": "d"}], session_header=False) as server:
            result = scanner.probe_mcp_tools(server.url, None)
        self.assertEqual(result, [{"name": "t", "description": "d"}])

    def test_the_configured_header_is_sent_and_a_missing_one_is_refused(self):
        with FakeMcpServer([{"name": "t", "description": "d"}], require_auth="Bearer secret-1") as server:
            self.assertIsNone(scanner.probe_mcp_tools(server.url, None))
            self.assertEqual(
                scanner.probe_mcp_tools(server.url, {"Authorization": "Bearer secret-1"}),
                [{"name": "t", "description": "d"}],
            )

    def test_connection_refused_is_none_not_an_exception(self):
        # Nothing listens on this loopback port; refused immediately, no
        # timeout wait.
        result = scanner.probe_mcp_tools("http://127.0.0.1:1/mcp", None, timeout=1.0)
        self.assertIsNone(result)

    def test_a_file_url_is_never_opened(self):
        # urllib has a file:// handler that ignores the POST method and body;
        # a config entry pointing there must not become a local file read.
        result = scanner.probe_mcp_tools("file:///etc/passwd", None, timeout=1.0)
        self.assertIsNone(result)


class McpServerSkillsTest(unittest.TestCase):
    def test_reachable_server_yields_one_skill_per_tool_with_its_own_description(self):
        tools = [
            {"name": "track_package", "description": "Track one package."},
            {"name": "forbidden_tool", "description": "A tool a policy denies."},
        ]
        with FakeMcpServer(tools) as server:
            skills = scanner.mcp_server_skills("shipping", {"url": server.url}, Path("agent.mcp.json"))

        self.assertEqual(
            [(s["name"], s["description"]) for s in skills],
            [("track_package", "Track one package."), ("forbidden_tool", "A tool a policy denies.")],
        )
        for skill in skills:
            self.assertEqual(skill["source_type"], "mcp_config")

    def test_a_key_shaped_endpoint_stays_out_of_the_tool_description(self):
        with FakeMcpServer([{"name": "t", "description": "d"}]) as server:
            skills = scanner.mcp_server_skills(
                "shipping", {"url": server.url, "headers": {"Authorization": "Bearer sk-live-abc123"}}, Path("a.json")
            )
        self.assertNotIn("sk-live-abc123", repr(skills))

    def test_a_credential_the_config_does_not_have_is_unreachable_not_skipped(self):
        with FakeMcpServer([{"name": "t", "description": "d"}], require_auth="Bearer secret-1") as server:
            skills = scanner.mcp_server_skills("shipping", {"url": server.url}, Path("agent.mcp.json"))

        self.assertEqual(len(skills), 1)
        self.assertEqual(skills[0]["name"], "shipping")
        self.assertEqual(skills[0]["description"], "MCP server configured via agent.mcp.json: unreachable")

    def test_an_unreachable_server_is_still_recorded(self):
        skills = scanner.mcp_server_skills("shipping", {"url": "http://127.0.0.1:1/mcp"}, Path("agent.mcp.json"))
        self.assertEqual(len(skills), 1)
        self.assertEqual(skills[0]["name"], "shipping")
        self.assertEqual(skills[0]["description"], "MCP server configured via agent.mcp.json: unreachable")

    def test_a_reachable_server_that_declares_nothing_is_not_skipped_either(self):
        with FakeMcpServer([]) as server:
            skills = scanner.mcp_server_skills("shipping", {"url": server.url}, Path("agent.mcp.json"))
        self.assertEqual(len(skills), 1)
        self.assertEqual(
            skills[0]["description"], "MCP server configured via agent.mcp.json: reachable, declares no tools"
        )

    def test_a_stdio_server_keeps_its_existing_single_skill_shape(self):
        skills = scanner.mcp_server_skills(
            "local", {"command": "/usr/local/bin/mcp-server", "args": ["--token", "sk-secret"]}, Path("agent.mcp.json")
        )
        self.assertEqual(len(skills), 1)
        self.assertEqual(skills[0]["name"], "local")
        self.assertEqual(skills[0]["description"], "MCP server configured via agent.mcp.json: mcp-server")
        self.assertNotIn("sk-secret", repr(skills))

    def test_a_server_with_neither_url_nor_command_is_unreachable(self):
        skills = scanner.mcp_server_skills("mystery", {}, Path("agent.mcp.json"))
        self.assertEqual(len(skills), 1)
        self.assertEqual(skills[0]["description"], "MCP server configured via agent.mcp.json: unreachable")


class CollectSkillsCollisionTest(unittest.TestCase):
    def test_two_servers_with_the_same_tool_name_both_survive(self):
        # Two independent MCP servers commonly expose a same-named tool
        # ("search"). Each keeps its own skill, with its server, description
        # and endpoint (DR-264: merged into one, the other server's text
        # never reached Rail Center).
        import json
        import tempfile

        with FakeMcpServer([{"name": "search", "description": "Search alpha's index."}]) as alpha, FakeMcpServer(
            [{"name": "search", "description": "Search beta's index."}]
        ) as beta:
            config = {"mcpServers": {"alpha": {"url": alpha.url}, "beta": {"url": beta.url}}}
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / ".mcp.json"
                path.write_text(json.dumps(config), encoding="utf-8")
                skills = scanner.collect_skills([path])

            search = sorted((s["server"], s["description"], s["destination_endpoints"])
                            for s in skills if s["name"] == "search")
            self.assertEqual(search, [("alpha", "Search alpha's index.", [alpha.url]),
                                      ("beta", "Search beta's index.", [beta.url])])


class SkillShapeForRailCenterTest(unittest.TestCase):
    """DR-264 (Eason, 2026-10-29): what Rail Center's Profiler needs to tell a
    tool from a server, one server from another, and an upload or a
    destructive call from a read-looking name."""

    def test_a_server_that_could_not_be_listed_is_a_server_entry_not_a_tool(self):
        # source_type stays mcp_config: Rail Center stores it in a Postgres
        # enum (skills_config, mcp_config, api_config), and a new value would
        # fail the registration. `entry` says server or tool.
        unreachable = scanner.mcp_server_skills("fetch", {"url": "http://127.0.0.1:1/mcp"}, Path("a.json"))
        stdio = scanner.mcp_server_skills("local", {"command": "mcp-server"}, Path("a.json"))
        with FakeMcpServer([]) as server:
            empty = scanner.mcp_server_skills("quiet", {"url": server.url}, Path("a.json"))
        for skills, name in ((unreachable, "fetch"), (stdio, "local"), (empty, "quiet")):
            for skill in (*skills, *scanner.merge_skill_lists(skills)):
                self.assertEqual((skill["source_type"], skill["entry"], skill["server"]),
                                 ("mcp_config", "server", name))
        with FakeMcpServer([{"name": "t", "description": "d"}]) as server:
            tool = scanner.merge_skill_lists(scanner.mcp_server_skills("alpha", {"url": server.url}, Path("a.json")))
        self.assertEqual([(s["source_type"], s["entry"], s["server"]) for s in tool], [("mcp_config", "tool", "alpha")])
        # A server and a tool of one name on one server are two entries.
        both = scanner.merge_skill_lists([*stdio, {**stdio[0], "entry": "tool"}])
        self.assertEqual(sorted(s["entry"] for s in both), ["server", "tool"])

    def test_source_type_is_a_closed_set_and_a_skills_file_cannot_pick_one(self):
        import json
        import tempfile

        for given, kept in (("mcp_config", "mcp_config"), ("skills_config", "skills_config"),
                            ("mcp_server", "skills_config"), ("api_config", "skills_config"),
                            ("MCP_CONFIG", "skills_config"), ("", "skills_config")):
            skill = scanner.normalize_skill({"name": "n", "description": "d", "source_type": given}, "t")
            self.assertEqual(skill["source_type"], kept, given)
        odd = scanner.normalize_skill({"name": "n", "description": "d", "source_type": "mcp_config",
                                       "entry": "prompt", "inputSchema": {"type": "object"}}, "t")
        self.assertNotIn("entry", odd)
        self.assertNotIn("inputSchema", odd)  # only a tool keeps a schema
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "skills.json"
            path.write_text(json.dumps({"skills": [
                {"name": "fetch", "description": "d", "source_type": "mcp_config", "server": "x",
                 "entry": "tool", "inputSchema": {"type": "object"}}]}), encoding="utf-8")
            skills = scanner.read_skills_file(path)
        self.assertEqual(skills, [{"name": "fetch", "description": "d", "destination_endpoints": [],
                                   "source_type": "skills_config"}])

    def test_a_probed_tool_keeps_its_input_schema_and_annotations_redacted(self):
        key = "sk-live-" + "a1B2c3D4" * 4
        tools = [{
            "name": "upload_file",
            "description": "Store a file.",
            "inputSchema": {"type": "object", "required": ["data"], "properties": {
                "data": {"type": "string", "format": "binary", "description": f"the bytes; demo key {key}"},
                "size": {"type": "integer", "maximum": 1048576}}},
            "annotations": {"title": "Upload", "readOnlyHint": False, "destructiveHint": True,
                            "openWorldHint": "yes", "x-vendor": {"k": 1}},
        }]
        with FakeMcpServer(tools) as server:
            skills = scanner.merge_skill_lists(scanner.mcp_server_skills("store", {"url": server.url}, Path("a.json")))
        (skill,) = skills
        self.assertNotIn(key, repr(skill))
        self.assertEqual(skill["inputSchema"]["properties"]["data"]["format"], "binary")
        self.assertEqual(skill["inputSchema"]["required"], ["data"])
        self.assertEqual(skill["inputSchema"]["properties"]["size"]["maximum"], 1048576)
        self.assertEqual(skill["annotations"], {"title": "Upload", "readOnlyHint": False, "destructiveHint": True})

    def test_all_schemas_together_stay_within_their_budget(self):
        # One server's many tools must not push the bundle past 1 MiB.
        import json

        schema = {"type": "object", "properties": {f"p{i}": {"type": "string", "description": "x" * 40}
                                                   for i in range(60)}}
        tools = [{"name": f"t{i:03d}", "description": "d", "source_type": "mcp_config", "entry": "tool",
                  "server": "big", "inputSchema": schema} for i in range(200)]
        skills = scanner.merge_skill_lists(tools)
        kept = [s for s in skills if "inputSchema" in s]
        self.assertTrue(0 < len(kept) < 200)
        self.assertEqual([s["name"] for s in kept], [f"t{i:03d}" for i in range(len(kept))])
        rendered = sum(len(json.dumps(s["inputSchema"], indent=2)) for s in kept)
        self.assertLessEqual(rendered, scanner.SKILL_SCHEMAS_BYTES)
        self.assertEqual(len(skills), 200)  # the skills stay, only schemas go

    def test_an_oversized_or_malformed_schema_is_left_out(self):
        big = {"type": "object", "description": "x" * (scanner.SKILL_SCHEMA_BYTES + 1)}
        deep: dict = {"type": "object"}
        node = deep
        for _ in range(scanner.SKILL_SCHEMA_DEPTH + 2):
            node["items"] = {"type": "array"}
            node = node["items"]
        # Left out, and said why (DR-293): a reader can tell it from a tool
        # that declares no schema at all.
        for schema, reason in ((big, "per_tool_budget"), (deep, "unrepresentable"), ("object", "unrepresentable"),
                               (["a"], "unrepresentable"), ({"n": float("nan")}, "unrepresentable")):
            fields = scanner.tool_schema_fields({"inputSchema": schema, "annotations": {"note": "only"}})
            self.assertEqual(fields, {"schema_omitted": reason}, repr(schema)[:60])
        self.assertEqual(scanner.tool_schema_fields({"annotations": {"note": "only"}}), {})


class ReachabilityAndOmissionMarksTest(unittest.TestCase):
    """DR-293: Rail Center's capture plan reads skills_inventory, and must be
    able to tell a tool the server doesn't have from a server RailMon could
    not ask, a dropped schema from none, and a cut list from a whole one."""

    def test_each_kind_of_server_entry_says_how_it_answered(self):
        with FakeMcpServer([{"name": "t", "description": "d"}]) as server:
            tools = scanner.mcp_server_skills("ok", {"url": server.url}, Path("a.json"))
        with FakeMcpServer([]) as server:
            empty = scanner.mcp_server_skills("quiet", {"url": server.url}, Path("a.json"))
        refused = scanner.mcp_server_skills("down", {"url": "http://127.0.0.1:1/mcp"}, Path("a.json"))
        stdio = scanner.mcp_server_skills("local", {"command": "mcp-server"}, Path("a.json"))
        bare = scanner.mcp_server_skills("mystery", {}, Path("a.json"))
        for skills, entry, reachability in ((tools, "tool", "reached"), (empty, "server", "declares_none"),
                                            (refused, "server", "unreachable"), (stdio, "server", "not_probed_stdio"),
                                            (bare, "server", "unreachable")):
            for skill in (*skills, *scanner.merge_skill_lists(skills)):
                self.assertEqual((skill["entry"], skill["reachability"]), (entry, reachability))
                self.assertNotIn("tools_truncated", skill)
        # The descriptions read as they did before the marks.
        self.assertEqual(empty[0]["description"], "MCP server configured via a.json: reachable, declares no tools")
        self.assertEqual(refused[0]["description"], "MCP server configured via a.json: unreachable")

    def test_a_401_or_403_is_auth_refused(self):
        for status in (401, 403):
            with FakeMcpServer([{"name": "t", "description": "d"}], require_auth="Bearer secret-1",
                               refuse_status=status) as server:
                probed = scanner.mcp_server_skills("crm", {"url": server.url}, Path("a.json"))
            skills = scanner.merge_skill_lists(probed)
            self.assertEqual([(s["entry"], s["reachability"]) for s in skills], [("server", "auth_refused")], status)
            self.assertEqual(skills[0]["description"], "MCP server configured via a.json: unreachable")
        with FakeMcpServer([], require_auth="Bearer secret-1", refuse_status=500) as server:
            skills = scanner.mcp_server_skills("crm", {"url": server.url}, Path("a.json"))
        self.assertEqual(skills[0]["reachability"], "unreachable")

    def test_tools_list_follows_next_cursor(self):
        tools = [{"name": f"t{i:02d}", "description": "d"} for i in range(7)]
        with FakeMcpServer(tools, page_size=3) as server:
            result = scanner.probe_mcp_server(server.url, None)
        self.assertEqual(result, (tools, "reached", False))
        self.assertEqual(server.seen_cursors, [None, "page-3", "page-6"])

    def test_the_page_and_tool_bounds_truncate_and_say_so(self):
        tools = [{"name": f"t{i:02d}", "description": "d"} for i in range(10)]
        with mock.patch.object(scanner, "MCP_TOOLS_PAGES", 2), FakeMcpServer(tools, page_size=3) as server:
            self.assertEqual(scanner.probe_mcp_server(server.url, None), (tools[:6], "reached", True))
        with mock.patch.object(scanner, "MCP_TOOLS_MAX", 4), FakeMcpServer(tools, page_size=3) as server:
            self.assertEqual(scanner.probe_mcp_server(server.url, None), (tools[:4], "reached", True))
        with mock.patch.object(scanner, "MCP_TOOLS_MAX", 4), FakeMcpServer(tools) as server:
            skills = scanner.merge_skill_lists(scanner.mcp_server_skills("big", {"url": server.url}, Path("a.json")))
        self.assertEqual([s["name"] for s in skills], ["t00", "t01", "t02", "t03"])
        for skill in skills:
            self.assertEqual((skill["reachability"], skill["tools_truncated"]), ("reached", True))

    def test_a_later_page_failing_keeps_what_was_read_as_truncated(self):
        tools = [{"name": f"t{i:02d}", "description": "d"} for i in range(5)]
        with FakeMcpServer(tools, page_size=2, fail_after_pages=1) as server:
            self.assertEqual(scanner.probe_mcp_server(server.url, None), (tools[:2], "reached", True))

    def test_a_schema_left_out_for_the_bundle_budget_says_so(self):
        schema = {"type": "object", "properties": {f"p{i}": {"type": "string", "description": "x" * 40}
                                                   for i in range(60)}}
        tools = [{"name": f"t{i:03d}", "description": "d", "source_type": "mcp_config", "entry": "tool",
                  "server": "big", "inputSchema": schema} for i in range(200)]
        skills = scanner.merge_skill_lists(tools)
        dropped = [s for s in skills if "inputSchema" not in s]
        self.assertTrue(dropped)
        for skill in skills:
            self.assertEqual(skill.get("schema_omitted"), None if "inputSchema" in skill else "bundle_budget")
        # The mark survives the scan's second merge (MCP skills with a skills file's).
        again = scanner.merge_skill_lists(skills, [])
        self.assertEqual([s.get("schema_omitted") for s in again], [s.get("schema_omitted") for s in skills])

    def test_a_schema_too_large_for_one_tool_says_so_through_the_merge(self):
        big = {"type": "object", "description": "x" * (scanner.SKILL_SCHEMA_BYTES + 1)}
        with FakeMcpServer([{"name": "t", "description": "d", "inputSchema": big}]) as server:
            (skill,) = scanner.merge_skill_lists(scanner.mcp_server_skills("s", {"url": server.url}, Path("a.json")))
        self.assertNotIn("inputSchema", skill)
        self.assertEqual(skill["schema_omitted"], "per_tool_budget")

    def test_marks_are_closed_sets_and_a_skills_file_cannot_set_them(self):
        odd = scanner.normalize_skill({"name": "n", "description": "d", "source_type": "mcp_config", "entry": "tool",
                                       "reachability": "maybe", "schema_omitted": "felt_like_it",
                                       "tools_truncated": "yes"}, "t")
        for field in ("reachability", "schema_omitted", "tools_truncated"):
            self.assertNotIn(field, odd)
        filed = scanner.normalize_skill({"name": "n", "description": "d", "source_type": "skills_config",
                                         "reachability": "reached", "tools_truncated": True}, "t")
        self.assertNotIn("reachability", filed)
        self.assertNotIn("tools_truncated", filed)

    def test_one_server_read_from_two_configs_keeps_the_answer_that_reached_it(self):
        down = {"name": "crm", "description": "MCP server configured via a.json: unreachable",
                "destination_endpoints": [], "source_type": "mcp_config", "entry": "server", "server": "crm",
                "reachability": "unreachable"}
        refused = {**down, "reachability": "auth_refused"}
        (merged,) = scanner.merge_skill_lists([down, refused])
        self.assertEqual(merged["reachability"], "auth_refused")


class MalformedMcpResponseTest(unittest.TestCase):
    """A server that breaks HTTP itself is unreachable, never a scan abort."""

    def _garbage_server(self, reply: bytes):
        import socket

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)

        def serve():
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                with conn:
                    conn.recv(65536)
                    conn.sendall(reply)

        threading.Thread(target=serve, daemon=True).start()
        self.addCleanup(listener.close)
        return f"http://127.0.0.1:{listener.getsockname()[1]}/mcp"

    def test_garbage_status_line_is_unreachable(self):
        url = self._garbage_server(b"NOT-HTTP garbage\r\n\r\n")
        self.assertEqual(scanner.probe_mcp_server(url, None), (None, "unreachable", False))

    def test_truncated_body_is_unreachable(self):
        url = self._garbage_server(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{}")
        self.assertEqual(scanner.probe_mcp_server(url, None), (None, "unreachable", False))

    def test_bad_port_is_unreachable(self):
        self.assertEqual(scanner.probe_mcp_server("http://127.0.0.1:abc/mcp", None), (None, "unreachable", False))


if __name__ == "__main__":
    unittest.main()
