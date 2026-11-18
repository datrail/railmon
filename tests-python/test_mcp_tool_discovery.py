"""DSC.G2 — the scanner asks a live MCP server what it exposes.

A real loopback HTTP server, not a mock of `probe_mcp_tools`'s internals:
the acceptance criterion is that a real tool the server declares arrives as
its own skill carrying the server's own description, and that failure is
recorded as unreachable rather than skipped. Both are wire-level claims a
mocked prober couldn't verify. Stdlib only, to match the scanner itself.
"""

from __future__ import annotations

import importlib.util
import hashlib
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
        # Every request's Authorization header, None when it had none (RC-511).
        self.seen_authorization = []
        self._issued_session_id = "test-session-1"

        tools_by_call = self.tools
        require_auth_ = self.require_auth
        issued_session_id = self._issued_session_id
        send_session_header = self.session_header
        seen = self.seen_session_ids
        seen_auth = self.seen_authorization
        cursors = self.seen_cursors = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                seen.append(self.headers.get("Mcp-Session-Id"))
                seen_auth.append(self.headers.get("Authorization"))
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


# ── RC-511: tool_schemas ─────────────────────────────────────────────────────

_evidence_spec = importlib.util.spec_from_file_location(
    "evidence_bundle", ROOT / "tools" / "scan" / "evidence_bundle.py"
)
evidence_bundle = importlib.util.module_from_spec(_evidence_spec)
assert _evidence_spec.loader is not None
_evidence_spec.loader.exec_module(evidence_bundle)

KEY = "sk-live-" + "a1B2c3D4" * 4
FINRETAIL_TOOLS = [
    {
        "name": "getInterestRate",
        "description": "The interest rate for a product.",
        "inputSchema": {
            "type": "object",
            "required": ["product"],
            "properties": {
                "product": {"type": "string", "enum": ["savings", "mortgage"], "description": "Which product"},
                "term_months": {"type": "integer", "minimum": 1, "maximum": 360, "default": 12},
                "as_of": {"type": "string", "format": "date", "examples": ["2026-11-01"]},
            },
            "additionalProperties": False,
        },
        "annotations": {"title": "Interest rate", "readOnlyHint": True, "x-owner": "retail"},
    },
    {"name": "listBranches", "description": "Every branch."},
]


def tool_schemas_from(servers: list[tuple[str, dict]], *, send_headers: bool = True) -> list[dict]:
    """tool_schemas' servers, as build_registration_payload collects them."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / ".mcp.json"
        path.write_text(json.dumps({"mcpServers": dict(servers)}))
        schemas: list[dict] = []
        scanner.collect_skills([path], {}, send_headers=send_headers, schemas=schemas)
    return scanner.cap_tool_schemas(schemas)


class RecordToolSchemaTest(unittest.TestCase):
    """record_tool_schema, redact_json and the tool_schemas attribute against
    a live loopback MCP server."""

    def test_the_schema_matches_what_the_server_declares(self):
        with FakeMcpServer(FINRETAIL_TOOLS) as server:
            (entry,) = tool_schemas_from([("finretail", {"url": server.url})])
        self.assertEqual((entry["server"], entry["reachability"]), ("finretail", "reached"))
        self.assertEqual(entry["endpoints"], [server.url])
        self.assertEqual(entry["source_kind"], "file")
        self.assertTrue(entry["source"].endswith("/.mcp.json"))
        rate, branches = entry["tools"]
        self.assertEqual(rate, {
            "name": "getInterestRate",
            "description": "The interest rate for a product.",
            "inputSchema": FINRETAIL_TOOLS[0]["inputSchema"],
            "annotations": FINRETAIL_TOOLS[0]["annotations"],
            "schema_sha256": scanner.tool_schema_digest(
                "The interest rate for a product.", FINRETAIL_TOOLS[0]["inputSchema"],
                FINRETAIL_TOOLS[0]["annotations"]),
        })
        # declares no schema: none, and no omission mark
        self.assertEqual(branches, {"name": "listBranches", "description": "Every branch.",
                                    "schema_sha256": scanner.tool_schema_digest("Every branch.", None, None)})

        field = evidence_bundle.tool_schemas_attribute([entry], [])
        self.assertEqual((field["status"], field["tier"], field["authored_by"]), ("ANSWERED", "declared", "subject"))
        self.assertEqual(field["value"], [entry])

    def test_the_digest_is_raildash_schema_hash_of_the_same_tool(self):
        # DR-294: with nothing redacted, a copy's identity is the hash RailDash
        # takes of the same tool seen in captured traffic (raildash
        # tool_schemas.schema_hash: a string description as sent, annotations
        # as sent when an object), so the two can be matched. Whitespace, an
        # empty description and empty annotations are hashed as sent too.
        def raildash_hash(description, input_schema, annotations):
            description = description if isinstance(description, str) else None
            annotations = annotations if isinstance(annotations, dict) else None
            canonical = json.dumps(
                {"description": description, "input_schema": input_schema, "annotations": annotations},
                sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            )
            return hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()

        schema = FINRETAIL_TOOLS[0]["inputSchema"]
        for description, annotations in [
            ("The interest rate for a product.", FINRETAIL_TOOLS[0]["annotations"]),
            ("    Search files.\n", None),
            ("", {}),
            (None, {"readOnlyHint": True}),
            ("Zinssatz für ein Produkt", {}),
        ]:
            tool = {"name": "t", "inputSchema": schema}
            if description is not None:
                tool["description"] = description
            if annotations is not None:
                tool["annotations"] = annotations
            with self.subTest(description=description, annotations=annotations):
                self.assertEqual(scanner.record_tool_schema(tool)["schema_sha256"],
                                 raildash_hash(description, schema, annotations))
        record = scanner.record_tool_schema({"name": "t", "description": "  Search files.\n"})
        self.assertEqual(record["description"], "Search files.")  # shown stripped, hashed as sent

    def test_the_per_tool_cap_counts_every_field_kept(self):
        tool = {"name": "t", "description": "d" * 200, "annotations": {"title": "a" * 200},
                "inputSchema": {"type": "object", "description": "x" * (scanner.TOOL_SCHEMA_BYTES - 120)}}
        record = scanner.record_tool_schema(tool)
        self.assertLessEqual(scanner._compact_size(record), scanner.TOOL_SCHEMA_BYTES)

    def test_a_copy_keeps_its_digest_when_the_budget_drops_its_schema(self):
        schema = {"type": "object", "properties": {f"p{i}": {"type": "string", "description": "x" * 40}
                                                   for i in range(60)}}
        tools = [{"name": f"t{i:03d}", "description": f"tool {i}", "inputSchema": schema} for i in range(200)]
        (server,) = scanner.cap_tool_schemas([scanner.tool_schema_server("big", "a.json", [], "reached", tools, False)])
        last = server["tools"][-1]
        self.assertEqual(last["schema_omitted"], "bundle_budget")
        self.assertEqual(last["description_omitted"], "bundle_budget")
        self.assertNotIn("description", last)
        self.assertEqual(last["schema_sha256"], scanner.record_tool_schema(tools[-1])["schema_sha256"])

    def test_a_description_past_the_per_tool_cap_is_marked(self):
        tool = {"name": "chatty", "description": "y" * (scanner.TOOL_SCHEMA_BYTES + 1)}
        record = scanner.record_tool_schema(tool)
        self.assertNotIn("description", record)
        self.assertEqual(record["description_omitted"], "per_tool_budget")
        field = evidence_bundle.tool_schemas_attribute(
            [scanner.tool_schema_server("s", "a.json", [], "reached", [tool], False)], [])
        self.assertEqual((field["status"], field["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))

    def test_a_server_in_two_config_files_is_two_copies_with_their_origin(self):
        # DR-294: ./.mcp.json and ~/.mcp.json both naming "finretail" are two
        # sources; each keeps its own tools, nothing merged, and the home
        # folder is `~`. skills_inventory still reads one tool per name.
        import tempfile

        other = [{**FINRETAIL_TOOLS[0], "description": "A different description."}]
        with tempfile.TemporaryDirectory() as tmp, FakeMcpServer(FINRETAIL_TOOLS) as one, \
                FakeMcpServer(other) as two:
            home = Path(tmp) / "home" / "alice"
            work = Path(tmp) / "work"
            home.mkdir(parents=True)
            work.mkdir()
            (work / ".mcp.json").write_text(json.dumps({"mcpServers": {"finretail": {"url": one.url}}}))
            (home / ".mcp.json").write_text(json.dumps({"mcpServers": {"finretail": {"url": two.url}}}))
            schemas: list[dict] = []
            skills = scanner.collect_skills([work / ".mcp.json", home / ".mcp.json"], {"HOME": str(home)},
                                            schemas=schemas)
            servers = scanner.cap_tool_schemas(schemas)
        self.assertEqual([(s["server"], s["source"], s["source_kind"]) for s in servers],
                         [("finretail", str(work / ".mcp.json"), "file"), ("finretail", "~/.mcp.json", "file")])
        self.assertNotIn("alice", json.dumps(servers))
        self.assertEqual([len(s["tools"]) for s in servers], [2, 1])
        self.assertEqual(servers[1]["tools"][0]["description"], "A different description.")
        self.assertNotEqual(servers[0]["tools"][0]["schema_sha256"], servers[1]["tools"][0]["schema_sha256"])
        self.assertEqual(sorted(s["name"] for s in skills), ["getInterestRate", "listBranches"])
        field = evidence_bundle.tool_schemas_attribute(servers, [])
        self.assertEqual(field["status"], "ANSWERED")

    def test_the_environment_server_is_its_own_source(self):
        with FakeMcpServer(FINRETAIL_TOOLS) as server:
            schemas: list[dict] = []
            scanner.collect_skills([], {"AGENT_MCP_NAME": "finretail", "AGENT_MCP_URL": server.url}, schemas=schemas)
        (entry,) = scanner.cap_tool_schemas(schemas)
        self.assertEqual((entry["source"], entry["source_kind"]), ("environment", "environment"))

    def test_config_origin_reads_home_as_tilde_only_on_a_whole_segment(self):
        self.assertEqual(scanner.config_origin(Path("/home/al/.mcp.json"), "/home/al"), "~/.mcp.json")
        self.assertEqual(scanner.config_origin(Path("/home/al/.mcp.json"), "/home/al/"), "~/.mcp.json")
        self.assertEqual(scanner.config_origin(Path("/home/alice/.mcp.json"), "/home/al"), "/home/alice/.mcp.json")
        self.assertEqual(scanner.config_origin(Path("/work/.mcp.json"), "/"), "/work/.mcp.json")
        self.assertEqual(scanner.config_origin(Path("/work/.mcp.json"), None), "/work/.mcp.json")

    def test_a_key_in_a_default_is_redacted(self):
        tools = [{
            "name": "callPartner",
            "inputSchema": {"type": "object", "properties": {
                "api_key": {"type": "string", "default": KEY},
                "note": {"type": "string", "examples": [f"use {KEY} here"], "description": f"demo {KEY}"},
                KEY: {"type": "string"},
            }},
            "annotations": {"title": f"Partner {KEY}"},
        }]
        with FakeMcpServer(tools) as server:
            (entry,) = tool_schemas_from([("partner", {"url": server.url})])
        (tool,) = entry["tools"]
        self.assertNotIn(KEY, json.dumps(entry))
        properties = tool["inputSchema"]["properties"]
        self.assertEqual(properties["api_key"], {"type": "string", "default": "[redacted]"})
        self.assertEqual(properties["note"]["examples"], ["use [redacted] here"])
        self.assertIn("[redacted]", properties)  # a key used as a property name, too
        self.assertEqual(tool["annotations"], {"title": "Partner [redacted]"})

    def test_redact_json_redacts_every_string_and_keeps_the_rest(self):
        self.assertEqual(
            scanner.redact_json({"a": [KEY, 1, 2.5, True, None], KEY: {"b": "plain"}}),
            {"a": ["[redacted]", 1, 2.5, True, None], "[redacted]": {"b": "plain"}},
        )

    def test_without_headers_the_server_sees_no_authorization(self):
        spec = {"url": None, "headers": {"Authorization": f"Bearer {KEY}"}}
        with FakeMcpServer(FINRETAIL_TOOLS) as server:
            spec["url"] = server.url
            (entry,) = tool_schemas_from([("finretail", spec)], send_headers=False)
        self.assertTrue(server.seen_authorization)
        self.assertEqual(set(server.seen_authorization), {None})
        self.assertEqual(entry["reachability"], "reached")
        # Self and docker mode still send the config's header, as before.
        with FakeMcpServer(FINRETAIL_TOOLS) as server:
            spec["url"] = server.url
            tool_schemas_from([("finretail", spec)])
        self.assertEqual(set(server.seen_authorization), {f"Bearer {KEY}"})

    def test_a_server_that_needs_auth_is_blind_with_private_store(self):
        with FakeMcpServer(FINRETAIL_TOOLS, require_auth="Bearer secret-1") as server:
            (entry,) = tool_schemas_from(
                [("crm", {"url": server.url, "headers": {"Authorization": "Bearer secret-1"}})], send_headers=False
            )
        self.assertEqual(server.seen_authorization, [None])  # asked once, never retried with a credential
        self.assertEqual((entry["reachability"], entry["tools"]), ("auth_refused", []))
        field = evidence_bundle.tool_schemas_attribute([entry], [])
        self.assertEqual((field["status"], field["reason"], field["value"]), ("BLIND", "PRIVATE_STORE", None))
        self.assertIn("crm", field["note"])

    def test_one_private_server_beside_a_public_one_is_partial_with_private_store(self):
        with FakeMcpServer(FINRETAIL_TOOLS) as public, \
                FakeMcpServer(FINRETAIL_TOOLS, require_auth="Bearer secret-1") as private:
            servers = tool_schemas_from([("finretail", {"url": public.url}), ("crm", {"url": private.url})])
        field = evidence_bundle.tool_schemas_attribute(servers, [])
        self.assertEqual((field["status"], field["reason"]), ("PARTIAL", "PRIVATE_STORE"))
        self.assertEqual([s["server"] for s in field["value"]], ["crm", "finretail"])

    def test_an_oversized_schema_is_partial_with_size_cap_exceeded(self):
        big = {"type": "object", "description": "x" * (scanner.TOOL_SCHEMA_BYTES + 1)}
        with FakeMcpServer([{"name": "bulkImport", "inputSchema": big}, FINRETAIL_TOOLS[1]]) as server:
            (entry,) = tool_schemas_from([("bulk", {"url": server.url})])
        self.assertEqual(entry["tools"][0], {"name": "bulkImport", "schema_omitted": "per_tool_budget",
                                             "schema_sha256": scanner.tool_schema_digest(None, big, None)})
        field = evidence_bundle.tool_schemas_attribute([entry], [])
        self.assertEqual((field["status"], field["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))
        self.assertIn("bulk", field["note"])

    def test_all_schemas_together_stay_within_their_budget(self):
        schema = {"type": "object", "properties": {f"p{i}": {"type": "string", "description": "x" * 40}
                                                   for i in range(60)}}
        tools = [{"name": f"t{i:03d}", "inputSchema": schema} for i in range(200)]
        servers = scanner.cap_tool_schemas([scanner.tool_schema_server("big", "a.json", [], "reached", tools, False)])
        kept = [tool for tool in servers[0]["tools"] if "inputSchema" in tool]
        self.assertTrue(0 < len(kept) < 200)
        self.assertEqual([t["name"] for t in servers[0]["tools"]], [f"t{i:03d}" for i in range(200)])
        self.assertEqual({t.get("schema_omitted") for t in servers[0]["tools"][len(kept):]}, {"bundle_budget"})
        field = evidence_bundle.tool_schemas_attribute(servers, [])
        self.assertEqual((field["status"], field["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))

        # The budget is what the bundle writes: render_json's indent=2, at the
        # value's deepest place (a v2 agent scope), not compact JSON.
        def rendered(value):
            bundle = {"agents": [{"attributes": {"tool_schemas": {"value": value}}}]}
            return len(scanner.render_json(bundle, compact=False))

        self.assertLessEqual(rendered(field["value"]) - rendered([]), scanner.TOOL_SCHEMAS_BYTES)
        self.assertGreater(rendered(field["value"]) - rendered([]), scanner.TOOL_SCHEMAS_BYTES * 0.9)

    def test_a_large_server_keeps_the_rendered_bundle_under_its_1_mib_bound(self):
        # The review's case: one server's 200 large schemas land in both
        # tool_schemas and skills_inventory, each within its own budget.
        schema = {"type": "object", "properties": {f"p{i}": {"type": "string", "description": "x" * 40}
                                                   for i in range(60)}}
        tools = [{"name": f"t{i:03d}", "description": "d", "inputSchema": schema} for i in range(200)]
        servers = scanner.cap_tool_schemas([scanner.tool_schema_server("big", "a.json", [], "reached", tools, False)])
        skills = scanner.merge_skill_lists([
            {"name": t["name"], "description": "d", "source_type": "mcp_config", "entry": "tool", "server": "big",
             "inputSchema": schema} for t in tools
        ])
        bundle = {"attributes": {
            "tool_schemas": evidence_bundle.tool_schemas_attribute(servers, []),
            "skills_inventory": {"value": skills, "status": "ANSWERED", "tier": "declared"},
        }}
        size = len(scanner.render_json(bundle, compact=False))
        self.assertLess(size, 600 * 1024)  # leaves the rest of the 1 MiB for the other attributes

    def test_down_stdio_and_no_config(self):
        servers = tool_schemas_from([("down", {"url": "http://127.0.0.1:1/mcp"})])
        field = evidence_bundle.tool_schemas_attribute(servers, [])
        self.assertEqual((field["status"], field["reason"]), ("BLIND", "NO_SOURCE_ACCESS"))
        servers = tool_schemas_from([("local", {"command": "mcp-server", "args": ["--token", KEY]})])
        self.assertNotIn(KEY, json.dumps(servers))
        field = evidence_bundle.tool_schemas_attribute(servers, [])
        self.assertEqual((field["status"], field["reason"]), ("BLIND", "NOT_COLLECTED_BY_PACK"))
        field = evidence_bundle.tool_schemas_attribute([], ["/agent/.mcp.json"])
        self.assertEqual((field["status"], field["method"]), ("ABSENT", "scanned /agent/.mcp.json"))
        field = evidence_bundle.tool_schemas_attribute(None, [])
        self.assertEqual((field["status"], field["reason"]), ("BLIND", "NOT_COLLECTED_BY_PACK"))


class PodModeToolSchemasTest(unittest.TestCase):
    """The real scanner in pod mode, as a subprocess, against a local fake
    MCP server named in the agent's .mcp.json with a credential header."""

    POD = {
        "POD_NAME": "agent-finretail-58cd78b55d-48jcw",
        "POD_NAMESPACE": "gke-test",
        "POD_UID": "f3fe5e58-b328-40cb-9b03-1acf558d773d",
        "NODE_NAME": "gke-gke-test-default-pool-1c6529e9-aqik",
    }

    def scan(self, server_url: str) -> dict:
        import os
        import subprocess
        import sys
        import tempfile

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, tmp, ignore_errors=True)
        (tmp / "config").mkdir()
        (tmp / "config" / ".mcp.json").write_text(json.dumps({"mcpServers": {
            "finretail": {"url": server_url, "headers": {"Authorization": f"Bearer {KEY}"}},
        }}))
        (tmp / "podinfo").mkdir()
        (tmp / "podinfo" / "labels").write_text('app="agent-finretail"\npod-template-hash="58cd78b55d"\n')
        (tmp / "home").mkdir()
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("RAIL_", "GCE_", "POD_", "GIT_")) and key not in ("NODE_NAME", "USER", "LOGNAME")}
        env.update(self.POD, HOME=str(tmp / "home"), RAIL_POD_INFO_DIR=str(tmp / "podinfo"))
        proc = subprocess.run(
            [sys.executable, str(SCANNER), "--mode", "pod", "--config-path", str(tmp / "config"),
             "--host-id", "gke-test",
             "--feature-output", str(tmp / "features.json"),
             "--evidence-bundle-output", str(tmp / "bundle.json"),
             "--output", str(tmp / "payload.json")],
            cwd=tmp, capture_output=True, text=True, env=env, timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        bundle = json.loads((tmp / "bundle.json").read_text())
        evidence_bundle.verify_bundle(bundle)
        self.assertNotIn(KEY, (tmp / "bundle.json").read_text())
        self.assertNotIn("tool_schemas", json.loads((tmp / "payload.json").read_text()))
        return bundle["attributes"]

    def test_the_sidecar_sends_no_credential_and_records_the_schemas(self):
        with FakeMcpServer(FINRETAIL_TOOLS) as server:
            field = self.scan(server.url)["tool_schemas"]
        self.assertTrue(server.seen_authorization)
        self.assertEqual(set(server.seen_authorization), {None})
        self.assertEqual(field["status"], "ANSWERED")
        (entry,) = field["value"]
        self.assertEqual(entry["tools"][0]["inputSchema"], FINRETAIL_TOOLS[0]["inputSchema"])

    def test_a_server_that_needs_the_agents_credential_is_private_store(self):
        with FakeMcpServer(FINRETAIL_TOOLS, require_auth=f"Bearer {KEY}") as server:
            attributes = self.scan(server.url)
        self.assertEqual(set(server.seen_authorization), {None})
        field = attributes["tool_schemas"]
        self.assertEqual((field["status"], field["reason"]), ("BLIND", "PRIVATE_STORE"))
        # The same credential-free probe feeds skills_inventory: the server is
        # an auth_refused server entry, and the inventory is PARTIAL, rather
        # than the sidecar presenting the agent's credential to list it.
        skills = attributes["skills_inventory"]
        self.assertEqual((skills["status"], skills["reason"]), ("PARTIAL", "NO_SOURCE_ACCESS"))
        (entry,) = [skill for skill in skills["value"] if skill.get("server") == "finretail"]
        self.assertEqual((entry["entry"], entry["reachability"]), ("server", "auth_refused"))
        self.assertIn("finretail", skills["note"])


if __name__ == "__main__":
    unittest.main()
