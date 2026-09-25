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
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "tools" / "agent-environment-scanner" / "scan_agent_environment.py"

_spec = importlib.util.spec_from_file_location("scan_agent_environment", SCANNER)
scanner = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(scanner)


class FakeMcpServer:
    """A minimal Streamable HTTP MCP server: `initialize`, then `tools/list`.

    Runs on an ephemeral loopback port in a background thread so tests hit a
    real socket without any external network dependency.
    """

    def __init__(self, tools, *, require_auth=None, session_header=True):
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

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                seen.append(self.headers.get("Mcp-Session-Id"))
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                if require_auth_ is not None and self.headers.get("Authorization") != require_auth_:
                    self.send_response(401)
                    self.end_headers()
                    return
                method = body.get("method")
                if method == "initialize":
                    result = {"protocolVersion": scanner.MCP_PROTOCOL_VERSION, "capabilities": {}}
                elif method == "tools/list":
                    result = {"tools": tools_by_call}
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
        # `name` used to be an operator-chosen server nickname, unlikely to
        # collide; it is now the tool's own name, and two independent MCP
        # servers commonly expose a same-named tool ("search"). The old
        # first-wins dedup in `collect_skills` would silently drop the
        # second server's reachability from the inventory.
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

            search_skills = [s for s in skills if s["name"] == "search"]
            self.assertEqual(len(search_skills), 1, "both servers' `search` tool should merge, not vanish")
            endpoints = search_skills[0]["destination_endpoints"]
            self.assertEqual(len(endpoints), 2, f"expected both servers' endpoints, got {endpoints}")


if __name__ == "__main__":
    unittest.main()
