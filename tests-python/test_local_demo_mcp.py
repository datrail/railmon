"""DR-205: the demo agent's MCP server (tools/local-demo/demo_server.py);
DR-237: its declaration and the demo client's session requests."""

from __future__ import annotations

import http.client
import http.server
import importlib.util
import io
import json
import re
import threading
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, path: str):
    """A private copy, never put in sys.modules (see test_egress_containment)."""
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


demo = _load("demo_server", "tools/local-demo/demo_server.py")
client = _load("demo_client", "tools/local-demo/demo_client.py")
scanner = _load("scan_agent_environment", "tools/scan/scan_agent_environment.py")


class DemoMcpServer(unittest.TestCase):
    def test_the_listing_offers_one_read_tool_and_one_upload_tool(self):
        reply = demo.mcp_reply({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        tools = {tool["name"]: tool for tool in reply["result"]["tools"]}
        self.assertEqual(set(tools), {"read_doc", "upload_file"})
        self.assertEqual(tools["upload_file"]["inputSchema"]["properties"]["content"]["contentEncoding"], "base64")

    def test_calls_notifications_and_unknown_tools(self):
        read = demo.mcp_reply({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                               "params": {"name": "read_doc", "arguments": {"doc_id": "x"}}})
        self.assertEqual(read["result"]["content"][0]["text"], "document x")
        self.assertIsNone(demo.mcp_reply({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        unknown = demo.mcp_reply({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                  "params": {"name": "export_all"}})
        self.assertEqual(unknown["error"]["code"], -32602)

    def test_the_handler_serves_mcp_beside_the_demo_paths(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), demo.DemoHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        def post(path, body):
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            conn.request("POST", path, body=body)
            response = conn.getresponse()
            return response.status, response.read()

        status, body = post("/mcp", json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                                                {"jsonrpc": "2.0", "method": "notifications/x"}]))
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)), 1)
        self.assertEqual(post("/mcp", b"\x00 not json")[0], 400)
        self.assertEqual(post("/mcp", json.dumps({"jsonrpc": "2.0", "method": "notifications/x"}))[0], 202)
        status, body = post("/v1/demo", b"{}")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True, "path": "/v1/demo"})


class RecordingHandler(demo.DemoHandler):
    """The demo handler, noting each request's method, path, session and body."""

    seen: list[tuple[str, str, str | None, bytes]] = []

    def _note(self) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        self.rfile = io.BytesIO(raw)  # the handler reads the body again
        self.seen.append((self.command, self.path, self.headers.get(demo.SESSION_HEADER), raw))

    def do_GET(self):  # noqa: N802
        self._note()
        super().do_GET()

    def do_DELETE(self):  # noqa: N802
        self._note()
        super().do_DELETE()

    def do_POST(self):  # noqa: N802
        self._note()
        super().do_POST()


def _serve(handler) -> http.server.HTTPServer:
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class DemoMcpTransport(unittest.TestCase):
    """DR-237: the streamable HTTP requests that carry no call."""

    def setUp(self):
        server = _serve(demo.DemoHandler)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.port = server.server_port

    def request(self, method, body=None, headers=None, path="/mcp"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def test_initialize_hands_out_a_session(self):
        status, headers, _ = self.request("POST", json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize"}))
        self.assertEqual(status, 200)
        self.assertRegex(headers[demo.SESSION_HEADER], r"^[0-9a-f]{32}$")
        status, headers, _ = self.request("POST", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        self.assertNotIn(demo.SESSION_HEADER, headers)

    def test_the_get_stream_is_server_sent_events_and_ends(self):
        status, headers, body = self.request("GET", headers={demo.SESSION_HEADER: "s"})
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/event-stream")
        self.assertTrue(body.startswith(b":"))
        self.assertEqual(self.request("GET", path="/v1/demo")[0], 404)

    def test_delete_ends_a_named_session(self):
        self.assertEqual(self.request("DELETE", headers={demo.SESSION_HEADER: "s"})[:3:2], (204, b""))
        self.assertEqual(self.request("DELETE")[0], 400)
        self.assertEqual(self.request("DELETE", path="/v1/demo", headers={demo.SESSION_HEADER: "s"})[0], 404)


class DemoClientCycle(unittest.TestCase):
    """DR-237: one cycle of demo_client.py, as the server sees it."""

    def test_one_cycle_adds_the_session_requests_and_no_other_call(self):
        RecordingHandler.seen = []
        server = _serve(RecordingHandler)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_port

        def connection(host, _port, context=None, timeout=None):
            self.assertEqual((host, _port), ("127.0.0.1", 8443))
            return http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)

        with mock.patch.object(client.http.client, "HTTPSConnection", connection), \
                mock.patch.object(client.time, "sleep"), mock.patch("builtins.print"):
            self.assertEqual(client.main(), 0)

        seen = RecordingHandler.seen
        self.assertEqual([(method, path) for method, path, _, _ in seen], [
            ("POST", "/mcp"), ("POST", "/mcp"), ("POST", "/mcp"), ("GET", "/mcp"), ("DELETE", "/mcp"),
            ("POST", "/v1/demo"), ("POST", "/v1/demo"), ("POST", "/v1/demo/other"),
        ])
        methods = [json.loads(body)["method"] for method, path, _, body in seen if path == "/mcp" and method == "POST"]
        self.assertEqual(methods, ["initialize", "tools/list", "tools/call"])
        # The one call is read_doc, as before: it never uploads.
        call = json.loads(seen[2][3])
        self.assertEqual(call["params"], {"name": "read_doc", "arguments": {"doc_id": "notes"}})
        # Every request after initialize carries the session it handed out,
        # and the GET and DELETE carry no body (no call).
        sessions = {session for _, path, session, _ in seen[1:5]}
        self.assertEqual(len(sessions), 1)
        self.assertRegex(sessions.pop() or "", r"^[0-9a-f]{32}$")
        self.assertEqual([body for _, _, _, body in seen[3:5]], [b"", b""])


class DemoMcpDeclaration(unittest.TestCase):
    """DR-237: the demo agent declares its own MCP server, so its ASP's
    `mcp_servers_declared` names it and RailDash lines its calls up as
    `mcp__demo__<tool>`."""

    ENV = {"AGENT_MCP_NAME": demo.MCP_SERVER_NAME, "AGENT_MCP_URL": demo.MCP_URL}

    def test_the_declaration_names_the_server_the_client_calls(self):
        self.assertEqual(demo.MCP_SERVER_NAME, "demo")
        self.assertEqual(demo.MCP_URL, "https://127.0.0.1:8443/mcp")
        parts = urlsplit(demo.MCP_URL)
        self.assertEqual((parts.hostname, parts.port, parts.path), ("127.0.0.1", 8443, client.MCP_PATH))
        self.assertEqual(client.MCP_PATH, demo.MCP_PATH)
        # RailDash's `normalize_mcp_server` leaves this name as it is, and
        # it holds no `__`, so the line-up keeps it.
        self.assertRegex(demo.MCP_SERVER_NAME, r"^[A-Za-z0-9_-]+$")
        self.assertNotIn("__", demo.MCP_SERVER_NAME)

    def test_scanning_the_demo_agents_environment_yields_the_server(self):
        inventory = scanner.collect_mcp_inventory([], self.ENV)
        self.assertEqual(inventory, [{
            "name": "demo", "command": None, "url": "https://127.0.0.1:8443/mcp", "transport": "http",
            "source": "environment", "include_tools": None, "exclude_tools": None,
        }])

    def test_a_docker_scan_reads_it_from_the_container_environment(self):
        inspect = {"Name": "/datrail-demo-agent", "Config": {"Env": [
            "PATH=/usr/bin", *(f"{key}={value}" for key, value in self.ENV.items())]}}
        with mock.patch.object(scanner, "docker_inspect", return_value=inspect), \
                mock.patch.object(scanner, "run_command", return_value=None), \
                mock.patch.object(scanner, "collect_egress_containment", return_value={}):
            context = scanner.collect_docker_context("datrail-demo-agent")
        names = [entry["name"] for entry in scanner.collect_mcp_inventory([], context["env"])]
        self.assertEqual(names, ["demo"])

    def test_the_local_demo_self_scan_declares_the_same_server(self):
        script = (ROOT / "tools/local-demo/run_local_demo.sh").read_text(encoding="utf-8")
        self.assertIn(f"AGENT_MCP_NAME={demo.MCP_SERVER_NAME} AGENT_MCP_URL={demo.MCP_URL} ", script)
        self.assertTrue(re.search(r"AGENT_MCP_URL=\S+ \\\npython3 \"\$root/tools/scan/scan_agent_environment.py\"",
                                  script))


if __name__ == "__main__":
    unittest.main()
