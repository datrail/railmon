"""DR-205: the demo agent's MCP server (tools/local-demo/demo_server.py)."""

from __future__ import annotations

import http.client
import http.server
import importlib.util
import json
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("demo_server", ROOT / "tools/local-demo/demo_server.py")
demo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo)


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


if __name__ == "__main__":
    unittest.main()
