#!/usr/bin/env python3
"""A local, offline HTTPS server for `railmon demo` — DR-48's local quickstart.

RailMon's `collect` command has nothing to read from disk the way RailDash's
fixture does: it taps *live* TLS traffic between real processes, so a clean
checkout has nothing to show until some agent is running under it. Rather
than depend on a real agent (which a fresh install does not have yet) or on
internet access to a public host (which makes the quickstart flaky and
non-reproducible), this pairs with `demo_client.py` to generate one real,
local, self-signed HTTPS exchange for the tap to see. Nothing here is used
outside `railmon demo`.

Stdlib only, matching the scanner and forwarder's own rule: this is
infrastructure that ships inside the image, not a dependency to manage.
"""

from __future__ import annotations

import http.server
import json
import ssl
import sys
import uuid

# DR-205: the demo's MCP server, at /mcp on the same HTTPS port (so the demo
# opens no port it didn't before). It offers one tool that reads and one
# that uploads; the demo agent only ever reads. RailDash reads the listing,
# classifies `upload_file` as an upload (its name, and its base64 `content`)
# and proposes a guardrail that blocks it until allowed -- the KubeCon demo.
MCP_PATH = "/mcp"
# DR-237: the demo agent's own declaration of this server, which every way
# the demo agent is started sets in its environment (AGENT_MCP_NAME and
# AGENT_MCP_URL, the scanner's env convention; `scan --mode docker` reads a
# container's environment, not files inside it). Its ASP's
# `mcp_servers_declared` then names `demo` at this URL, and RailDash lines
# the calls to the URL's host and path up as `mcp__demo__<tool>`.
MCP_SERVER_NAME = "demo"
MCP_URL = f"https://127.0.0.1:8443{MCP_PATH}"
SESSION_HEADER = "Mcp-Session-Id"
MCP_TOOLS = [
    {
        "name": "read_doc",
        "description": "Read one document by its id.",
        "inputSchema": {
            "type": "object",
            "properties": {"doc_id": {"type": "string"}},
            "required": ["doc_id"],
        },
    },
    {
        "name": "upload_file",
        "description": "Upload a file to the team's shared drive.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string", "contentEncoding": "base64"},
            },
            "required": ["path", "content"],
        },
    },
]


def mcp_reply(message: object) -> dict | None:
    """One JSON-RPC message's reply (None for a notification): initialize,
    tools/list and tools/call, enough of MCP for the demo."""
    if not isinstance(message, dict):
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
    if "id" not in message:
        return None
    reply: dict = {"jsonrpc": "2.0", "id": message["id"]}
    method = message.get("method")
    params = message.get("params") if isinstance(message.get("params"), dict) else {}
    if method == "initialize":
        reply["result"] = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                           "serverInfo": {"name": "datrail-demo-docs", "version": "1"}}
    elif method == "tools/list":
        reply["result"] = {"tools": MCP_TOOLS}
    elif method == "tools/call" and params.get("name") == "read_doc":
        args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        reply["result"] = {"content": [{"type": "text", "text": f"document {args.get('doc_id')}"}]}
    elif method == "tools/call" and params.get("name") == "upload_file":
        args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        size = len(str(args.get("content", "")))
        reply["result"] = {"content": [{"type": "text", "text": f"stored {size} bytes"}]}
    elif method == "tools/call":
        reply["error"] = {"code": -32602, "message": f"unknown tool {params.get('name')!r}"}
    else:
        reply["error"] = {"code": -32601, "message": f"unknown method {method!r}"}
    return reply


class DemoHandler(http.server.BaseHTTPRequestHandler):
    # Quiet by default — `railmon demo` narrates its own progress; a second,
    # differently-formatted log line per request would just be noise.
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    def do_GET(self) -> None:  # noqa: N802
        """The streamable HTTP transport's server-to-client stream (DR-237).

        The demo server has nothing to push, so the stream carries one
        comment and ends; it is there so the capture holds the GET a real
        MCP client opens, which carries no call."""
        if self.path != MCP_PATH:
            self._reply(404, {"error": "not found"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(b": demo stream, nothing to push\n\n")
        self.close_connection = True

    def do_DELETE(self) -> None:  # noqa: N802
        """Ending a session (DR-237): no call, no body."""
        if self.path != MCP_PATH:
            self._reply(404, {"error": "not found"})
        elif not self.headers.get(SESSION_HEADER):
            self._reply(400, {"error": f"{SESSION_HEADER} required"})
        else:
            self._reply(204, None)

    def _reply(self, status: int, payload: object, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload).encode("utf-8") if payload is not None else b""
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        if status != 204:
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if status != 204:
            self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler's naming)
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        status = 200
        headers: dict[str, str] = {}
        if self.path == MCP_PATH:
            try:
                message = json.loads(raw)
            except ValueError:
                status, payload = 400, {"error": "not JSON-RPC"}
            else:
                if isinstance(message, list):
                    payload = [r for r in (mcp_reply(m) for m in message) if r is not None]
                else:
                    payload = mcp_reply(message)
                    if isinstance(message, dict) and message.get("method") == "initialize":
                        # A session for the client's later requests, its
                        # GET stream and its DELETE (DR-237).
                        headers[SESSION_HEADER] = uuid.uuid4().hex
                if payload is None or payload == []:
                    status, payload = 202, None
        else:
            payload = {"ok": True, "path": self.path}
        self._reply(status, payload, headers)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} <cert.pem> <key.pem>", file=sys.stderr)
        return 2
    cert_path, key_path = argv[1], argv[2]

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    server = http.server.HTTPServer(("127.0.0.1", 8443), DemoHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    # A line the orchestrating shell script waits on before starting the
    # client, so the client never races a socket that is not accepting yet.
    print("demo-server: listening on 127.0.0.1:8443", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
