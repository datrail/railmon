#!/usr/bin/env python3
"""The other half of `railmon demo` — see demo_server.py.

Makes a few real HTTPS requests to the local demo server so `collect` has
live TLS traffic to tap. Certificate verification is off on purpose: the
server's certificate is a throwaway, generated fresh by run_local_demo.sh on
every run, and verifying it against nothing would just fail every time. This
talks to 127.0.0.1 only — it is not a general-purpose HTTP client.
"""

from __future__ import annotations

import http.client
import json
import ssl
import time

MCP_PATH = "/mcp"


def mcp_request(context: ssl.SSLContext, method: str, message: dict | None = None,
                session: str | None = None) -> tuple[int, str | None]:
    """One request to the demo's MCP endpoint (demo_server.py): its status
    and the session id it handed out, if any. A POST carries one JSON-RPC
    message; a GET opens the server-to-client stream and reads it to its
    end; a DELETE ends the session."""
    headers = {"Accept": "application/json, text/event-stream"}
    if message is not None:
        headers["Content-Type"] = "application/json"
    if session:
        headers["Mcp-Session-Id"] = session
    conn = http.client.HTTPSConnection("127.0.0.1", 8443, context=context, timeout=5)
    try:
        conn.request(method, MCP_PATH, body=json.dumps(message) if message is not None else None,
                     headers=headers)
        response = conn.getresponse()
        response.read()
        return response.status, response.getheader("Mcp-Session-Id")
    finally:
        conn.close()


def main() -> int:
    context = ssl._create_unverified_context()  # noqa: SLF001 — see module docstring
    # DR-205: like an agent with an MCP server, it lists the server's tools
    # and reads a document. It never uploads: that's the demo's later step.
    # DR-237: and like a streamable HTTP client, it opens a session, opens
    # the server's GET stream and ends the session with a DELETE. None of
    # those carries a call, so none makes a data-actions row.
    status, session = mcp_request(context, "POST", {
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                   "clientInfo": {"name": "datrail-demo-client", "version": "1"}}})
    print(f"demo-client: MCP initialize -> {status}", flush=True)
    status, _ = mcp_request(context, "POST", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, session)
    print(f"demo-client: MCP tools/list -> {status}", flush=True)
    status, _ = mcp_request(context, "POST", {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                              "params": {"name": "read_doc", "arguments": {"doc_id": "notes"}}},
                            session)
    print(f"demo-client: MCP read_doc -> {status}", flush=True)
    status, _ = mcp_request(context, "GET", session=session)
    print(f"demo-client: MCP GET stream -> {status}", flush=True)
    status, _ = mcp_request(context, "DELETE", session=session)
    print(f"demo-client: MCP DELETE session -> {status}", flush=True)
    paths = ["/v1/demo", "/v1/demo", "/v1/demo/other"]
    for path in paths:
        conn = http.client.HTTPSConnection("127.0.0.1", 8443, context=context, timeout=5)
        try:
            conn.request("POST", path, body=json.dumps({"hello": "railmon"}))
            response = conn.getresponse()
            response.read()
            print(f"demo-client: POST {path} -> {response.status}", flush=True)
        finally:
            conn.close()
        time.sleep(0.3)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
