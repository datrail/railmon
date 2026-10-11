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


def mcp(context: ssl.SSLContext, message: dict) -> int:
    """One JSON-RPC message to the demo's MCP server (demo_server.py)."""
    conn = http.client.HTTPSConnection("127.0.0.1", 8443, context=context, timeout=5)
    try:
        conn.request("POST", "/mcp", body=json.dumps(message),
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()


def main() -> int:
    context = ssl._create_unverified_context()  # noqa: SLF001 — see module docstring
    # DR-205: like an agent with an MCP server, it lists the server's tools
    # and reads a document. It never uploads: that's the demo's later step.
    status = mcp(context, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    print(f"demo-client: MCP tools/list -> {status}", flush=True)
    status = mcp(context, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                           "params": {"name": "read_doc", "arguments": {"doc_id": "notes"}}})
    print(f"demo-client: MCP read_doc -> {status}", flush=True)
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
