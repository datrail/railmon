#!/usr/bin/env python3
"""The demo agent's MCP calls on demand, for the Data Guardrail's data-actions
step (DR-205; datrail-project's README and stack test run it in the agent):

    demo_mcp_call.py upload_file   # upload a small PNG through upload_file
    demo_mcp_call.py <tool>        # call a tool the server never listed
    demo_mcp_call.py --garbage     # a POST to /mcp that isn't JSON-RPC

Each goes to the demo's own server on 127.0.0.1:8443 (demo_server.py), so
nothing leaves the machine; its certificate is a throwaway, hence no
verification.
"""

from __future__ import annotations

import base64
import http.client
import json
import ssl
import sys

# A 1x1 PNG: enough for RailDash to see an image in the upload.
PNG = base64.b64encode(
    bytes.fromhex(
        "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
        "1f15c4890000000d4944415478da63f8ffff3f0005fe02fea7d6a4"
        "6f0000000049454e44ae426082"
    )
).decode()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "--garbage":
        body = b"\x00 not json-rpc"
    else:
        arguments = {"path": "screenshot.png", "content": PNG} if argv[1] == "upload_file" else {}
        body = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                           "params": {"name": argv[1], "arguments": arguments}}).encode()
    context = ssl._create_unverified_context()  # noqa: SLF001 — see module docstring
    conn = http.client.HTTPSConnection("127.0.0.1", 8443, context=context, timeout=5)
    try:
        conn.request("POST", "/mcp", body=body, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        print(f"{argv[1]} -> {response.status} {response.read().decode(errors='replace')[:120]}")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
