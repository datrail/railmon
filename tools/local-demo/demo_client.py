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
import sys
import time


def main() -> int:
    context = ssl._create_unverified_context()  # noqa: SLF001 — see module docstring
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
