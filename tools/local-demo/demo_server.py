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


class DemoHandler(http.server.BaseHTTPRequestHandler):
    # Quiet by default — `railmon demo` narrates its own progress; a second,
    # differently-formatted log line per request would just be noise.
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    def do_POST(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler's naming)
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = json.dumps({"ok": True, "path": self.path}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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
