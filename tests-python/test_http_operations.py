"""RC-512: http_operations records each destination's API spec, and a pod
scan's probes run in a pool of four with a deadline.

Real loopback HTTP servers, as in test_mcp_tool_discovery.py: what is
claimed is wire-level (no credential sent, a file:// URL never opened, a
server that never answers doesn't hold up the scan), which a mocked
prober couldn't show. Stdlib only, to match the scanner itself.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "tools" / "scan" / "scan_agent_environment.py"
EVIDENCE_BUNDLE = ROOT / "tools" / "scan" / "evidence_bundle.py"

_spec = importlib.util.spec_from_file_location("scan_agent_environment", SCANNER)
scanner = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(scanner)

_evidence_spec = importlib.util.spec_from_file_location("evidence_bundle_rc512", EVIDENCE_BUNDLE)
evidence_bundle = importlib.util.module_from_spec(_evidence_spec)
assert _evidence_spec.loader is not None
_evidence_spec.loader.exec_module(evidence_bundle)

KEY = "sk-live-" + "a1B2c3D4" * 4

# The pod-mode modules the moved code lives in (tools/scan/gke/), loaded the
# way the scanner loads them, so they use this file's scanner.
spec_probe = scanner._spec_probe()
probe_pool = scanner._probe_pool()
BUILDERS = {"answered": evidence_bundle._answered, "absent": evidence_bundle._absent,
            "blind": evidence_bundle._blind, "partial": evidence_bundle._partial}

# The in-process pod scan's lazy imports must resolve to the modules above,
# for this file's run only (as in test_register_bundle.py).
_PATCHED_MODULES = {"scan_agent_environment": scanner, "evidence_bundle": evidence_bundle}
_saved_modules: dict = {}


def setUpModule() -> None:
    import sys

    for name, module in _PATCHED_MODULES.items():
        _saved_modules[name] = sys.modules.get(name)
        sys.modules[name] = module


def tearDownModule() -> None:
    import sys

    for name, original in _saved_modules.items():
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original

OPENAPI3 = {
    "openapi": "3.0.3",
    "info": {"title": "finretail", "version": "1"},
    "paths": {
        "/rates/{product}": {
            "get": {
                "operationId": "getInterestRate",
                "parameters": [{"name": "product", "in": "path", "example": KEY}],
                "responses": {"200": {"content": {"application/json": {}}},
                              "404": {"content": {"application/problem+json": {}}}},
            },
        },
        "/transfers": {
            "post": {
                "operationId": "createTransfer",
                "requestBody": {"content": {"application/json": {}, "application/xml": {}}},
                "responses": {"201": {"description": "created"}},
            },
            "parameters": [],
        },
    },
}

SWAGGER2 = {
    "swagger": "2.0",
    "consumes": ["application/json"],
    "produces": ["application/json"],
    "paths": {
        "/accounts": {"get": {"operationId": "listAccounts"},
                      "put": {"operationId": "replaceAccounts", "consumes": ["text/csv"]}},
    },
}

FINRETAIL_TOOLS = [{"name": "getInterestRate", "description": "A product's interest rate.",
                    "inputSchema": {"type": "object", "properties": {"product": {"type": "string"}}}}]


class FakeServer:
    """One loopback server for both sides of a destination: MCP on POST
    (initialize, then tools/list) and spec paths on GET, each GET path
    answering `routes[path]` as (status, body) and anything else 404."""

    def __init__(self, routes=None, tools=None):
        self.routes = routes or {}
        self.tools = tools
        self.requests = []  # (method, path, Authorization header)
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body=b"", content_type="application/json", headers=()):
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                for name, value in headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # the prober stops reading at OPENAPI_MAX_BYTES

            def do_GET(self):
                server.requests.append(("GET", self.path, self.headers.get("Authorization")))
                status, body, *headers = server.routes.get(self.path, (404, b""))
                self._send(status, body if isinstance(body, bytes) else json.dumps(body).encode(),
                           headers=headers[0] if headers else ())

            def do_POST(self):
                server.requests.append(("POST", self.path, self.headers.get("Authorization")))
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                if server.tools is None:
                    return self._send(404)
                result = ({"protocolVersion": scanner.MCP_PROTOCOL_VERSION, "capabilities": {}}
                          if body.get("method") == "initialize" else {"tools": server.tools})
                self._send(200, json.dumps({"jsonrpc": "2.0", "id": body.get("id"), "result": result}).encode())

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def origin(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


class SilentServer:
    """Accepts connections (the kernel's backlog does) and never answers."""

    def __enter__(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(64)
        host, port = self._socket.getsockname()
        self.origin = f"http://{host}:{port}"
        return self

    def __exit__(self, *exc):
        self._socket.close()


class RawServer:
    """A loopback server that answers each request by the script `answer`
    returns for its request line: a list of (bytes, seconds to wait after),
    then it holds the connection open without closing. So a test can send
    headers that promise a body and then never send it, or drip it."""

    def __init__(self, answer):
        self._answer = answer
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(16)
        self._stop = threading.Event()
        self._open = []
        self.requests = []

    @property
    def origin(self):
        host, port = self._socket.getsockname()
        return f"http://{host}:{port}"

    def _serve(self):
        self._socket.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._socket.accept()
            except OSError:
                continue
            self._open.append(conn)
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                data += chunk
            line = data.split(b"\r\n", 1)[0].decode()
            self.requests.append(line)
            for payload, wait in self._answer(line):
                conn.sendall(payload)
                if self._stop.wait(wait):
                    return
            self._stop.wait()  # hold the connection open, body unfinished
        except OSError:
            pass

    def __enter__(self):
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        for conn in self._open:
            conn.close()
        self._socket.close()


class ProbeOpenapiTest(unittest.TestCase):
    def test_an_openapi_3_specs_operations_are_parsed(self):
        with FakeServer({"/v3/api-docs": (200, OPENAPI3)}) as server:
            entry = spec_probe.probe_openapi(server.origin)
        self.assertEqual((entry["status"], entry["spec_path"], entry["spec_version"]),
                         ("ANSWERED", "/v3/api-docs", "3.0.3"))
        self.assertEqual(entry["destination"], server.origin)
        self.assertEqual(entry["operations"], [
            {"method": "GET", "path": "/rates/{product}", "operationId": "getInterestRate",
             "response_content_types": ["application/json", "application/problem+json"]},
            {"method": "POST", "path": "/transfers", "operationId": "createTransfer",
             "request_content_types": ["application/json", "application/xml"]},
        ])
        # The paths are asked in order, up to the first that serves a spec.
        self.assertEqual([path for _, path, _ in server.requests], ["/openapi.json", "/v3/api-docs"])
        self.assertNotIn(KEY, json.dumps(entry))  # nothing but the operations' own fields is kept

    def test_a_swagger_2_specs_content_types_come_from_consumes_and_produces(self):
        with FakeServer({"/swagger.json": (200, SWAGGER2)}) as server:
            entry = spec_probe.probe_openapi(server.origin)
        self.assertEqual(entry["operations"], [
            {"method": "GET", "path": "/accounts", "operationId": "listAccounts",
             "request_content_types": ["application/json"], "response_content_types": ["application/json"]},
            {"method": "PUT", "path": "/accounts", "operationId": "replaceAccounts",
             "request_content_types": ["text/csv"], "response_content_types": ["application/json"]},
        ])

    def test_a_key_in_an_operation_id_is_redacted(self):
        spec = {"openapi": "3.1.0", "paths": {"/x": {"get": {"operationId": f"call_{KEY}"}}}}
        with FakeServer({"/openapi.json": (200, spec)}) as server:
            entry = spec_probe.probe_openapi(server.origin)
        self.assertNotIn(KEY, json.dumps(entry))

    def test_401_is_blind_with_private_store_and_no_credential_is_sent(self):
        with FakeServer({path: (401, b"") for path in spec_probe.OPENAPI_PATHS}) as server:
            entry = spec_probe.probe_openapi(server.origin)
        self.assertEqual((entry["status"], entry["reason"]), ("BLIND", "PRIVATE_STORE"))
        self.assertEqual({auth for _, _, auth in server.requests}, {None})
        field = spec_probe.http_operations_attribute([entry], {}, BUILDERS)
        self.assertEqual((field["status"], field["reason"]), ("BLIND", "PRIVATE_STORE"))
        self.assertIn(server.origin, field["note"])

    def test_a_spec_over_4_mb_is_partial_with_size_cap_exceeded_and_keeps_what_fits(self):
        filler = "x" * 1000
        paths = {f"/items/{index}": {"get": {"operationId": f"getItem{index}", "description": filler}}
                 for index in range(6000)}  # about 6 MB
        body = json.dumps({"openapi": "3.0.0", "paths": paths}).encode()
        self.assertGreater(len(body), spec_probe.OPENAPI_MAX_BYTES)
        with FakeServer({"/openapi.json": (200, body)}) as server:
            entry = spec_probe.probe_openapi(server.origin)
        self.assertEqual((entry["status"], entry["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))
        self.assertTrue(entry["operations_truncated"])
        # The path items before the cut are kept whole, and none past it.
        kept = len(entry["operations"])
        self.assertTrue(3000 < kept < 6000 or kept == spec_probe.HTTP_OPERATIONS_MAX, kept)
        self.assertEqual(entry["operations"][0], {"method": "GET", "path": "/items/0", "operationId": "getItem0"})
        field = spec_probe.http_operations_attribute(spec_probe.cap_http_operations([entry]), {}, BUILDERS)
        self.assertEqual((field["status"], field["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))

    def test_a_file_url_is_never_requested(self):
        refuse = mock.Mock(side_effect=AssertionError("opened"))
        with mock.patch.object(spec_probe._SPEC_OPENER, "open", refuse), mock.patch.object(scanner, "urlopen", refuse):
            entry = spec_probe.probe_openapi("file:///etc/passwd")
            self.assertEqual(spec_probe.fetch_openapi_document("file:///etc/passwd"), (None, None, False))
        refuse.assert_not_called()
        self.assertEqual((entry["status"], entry["reason"]), ("BLIND", "NOT_COLLECTED_BY_PACK"))
        # Nor is one ever a destination: only http and https MCP servers are.
        plan = [("local", {"url": "file:///etc/passwd"}, ".mcp.json"),
                ("stdio", {"command": "mcp-server"}, ".mcp.json"),
                ("finretail", {"url": "http://user:pw@finretail:23004/mcp?key=1"}, ".mcp.json"),
                ("again", {"url": "http://FINRETAIL:23004/other"}, ".mcp.json")]
        self.assertEqual(spec_probe.spec_destinations(plan), ["http://finretail:23004"])

    def test_a_redirects_body_is_never_read(self):
        # The fourth review on #151: urllib read a followed 3xx's whole body
        # first. This one promises 200 MB and never sends it.
        spec = json.dumps(OPENAPI3).encode()

        def answer(line):
            if line.startswith("GET /openapi.json "):
                return [(b"HTTP/1.1 302 Found\r\nLocation: /real.json\r\nContent-Length: 200000000\r\n\r\n", 0)]
            if line.startswith("GET /real.json "):
                return [(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                         + str(len(spec)).encode() + b"\r\nConnection: close\r\n\r\n" + spec, 0)]
            return [(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0)]

        with RawServer(answer) as server:
            started = time.perf_counter()
            status, body, over_cap = spec_probe.fetch_openapi_document(server.origin + "/openapi.json", timeout=5)
            elapsed = time.perf_counter() - started
        # Waiting on the promised body would take the whole 5 s and fail.
        self.assertLess(elapsed, 2.0)
        self.assertEqual((status, json.loads(body), over_cap), (200, OPENAPI3, False))
        self.assertEqual([line.split()[1] for line in server.requests], ["/openapi.json", "/real.json"])

    def test_a_redirect_loop_stops_after_three_hops(self):
        def answer(line):
            hop = int(line.split()[1].strip("/") or 0)
            return [(f"HTTP/1.1 302 Found\r\nLocation: /{hop + 1}\r\nContent-Length: 0\r\n\r\n".encode(), 0)]

        with RawServer(answer) as server:
            status, body, _ = spec_probe.fetch_openapi_document(server.origin + "/0", timeout=5)
        self.assertEqual((status, body), (302, None))
        self.assertEqual(len(server.requests), spec_probe.SPEC_REDIRECTS_MAX + 1)

    def test_a_server_whose_url_carries_a_credential_is_no_destination(self):
        plan = [("tenant", {"url": f"https://mcp.example.com/api/mcp/s/{KEY}/mcp"}, ".mcp.json"),
                ("userinfo", {"url": "http://u:p@billing:8080/mcp"}, ".mcp.json"),
                ("query", {"url": "http://ledger:8080/mcp?api_key=1"}, ".mcp.json"),
                ("plain", {"url": "http://ledger:8080/mcp"}, ".mcp.json")]
        # Only the plain server makes its origin a destination, as the MCP probe asks only it.
        self.assertEqual(spec_probe.spec_destinations(plan), ["http://ledger:8080"])
        self.assertEqual(spec_probe.spec_mount_paths(plan), {})

    def test_a_redirect_to_another_origin_or_scheme_is_not_followed(self):
        with FakeServer() as elsewhere, FakeServer({
            "/openapi.json": (302, b"", [("Location", "file:///etc/passwd")]),
            "/v3/api-docs": (302, b"", [("Location", elsewhere.origin + "/openapi.json")]),
            "/swagger.json": (302, b"", [("Location", "/real.json")]),
            "/real.json": (200, SWAGGER2),
        }) as server:
            entry = spec_probe.probe_openapi(server.origin)
        self.assertEqual(elsewhere.requests, [])
        self.assertEqual((entry["status"], entry["spec_path"]), ("ANSWERED", "/swagger.json"))

    def test_no_spec_anywhere_is_absent_and_html_is_no_spec(self):
        with FakeServer({"/api-docs": (200, b"<html>docs</html>")}) as server:
            entry = spec_probe.probe_openapi(server.origin)
        self.assertEqual(entry["status"], "ABSENT")
        self.assertEqual(spec_probe.http_operations_attribute([entry], {}, BUILDERS)["status"], "ABSENT")

    def test_a_down_destination_is_blind_and_asked_once(self):
        with FakeServer() as server:
            origin = server.origin
        entry = spec_probe.probe_openapi(origin)  # closed: connection refused
        self.assertEqual((entry["status"], entry["reason"]), ("BLIND", "NO_SOURCE_ACCESS"))
        self.assertEqual(entry["note"], "no answer, or an error status, at /openapi.json")

    def test_a_service_behind_a_context_path_is_found_under_its_mount_path(self):
        with FakeServer({"/finretail/v3/api-docs": (200, OPENAPI3)}) as server:
            entry = spec_probe.probe_openapi(server.origin, mount_paths=["/finretail"])
        self.assertEqual((entry["status"], entry["destination"], entry["spec_path"]),
                         ("ANSWERED", server.origin, "/finretail/v3/api-docs"))
        # The origin first, then the mount path, each in the usual order.
        self.assertEqual([path for _, path, _ in server.requests],
                         [*spec_probe.OPENAPI_PATHS, "/finretail/openapi.json", "/finretail/v3/api-docs"])

    def test_mount_paths_come_from_the_servers_urls_and_never_carry_a_credential(self):
        self.assertIsNone(spec_probe.mcp_mount_path("http://h:1/mcp"))
        self.assertIsNone(spec_probe.mcp_mount_path("http://h:1/"))
        self.assertEqual(spec_probe.mcp_mount_path("http://h:1/finretail/mcp"), "/finretail")
        self.assertEqual(spec_probe.mcp_mount_path("http://h:1/api/v1/mcp/?x=1"), "/api/v1")
        self.assertIsNone(spec_probe.mcp_mount_path(f"http://h:1/{KEY}/mcp"))
        self.assertIsNone(spec_probe.mcp_mount_path("http://h:1/a/../mcp"))
        self.assertIsNone(spec_probe.mcp_mount_path("file:///srv/app/mcp"))
        plan = [("a", {"url": "http://h:1/one/mcp"}, "x"), ("b", {"url": "http://h:1/one/sse"}, "x"),
                ("c", {"url": "http://h:1/two/mcp"}, "x"), ("d", {"url": "http://h:1/three/mcp"}, "x"),
                ("e", {"url": "http://g:2/mcp"}, "x")]
        self.assertEqual(spec_probe.spec_mount_paths(plan), {"http://h:1": ["/one", "/two"]})

    def test_with_no_destination_it_is_absent_unless_tool_schemas_servers_were_not_established(self):
        # tool_schemas ABSENT, or with servers: "no destination" is established.
        for tool_schemas in ({}, {"status": "ABSENT", "value": None},
                             {"status": "BLIND", "reason": "NO_SOURCE_ACCESS", "value": [{"server": "down"}]}):
            with self.subTest(tool_schemas=tool_schemas):
                field = spec_probe.http_operations_attribute([], tool_schemas, BUILDERS)
                self.assertEqual((field["status"], field["note"]),
                                 ("ABSENT", spec_probe.HTTP_OPERATIONS_NO_DESTINATION))
        # BLIND or FAILED with no server (a profile that couldn't read the MCP
        # config, RC-520's generic reader with none): BLIND with its reason.
        for status, reason in (("BLIND", "UNKNOWN_HARNESS"), ("BLIND", "PARSE_FAILED"), ("FAILED", "PARSE_FAILED")):
            with self.subTest(status=status, reason=reason):
                field = spec_probe.http_operations_attribute(
                    [], {"status": status, "reason": reason, "value": None, "note": "no MCP config"}, BUILDERS)
                self.assertEqual((field["status"], field["reason"]), ("BLIND", reason))
                self.assertIn("no MCP config", field["note"])

    def test_servers_with_no_origin_to_ask_are_absent_not_blind(self):
        # The fifth review: servers were found, just none with an HTTP origin.
        cases = {
            "stdio only": [scanner.tool_schema_server("fs", "a.json", [], "not_probed_stdio", None, False)],
            "credential URL only": [scanner.tool_schema_server("t", "a.json", [], "auth_refused", None, False)],
        }
        for label, servers in cases.items():
            with self.subTest(label):
                tool_schemas = evidence_bundle.tool_schemas_attribute(servers, [])
                self.assertEqual(tool_schemas["status"], "BLIND")
                field = spec_probe.http_operations_attribute([], tool_schemas, BUILDERS, servers=len(servers))
                self.assertEqual((field["status"], field["note"]),
                                 ("ABSENT", spec_probe.HTTP_OPERATIONS_NO_HTTP_SERVER))

    def test_the_bundle_budget_cuts_operations_and_says_so(self):
        operations = [{"method": "GET", "path": f"/p/{'x' * 200}/{index}"} for index in range(1000)]
        entry = {"destination": "http://a:1", "status": "ANSWERED", "spec_path": "/openapi.json",
                 "operations": operations}
        (capped,) = spec_probe.cap_http_operations([entry])
        self.assertTrue(0 < len(capped["operations"]) < 1000)
        self.assertEqual((capped["status"], capped["reason"], capped["operations_truncated"]),
                         ("PARTIAL", "SIZE_CAP_EXCEEDED", True))
        rendered = len(scanner.render_json({"agents": [{"attributes": {"http_operations": {"value": [capped]}}}]},
                                           compact=False))
        self.assertLess(rendered, spec_probe.HTTP_OPERATIONS_BYTES + 4096)

    def test_the_large_attributes_budgets_together_leave_room_in_the_1_mib_bundle(self):
        # A pod-mode bundle's capped values: egress_containment is always BLIND
        # there, and observed_file_access is filled only from a files snapshot.
        # Raising any of these past the bound fails here, not in delivery.
        budgets = (scanner.SKILL_SCHEMAS_BYTES + scanner.TOOL_SCHEMAS_BYTES + spec_probe.HTTP_OPERATIONS_BYTES
                   + scanner.FILE_ACCESS_BYTES)
        self.assertLessEqual(budgets, 1024 * 1024 - 128 * 1024)  # 128 KiB left for every other attribute


class RedactJsonTest(unittest.TestCase):
    """A credential in a tool schema that no vendor key shape matches
    (rail review of RC-512): a secret-named property's sample values, an
    example object's password, and a URL's userinfo."""

    SCHEMA = {
        "type": "object",
        "required": ["password"],
        "properties": {
            "password": {"type": "string", "format": "password", "description": "The user's password",
                         "default": "hunter2", "examples": ["hunter2"]},
            "api_key": {"type": "string", "enum": ["k-123"], "const": "k-123"},
            "db_url": {"type": "string", "examples": ["postgres://admin:hunter2@db:5432/app"]},
            "login": {"type": "object", "examples": [{"user": "ops", "password": "hunter2"}]},
            "docs": {"type": "string", "default": "https://example.com/docs?page=2"},
            "max_tokens": {"type": "integer", "default": 1024, "enum": ["short", "long"]},
            "mode": {"type": "string", "enum": ["read", "write"]},
        },
    }

    def test_a_plain_password_or_a_urls_userinfo_never_reaches_the_bundle(self):
        redacted = scanner.redact_json(self.SCHEMA)
        self.assertNotIn("hunter2", json.dumps(redacted))
        self.assertNotIn("k-123", json.dumps(redacted))
        props = redacted["properties"]
        self.assertEqual((props["password"]["default"], props["password"]["examples"]), ("[redacted]", ["[redacted]"]))
        self.assertEqual(props["db_url"]["examples"], ["postgres://db:5432/app"])
        self.assertEqual(props["login"]["examples"], [{"user": "ops", "password": "[redacted]"}])

    def test_the_schemas_structure_and_harmless_values_are_kept(self):
        props = scanner.redact_json(self.SCHEMA)["properties"]
        self.assertEqual(props["password"]["type"], "string")
        self.assertEqual(props["password"]["format"], "password")
        self.assertEqual(props["password"]["description"], "The user's password")
        self.assertEqual(props["docs"]["default"], "https://example.com/docs?page=2")
        self.assertEqual(props["max_tokens"], {"type": "integer", "default": 1024, "enum": ["short", "long"]})
        self.assertEqual(props["mode"]["enum"], ["read", "write"])

    def test_a_placeholder_or_bad_port_does_not_hide_a_urls_password(self):
        # The second rail review: url_carries_credential can't parse these ports.
        cases = {
            "postgres://admin:hunter2@db:PORT/app": "postgres://db:PORT/app",
            "postgres://admin:hunter2@db:${DB_PORT}/app": "postgres://db:${DB_PORT}/app",
            "http://admin:hunter2@h:99999/x": "http://h:99999/x",
            "https://h:PORT/x?api_key=hunter2": "https://h:PORT/x?[redacted]",
            "see postgres://u:hunter2@db:PORT/app here": "see postgres://db:PORT/app here",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(scanner.redact_schema_text(raw), expected)
        # No credential: left exactly as written, placeholder port and all.
        self.assertEqual(scanner.redact_schema_text("https://example.com:PORT/docs?page=2"),
                         "https://example.com:PORT/docs?page=2")

    def test_pwd_is_a_password_in_a_schema(self):
        redacted = scanner.redact_json({"properties": {"pwd": {"default": "hunter2"},
                                                       "db_pwd": {"examples": ["hunter2"]}}})
        self.assertNotIn("hunter2", json.dumps(redacted))

    def test_any_value_under_a_credential_key_in_sample_data_is_concealed(self):
        schema = {"type": "object", "examples": [{
            "user": "ops", "passwords": ["hunter2"], "api_keys": ["k-123"],
            "password": {"value": "hunter2"}, "pin_token": 4321, "enabled": True,
        }]}
        (example,) = scanner.redact_json(schema)["examples"]
        self.assertNotIn("hunter2", json.dumps(example))
        self.assertNotIn("k-123", json.dumps(example))
        self.assertEqual(example, {"user": "ops", "passwords": ["[redacted]"], "api_keys": ["[redacted]"],
                                   "password": {"value": "[redacted]"}, "pin_token": "[redacted]",
                                   "enabled": True})

    def test_http_auth_names_and_values_are_credentials(self):
        # The third rail review: names the environment's markers miss, and
        # header values no vendor key shape matches.
        for name in ("authorization", "Authorization", "auth", "x-auth-token", "oauth_code", "cookie",
                     "set_cookie", "bearer", "passphrase", "passcode", "session_id", "sessionToken", "jwt",
                     "signature"):
            with self.subTest(name=name):
                redacted = scanner.redact_json({"properties": {name: {"default": "sid=abcDEF123456"}}})
                self.assertEqual(redacted["properties"][name]["default"], "[redacted]")
        for value in ("Bearer abcDEF123456", "Basic dXNlcjpwYXNz", "token ghx0123456789abcdef"):
            with self.subTest(value=value):
                redacted = scanner.redact_schema_text(f"send {value} with it")
                self.assertEqual(redacted, f"send {value.split()[0]} [redacted] with it")
        example = scanner.redact_json({"examples": [{"X-Auth": "Basic dXNlcjpwYXNz", "Accept": "application/json"}]})
        self.assertEqual(example["examples"], [{"X-Auth": "[redacted]", "Accept": "application/json"}])

    def test_author_is_not_a_credential_name_and_short_scheme_words_are_kept(self):
        redacted = scanner.redact_json({"properties": {
            "author": {"default": "Ada Lovelace"}, "authors": {"enum": ["Ada", "Grace"]},
            "flow": {"enum": ["Basic", "Bearer token flow"]},
        }})["properties"]
        self.assertEqual(redacted["author"]["default"], "Ada Lovelace")
        self.assertEqual(redacted["authors"]["enum"], ["Ada", "Grace"])
        self.assertEqual(redacted["flow"]["enum"], ["Basic", "Bearer token flow"])

    def test_key_shaped_tool_server_and_destination_names_are_redacted(self):
        # The fourth rail review: skills_inventory redacted these names, tool_schemas didn't.
        entry = scanner.tool_schema_server(KEY, f"{KEY}.json", [], "reached",
                                           [{"name": KEY, "inputSchema": {"type": "object"}}, {"name": "getRate"}],
                                           False)
        self.assertNotIn(KEY, json.dumps(entry))
        self.assertEqual((entry["server"], [tool["name"] for tool in entry["tools"]]),
                         ("[redacted]", ["[redacted]", "getRate"]))
        skill = scanner.normalize_skill({"name": KEY, "description": "d", "server": KEY,
                                         "source_type": "mcp_config"}, "x")
        self.assertEqual(skill["server"], entry["server"])  # both attributes name the server alike
        host = f"http://{KEY}.example.com:8080"
        self.assertNotIn(KEY, json.dumps(probe_pool.deadline_spec_entry(host)))
        with mock.patch.object(spec_probe, "fetch_openapi_document", return_value=(404, None, False)):
            self.assertNotIn(KEY, json.dumps(spec_probe.probe_openapi(host)))

    def test_a_huge_string_costs_linear_time_not_quadratic(self):
        # The fifth rail review: an unbounded URL scheme made 80 KB take 5 s.
        started = time.perf_counter()
        scanner.redact_schema_text("a" * 1_000_000)
        scanner.redact_schema_text("Bearer" + " " * 1_000_000)
        self.assertLess(time.perf_counter() - started, 1.0)
        self.assertEqual(scanner.redact_schema_text("see https://u:hunter2@h/x here"), "see https://h/x here")

    def test_an_oversized_schema_is_left_out_quickly_and_skills_never_redact_it(self):
        huge = {"type": "object", "description": "a" * 1_000_000}
        # tool_schemas redacts it whole, since schema_sha256 (DR-294) is taken
        # before any cap; with the linear redaction that stays quick.
        started = time.perf_counter()
        record = scanner.record_tool_schema({"name": "x", "inputSchema": huge, "annotations": {"t": "a" * 1_000_000}})
        self.assertLess(time.perf_counter() - started, 1.0)
        self.assertEqual(record["schema_omitted"], "per_tool_budget")
        self.assertNotIn("inputSchema", record)
        self.assertNotIn("annotations", record)
        self.assertEqual(len(record["schema_sha256"]), 64)
        # skills_inventory has no digest, so it never redacts what it would drop.
        with mock.patch.object(scanner, "redact_json", side_effect=AssertionError("redacted")):
            self.assertEqual(scanner.tool_schema_fields({"name": "x", "inputSchema": huge}),
                             {"schema_omitted": "per_tool_budget"})

    def test_an_mcp_response_past_its_cap_is_not_read_on(self):
        tools = [{"name": f"t{i}", "description": "d" * 200} for i in range(50)]
        with FakeServer(tools=tools) as server, mock.patch.object(scanner, "MCP_RESPONSE_MAX_BYTES", 4096):
            self.assertEqual(scanner.probe_mcp_server(server.origin + "/mcp", None), (None, "unreachable", False))
        with FakeServer(tools=tools) as server:
            listed, reachability, _ = scanner.probe_mcp_server(server.origin + "/mcp", None)
        self.assertEqual((len(listed), reachability), (50, "reached"))

    def test_element_counts_bound_what_a_body_parses_to(self):
        body = b'{"a":[{},{},{}],"b":"x,y"}'
        # 4 `{`, 1 `[`, 4 `,` (one inside "x,y"): over the 7 values parsed, never under.
        self.assertEqual(scanner.json_element_count(body), 9)
        self.assertIsNone(spec_probe.json_element_cut(body, 100))
        cut = spec_probe.json_element_cut(body, 3)
        self.assertEqual(scanner.json_element_count(body[:cut]), 3)

    def test_a_response_of_tiny_elements_is_not_parsed(self):
        # The sixth rail review: 8 MiB of [{},{},...] parsed to about 400 MB.
        tools = [{} for _ in range(3000)]
        with FakeServer(tools=tools) as server, mock.patch.object(scanner, "MCP_RESPONSE_MAX_ELEMENTS", 1000), \
                mock.patch.object(scanner, "parse_mcp_body", wraps=scanner.parse_mcp_body) as parse:
            self.assertEqual(scanner.probe_mcp_server(server.origin + "/mcp", None), (None, "unreachable", False))
        self.assertEqual(parse.call_count, 1)  # initialize only; the tools/list page never reached the parser

    def test_the_scans_element_budget_is_shared_by_every_server(self):
        tools = [{"name": f"t{index}"} for index in range(100)]
        with FakeServer(tools=tools) as first, FakeServer(tools=tools) as second:
            budget = scanner.JsonElementBudget(scanner.json_element_count(
                json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": tools}}).encode()) + 50)
            listed, reachability, _ = scanner.probe_mcp_server(first.origin + "/mcp", None, scan_budget=budget)
            self.assertEqual((len(listed), reachability), (100, "reached"))
            self.assertEqual(scanner.probe_mcp_server(second.origin + "/mcp", None, scan_budget=budget)[1],
                             "unreachable")

    def test_a_spec_of_tiny_elements_is_cut_and_keeps_the_operations_that_fit(self):
        spec = {"openapi": "3.0.0", "paths": {"/b": {"get": {"operationId": "ok"}},
                                              "/a": {"get": {"x": [{} for _ in range(5000)]}}}}
        with FakeServer({"/openapi.json": (200, spec)}) as server, \
                mock.patch.object(spec_probe, "OPENAPI_MAX_ELEMENTS", 1000):
            entry = spec_probe.probe_openapi(server.origin)
        self.assertEqual((entry["status"], entry["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))
        self.assertEqual(entry["operations"], [{"method": "GET", "path": "/b", "operationId": "ok"}])
        self.assertIn("JSON elements", entry["note"])

    def test_an_mcp_redirect_body_is_never_read(self):
        def answer(line):
            return [(b"HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 200000000\r\n\r\n", 0)]

        with RawServer(answer) as server:
            started = time.perf_counter()
            result = scanner.mcp_rpc_call(server.origin + "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "x"},
                                          {"Content-Type": "application/json"}, 5)
            elapsed = time.perf_counter() - started
        self.assertEqual(result, (None, {}, 302))
        self.assertLess(elapsed, 2.0)
        self.assertEqual(len(server.requests), 1)  # not followed either

    def test_a_drip_fed_mcp_answer_ends_at_the_calls_timeout(self):
        # Below the bar in the fourth review: a per-read timeout alone let a
        # server that sends a byte now and then hold a pool worker for good.
        def answer(line):
            head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n"
            return [(head, 0.2)] + [(b" ", 0.2) for _ in range(100)]

        with RawServer(answer) as server:
            started = time.perf_counter()
            result = scanner.mcp_rpc_call(server.origin + "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "x"},
                                          {"Content-Type": "application/json"}, 1.0)
            elapsed = time.perf_counter() - started
        self.assertEqual(result, (None, {}, None))
        self.assertLess(elapsed, 2.0)

    def test_a_description_s_own_words_after_an_auth_scheme_are_kept(self):
        # The fourth review on #151: the rule redacted ordinary prose.
        for text in ("An access token obtained from the login endpoint",
                     "Pagination token returned by a previous call",
                     "Basic information about the customer",
                     "Basic Information about the customer"):
            with self.subTest(text=text):
                self.assertEqual(scanner.redact_schema_text(text), text)
        for value in ("Bearer eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM", "Basic dXNlcjpwYXNzd29yZA=="):
            with self.subTest(value=value):
                self.assertEqual(scanner.redact_schema_text(value), value.split()[0] + " [redacted]")

    def test_tool_schemas_records_the_redacted_schema(self):
        record = scanner.record_tool_schema({"name": "login", "inputSchema": self.SCHEMA,
                                             "annotations": {"title": "Log in", "password": "hunter2"}})
        self.assertNotIn("hunter2", json.dumps(record))
        self.assertEqual(record["annotations"], {"title": "Log in", "password": "[redacted]"})


class ProbePoolTest(unittest.TestCase):
    def test_at_most_four_probes_run_at_once(self):
        lock, running, peak = threading.Lock(), [0], [0]

        def probe(value):
            with lock:
                running[0] += 1
                peak[0] = max(peak[0], running[0])
            time.sleep(0.1)
            with lock:
                running[0] -= 1
            return value * 2

        with probe_pool.ProbePool(4, time.monotonic() + 10) as pool:
            for index in range(10):
                pool.submit(index, probe, index)
            results = [pool.wait(index, None) for index in range(10)]
        self.assertEqual(results, [index * 2 for index in range(10)])
        self.assertEqual(peak[0], 4)

    def test_a_probe_past_the_deadline_gets_the_fallback_without_waiting_for_it(self):
        release = threading.Event()
        self.addCleanup(release.set)
        started = time.monotonic()
        with probe_pool.ProbePool(4, started + 0.3) as pool:
            pool.submit("slow", release.wait, 30)
            pool.submit("fast", lambda: "ok")
            self.assertEqual(pool.wait("fast", "late"), "ok")
            self.assertEqual(pool.wait("slow", "late"), "late")
            self.assertEqual(pool.unanswered(), 1)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_a_probe_is_submitted_once_by_key_and_one_that_raises_is_its_own_failure(self):
        calls = []
        with probe_pool.ProbePool(2, None) as pool:
            pool.submit("a", calls.append, 1)
            pool.submit("a", calls.append, 2)
            pool.submit("boom", lambda: 1 / 0)
            self.assertIsNone(pool.wait("a", "late"))
            self.assertEqual(pool.wait("boom", "late", "failed"), "failed")
        self.assertEqual(calls, [1])


class PodScanDeadlineTest(unittest.TestCase):
    """The real scanner in pod mode, in process so the deadline can be
    shortened, against two fake servers that answer and one that never does."""

    DEADLINE = 1.5
    POD = {
        "POD_NAME": "agent-finretail-58cd78b55d-48jcw",
        "POD_NAMESPACE": "gke-test",
        "POD_UID": "f3fe5e58-b328-40cb-9b03-1acf558d773d",
        "NODE_NAME": "gke-gke-test-default-pool-1c6529e9-aqik",
    }

    def scan(self, servers: dict[str, str], mode: str = "pod") -> tuple[dict, float]:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "config").mkdir()
        (tmp / "config" / ".mcp.json").write_text(json.dumps({"mcpServers": {
            name: url if isinstance(url, dict) else {"url": url, "headers": {"Authorization": f"Bearer {KEY}"}}
            for name, url in servers.items()
        }}))
        (tmp / "podinfo").mkdir()
        (tmp / "podinfo" / "labels").write_text('app="agent-finretail"\npod-template-hash="58cd78b55d"\n')
        (tmp / "home").mkdir()
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(tmp / "home"),
               "RAIL_POD_INFO_DIR": str(tmp / "podinfo"), **self.POD}
        target = (["--mode", "pod", "--config-path", str(tmp / "config")] if mode == "pod"
                  else ["--mode", "self", "--mcp-config", str(tmp / "config" / ".mcp.json")])
        argv = [*target, "--host-id", "gke-test", "--sandbox-name", "gke-test/agent-finretail",
                "--feature-output", str(tmp / "features.json"),
                "--evidence-bundle-output", str(tmp / "bundle.json"), "--output", str(tmp / "payload.json")]
        cwd = os.getcwd()
        os.chdir(tmp)
        self.addCleanup(os.chdir, cwd)
        started = time.monotonic()
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(probe_pool, "SCAN_DEADLINE_SECONDS", self.DEADLINE), \
                mock.patch("sys.stderr"):
            self.assertEqual(scanner.main(argv), 0)
        elapsed = time.monotonic() - started
        bundle = json.loads((tmp / "bundle.json").read_text())
        evidence_bundle.verify_bundle(bundle)
        self.assertNotIn(KEY, (tmp / "bundle.json").read_text())
        return bundle["attributes"], elapsed

    def test_a_server_that_never_answers_is_blind_and_the_scan_ends_within_the_deadline(self):
        with FakeServer({"/openapi.json": (200, OPENAPI3)}, FINRETAIL_TOOLS) as first, \
                FakeServer({"/swagger.json": (200, SWAGGER2)}, FINRETAIL_TOOLS) as second, \
                SilentServer() as silent:
            attributes, elapsed = self.scan({"finretail": first.origin + "/mcp", "accounts": second.origin + "/mcp",
                                             "silent": silent.origin + "/mcp"})
        # The silent server's own timeouts (3 s an MCP call, 5 s a spec path)
        # are longer than the deadline: only the deadline can end the scan this soon.
        self.assertLess(elapsed, self.DEADLINE + 1.0)
        self.assertLess(self.DEADLINE, scanner.MCP_PROBE_TIMEOUT_SECONDS)

        operations = attributes["http_operations"]
        self.assertEqual((operations["status"], operations["reason"]), ("PARTIAL", "NO_SOURCE_ACCESS"))
        by_destination = {entry["destination"]: entry for entry in operations["value"]}
        self.assertEqual(by_destination[first.origin]["status"], "ANSWERED")
        self.assertEqual(by_destination[second.origin]["status"], "ANSWERED")
        self.assertEqual(len(by_destination[first.origin]["operations"]), 2)
        late = by_destination[silent.origin]
        self.assertEqual((late["status"], late["reason"], late["deadline_exceeded"]),
                         ("BLIND", "NO_SOURCE_ACCESS", True))

        schemas = attributes["tool_schemas"]
        self.assertEqual((schemas["status"], schemas["reason"]), ("PARTIAL", "NO_SOURCE_ACCESS"))
        by_server = {entry["server"]: entry for entry in schemas["value"]}
        self.assertEqual(by_server["finretail"]["reachability"], "reached")
        self.assertEqual(by_server["accounts"]["reachability"], "reached")
        self.assertEqual((by_server["silent"]["reachability"], by_server["silent"]["deadline_exceeded"]),
                         ("unreachable", True))
        self.assertIn("deadline: silent", schemas["note"])

        # No credential went to any server, MCP or spec path.
        self.assertEqual({auth for _, _, auth in first.requests + second.requests}, {None})

    def test_every_server_answering_is_answered_well_inside_the_deadline(self):
        with FakeServer({"/openapi.json": (200, OPENAPI3)}, FINRETAIL_TOOLS) as server:
            attributes, elapsed = self.scan({"finretail": server.origin + "/mcp",
                                             "local": "file:///etc/passwd"})
        self.assertLess(elapsed, self.DEADLINE)
        self.assertEqual(attributes["http_operations"]["status"], "ANSWERED")
        self.assertEqual([entry["destination"] for entry in attributes["http_operations"]["value"]],
                         [server.origin])

    def test_a_pod_scan_finds_a_spec_under_the_mcp_servers_mount_path(self):
        with FakeServer({"/finretail/openapi.json": (200, OPENAPI3)}, FINRETAIL_TOOLS) as server:
            attributes, _ = self.scan({"finretail": server.origin + "/finretail/mcp"})
        (entry,) = attributes["http_operations"]["value"]
        self.assertEqual((entry["status"], entry["spec_path"]), ("ANSWERED", "/finretail/openapi.json"))

    def test_a_pod_scan_of_stdio_servers_only_is_absent(self):
        attributes, _ = self.scan({"fs": {"command": "mcp-server-filesystem", "args": ["/data"]},
                                   "git": {"command": "uvx", "args": ["mcp-server-git"]}})
        self.assertEqual(attributes["tool_schemas"]["status"], "BLIND")
        field = attributes["http_operations"]
        self.assertEqual((field["status"], field["note"]), ("ABSENT", spec_probe.HTTP_OPERATIONS_NO_HTTP_SERVER))

    def test_a_self_scan_asks_no_spec_path_and_says_so(self):
        with FakeServer({"/openapi.json": (200, OPENAPI3)}, FINRETAIL_TOOLS) as server:
            attributes, _ = self.scan({"finretail": server.origin + "/mcp"}, mode="self")
        self.assertEqual([method for method, _, _ in server.requests if method == "GET"], [])
        self.assertTrue(any(method == "POST" for method, _, _ in server.requests))  # the MCP probe still runs
        field = attributes["http_operations"]
        self.assertEqual((field["status"], field["reason"]), ("BLIND", "NOT_COLLECTED_BY_PACK"))
        self.assertEqual(attributes["tool_schemas"]["status"], "ANSWERED")


if __name__ == "__main__":
    unittest.main()
