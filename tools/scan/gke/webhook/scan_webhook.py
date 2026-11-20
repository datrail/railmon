"""`railmon scan-webhook`: adds the scan sidecar to labeled pods (RC-518).

A mutating admission webhook, one Deployment in rail-system. The chart's
MutatingWebhookConfiguration sends it every pod created with the label
`rail.datrail.io/scan=true` in an enrolled namespace; it answers with a JSON
patch that adds the sidecar (patch.py). It always allows the pod: anything
it can't do, it logs, answers with no patch and lets the pod start without a
sidecar. With `failurePolicy: Ignore` in the chart, a webhook that is down or
slow does the same, and gke-scan's own view still covers the pod.

It holds no credential and calls nothing: no Kubernetes API, no Rail Center.
Like the scanner and gke-scan, it uses only the Python standard library.

Configuration, each flag also read from its environment variable:

* `--sidecar-spec` / RAIL_SCAN_SIDECAR_SPEC: the sidecar spec, a JSON file
  from the chart's ConfigMap. Read once at start; the chart restarts the
  webhook when the spec changes. Required.
* `--tls-cert-file`, `--tls-key-file` / RAIL_WEBHOOK_TLS_CERT_FILE,
  RAIL_WEBHOOK_TLS_KEY_FILE: the webhook's certificate from the chart's CA,
  which the MutatingWebhookConfiguration's caBundle names. Loaded again when
  its Secret changes (tls_reload.py), so a renewed one needs no restart.
  Required.
* `--listen` / RAIL_WEBHOOK_LISTEN: host:port, default 0.0.0.0:9443.

POST /mutate takes an AdmissionReview (admission.k8s.io/v1); GET /healthz
answers 200 for the readiness probe. SIGTERM stops taking requests, lets
those in flight finish (an admission request has at most 10 seconds), and
exits 0.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import signal
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any

HERE = Path(__file__).resolve().parent
DEFAULT_LISTEN = "0.0.0.0:9443"
# An AdmissionReview carries the whole pod, and Kubernetes caps an object at
# about 1.5 MB; anything past 3 MiB isn't a pod.
MAX_REQUEST_BYTES = 3 * 1024 * 1024
# Each read on a connection, the TLS handshake included, gives up after this.
# The API server gives an admission request at most 10 seconds, so a client
# slower than that isn't the API server.
REQUEST_READ_TIMEOUT_SECONDS = 10.0


def patch_module() -> ModuleType:
    module = sys.modules.get("gke_scan_webhook_patch")
    if module is None:
        spec = importlib.util.spec_from_file_location("gke_scan_webhook_patch", HERE / "patch.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules["gke_scan_webhook_patch"] = module
        spec.loader.exec_module(module)
    return module


def tls_reload_module() -> ModuleType:
    """tls_reload.py, shared with gke-scan (tools/scan/gke/), loaded by path once."""
    module = sys.modules.get("gke_tls_reload")
    if module is None:
        spec = importlib.util.spec_from_file_location("gke_tls_reload", HERE.parent / "tls_reload.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules["gke_tls_reload"] = module
        spec.loader.exec_module(module)
    return module


def log(message: str) -> None:
    print(f"[scan-webhook] {message}", file=sys.stderr, flush=True)


def load_spec(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        spec = json.load(handle)
    if not isinstance(spec, dict) or not isinstance(spec.get("container"), dict) or not spec["container"].get("image"):
        raise ValueError(f"{path}: the sidecar spec needs a container with an image")
    return spec


def _pod_name(request: dict[str, Any]) -> str:
    pod = request.get("object") or {}
    metadata = pod.get("metadata") or {}
    # A controller's pod has no name yet at admission, only its generateName.
    name = metadata.get("name") or (metadata["generateName"] + "*" if metadata.get("generateName") else "?")
    return f"{request.get('namespace') or metadata.get('namespace') or '?'}/{name}"


def review_response(review: Any, spec: dict[str, Any]) -> dict[str, Any]:
    """The AdmissionReview answer for one request. Always `allowed`."""
    request = review.get("request") if isinstance(review, dict) else None
    uid = request.get("uid", "") if isinstance(request, dict) else ""
    response: dict[str, Any] = {"uid": uid, "allowed": True}
    answer = {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "response": response}
    if not isinstance(request, dict):
        log("an AdmissionReview with no request; allowed with no patch")
        return answer
    who = _pod_name(request)
    kind = (request.get("kind") or {}).get("kind")
    if kind != "Pod" or request.get("operation") != "CREATE" or request.get("subResource"):
        log(f"{who}: not a pod being created ({kind} {request.get('operation')}); allowed with no patch")
        return answer
    try:
        result = patch_module().sidecar_patch(request.get("object") or {}, spec)
    except Exception as error:  # fail open: a pod must never be stopped by this webhook
        log(f"{who}: couldn't build the patch ({type(error).__name__}: {error}); allowed with no sidecar")
        return answer
    for warning in result.warnings:
        log(f"{who}: {warning}")
    if result.warnings:
        response["warnings"] = [f"rail scan sidecar: {w}" for w in result.warnings]
    if result.skipped:
        log(f"{who}: no sidecar added: {result.skipped}")
        return answer
    response["patchType"] = "JSONPatch"
    response["patch"] = base64.b64encode(json.dumps(result.patch, separators=(",", ":")).encode()).decode()
    log(f"{who}: scan sidecar added")
    return answer


class WebhookHandler(BaseHTTPRequestHandler):
    server: "WebhookServer"
    protocol_version = "HTTP/1.1"
    timeout = REQUEST_READ_TIMEOUT_SECONDS

    def log_message(self, format: str, *args: Any) -> None:  # one line per request, from review_response
        return

    def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, b"ok\n", "text/plain")
        else:
            self._send(404, b'{"error": "not found"}')

    def do_POST(self) -> None:
        if self.path.split("?", 1)[0] != "/mutate":
            self._send(404, b'{"error": "not found"}')
            return
        length = self.headers.get("Content-Length")
        if length is None or not length.isdigit():
            self._send(411, b'{"error": "Content-Length required"}')
            return
        if int(length) > MAX_REQUEST_BYTES:
            self.close_connection = True
            self._send(413, b'{"error": "too large"}')
            return
        data = self.rfile.read(int(length))
        try:
            review = json.loads(data)
        except ValueError:
            log("a request that isn't JSON; answered 400 (the API server lets the pod start: failurePolicy Ignore)")
            self._send(400, b'{"error": "not JSON"}')
            return
        answer = review_response(review, self.server.spec)
        self._send(200, json.dumps(answer, separators=(",", ":")).encode())


class WebhookServer(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True

    def __init__(self, address: tuple[str, int], spec: dict[str, Any], tls: Any | None):
        super().__init__(address, WebhookHandler)
        self.spec = spec
        self.tls = tls

    def get_request(self) -> tuple[Any, Any]:
        conn, address = self.socket.accept()
        if self.tls is not None:
            # Each connection gets the certificate the Secret holds now
            # (tls_reload.py): the chart signs a new one on every render, and
            # the API server stops calling a webhook whose certificate its
            # caBundle doesn't trust. The handshake is deferred to the
            # request's own thread, under its read timeout, so a client that
            # stalls in it can't hold up the accept loop (as in gke-scan's intake).
            conn = tls_reload_module().wrap_accepted(conn, self.tls)
        return conn, address


def server_tls_context(cert_file: str, key_file: str) -> Any:
    """The webhook's certificate, followed as its Secret is renewed. Raises
    when the files won't load at start."""
    return tls_reload_module().ReloadingContext(cert_file, key_file, log=lambda line: log(line))


def first(*values: str | None) -> str | None:
    for value in values:
        if value:
            return value
    return None


def parse_listen(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    if not port.isdigit():
        raise ValueError(f"--listen {value!r}: expected host:port")
    return host or "0.0.0.0", int(port)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="railmon scan-webhook",
        description="Admission webhook: adds the scan sidecar to pods labeled rail.datrail.io/scan=true.",
    )
    parser.add_argument("--sidecar-spec", help="The sidecar spec (JSON) from the chart. RAIL_SCAN_SIDECAR_SPEC.")
    parser.add_argument("--tls-cert-file", help="The webhook's certificate. RAIL_WEBHOOK_TLS_CERT_FILE.")
    parser.add_argument("--tls-key-file", help="Its key. RAIL_WEBHOOK_TLS_KEY_FILE.")
    parser.add_argument("--listen", help=f"host:port, default {DEFAULT_LISTEN}. RAIL_WEBHOOK_LISTEN.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    spec_file = first(args.sidecar_spec, os.environ.get("RAIL_SCAN_SIDECAR_SPEC"))
    cert = first(args.tls_cert_file, os.environ.get("RAIL_WEBHOOK_TLS_CERT_FILE"))
    key = first(args.tls_key_file, os.environ.get("RAIL_WEBHOOK_TLS_KEY_FILE"))
    missing = [name for name, value in (("--sidecar-spec", spec_file), ("--tls-cert-file", cert),
                                        ("--tls-key-file", key)) if not value]
    if missing:
        print(f"railmon scan-webhook: missing {', '.join(missing)}", file=sys.stderr)
        return 2
    try:
        spec = load_spec(spec_file)  # type: ignore[arg-type]
        address = parse_listen(first(args.listen, os.environ.get("RAIL_WEBHOOK_LISTEN")) or DEFAULT_LISTEN)
        server = WebhookServer(address, spec, server_tls_context(cert, key))  # type: ignore[arg-type]
    except (OSError, ValueError, ssl.SSLError) as error:
        print(f"railmon scan-webhook: {error}", file=sys.stderr)
        return 2

    def stop(signum: int, frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    log(f"listening on {address[0]}:{address[1]}, adding {spec['container']['image']}")
    server.serve_forever()
    server.server_close()
    log("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
