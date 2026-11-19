"""gke-scan's sidecar intake (RC-515): take a sidecar's evidence bundle, check
who sent it, and relay the same bytes to Rail Center.

The sidecar posts to `POST /v1/agents/register` on gke-scan's ClusterIP
Service in rail-system, over HTTPS, with its projected token (audience
gke-scan) as a bearer token. Before anything is relayed:

1. **The token.** A TokenReview checks its signature, audience and expiry
   (401 if it fails). It must be a service account's token bound to a pod,
   which a projected token is (403 if not).
2. **The size.** At most 4 MB (MAX_BUNDLE_BYTES), by Content-Length, checked
   before the body is read (413; 411 without a length).
3. **The bundle.** A JSON object with `bundle_version` 1: only v1 is relayed
   (422 otherwise).
4. **The key and the pod.** The bundle's `host_id` is this cluster's name, the
   namespace in its `sandbox_name` (namespace/workload) is the token's, and
   the pod UID in its `agent_instance` is the token's (403 if any differs). The
   pod the token names still exists with that UID and carries the label
   rail.datrail.io/scan=true, and the whole `sandbox_name` is the pod's own
   namespace/workload as the Kubernetes API bears it out (workload.py): each
   owner the pod names is read and must exist with that UID and select the
   pod, up to its Deployment, Rollout or CronJob (which must list the Job
   as active), and no other workload may be keyed the same way (403 if
   not). It can't stop someone who may create pods in the namespace from
   making one that, to Kubernetes, is a workload's replica, and gke-scan
   can't tell it apart: pod creation in an enrolled namespace is the trust
   boundary (workload.py).
5. **No agent key.** A post naming `?agent_key=` is refused (422). A v1
   bundle names no key of its own, and Rail Center files one under the
   `?agent_key=` it is sent with, so a key passed through would let a pod
   file its bundle under another agent's key, past the checks above. A
   sidecar's bundle is filed under its checked host_id and sandbox_name.
6. **One at a time.** One bundle per pod in flight (409 for a second).

A bundle that fails any check is refused and never relayed. One that passes
goes to Rail Center unchanged, with `X-Rail-Source: sidecar` and
`X-Rail-Pod-UID`, under gke-scan's own credential. Rail Center's answer goes
back to the sidecar as is, except that 401, 403, 5xx or no answer becomes 503:
none of them is the sidecar's to fix, and the sidecar retries a 503 with its
own backoff (RC-513). gke-scan doesn't parse beyond these checks, merge,
change or retry the bundle. When the Kubernetes API can't answer a check, the
answer is 503 for the same reason.

The pod check reads the pod from the Kubernetes API on each post. The cluster
reader (gke-scan's watch of labeled pods, a later task) can answer it from
memory instead, through the same `get_pod`.

Like the sidecar's modules, this one imports nothing of railmon's: the entry
point (gke_scan.py) hands it the Kubernetes client and the relay.
"""

from __future__ import annotations

import importlib.util
import json
import ssl
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Protocol
from urllib.parse import parse_qsl, urlsplit

REGISTER_PATH = "/v1/agents/register"
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
BUNDLE_VERSION = 1
SCAN_LABEL = "rail.datrail.io/scan"
SOURCE_HEADER = "X-Rail-Source"
POD_UID_HEADER = "X-Rail-Pod-UID"
SOURCE_SIDECAR = "sidecar"
# How long a sidecar may take to send its request, so a slow or stalled
# client can't hold a server thread.
REQUEST_READ_TIMEOUT_SECONDS = 30.0
# A refused body is read and dropped up to this much (IntakeHandler._discard_body).
DISCARD_MAX_BYTES = 2 * MAX_BUNDLE_BYTES
# On SIGTERM, relays in flight get this long (the gke-scan design's shutdown).
SHUTDOWN_GRACE_SECONDS = 10.0


def _workload() -> ModuleType:
    """workload.py beside this file, loaded by path once."""
    module = sys.modules.get("gke_scan_workload")
    if module is None:
        spec = importlib.util.spec_from_file_location("gke_scan_workload", Path(__file__).with_name("workload.py"))
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules["gke_scan_workload"] = module
        spec.loader.exec_module(module)
    return module


class KubeAPI(Protocol):
    def token_review(self, token: str, audience: str) -> Any: ...
    def get_pod(self, namespace: str, name: str) -> dict[str, Any] | None: ...
    def get_object(self, api_version: str, plural: str, namespace: str, name: str) -> dict[str, Any] | None: ...


@dataclass(frozen=True)
class RelayAnswer:
    """What Rail Center answered: `status` is None when nothing answered."""

    status: int | None
    body: bytes = b""
    content_type: str | None = None
    retry_after: str | None = None
    detail: str = ""


# The relay takes the bundle's bytes and the pod UID, and nothing that would
# let the sender choose where Rail Center files it.
Relay = Callable[[bytes, str], RelayAnswer]


@dataclass(frozen=True)
class Answer:
    status: int
    body: bytes
    content_type: str = "application/json"
    retry_after: str | None = None
    log: str = ""


def refusal(status: int, error: str, log: str | None = None) -> Answer:
    return Answer(status, json.dumps({"error": error}).encode(), log=log if log is not None else error)


def bearer_token(header: str | None) -> str | None:
    if not header:
        return None
    scheme, _, token = header.strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or " " in token:
        return None
    return token


def bundle_pod_uid(bundle: dict[str, Any]) -> str | None:
    """The pod UID the sidecar wrote in its agent_instance attribute."""
    attributes = bundle.get("attributes")
    instance = attributes.get("agent_instance") if isinstance(attributes, dict) else None
    value = instance.get("value") if isinstance(instance, dict) else None
    pod = value.get("pod") if isinstance(value, dict) else None
    uid = pod.get("uid") if isinstance(pod, dict) else None
    return uid if isinstance(uid, str) and uid else None


def relayed_answer(answer: RelayAnswer) -> Answer:
    """Rail Center's answer as the sidecar gets it: 401, 403, 5xx or no answer
    becomes 503, and everything else passes through."""
    status = answer.status
    if status is None:
        return refusal(503, "rail center did not answer", f"rail center did not answer ({answer.detail}): 503")
    if status in (401, 403):
        return refusal(503, "rail center refused gke-scan's credential",
                       f"rail center answered {status} to gke-scan's credential: 503")
    if 500 <= status <= 599:
        out = refusal(503, f"rail center answered {status}", f"rail center answered {status}: 503")
        return Answer(503, out.body, retry_after=answer.retry_after, log=out.log)
    return Answer(status, answer.body, answer.content_type or "application/json",
                  retry_after=answer.retry_after, log=f"rail center answered {status}")


class Intake:
    """The checks and the relay, apart from HTTP, so each step is testable."""

    def __init__(self, kube: KubeAPI, relay: Relay, cluster_name: str, audience: str,
                 max_bytes: int = MAX_BUNDLE_BYTES):
        self.kube = kube
        self.relay = relay
        self.cluster_name = cluster_name
        self.audience = audience
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self._in_flight: set[str] = set()

    def authenticate(self, authorization: str | None) -> tuple[Any, Answer | None]:
        token = bearer_token(authorization)
        if token is None:
            return None, refusal(401, "a bearer token is required")
        try:
            identity = self.kube.token_review(token, self.audience)
        except Exception as exc:  # the Kubernetes API, not the sidecar
            return None, refusal(503, "the token can't be checked now", f"TokenReview failed: {exc}: 503")
        if identity is None:
            return None, refusal(401, f"the token isn't valid for audience {self.audience}")
        if not identity.pod_name or not identity.pod_uid:
            return None, refusal(403, "the token isn't bound to a pod",
                                 f"token for {identity.namespace}/{identity.service_account} names no pod: 403")
        return identity, None

    def check_bundle(self, identity: Any, data: bytes) -> Answer | None:
        """None when the bundle may be relayed for this token's pod."""
        try:
            bundle = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            return refusal(422, "the body isn't JSON")
        if not isinstance(bundle, dict):
            return refusal(422, "the body isn't a JSON object")
        version = bundle.get("bundle_version")
        if version != BUNDLE_VERSION or isinstance(version, bool):
            return refusal(422, f"only bundle_version {BUNDLE_VERSION} is relayed",
                           f"bundle_version {version!r}: 422")
        who = f"{identity.namespace}/{identity.pod_name}"
        host_id = bundle.get("host_id")
        if host_id != self.cluster_name:
            return refusal(403, "the bundle's host_id isn't this cluster's name",
                           f"{who}: host_id {host_id!r}, not {self.cluster_name!r}: 403")
        sandbox_name = bundle.get("sandbox_name")
        namespace = sandbox_name.partition("/")[0] if isinstance(sandbox_name, str) else None
        if namespace != identity.namespace:
            return refusal(403, "the bundle's sandbox_name isn't in the token's namespace",
                           f"{who}: sandbox_name {sandbox_name!r} outside namespace {identity.namespace}: 403")
        uid = bundle_pod_uid(bundle)
        if uid != identity.pod_uid:
            return refusal(403, "the bundle's pod UID isn't the token's",
                           f"{who}: bundle pod UID {uid!r}, token's {identity.pod_uid}: 403")
        try:
            pod = self.kube.get_pod(identity.namespace, identity.pod_name)
        except Exception as exc:
            return refusal(503, "the pod can't be checked now", f"{who}: reading the pod failed: {exc}: 503")
        metadata = pod.get("metadata") if isinstance(pod, dict) else None
        if not isinstance(metadata, dict) or metadata.get("uid") != identity.pod_uid:
            return refusal(403, "the token's pod isn't running", f"{who}: no pod with UID {identity.pod_uid}: 403")
        labels = metadata.get("labels") if isinstance(metadata.get("labels"), dict) else {}
        if labels.get(SCAN_LABEL) != "true":
            return refusal(403, f"the pod isn't labeled {SCAN_LABEL}=true", f"{who}: not labeled for scanning: 403")
        try:
            expected, how = _workload().sandbox_name(self.kube, identity.namespace, pod)
        except Exception as exc:  # the Kubernetes API, not the sidecar
            return refusal(503, "the pod's workload can't be checked now", f"{who}: reading its owners failed: {exc}: 503")
        if expected is None:
            return refusal(403, "the pod's workload can't be confirmed", f"{who}: workload not confirmed ({how}): 403")
        if sandbox_name != expected:
            return refusal(403, "the bundle's sandbox_name isn't the pod's workload",
                           f"{who}: sandbox_name {sandbox_name!r}, the pod's is {expected!r} ({how}): 403")
        return None

    def relay_bundle(self, identity: Any, data: bytes) -> Answer:
        uid = identity.pod_uid
        with self._lock:
            if uid in self._in_flight:
                return refusal(409, "a bundle from this pod is already being relayed",
                               f"{identity.namespace}/{identity.pod_name}: a bundle already in flight: 409")
            self._in_flight.add(uid)
        try:
            try:
                answer = self.relay(data, uid)
            except Exception as exc:  # no credential to mint, say: not the sidecar's to fix
                answer = RelayAnswer(None, detail=f"{exc.__class__.__name__}: {exc}")
            return relayed_answer(answer)
        finally:
            with self._lock:
                self._in_flight.discard(uid)

    def in_flight(self) -> int:
        with self._lock:
            return len(self._in_flight)


def log(message: str) -> None:
    print(f"gke-scan: intake: {message}", file=sys.stderr, flush=True)


class IntakeHandler(BaseHTTPRequestHandler):
    server: "IntakeServer"
    protocol_version = "HTTP/1.1"
    timeout = REQUEST_READ_TIMEOUT_SECONDS
    server_version = "gke-scan"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:  # one line per post, written below
        return

    def _send(self, answer: Answer) -> None:
        self.send_response(answer.status)
        self.send_header("Content-Type", answer.content_type)
        self.send_header("Content-Length", str(len(answer.body)))
        if answer.retry_after:
            self.send_header("Retry-After", answer.retry_after)
        if answer.status == 405:
            self.send_header("Allow", "POST")
        self.end_headers()
        self.wfile.write(answer.body)

    def _refuse_other(self) -> None:
        path = urlsplit(self.path).path
        self.close_connection = True
        self._send(refusal(405 if path == REGISTER_PATH else 404,
                           "method not allowed" if path == REGISTER_PATH else "not found"))

    do_GET = do_PUT = do_DELETE = do_PATCH = do_HEAD = _refuse_other

    def do_POST(self) -> None:
        intake = self.server.intake
        parts = urlsplit(self.path)
        if parts.path.rstrip("/") != REGISTER_PATH:
            self.close_connection = True
            self._send(refusal(404, "not found"))
            return
        # Nothing is read past the headers until the sender is known, and the
        # connection is closed after each answer, so an unread body can't be
        # taken for the next request.
        self.close_connection = True
        identity, answer = intake.authenticate(self.headers.get("Authorization"))
        if answer is None:
            answer = self._read_and_relay(intake, identity, parts.query)
        else:
            self._discard_body()
        who = f"{identity.namespace}/{identity.pod_name}" if identity is not None else self.client_address[0]
        log(answer.log if answer.log.startswith(who) else f"{who}: {answer.log}")
        self._send(answer)

    def _discard_body(self) -> None:
        """Read and drop a body that won't be used, up to DISCARD_MAX_BYTES,
        so the sender, which writes its whole body before reading the answer,
        gets the answer rather than a reset connection."""
        try:
            left = min(int(self.headers.get("Content-Length", "0")), DISCARD_MAX_BYTES)
            while left > 0:
                chunk = self.rfile.read(min(left, 64 * 1024))
                if not chunk:
                    return
                left -= len(chunk)
        except (ValueError, OSError):
            return

    def _read_and_relay(self, intake: Intake, identity: Any, query: str) -> Answer:
        if "agent_key" in dict(parse_qsl(query, keep_blank_values=True)):
            self._discard_body()
            return refusal(422, "agent_key isn't accepted: a sidecar's bundle is filed under its host_id "
                                "and sandbox_name", "a post naming agent_key: 422")
        if self.headers.get("Transfer-Encoding"):
            return refusal(411, "a Content-Length is required")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return refusal(411, "a Content-Length is required")
        if length < 0:
            return refusal(411, "a Content-Length is required")
        if length > intake.max_bytes:
            self._discard_body()
            return refusal(413, f"bundles are limited to {intake.max_bytes} bytes", f"{length} bytes: 413")
        try:
            data = self.rfile.read(length)
        except OSError as exc:
            return refusal(400, "the body couldn't be read", f"reading the body failed: {exc}: 400")
        if len(data) != length:
            return refusal(400, "the body is shorter than its Content-Length")
        problem = intake.check_bundle(identity, data)
        if problem is not None:
            return problem
        return intake.relay_bundle(identity, data)


class IntakeServer(ThreadingHTTPServer):
    """The intake's HTTPS server: a thread per request, TLS from the chart's
    certificate. `ssl_context` None serves plain HTTP, for tests only."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], intake: Intake, ssl_context: ssl.SSLContext | None):
        super().__init__(address, IntakeHandler)
        self.intake = intake
        if ssl_context is not None:
            # The handshake runs on the first read, in the request's own
            # thread under its read timeout, so a client that stalls in it
            # can't hold up the accept loop.
            self.socket = ssl_context.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)

    def drain(self, grace: float = SHUTDOWN_GRACE_SECONDS, clock: Callable[[], float] = time.monotonic,
              sleep: Callable[[float], None] = time.sleep) -> int:
        """Wait up to `grace` seconds for relays in flight; how many are left."""
        deadline = clock() + grace
        while self.intake.in_flight() and clock() < deadline:
            sleep(0.05)
        return self.intake.in_flight()


def server_tls_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file, key_file)
    return context
