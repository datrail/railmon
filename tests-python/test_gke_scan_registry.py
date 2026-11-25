"""RC-553: gke-scan's registry reader and the image fields
(tools/scan/gke/central_service/registry.py and image_fields.py).

The ticket's exit criteria, against a local registry (an OCI distribution
API on loopback, with an anonymous-token endpoint, a private repository, a
Google-identity repository and blob redirects to another host):

* A multi-arch index resolves to the right manifest; a second read of a
  digest is a cache hit.
* 401 from a private registry gives PRIVATE_STORE.
* A layer past the budget stops streaming and gives SIZE_CAP_EXCEEDED, with
  memory flat while it streams.
* A test image with a secret file added in one layer and deleted in the next
  is reported with both layer indexes and no content.
* `user` order is followed in all three positions; `framework_identity` is
  read from a test image.
* A secretKeyRef shows the Secret and key, never the value; envFrom gives
  PARTIAL; no env value appears in the bundle.
"""

from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
import socket
import sys
import tarfile
import threading
import time
import tracemalloc
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "tools" / "scan"
CENTRAL = SCAN / "gke" / "central_service"
sys.path.insert(0, str(SCAN))


def _load(name: str, path: Path):
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


registry = _load("gke_scan_registry", CENTRAL / "registry.py")
image_fields = _load("gke_scan_image_fields", CENTRAL / "image_fields.py")
evidence = _load("evidence_bundle", SCAN / "evidence_bundle.py")
scanner = _load("scan_agent_environment", SCAN / "scan_agent_environment.py")

B = {"answered": evidence._answered, "partial": evidence._partial, "blind": evidence._blind,
     "absent": evidence._absent, "failed": evidence._failed}
SHAPERS = {name: getattr(scanner, name) for name in
           ("looks_secret", "is_benign_secret_name", "classify_secret_type", "url_carries_credential", "redact_url")}

# The test bed image's marked test values (research k8s/image/Dockerfile).
BAKED_VALUE = "railtest-not-a-real-key-0001"
DELETED_CONTENT = b"RAILTEST_DELETED_TOKEN=railtest-not-a-real-token-0002\n"
SECRET_VALUE = "railtest-injected-value-0003"
URL_PASSWORD = "railtest-url-password-0004"
GOOGLE_TOKEN = "google-access-token-for-gke-scan"
ANON_TOKEN = "anonymous-pull-token"

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
LAYER_TAR = "application/vnd.oci.image.layer.v1.tar"
LAYER_ZSTD = "application/vnd.oci.image.layer.v1.tar+zstd"


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def tar(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class Image:
    """An image's blobs and manifests, as a registry serves them."""

    def __init__(self, layers: list[dict[str, bytes] | bytes], env: list[str] | None = None, user: str = "",
                 media_type: str = LAYER_GZIP, arches: tuple[str, ...] = ("amd64", "arm64")):
        self.blobs: dict[str, bytes] = {}
        self.manifests: dict[str, tuple[bytes, str]] = {}
        self.layer_digests: list[str] = []
        entries = []
        for arch in arches:
            descriptors, diff_ids = [], []
            for layer in layers:
                if isinstance(layer, bytes):  # a blob built by the test, already in media_type
                    raw = blob = layer
                else:
                    raw = tar({**layer, f"etc/arch-{arch}": arch.encode()})
                    blob = gzip.compress(raw, mtime=0) if media_type == LAYER_GZIP else raw
                self.blobs[sha(blob)] = blob
                self.layer_digests.append(sha(blob))
                descriptors.append({"mediaType": media_type, "digest": sha(blob), "size": len(blob)})
                diff_ids.append(sha(raw))
            config = json.dumps({"architecture": arch, "os": "linux",
                                 "config": {"Env": env or [], "User": user},
                                 "rootfs": {"type": "layers", "diff_ids": diff_ids}}).encode()
            self.blobs[sha(config)] = config
            manifest = json.dumps({"schemaVersion": 2, "mediaType": OCI_MANIFEST,
                                   "config": {"mediaType": OCI_CONFIG, "digest": sha(config), "size": len(config)},
                                   "layers": descriptors}).encode()
            self.manifests[sha(manifest)] = (manifest, OCI_MANIFEST)
            entries.append({"mediaType": OCI_MANIFEST, "digest": sha(manifest), "size": len(manifest),
                            "platform": {"os": "linux", "architecture": arch}})
        if len(arches) > 1:
            index = json.dumps({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": entries}).encode()
            self.manifests[sha(index)] = (index, OCI_INDEX)
            self.digest = sha(index)
        else:
            self.digest = entries[0]["digest"]
        self.arch_manifests = {e["platform"]["architecture"]: e["digest"] for e in entries}


class FakeRegistry:
    """The distribution API on loopback. A repository's auth is `open`,
    `token` (an anonymous token from /token), `private` (no token is given) or
    `google` (gke-scan's Google token). Blobs can redirect to `storage`, a
    second server that records whether a credential reached it."""

    def __init__(self) -> None:
        self.repos: dict[str, tuple[str, Image]] = {}
        self.requests: list[tuple[str, str | None]] = []
        self.sent: dict[str, int] = {}
        self.redirect_blobs = False
        self.redirect_body = 0
        self.drip: set[str] = set()  # refs whose body is sent a byte at a time
        self.drip_headers: set[str] = set()  # refs whose status line is
        self.storage_auth: list[str | None] = []
        self.corrupt: set[str] = set()
        self.realm: str | None = None  # the token endpoint a 401 names, when not this server's /token
        self.token_body: bytes | None = None  # the token endpoint's answer, when not a good token
        self.redirect_location: str | None = None  # a blob redirect's Location, when not storage
        self.cut_short: set[str] = set()  # refs whose body stops halfway, the connection closed
        self.redirect_only: set[str] | None = None  # with redirect_blobs, only these blobs are redirected
        api = self

        class Storage(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                api.storage_auth.append(self.headers.get("Authorization"))
                api._send_blob(self, self.path.rsplit("/", 1)[-1])

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                return

            def _deny(self, repo: str) -> None:
                self.send_response(401)
                realm = api.realm or f"http://127.0.0.1:{api.port}/token"
                # The scope names the repository as the test registered it,
                # never as the request spelled it: nothing from the request
                # reaches a response header.
                known = next((name for name in api.repos if name == repo), "unknown")
                self.send_header("WWW-Authenticate", f'Bearer realm="{realm}",service="fake",'
                                                     f'scope="repository:{known}:pull"')
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self) -> None:
                parts = urlsplit(self.path)
                auth = self.headers.get("Authorization")
                api.requests.append((parts.path, auth))
                if parts.path == "/token":
                    scope = parse_qs(parts.query).get("scope", [""])[0]
                    repo = scope.split(":")[1] if scope.count(":") >= 2 else ""
                    mode = api.repos.get(repo, ("open", None))[0]
                    if mode != "token":
                        self.send_response(401)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    body = api.token_body or json.dumps({"token": ANON_TOKEN, "expires_in": 300}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                path = parts.path[len("/v2/"):]
                repo, kind, ref = path.rsplit("/", 2)[0], path.rsplit("/", 2)[1], path.rsplit("/", 2)[2]
                mode, image = api.repos.get(repo, ("open", None))
                wanted = {"token": f"Bearer {ANON_TOKEN}", "google": f"Bearer {GOOGLE_TOKEN}"}.get(mode)
                if mode == "private" or (wanted and auth != wanted):
                    self._deny(repo)
                    return
                if image is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if ref in api.drip_headers:
                    api._drip(self, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                    return
                if kind == "manifests" and ref in image.manifests:
                    body, media_type = image.manifests[ref]
                    if ref in api.corrupt:
                        body = body + b" "
                    if ref in api.drip:
                        self.send_response(200)
                        self.send_header("Content-Type", media_type)
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        api._drip(self, body)
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", media_type)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    if ref in api.cut_short:
                        api._cut(self, body)
                        return
                    self.wfile.write(body)
                elif kind == "blobs" and ref in image.blobs:
                    if api.redirect_blobs and (api.redirect_only is None or ref in api.redirect_only):
                        # The digest as the image holds it, not as the request spelled it.
                        digest = next(d for d in image.blobs if d == ref)
                        self.send_response(307)
                        self.send_header("Location", api.redirect_location
                                         or f"http://127.0.0.1:{api.storage_port}/storage/{digest}")
                        self.send_header("Content-Length", str(api.redirect_body))
                        self.end_headers()
                        try:
                            for start in range(0, api.redirect_body, 1 << 20):
                                self.wfile.write(bytes(min(1 << 20, api.redirect_body - start)))
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                        return
                    api._send_blob(self, ref)
                else:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.storage = ThreadingHTTPServer(("127.0.0.1", 0), Storage)
        for server in (self.server, self.storage):
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        self.port = self.server.server_address[1]
        self.storage_port = self.storage.server_address[1]
        self.host = f"127.0.0.1:{self.port}"

    def _send_blob(self, handler: BaseHTTPRequestHandler, ref: str) -> None:
        blob = next((image.blobs[ref] for _, image in self.repos.values() if image and ref in image.blobs), None)
        if blob is None:
            handler.send_response(404)
            handler.send_header("Content-Length", "0")
            handler.end_headers()
            return
        handler.send_response(200)
        handler.send_header("Content-Length", str(len(blob)))
        handler.end_headers()
        if ref in self.cut_short:
            self._cut(handler, blob)
            return
        if ref in self.drip:
            self._drip(handler, blob)
            return
        view = memoryview(blob)
        try:
            for start in range(0, len(blob), 65536):
                handler.wfile.write(view[start:start + 65536])
                self.sent[ref] = self.sent.get(ref, 0) + min(65536, len(blob) - start)
        except (BrokenPipeError, ConnectionResetError):
            return

    @staticmethod
    def _cut(handler: BaseHTTPRequestHandler, data: bytes) -> None:
        """Half the body its Content-Length promised, then the connection closed."""
        handler.close_connection = True
        try:
            handler.wfile.write(data[:len(data) // 2])
            handler.wfile.flush()
            handler.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    @staticmethod
    def _drip(handler: BaseHTTPRequestHandler, data: bytes) -> None:
        """A byte every 50 ms: never long enough apart for a socket timeout."""
        try:
            for i in range(len(data)):
                handler.wfile.write(data[i:i + 1])
                handler.wfile.flush()
                time.sleep(0.05)
        except OSError:
            return

    def add(self, repo: str, image: Image, mode: str = "open") -> str:
        self.repos[repo] = (mode, image)
        return f"{self.host}/{repo}@{image.digest}"

    def close(self) -> None:
        for server in (self.server, self.storage):
            server.shutdown()
            server.server_close()


def rewrap(image: Image, config: bytes | None = None, layer_media_type: str | None = None) -> Image:
    """A single-platform image with its config blob or layers' media type replaced, its manifest rebuilt."""
    manifest = json.loads(image.manifests[image.digest][0])
    if config is not None:
        image.blobs[sha(config)] = config
        manifest["config"] = {"mediaType": OCI_CONFIG, "digest": sha(config), "size": len(config)}
    if layer_media_type is not None:
        for layer in manifest["layers"]:
            layer["mediaType"] = layer_media_type
    body = json.dumps(manifest).encode()
    image.manifests = {sha(body): (body, OCI_MANIFEST)}
    image.digest = sha(body)
    return image


def base_layers() -> list[dict[str, bytes]]:
    """The test bed's shape: a base, a layer adding a secret file, and one deleting it."""
    return [{"usr/lib/x": b"x" * 4096},
            {"opt/railtest/deleted-secret.env": DELETED_CONTENT, "opt/railtest/readme": b"hi"},
            {"opt/railtest/.wh.deleted-secret.env": b""}]


TEST_ENV = ["PATH=/usr/local/bin:/usr/bin", "NODE_VERSION=24.18.1", "YARN_VERSION=1.22.22",
            f"RAIL_TEST_BAKED_API_KEY={BAKED_VALUE}"]


def agent_pod(image_id: str, container_context: dict[str, Any] | None = None,
              pod_context: dict[str, Any] | None = None, env: list[dict[str, Any]] | None = None,
              env_from: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    container: dict[str, Any] = {"name": "agent", "image": "registry.example.com/agent:1"}
    if container_context is not None:
        container["securityContext"] = container_context
    if env is not None:
        container["env"] = env
    if env_from is not None:
        container["envFrom"] = env_from
    return {"metadata": {"name": "agent-6d9f8c7b5-x2x4z", "namespace": "agents", "uid": "uid-1"},
            "spec": {"containers": [container, {"name": "rail-scan", "args": ["scan", "--mode", "pod"]}],
                     **({"securityContext": pod_context} if pod_context is not None else {})},
            "status": {"conditions": [{"type": "Ready", "status": "True"}],
                       "containerStatuses": [{"name": "agent", "imageID": image_id}]}}


def bundle(attributes: dict[str, Any]) -> dict[str, Any]:
    """A v1 bundle as gke-scan will send it (RC-555 attaches authored_by)."""
    attributes = copy.deepcopy(attributes)
    for attribute in attributes.values():
        if attribute["status"] in ("ANSWERED", "PARTIAL", "TEMPLATED"):
            attribute.setdefault("authored_by", "platform")
    return {"bundle_version": 1, "bundle_id": "bnd-0123456789ab", "host_id": "gke-test",
            "sandbox_name": "agents/agent", "collected_at": "2026-11-25T12:00:00+00:00",
            "rule_pack_version": evidence.RULE_PACK_VERSION,
            "inputs_attempted": {"runtime": {"attempted": True, "reached": True},
                                 "image": {"attempted": True, "reached": True},
                                 "manifest": {"attempted": True, "reached": True},
                                 "repo": {"attempted": False, "reason": "NOT_COLLECTED_BY_PACK"}},
            "attestations": [], "attributes": attributes}


class RegistryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = FakeRegistry()
        self.addCleanup(self.registry.close)
        self.google_calls = 0

        def google_token() -> tuple[str, float]:
            self.google_calls += 1
            return GOOGLE_TOKEN, 3600

        self.reader = registry.RegistryReader(google_token=google_token, plain_http_hosts=frozenset({"127.0.0.1"}),
                                              google_hosts=frozenset({self.registry.host}))
        self.public = FakeRegistry()  # another host: anonymous reads, never Google's token
        self.addCleanup(self.public.close)
        self.reader.plain_http_hosts = frozenset({"127.0.0.1"})
        self.offset = 0.0
        self.reader.clock = lambda: time.monotonic() + self.offset

    def later(self) -> None:
        """Move the reader's clock past RETRY_SECONDS, when a failed read is tried again."""
        self.offset += registry.RETRY_SECONDS + 1

    def ref(self, image_id: str):
        ref = registry.parse_image_id(image_id)
        self.assertIsNotNone(ref)
        return ref

    def attributes(self, pod: dict[str, Any], registry_access: bool = True) -> dict[str, Any]:
        report = image_fields.read_agent_image(self.reader, pod, registry_access)
        attributes = image_fields.image_field_attributes(pod, report, registry_access, B, SHAPERS)
        self.assertEqual(evidence.contract_problems(bundle(attributes)), [])
        return attributes


class ImageRefTest(unittest.TestCase):
    def test_image_ids_as_kubelets_report_them(self):
        digest = "sha256:" + "a" * 64
        cases = {
            f"docker.io/library/python@{digest}": ("docker.io", "library/python", "registry-1.docker.io", False),
            f"docker-pullable://python@{digest}": ("docker.io", "library/python", "registry-1.docker.io", False),
            f"nousresearch/hermes-agent@{digest}": ("docker.io", "nousresearch/hermes-agent", "registry-1.docker.io", False),
            f"ghcr.io/openclaw/openclaw@{digest}": ("ghcr.io", "openclaw/openclaw", "ghcr.io", False),
            f"us-central1-docker.pkg.dev/proj/repo/agent@{digest}": ("us-central1-docker.pkg.dev", "proj/repo/agent",
                                                                     "us-central1-docker.pkg.dev", True),
            f"gcr.io/proj/agent@{digest}": ("gcr.io", "proj/agent", "gcr.io", True),
            f"localhost:5000/agent@{digest}": ("localhost:5000", "agent", "localhost:5000", False),
        }
        for image_id, (reg, repo, host, google) in cases.items():
            with self.subTest(image_id=image_id):
                ref = registry.parse_image_id(image_id)
                self.assertEqual((ref.registry, ref.repository, ref.digest, ref.api_host, ref.google),
                                 (reg, repo, digest, host, google))

    def test_no_digest_is_no_ref(self):
        for image_id in ("python:3.12", "ghcr.io/x/y:latest", "", None, "ghcr.io/x/y@sha256:short"):
            self.assertIsNone(registry.parse_image_id(image_id))

    def test_a_registry_that_isnt_a_host_name_is_no_ref(self):
        # urllib would read what follows "#" or "?" as a fragment or query, so the
        # request would go to evil.example while the name ends in .gcr.io.
        digest = "sha256:" + "a" * 64
        for registry_part in ("evil.example#x.gcr.io", "evil.example?x.gcr.io", "evil.example\\x.gcr.io",
                              "evil.example%23x.gcr.io", "-bad.example", "bad..example", "evil.example:80#.gcr.io"):
            with self.subTest(registry=registry_part):
                self.assertIsNone(registry.parse_image_id(f"{registry_part}/proj/agent@{digest}"))
        ref = registry.parse_image_id(f"GHCR.io/openclaw/openclaw@{digest}")
        self.assertEqual(ref.registry, "ghcr.io")

    def test_googles_token_goes_only_where_the_url_itself_is_googles(self):
        # A ref built past parse_image_id's check still never sends the token
        # to a host the URL doesn't name as Google's.
        calls = []
        reader = registry.RegistryReader(google_token=lambda: calls.append(1) or (GOOGLE_TOKEN, 3600))
        sent = []

        def refuse(request, timeout=None):
            sent.append((request.host, request.get_header("Authorization")))
            raise registry.URLError("no network in this test")

        reader._opener = mock.Mock(open=refuse)
        ref = registry.ImageRef("evil.example#x.gcr.io", "proj/agent", "sha256:" + "a" * 64)
        self.assertTrue(ref.google, "the name alone looks like Google's")
        report = reader.read_image(ref, layers=False)
        self.assertEqual(report.config_error.reason, "NO_SOURCE_ACCESS")
        self.assertEqual(sent, [("evil.example", None)])
        self.assertEqual(calls, [], "the Google token wasn't even fetched")


class ReaderTest(RegistryTestCase):
    def test_a_multi_arch_index_resolves_to_the_nodes_manifest(self):
        image = Image(base_layers(), TEST_ENV)
        ref = self.ref(self.registry.add("proj/agent", image, "google"))
        manifest, digest = self.reader.read_manifest(ref, arch="amd64")
        self.assertEqual(digest, image.arch_manifests["amd64"])
        self.assertEqual(self.reader.read_config(ref, manifest)["architecture"], "amd64")
        _, arm = self.reader.read_manifest(ref, arch="arm64")
        self.assertEqual(arm, image.arch_manifests["arm64"])
        with self.assertRaises(registry.RegistryError) as raised:
            self.reader.read_manifest(ref, arch="s390x")
        self.assertIn("no linux/s390x image", raised.exception.detail)

    def test_a_second_read_of_a_digest_is_a_cache_hit(self):
        ref = self.ref(self.registry.add("proj/agent", Image(base_layers(), TEST_ENV), "google"))
        first = self.reader.read_image(ref)
        requests = len(self.registry.requests)
        second = self.reader.read_image(ref)
        self.assertIs(second, first)
        self.assertEqual(len(self.registry.requests), requests)
        self.assertEqual((self.reader.hits, self.reader.misses), (1, 1))
        self.assertEqual(self.google_calls, 1, "the Google token is kept until it expires")

    def test_the_cache_keeps_the_newest_256(self):
        reader = registry.RegistryReader(google_token=lambda: (GOOGLE_TOKEN, 3600), cache_size=2,
                                         plain_http_hosts=frozenset({"127.0.0.1"}), google_hosts=frozenset({self.registry.host}))
        refs = [self.ref(self.registry.add(f"proj/agent{i}", Image([{"f": bytes([i])}], arches=("amd64",)), "google"))
                for i in range(3)]
        for ref in refs:
            reader.read_image(ref)
        reader.read_image(refs[2])
        reader.read_image(refs[0])
        self.assertEqual((reader.hits, reader.misses), (1, 4))
        self.assertEqual(registry.CACHE_IMAGES, 256)

    def test_the_google_identity_reads_artifact_registry_and_never_reaches_storage(self):
        self.registry.redirect_blobs = True
        ref = self.ref(self.registry.add("proj/agent", Image(base_layers(), TEST_ENV), "google"))
        report = self.reader.read_image(ref)
        self.assertIsNone(report.config_error)
        self.assertIsNone(report.layers_error)
        self.assertTrue(all(auth == f"Bearer {GOOGLE_TOKEN}" for path, auth in self.registry.requests if "/v2/" in path))
        self.assertTrue(self.registry.storage_auth, "the layers were redirected to storage")
        self.assertEqual(set(self.registry.storage_auth), {None}, "no credential reaches another host")

    def test_a_public_image_elsewhere_is_read_with_an_anonymous_token(self):
        ref = self.ref(self.public.add("openclaw/openclaw", Image(base_layers(), TEST_ENV), "token"))
        report = self.reader.read_image(ref)
        self.assertIsNone(report.config_error)
        self.assertEqual(self.google_calls, 0, "Google's token only goes to Google's registries")
        self.assertIn(("/token", None), self.public.requests)

    def test_a_private_registry_is_private_store(self):
        ref = self.ref(self.public.add("someone/private-agent", Image(base_layers(), TEST_ENV), "private"))
        report = self.reader.read_image(ref)
        self.assertEqual(report.config_error.reason, "PRIVATE_STORE")
        self.assertIn("gives no anonymous pull token (HTTP 401)", report.config_error.detail)
        google_refused = self.ref(self.registry.add("proj/other", Image(base_layers()), "private"))
        self.assertEqual(self.reader.read_image(google_refused).config_error.reason, "PRIVATE_STORE")

    def test_a_manifest_that_doesnt_match_its_digest_is_refused(self):
        image = Image(base_layers(), arches=("amd64",))
        ref = self.ref(self.registry.add("proj/agent", image, "google"))
        self.registry.corrupt.add(image.digest)
        self.assertEqual(self.reader.read_image(ref).config_error.reason, "PARSE_FAILED")

    def test_a_redirects_body_isnt_read(self):
        self.registry.redirect_blobs = True
        self.registry.redirect_body = 64 * 1024 * 1024
        ref = self.ref(self.registry.add("proj/agent", Image(base_layers(), arches=("amd64",)), "google"))
        tracemalloc.start()
        try:
            report = self.reader.read_image(ref)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertIsNone(report.config_error)
        self.assertIsNone(report.layers_error)
        self.assertLess(peak, 4 * 1024 * 1024, f"peak {peak} bytes behind 64 MiB redirect bodies")

    def test_a_redirect_to_plain_http_elsewhere_is_refused(self):
        self.registry.redirect_blobs = True
        reader = registry.RegistryReader(google_token=lambda: (GOOGLE_TOKEN, 3600),
                                         plain_http_hosts=frozenset({"127.0.0.1"}), google_hosts=frozenset({self.registry.host}))
        reader._opener = registry.build_opener(registry._Redirects(frozenset()))  # storage isn't trusted for http
        ref = self.ref(self.registry.add("proj/agent", Image(base_layers(), arches=("amd64",)), "google"))
        reader.plain_http_hosts = frozenset({"127.0.0.1"})
        report = reader.read_image(ref)
        # The config blob is redirected first, so that read is refused.
        self.assertEqual(report.config_error.reason, "NO_SOURCE_ACCESS")
        self.assertIn("HTTP 307", report.config_error.detail)
        self.assertEqual(self.registry.storage_auth, [], "storage was never contacted")


class HostileRegistryTest(RegistryTestCase):
    """A registry other than Google's names its own token endpoint and redirects,
    and answers them as it likes."""

    def test_a_token_endpoints_answer_never_raises_out_of_the_reader(self):
        bad = {
            b"[]": "NO_SOURCE_ACCESS", b'"a token"': "NO_SOURCE_ACCESS", b"null": "NO_SOURCE_ACCESS",
            b'{"token": ["x"]}': "NO_SOURCE_ACCESS", b'{"token": ""}': "NO_SOURCE_ACCESS",
            json.dumps({"token": ANON_TOKEN + "\r\nX-Injected: 1"}).encode(): "NO_SOURCE_ACCESS",
            b"not json": "NO_SOURCE_ACCESS",
        }
        # A usable token with a lifetime that isn't a number is read with the default lifetime.
        usable = [json.dumps({"token": ANON_TOKEN, "expires_in": value}).encode()
                  for value in ("abc", [300], {"s": 1}, True, -5, 0)] + \
                 [b'{"token": "%s", "expires_in": 1e999}' % ANON_TOKEN.encode(),
                  b'{"token": "%s", "expires_in": NaN}' % ANON_TOKEN.encode()]
        for index, body in enumerate(list(bad) + usable):
            with self.subTest(body=body):
                self.public.token_body = body
                self.reader._tokens.clear()
                # Each its own image: a digest read once is served from the cache.
                image = Image([{"f": bytes([index])}], arches=("amd64",))
                ref = self.ref(self.public.add(f"someone/agent{index}", image, "token"))
                report = self.reader.read_image(ref)
                if body in bad:
                    self.assertEqual(report.config_error.reason, bad[body])
                    self.assertNotIn("X-Injected", report.config_error.detail)
                else:
                    self.assertIsNone(report.config_error)
                    self.assertIsNone(report.layers_error)
                    expires = self.reader._tokens[(ref.api_host, ref.repository)][1]
                    self.assertLess(expires - time.monotonic(), 60, "the default lifetime, not forever")

    def test_a_redirect_urllib_cant_follow_is_no_source_access(self):
        self.public.redirect_blobs = True
        self.public.redirect_location = "https://[not-a-host/storage"
        ref = self.ref(self.public.add("someone/agent", Image(base_layers(), arches=("amd64",)), "open"))
        report = self.reader.read_image(ref)
        self.assertEqual(report.config_error.reason, "NO_SOURCE_ACCESS")
        self.assertIn("couldn't be followed", report.config_error.detail)
        self.assertNotIn("not-a-host", report.config_error.detail)

    def refused_hosts(self):
        """The hosts a connection was refused for, as _create_connection refuses them."""
        refused: list[str] = []
        create = registry._create_connection

        def spy(address, *args):
            try:
                return create(address, *args)
            except registry.NonPublicAddress:
                refused.append(address[0])
                raise

        self.enterContext(mock.patch.object(registry, "_create_connection", spy))
        return refused

    def test_a_token_endpoint_at_a_private_address_isnt_reached(self):
        refused = self.refused_hosts()
        self.public.realm = f"https://localhost:{self.public.port}/token"  # another name, a loopback address
        ref = self.ref(self.public.add("someone/agent", Image(base_layers(), arches=("amd64",)), "token"))
        report = self.reader.read_image(ref)
        self.assertEqual(report.config_error.reason, "NO_SOURCE_ACCESS")
        self.assertEqual(refused, ["localhost"])
        self.assertNotIn(("/token", None), self.public.requests)

    def test_a_redirect_to_a_private_address_isnt_followed(self):
        refused = self.refused_hosts()
        self.public.redirect_blobs = True
        self.public.redirect_location = f"https://localhost:{self.public.storage_port}/storage/x"
        ref = self.ref(self.public.add("someone/agent", Image(base_layers(), arches=("amd64",)), "open"))
        report = self.reader.read_image(ref)
        self.assertEqual(report.config_error.reason, "NO_SOURCE_ACCESS")
        self.assertEqual(refused, ["localhost"])
        self.assertEqual(self.public.storage_auth, [], "storage was never contacted")

    def test_a_refused_address_is_never_connected_to(self):
        # Refused before any TCP handshake, so the refusal can't tell an open
        # port from a closed one.
        listener = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(listener.close)
        listener.settimeout(0.3)
        port = listener.getsockname()[1]
        for host in ("localhost", "127.0.0.1"):
            with self.subTest(host=host):
                connection = registry._WatchedHTTPConnection(host, port, timeout=5, private_ok=frozenset())
                with self.assertRaises(registry.NonPublicAddress) as raised:
                    connection.connect()
                self.assertEqual(str(raised.exception), f"{host} is at a non-public address")
                with self.assertRaises(TimeoutError, msg="no connection reached the listener"):
                    listener.accept()[0].close()
        closed = socket.create_server(("127.0.0.1", 0))
        closed_port = closed.getsockname()[1]
        closed.close()  # nothing listens there now: the same refusal, not "connection refused"
        connection = registry._WatchedHTTPConnection("localhost", closed_port, timeout=5, private_ok=frozenset())
        with self.assertRaises(registry.NonPublicAddress):
            connection.connect()

    def test_the_address_check(self):
        port = self.public.server.server_address[1]
        for private_ok in (frozenset({"localhost"}), None):
            with self.subTest(private_ok=private_ok):
                connection = registry._WatchedHTTPConnection("localhost", port, timeout=5, private_ok=private_ok)
                try:
                    connection.connect()
                finally:
                    connection.close()
        for address, public in (("8.8.8.8", True), ("10.0.0.1", False), ("169.254.169.254", False),
                                ("100.64.0.1", False), ("::1", False), ("::ffff:10.0.0.1", False),
                                ("2001:4860:4860::8888", True), ("fe80::1%eth0", False)):
            with self.subTest(address=address):
                self.assertEqual(registry._public_address(address), public)
        # A name with public and private addresses is connected to only at the public ones.
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443)),
                 (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        with mock.patch.object(registry.socket, "getaddrinfo", return_value=infos), \
                mock.patch.object(registry.socket, "socket") as make:
            registry._create_connection(("mixed.example", 443), 5, None, frozenset())
        make.return_value.connect.assert_called_once_with(("8.8.8.8", 443))

    def test_a_token_lifetime_past_a_floats_range_is_the_default(self):
        self.assertEqual(registry._token_lifetime(int("1" + "0" * 400), 60), 60)
        self.public.token_body = b'{"token": "%s", "expires_in": 1%s}' % (ANON_TOKEN.encode(), b"0" * 400)
        ref = self.ref(self.public.add("someone/agent", Image([{"f": b"big"}], arches=("amd64",)), "token"))
        report = self.reader.read_image(ref)
        self.assertIsNone(report.config_error)
        self.assertIsNone(report.layers_error)

    def test_a_deeply_nested_token_answer_is_no_source_access(self):
        self.public.token_body = b"[" * 60000
        ref = self.ref(self.public.add("someone/agent", Image([{"f": b"deep"}], arches=("amd64",)), "token"))
        self.assertEqual(self.reader.read_image(ref).config_error.reason, "NO_SOURCE_ACCESS")

    def test_what_one_registry_answers_for_a_digest_isnt_another_registrys(self):
        # A hostile registry serves a popular image's real bytes to the kubelet
        # and refuses the scanner: the same digest from a registry that answers
        # is still read.
        image = Image(base_layers(), TEST_ENV, arches=("amd64",))
        hostile = self.ref(self.public.add("someone/python", image, "private"))
        self.assertEqual(self.reader.read_image(hostile).config_error.reason, "PRIVATE_STORE")
        honest = self.ref(self.registry.add("proj/python", image, "google"))
        self.assertEqual(honest.digest, hostile.digest)
        report = self.reader.read_image(honest)
        self.assertIsNone(report.config_error)
        self.assertIsNone(report.layers_error)
        self.assertEqual(self.reader.read_image(hostile).config_error.reason, "PRIVATE_STORE")


class BoundedReadTest(RegistryTestCase):
    """What a hostile registry can make one read, or the threads waiting on
    it, cost: no more than the read's deadline, however its name resolves."""

    def blackholes(self, count: int) -> list[tuple[Any, float]]:
        """`count` public addresses for any name, each connect hanging for its whole timeout."""
        attempts: list[tuple[Any, float]] = []

        class Blackhole:
            def __init__(self, *args: Any) -> None:
                self.timeout = None

            def settimeout(self, timeout: float) -> None:
                self.timeout = timeout

            def bind(self, address: Any) -> None:
                return

            def connect(self, sockaddr: Any) -> None:
                attempts.append((sockaddr, self.timeout))
                time.sleep(self.timeout or 0)
                raise TimeoutError("timed out")

            def close(self) -> None:
                return

        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"8.8.4.{i}", 443)) for i in range(count)]
        self.enterContext(mock.patch.object(registry.socket, "getaddrinfo", return_value=infos))
        self.enterContext(mock.patch.object(registry.socket, "socket", Blackhole))
        return attempts

    def test_many_unreachable_addresses_end_at_the_deadline(self):
        attempts = self.blackholes(6)
        started = time.monotonic()
        with registry._Deadline(1.0) as deadline, self.assertRaises(TimeoutError):
            registry._create_connection(("many.example", 443), 1.0, None, frozenset(), deadline)
        self.assertLess(time.monotonic() - started, 1.5, "one deadline, not one per address")
        self.assertLessEqual(len(attempts), registry.MAX_ADDRESSES)
        self.assertTrue(all(timeout <= 1.0 for _, timeout in attempts))

    def test_at_most_max_addresses_are_tried(self):
        attempts = self.blackholes(10)
        with self.assertRaises(TimeoutError):
            registry._create_connection(("many.example", 443), 0.01, None, frozenset())
        self.assertEqual(len(attempts), registry.MAX_ADDRESSES)

    def test_a_name_that_resolves_slowly_ends_at_the_deadline(self):
        def slow(*args: Any, **kwargs: Any) -> list[Any]:
            time.sleep(3)
            return []

        started = time.monotonic()
        with mock.patch.object(registry.socket, "getaddrinfo", side_effect=slow), \
                registry._Deadline(0.5) as deadline, self.assertRaises(TimeoutError):
            registry._create_connection(("slow.example", 443), 5, None, frozenset(), deadline)
        self.assertLess(time.monotonic() - started, 1.5)

    def test_a_thread_waits_for_anothers_read_only_so_long(self):
        image = Image(base_layers(), TEST_ENV, arches=("amd64",))
        ref = self.ref(self.public.add("someone/agent", image, "open"))
        self.public.drip.add(image.layer_digests[0])
        first: list[Any] = []
        with mock.patch.object(registry, "WAIT_SECONDS", 0.3), mock.patch.object(registry, "LAYER_TIMEOUT_SECONDS", 3.0):
            reader = threading.Thread(target=lambda: first.append(self.reader.read_image(ref)))
            reader.start()
            while not self.reader._reading:
                time.sleep(0.01)
            started = time.monotonic()
            waited = self.reader.read_image(ref)
            self.assertLess(time.monotonic() - started, 1.5)
            reader.join(30)
        self.assertEqual(waited.config_error.reason, "NO_SOURCE_ACCESS")
        self.assertIn("still running", waited.config_error.detail)
        self.assertIs(self.reader.read_image(ref), first[0], "the first read's answer is what is cached")


class HostileImageTest(RegistryTestCase):
    def image_with_manifest(self, manifest: dict[str, Any], media_type: str, image: Any = None) -> Any:
        image = image or Image(base_layers(), arches=("amd64",))
        body = json.dumps(manifest).encode()
        image.manifests[sha(body)] = (body, media_type)
        image.digest = sha(body)
        return self.ref(self.public.add("someone/agent", image, "open"))

    def test_an_index_whose_manifests_isnt_a_list_is_parse_failed(self):
        for value in (5, True, "x", {"a": 1}):
            with self.subTest(value=value):
                self.reader._cache.clear()
                ref = self.image_with_manifest({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": value}, OCI_INDEX)
                self.assertEqual(self.reader.read_image(ref).config_error.reason, "PARSE_FAILED")

    def test_a_manifest_with_a_stray_manifests_key_is_read_as_a_manifest(self):
        image = Image(base_layers(), TEST_ENV, arches=("amd64",))
        manifest = json.loads(image.manifests[image.digest][0])
        ref = self.image_with_manifest({**manifest, "manifests": 5}, OCI_MANIFEST, image)
        report = self.reader.read_image(ref)
        self.assertIsNone(report.config_error)
        self.assertIsNone(report.layers_error)

    def test_nothing_unanticipated_raises_out_of_the_reader(self):
        ref = self.ref(self.public.add("someone/agent", Image(base_layers(), arches=("amd64",)), "open"))
        with mock.patch.object(self.reader, "stream_layers", side_effect=KeyError("surprise")):
            report = self.reader.read_image(ref)
        self.assertIsNotNone(report.config, "the config read before it is kept")
        self.assertEqual(report.layers_error.reason, "PARSE_FAILED")
        self.assertIn("KeyError", report.layers_error.detail)
        self.assertIs(self.reader.read_image(ref), report, "kept for RETRY_SECONDS, not read again at once")
        self.later()
        self.assertIsNone(self.reader.read_image(ref).layers_error)
        other = self.ref(self.public.add("someone/other", Image([{"f": b"o"}], arches=("amd64",)), "open"))
        with mock.patch.object(self.reader, "read_manifest", side_effect=KeyError("earlier")):
            self.assertEqual(self.reader.read_image(other).config_error.reason, "PARSE_FAILED")

    def test_an_env_past_what_is_kept_is_partial_and_small(self):
        env = [f"V{i}=x" for i in range(5000)] + ["LATE_API_KEY=railtest-late-0005"]
        image_id = self.public.add("someone/agent", Image(base_layers(), env, arches=("amd64",)), "open")
        report = self.reader.read_image(self.ref(image_id))
        kept = report.config["config"]
        self.assertEqual(len(kept["Env"]), registry.MAX_ENV)
        self.assertTrue(kept["EnvTruncated"])
        self.assertLess(registry._report_bytes(report), 256 * 1024)
        pod = agent_pod(image_id)
        provenance = self.attributes(pod)["credential_provenance"]
        self.assertEqual((provenance["status"], provenance["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))
        self.assertIn("1,024 entries", provenance["note"])

    def test_one_registrys_images_never_push_out_anothers(self):
        big_env = ["V=" + "x" * 4000] * 10  # about 41 KB a report
        mine = self.ref(self.registry.add("proj/agent", Image(base_layers(), big_env, arches=("amd64",)), "google"))
        self.reader.cache_bytes = 200_000  # a host's share: 50,000
        self.reader.read_image(mine)
        for i in range(8):
            image = Image([{"f": bytes([i])}], [f"V{i}=" + "x" * 4000] * 10, arches=("amd64",))
            self.reader.read_image(self.ref(self.public.add(f"someone/agent{i}", image, "open")))
        hits = self.reader.hits
        self.reader.read_image(mine)
        self.assertEqual(self.reader.hits, hits + 1, "the other registry's image is still cached")
        self.assertLessEqual(self.reader._cache_bytes, self.reader.cache_bytes)

    def test_a_refusal_is_tried_again_after_private_retry_seconds(self):
        image = Image(base_layers(), TEST_ENV, arches=("amd64",))
        ref = self.ref(self.public.add("someone/agent", image, "private"))
        refused = self.reader.read_image(ref)
        self.assertEqual(refused.config_error.reason, "PRIVATE_STORE")
        self.public.repos["someone/agent"] = ("token", image)  # access granted
        self.later()
        self.assertIs(self.reader.read_image(ref), refused, "a refusal is kept longer than RETRY_SECONDS")
        self.offset += registry.PRIVATE_RETRY_SECONDS
        self.assertIsNone(self.reader.read_image(ref).config_error, "and read again after PRIVATE_RETRY_SECONDS")


class HostileNamesAndListsTest(RegistryTestCase):
    """What a registry or an image names, however malformed or many, is a
    field that says so, never an exception or a list that reads as whole."""

    def test_a_name_the_resolver_wont_encode_is_an_oserror(self):
        for host in ("a..b", "x" * 70 + ".example"):
            with self.subTest(host=host):
                with self.assertRaises(OSError):
                    registry._resolve(host, 443, None)
                with registry._Deadline(2) as deadline, self.assertRaises(OSError):
                    registry._resolve(host, 443, deadline)

    def test_a_token_realm_the_resolver_wont_encode_is_no_source_access(self):
        self.public.realm = "https://a..b/token"
        ref = self.ref(self.public.add("someone/agent", Image(base_layers(), arches=("amd64",)), "token"))
        self.assertEqual(self.reader.read_image(ref).config_error.reason, "NO_SOURCE_ACCESS")

    def test_a_layer_redirect_the_resolver_wont_encode_keeps_the_config(self):
        image = Image(base_layers(), TEST_ENV, arches=("amd64",))
        ref = self.ref(self.public.add("someone/agent", image, "open"))
        self.public.redirect_blobs = True
        self.public.redirect_only = set(image.layer_digests)  # the config is served directly
        self.public.redirect_location = "https://a..b/storage/x"
        report = self.reader.read_image(ref)
        self.assertIsNotNone(report.config, "the config was read before the layer's redirect")
        self.assertEqual(report.layers_error.reason, "NO_SOURCE_ACCESS")

    def test_more_credentials_than_are_listed_is_partial(self):
        decoys = [f"A_TOKEN_{i:04d}=railtest-decoy" for i in range(300)]
        image_id = self.public.add("someone/agent", Image(base_layers(), decoys + ["ZZ_API_KEY=railtest-real-0006"],
                                                         arches=("amd64",)), "open")
        provenance = self.attributes(agent_pod(image_id))["credential_provenance"]
        self.assertEqual((provenance["status"], provenance["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))
        self.assertIn("301 credentials, of which the first 256 by name are listed", provenance["note"])

    def test_a_name_too_long_to_list_is_partial(self):
        image_id = self.public.add("someone/agent", Image(base_layers(), ["X" * 300 + "_TOKEN=railtest-long"],
                                                         arches=("amd64",)), "open")
        provenance = self.attributes(agent_pod(image_id))["credential_provenance"]
        self.assertEqual(provenance["status"], "PARTIAL")
        self.assertIn("1 names longer than 256 characters", provenance["note"])
        self.assertNotIn("X" * 300, json.dumps(provenance))

    def test_more_deleted_files_than_are_listed_is_partial(self):
        added = {f"opt/s/{i:04d}.env": b"x" for i in range(300)}
        whiteouts = {f"opt/s/.wh.{i:04d}.env": b"" for i in range(300)}
        image_id = self.public.add("someone/agent", Image([added, whiteouts], arches=("amd64",)), "open")
        deleted = self.attributes(agent_pod(image_id))["in_layer_deleted_secrets"]
        self.assertEqual((deleted["status"], deleted["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))
        self.assertEqual(len(deleted["value"]["deleted"]), 256)
        self.assertIn("300 secret-looking files", deleted["note"])

    def test_a_version_that_isnt_one_isnt_given(self):
        env = ["NODE_VERSION=24.18.1", "PYTHON_VERSION=" + "\x1b[31m" + "x" * 5000]
        image_id = self.public.add("someone/agent", Image(base_layers(), env, arches=("amd64",)), "open")
        identity = self.attributes(agent_pod(image_id))["framework_identity"]
        self.assertEqual((identity["status"], identity["reason"]), ("PARTIAL", "PARSE_FAILED"))
        self.assertEqual(identity["value"], {"node": "v24.18.1"})
        self.assertIn("PYTHON_VERSION isn't a version", identity["note"])
        self.assertNotIn("x" * 100, json.dumps(identity))

    def test_a_user_that_isnt_one_isnt_given(self):
        for user, given in (("node", True), ("1000:1000", True), ("x" * 5000, False), ("root\n; rm -rf", False)):
            with self.subTest(user=user[:20]):
                image_id = self.public.add(f"someone/u{len(user)}-{int(given)}",
                                           Image([{"f": user[:8].encode()}], user=user, arches=("amd64",)), "open")
                attribute = self.attributes(agent_pod(image_id))["user"]
                if given:
                    self.assertEqual((attribute["status"], attribute["value"]), ("ANSWERED", user))
                else:
                    self.assertEqual((attribute["status"], attribute["reason"]), ("FAILED", "PARSE_FAILED"))
                    self.assertNotIn(user[:64], json.dumps(attribute))
        report = registry.ImageReport(registry.ImageRef("h", "r", "sha256:" + "a" * 64), "linux/amd64")
        report.config = registry._kept_config({"config": {"User": "u" * 10000}})
        self.assertEqual(len(report.config["config"]["User"]), registry.MAX_USER + 1)

    def test_the_token_cache_is_bounded(self):
        self.assertIsNone(registry.BEARER_TOKEN.fullmatch("t" * 8193), "a token past 8 KiB isn't used")
        with mock.patch.object(registry, "MAX_TOKENS", 3):
            for i in range(6):
                image = Image([{"f": bytes([i])}], arches=("amd64",))
                self.reader.read_image(self.ref(self.public.add(f"someone/t{i}", image, "token")))
            self.assertEqual(len(self.reader._tokens), 3)
            self.assertEqual([k[1] for k in self.reader._tokens], ["someone/t3", "someone/t4", "someone/t5"])


class LaterLayerFailsTest(RegistryTestCase):
    """A secret one layer adds and the next deletes is still reported when a
    later layer can't be read: the image can't hide it behind that layer."""

    def secret_then(self, last: Any, media_type: str = LAYER_TAR) -> Any:
        """An image whose layer 0 adds a secret, layer 1 deletes it, and layer 2 is `last`."""
        layers = [tar({"opt/app/.env": b"A=1"}), tar({"opt/app/.wh..env": b""}), last]
        return Image(layers, media_type=media_type, arches=("amd64",))

    def test_an_empty_layer_is_an_empty_tar(self):
        image_id = self.public.add("someone/agent", self.secret_then(b""), "open")
        deleted = self.attributes(agent_pod(image_id))["in_layer_deleted_secrets"]
        self.assertEqual(deleted["status"], "ANSWERED")
        self.assertEqual([d["path"] for d in deleted["value"]["deleted"]], ["/opt/app/.env"])
        self.assertEqual(deleted["value"]["layers_read"], 3)

    def test_a_last_layer_that_isnt_a_tar_keeps_what_was_found(self):
        image_id = self.public.add("someone/agent", self.secret_then(b"not a tar at all" * 64), "open")
        deleted = self.attributes(agent_pod(image_id))["in_layer_deleted_secrets"]
        self.assertEqual((deleted["status"], deleted["reason"]), ("PARTIAL", "PARSE_FAILED"))
        self.assertEqual([d["path"] for d in deleted["value"]["deleted"]], ["/opt/app/.env"])
        self.assertIn("what layers 0 to 1 show is listed", deleted["note"])

    def test_a_last_layer_cut_short_by_the_network_keeps_what_was_found(self):
        image = self.secret_then(tar({"usr/lib/x": b"x" * 4096}))
        image_id = self.public.add("someone/agent", image, "open")
        self.public.cut_short = {image.layer_digests[2]}
        deleted = self.attributes(agent_pod(image_id))["in_layer_deleted_secrets"]
        self.assertEqual((deleted["status"], deleted["reason"]), ("PARTIAL", "NO_SOURCE_ACCESS"))
        self.assertEqual([d["path"] for d in deleted["value"]["deleted"]], ["/opt/app/.env"])

    def test_an_unanticipated_failure_keeps_what_was_found(self):
        image = self.secret_then(tar({"usr/lib/x": b"x"}))
        ref = self.ref(self.public.add("someone/agent", image, "open"))
        real = self.reader._read_layer
        calls = []

        def third_fails(*args: Any, **kwargs: Any) -> Any:
            calls.append(1)
            if len(calls) == 3:
                raise KeyError("surprise")
            return real(*args, **kwargs)

        with mock.patch.object(self.reader, "_read_layer", side_effect=third_fails):
            report = self.reader.read_image(ref)
        self.assertEqual(report.layers_error.reason, "PARSE_FAILED")
        self.assertEqual([d["path"] for d in report.deleted], ["/opt/app/.env"])

    def test_nothing_read_is_still_failed(self):
        image_id = self.public.add("someone/agent", Image([b"not a tar at all" * 64], media_type=LAYER_TAR,
                                                         arches=("amd64",)), "open")
        deleted = self.attributes(agent_pod(image_id))["in_layer_deleted_secrets"]
        self.assertEqual((deleted["status"], deleted["reason"]), ("FAILED", "PARSE_FAILED"))


class MetadataTokenTest(unittest.TestCase):
    def test_the_metadata_server_is_asked_directly_never_through_a_proxy(self):
        # Even with HTTP_PROXY set, the token request goes straight to the
        # metadata server: a proxy would see the token in clear.
        seen: list[str] = []

        class Metadata(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                seen.append(self.path)
                body = json.dumps({"access_token": GOOGLE_TOKEN, "expires_in": 3599}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        metadata, proxy = (ThreadingHTTPServer(("127.0.0.1", 0), Metadata) for _ in range(2))
        for server in (metadata, proxy):
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
        proxy_url = f"http://127.0.0.1:{proxy.server_address[1]}"
        with mock.patch.dict(os.environ, {"HTTP_PROXY": proxy_url, "http_proxy": proxy_url, "NO_PROXY": "", "no_proxy": ""}), \
                mock.patch.object(registry, "METADATA_TOKEN_URL", f"http://127.0.0.1:{metadata.server_address[1]}/token"):
            self.assertEqual(registry.google_token_from_metadata(), (GOOGLE_TOKEN, 3599))
        self.assertEqual(seen, ["/token"], "asked directly, not as a proxied absolute URL")

    def test_a_metadata_redirect_isnt_followed(self):
        class Redirecting(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/elsewhere")
                self.send_header("Content-Length", "0")
                self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), Redirecting)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with mock.patch.object(registry, "METADATA_TOKEN_URL", f"http://127.0.0.1:{server.server_address[1]}/token"):
            with self.assertRaises(registry.HTTPError) as raised:
                registry.google_token_from_metadata()
        self.assertEqual(raised.exception.code, 302)


class CutShortTest(RegistryTestCase):
    """A read the network ends is tried again, never cached as a bad image."""

    def test_a_layer_cut_short_is_no_source_access_and_tried_again(self):
        image = Image(base_layers(), TEST_ENV, arches=("amd64",))
        ref = self.ref(self.public.add("someone/agent", image, "open"))
        self.public.cut_short = set(image.layer_digests)
        report = self.reader.read_image(ref)
        self.assertIsNone(report.config_error)
        self.assertEqual(report.layers_error.reason, "NO_SOURCE_ACCESS")
        self.assertIn("ended after", report.layers_error.detail)
        self.public.cut_short = set()
        self.assertIs(self.reader.read_image(ref), report, "kept until RETRY_SECONDS have passed")
        self.later()
        again = self.reader.read_image(ref)
        self.assertIsNot(again, report, "tried again")
        self.assertIsNone(again.layers_error)

    def test_a_layer_whose_connection_resets_is_no_source_access(self):
        class Resetting:
            def read(self, size: int = -1) -> bytes:
                raise ConnectionResetError(54, "Connection reset by peer")

        counted = registry._Counted(Resetting(), 100, lambda n: None, what="layer 1")
        with self.assertRaises(registry.RegistryError) as raised:
            counted.read(16)
        self.assertEqual(raised.exception.reason, "NO_SOURCE_ACCESS")
        self.assertIn("ConnectionResetError", raised.exception.detail)

    def test_a_manifest_cut_short_is_no_source_access_and_tried_again(self):
        image = Image(base_layers(), arches=("amd64",))
        ref = self.ref(self.public.add("someone/agent", image, "open"))
        self.public.cut_short = {image.digest}
        report = self.reader.read_image(ref)
        self.assertEqual(report.config_error.reason, "NO_SOURCE_ACCESS")
        self.public.cut_short = set()
        self.later()
        self.assertIsNone(self.reader.read_image(ref).config_error)

    def test_a_registry_that_always_cuts_a_layer_short_is_read_once_per_retry(self):
        # Every scan asking for the image doesn't download it again.
        image = Image(base_layers(), TEST_ENV, arches=("amd64",))
        ref = self.ref(self.public.add("someone/agent", image, "open"))
        last = image.layer_digests[-1]
        self.public.cut_short = {last}
        first = self.reader.read_image(ref)
        self.assertEqual(first.layers_error.reason, "NO_SOURCE_ACCESS")
        sent = dict(self.public.sent)
        for _ in range(20):
            self.assertIs(self.reader.read_image(ref), first)
        self.assertEqual(self.public.sent, sent, "no layer was downloaded again")
        self.assertEqual((self.reader.hits, self.reader.misses), (20, 1))
        self.later()
        self.assertIsNot(self.reader.read_image(ref), first)
        self.assertEqual(self.reader.misses, 2)

    def test_concurrent_reads_of_one_image_read_it_once(self):
        image = Image(base_layers(), TEST_ENV, arches=("amd64",))
        ref = self.ref(self.public.add("someone/agent", image, "open"))
        self.public.drip.add(image.layer_digests[0])  # slow enough for the others to arrive while it reads
        reports: list[Any] = []
        threads = [threading.Thread(target=lambda: reports.append(self.reader.read_image(ref))) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(len(reports), 4)
        self.assertTrue(all(report is reports[0] for report in reports), "one read, one answer")
        self.assertEqual(self.reader.misses, 1)
        manifests = [path for path, _ in self.public.requests if "/manifests/" in path]
        self.assertEqual(len(manifests), 1, "the manifest was read once")
        self.assertEqual(self.reader._cache_bytes, registry._report_bytes(reports[0]), "counted once")


class BudgetTest(RegistryTestCase):
    def test_a_layer_past_the_budget_isnt_streamed(self):
        big = {"opt/data.bin": os.urandom(256 * 1024)}
        image = Image([{"a": b"a"}, {"opt/x.env": b"S=1"}, big, {"opt/.wh.x.env": b""}], arches=("amd64",))
        ref = self.ref(self.registry.add("proj/agent", image, "google"))
        sizes = [len(image.blobs[d]) for d in image.blobs if len(image.blobs[d]) > 1000 and d != image.digest]
        reader = registry.RegistryReader(layer_budget=64 * 1024, google_token=lambda: (GOOGLE_TOKEN, 3600),
                                         plain_http_hosts=frozenset({"127.0.0.1"}), google_hosts=frozenset({self.registry.host}))
        report = reader.read_image(ref)
        self.assertEqual(report.layers_error.reason, "SIZE_CAP_EXCEEDED")
        self.assertEqual((report.layers, report.layers_read), (4, 2))
        big_digest = json.loads(image.manifests[image.digest][0])["layers"][2]["digest"]
        self.assertNotIn(big_digest, self.registry.sent, "the layer past the budget isn't downloaded")
        self.assertTrue(sizes)
        attribute = image_fields.in_layer_deleted_secrets_attribute(report, True, B)
        self.assertEqual((attribute["status"], attribute["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))
        self.assertIn("layers 2 to 3 not read", attribute["note"])
        self.assertEqual(attribute["value"]["layers_read"], 2)

    def test_memory_stays_flat_while_a_large_layer_streams(self):
        layer_bytes = 24 * 1024 * 1024
        image = Image([{"opt/big.bin": os.urandom(layer_bytes)}], media_type=LAYER_TAR, arches=("amd64",))
        ref = self.ref(self.registry.add("proj/agent", image, "google"))
        tracemalloc.start()
        try:
            report = self.reader.read_image(ref)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertIsNone(report.layers_error)
        self.assertGreater(report.bytes_read, layer_bytes)
        self.assertLess(peak, 4 * 1024 * 1024, f"peak {peak} bytes while streaming a {layer_bytes}-byte layer")

    def test_a_zstd_layer_is_decompressed_no_faster_than_it_is_read(self):
        if not registry.zstd_supported():
            self.skipTest("this Python can't read zstd")
        from compression import zstd

        # 512 MiB of zeros behind a few kilobytes: one 64 KiB read of it is gigabytes.
        size = 512 * 1024 * 1024
        compressor = zstd.ZstdCompressor()
        info = tarfile.TarInfo("opt/zero.bin")
        info.size = size
        chunks = [compressor.compress(info.tobuf(tarfile.PAX_FORMAT))]
        zeros = bytes(1 << 20)
        chunks += [compressor.compress(zeros) for _ in range(size >> 20)]
        info = tarfile.TarInfo("opt/after.key")
        chunks += [compressor.compress(info.tobuf(tarfile.PAX_FORMAT) + bytes(2 * tarfile.RECORDSIZE)), compressor.flush()]
        image = rewrap(Image([zstd.compress(tar({"a": b"a"})), b"".join(chunks)], media_type=LAYER_TAR,
                             arches=("amd64",)), layer_media_type=LAYER_ZSTD)
        ref = self.ref(self.registry.add("proj/agent", image, "google"))
        tracemalloc.start()
        try:
            report = self.reader.read_image(ref)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertIsNone(report.layers_error)
        self.assertEqual(report.layers_read, 2)
        self.assertLess(peak, 8 * 1024 * 1024, f"peak {peak} bytes decompressing a {size}-byte zstd layer")

    def test_every_frame_of_a_zstd_layer_is_read(self):
        if not registry.zstd_supported():
            self.skipTest("this Python can't read zstd")
        from compression import zstd

        # The secret is in the layer's second frame, after a skippable frame.
        raw = tar({"usr/lib/x": b"x" * 4096, "opt/app/server.key": b"k"})
        split = 512 + 4096
        skippable = (0x184D2A50).to_bytes(4, "little") + (4).to_bytes(4, "little") + b"skip"
        added = zstd.compress(raw[:split]) + skippable + zstd.compress(raw[split:])
        deleted = zstd.compress(tar({"opt/app/.wh.server.key": b""}))
        ref = self.ref(self.registry.add("proj/agent", Image([added, deleted], media_type=LAYER_ZSTD, arches=("amd64",)),
                                         "google"))
        report = self.reader.read_image(ref)
        self.assertIsNone(report.layers_error)
        self.assertEqual([d["path"] for d in report.deleted], ["/opt/app/server.key"])

    def test_a_zstd_layer_that_ends_inside_a_frame_fails_the_field(self):
        if not registry.zstd_supported():
            self.skipTest("this Python can't read zstd")
        from compression import zstd

        blob = zstd.compress(tar({"opt/data.bin": os.urandom(65536)}))[:-100]
        ref = self.ref(self.registry.add("proj/agent", Image([blob], media_type=LAYER_ZSTD, arches=("amd64",)), "google"))
        report = self.reader.read_image(ref)
        self.assertEqual(report.layers_error.reason, "PARSE_FAILED")

    def test_a_zstd_frame_with_too_large_a_window_is_size_cap_exceeded(self):
        if not registry.zstd_supported():
            self.skipTest("this Python can't read zstd")
        from compression import zstd

        # A few kilobytes asking the decompressor to hold a 128 MiB window.
        compressor = zstd.ZstdCompressor(options={zstd.CompressionParameter.window_log: 27})
        blob = compressor.compress(tar({"opt/a.key": b"k" * 4096})) + compressor.flush()
        ref = self.ref(self.registry.add("proj/agent", Image([blob], media_type=LAYER_ZSTD, arches=("amd64",)), "google"))
        report = self.reader.read_image(ref)
        self.assertEqual(report.layers_error.reason, "SIZE_CAP_EXCEEDED")
        self.assertIn("window", report.layers_error.detail)
        small = zstd.ZstdCompressor(options={zstd.CompressionParameter.window_log: registry.MAX_ZSTD_WINDOW_LOG})
        blob = small.compress(tar({"opt/a.key": b"k"})) + small.flush()
        ref = self.ref(self.registry.add("proj/other", Image([blob], media_type=LAYER_ZSTD, arches=("amd64",)), "google"))
        self.assertIsNone(self.reader.read_image(ref).layers_error)

    def test_a_corrupt_zstd_layer_fails_the_field(self):
        if not registry.zstd_supported():
            self.skipTest("this Python can't read zstd")
        # A zstd frame header the decompressor refuses (ZstdError, which is no OSError or ValueError).
        image = Image([b"\x28\xb5\x2f\xfd\xff\xff\xff\xff" * 8], media_type=LAYER_ZSTD, arches=("amd64",))
        ref = self.ref(self.registry.add("proj/agent", image, "google"))
        report = self.reader.read_image(ref)
        self.assertEqual(report.layers_error.reason, "PARSE_FAILED")
        attribute = image_fields.in_layer_deleted_secrets_attribute(report, True, B)
        self.assertEqual(attribute["status"], "FAILED")

    def test_a_layer_past_image_layers_caps_is_partial(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
            archive.addfile(tarfile.TarInfo("opt/" + "a" * (2 * 1024 * 1024)))
        image = Image([{"opt/x.env": b"S=1"}, gzip.compress(buffer.getvalue(), mtime=0), {"opt/.wh.x.env": b""}],
                      arches=("amd64",))
        ref = self.ref(self.registry.add("proj/agent", image, "google"))
        report = self.reader.read_image(ref)
        self.assertEqual(report.layers_error.reason, "SIZE_CAP_EXCEEDED")
        self.assertEqual(report.layers_read, 1)
        attribute = image_fields.in_layer_deleted_secrets_attribute(report, True, B)
        self.assertEqual((attribute["status"], attribute["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))
        self.assertIn("layers 1 to 2 not read", attribute["note"])

    def test_a_zstd_layer_this_python_cant_read_fails_the_field(self):
        if registry.zstd_supported():
            self.skipTest("this Python reads zstd")
        image = Image([{"a": b"a"}], media_type=LAYER_ZSTD, arches=("amd64",))
        ref = self.ref(self.registry.add("proj/agent", image, "google"))
        attribute = image_fields.in_layer_deleted_secrets_attribute(self.reader.read_image(ref), True, B)
        self.assertEqual((attribute["status"], attribute["reason"]), ("FAILED", "NO_SOURCE_ACCESS"))


class DeadlineTest(RegistryTestCase):
    """Each read's time limit is a deadline, however slowly a server sends."""

    def timed(self, ref: Any) -> tuple[Any, float]:
        start = time.monotonic()
        report = self.reader.read_image(ref)
        return report, time.monotonic() - start

    def layer_digest(self, image: Image, index: int) -> str:
        return json.loads(image.manifests[image.digest][0])["layers"][index]["digest"]

    def test_a_manifest_sent_a_byte_at_a_time_stops_at_its_deadline(self):
        image = Image(base_layers(), arches=("amd64",))
        ref = self.ref(self.registry.add("proj/agent", image, "google"))
        self.registry.drip.add(image.digest)
        with mock.patch.object(registry, "MANIFEST_TIMEOUT_SECONDS", 1.0):
            report, took = self.timed(ref)
            self.assertEqual(report.config_error.reason, "NO_SOURCE_ACCESS")
            self.assertIn("took over 1 seconds", report.config_error.detail)
            self.assertLess(took, 3)
            self.registry.drip.clear()
            self.assertIs(self.reader.read_image(ref), report, "kept until RETRY_SECONDS have passed")
            self.later()
            self.assertIsNone(self.reader.read_image(ref).config_error, "a timed-out read is tried again")

    def test_a_status_line_sent_a_byte_at_a_time_stops_at_its_deadline(self):
        image = Image(base_layers(), arches=("amd64",))
        ref = self.ref(self.registry.add("proj/agent", image, "google"))
        self.registry.drip_headers.add(image.digest)
        with mock.patch.object(registry, "MANIFEST_TIMEOUT_SECONDS", 1.0):
            report, took = self.timed(ref)
        self.assertEqual(report.config_error.reason, "NO_SOURCE_ACCESS")
        self.assertIn("took over 1 seconds", report.config_error.detail)
        self.assertLess(took, 3)

    def test_a_layer_sent_a_byte_at_a_time_is_partial_at_its_deadline(self):
        for redirected in (False, True):
            with self.subTest(redirected=redirected):
                self.registry.redirect_blobs = redirected
                image = Image(base_layers(), arches=("amd64",))
                ref = self.ref(self.registry.add(f"proj/agent{int(redirected)}", image, "google"))
                self.registry.drip.add(self.layer_digest(image, 1))
                with mock.patch.object(registry, "LAYER_TIMEOUT_SECONDS", 1.0):
                    report, took = self.timed(ref)
                self.assertLess(took, 3)
                self.assertEqual(report.layers_error.reason, "SIZE_CAP_EXCEEDED")
                self.assertEqual(report.layers_read, 1)
                attribute = image_fields.in_layer_deleted_secrets_attribute(report, True, B)
                self.assertEqual((attribute["status"], attribute["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))
                self.assertIn("layer 1 took over 1 seconds; layers 1 to 2 not read", attribute["note"])

    def test_an_images_layers_share_one_deadline(self):
        image = Image(base_layers(), arches=("amd64",))
        ref = self.ref(self.registry.add("proj/agent", image, "google"))
        self.registry.drip.add(self.layer_digest(image, 0))
        with mock.patch.object(registry, "LAYERS_TIMEOUT_SECONDS", 1.0):
            report, took = self.timed(ref)
        self.assertLess(took, 3)
        self.assertEqual(report.layers_error.reason, "SIZE_CAP_EXCEEDED")
        self.assertEqual(report.layers_read, 0)

    def test_a_layer_slow_to_decompress_stops_at_its_deadline(self):
        if not registry.zstd_supported():
            self.skipTest("this Python can't read zstd")
        from compression import zstd

        # 8 GiB of zeros in a few hundred kilobytes: well past a short deadline to inflate and skip.
        compressor = zstd.ZstdCompressor()
        info = tarfile.TarInfo("opt/zero.bin")
        info.size = 8 << 30
        zeros = bytes(1 << 24)
        chunks = [compressor.compress(info.tobuf(tarfile.PAX_FORMAT))]
        chunks += [compressor.compress(zeros) for _ in range(info.size // len(zeros))]
        chunks.append(compressor.flush())
        image = Image([b"".join(chunks)], media_type=LAYER_ZSTD, arches=("amd64",))
        ref = self.ref(self.registry.add("proj/agent", image, "google"))
        with mock.patch.object(registry, "LAYER_TIMEOUT_SECONDS", 0.3):
            report, took = self.timed(ref)
        self.assertLess(took, 2)
        self.assertEqual(report.layers_error.reason, "SIZE_CAP_EXCEEDED")
        self.assertIn("took over 0.3 seconds", report.layers_error.detail)


class CacheMemoryTest(RegistryTestCase):
    def test_a_config_of_too_many_values_isnt_parsed(self):
        # 4 MiB of [{},{},...] is over 200 MiB once parsed.
        config = b'{"config": {}, "history": [' + b",".join([b"{}"] * 300_000) + b"]}"
        ref = self.ref(self.registry.add("proj/agent", rewrap(Image(base_layers(), arches=("amd64",)), config), "google"))
        tracemalloc.start()
        try:
            report = self.reader.read_image(ref)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(report.config_error.reason, "SIZE_CAP_EXCEEDED")
        self.assertLess(peak, 16 * 1024 * 1024, f"peak {peak} bytes")

    def test_a_deeply_nested_config_is_parse_failed(self):
        config = b'{"config": ' + b"[" * 200_000 + b"]" * 200_000 + b"}"
        ref = self.ref(self.registry.add("proj/agent", rewrap(Image(base_layers(), arches=("amd64",)), config), "google"))
        report = registry.RegistryReader(google_token=lambda: (GOOGLE_TOKEN, 3600), plain_http_hosts=frozenset({"127.0.0.1"}),
                                         google_hosts=frozenset({self.registry.host})).read_image(ref)
        self.assertIn(report.config_error.reason, ("PARSE_FAILED", "SIZE_CAP_EXCEEDED"))
        with mock.patch.object(registry, "MAX_JSON_VALUES", 1 << 30):
            report = registry.RegistryReader(google_token=lambda: (GOOGLE_TOKEN, 3600),
                                             plain_http_hosts=frozenset({"127.0.0.1"}),
                                             google_hosts=frozenset({self.registry.host})).read_image(ref)
        self.assertEqual(report.config_error.reason, "PARSE_FAILED")

    def test_a_cached_image_keeps_only_the_env_and_user(self):
        config = json.dumps({"architecture": "amd64", "config": {"Env": TEST_ENV, "User": "app", "Labels": {"a": "b"}},
                             "history": [{"created_by": "RUN x"}] * 50}).encode()
        ref = self.ref(self.registry.add("proj/agent", rewrap(Image(base_layers(), arches=("amd64",)), config), "google"))
        report = self.reader.read_image(ref)
        self.assertEqual(report.config, {"config": {"Env": TEST_ENV, "User": "app"}})

    def test_the_deleted_files_an_image_keeps_are_capped(self):
        names = {f"opt/s/{i}.key": b"" for i in range(registry.MAX_DELETED + 50)}
        image = Image([names, {"opt/.wh.s": b""}], arches=("amd64",))
        report = self.reader.read_image(self.ref(self.registry.add("proj/agent", image, "google")))
        self.assertIsNone(report.layers_error)
        self.assertEqual(len(report.deleted), registry.MAX_DELETED)

    def test_the_cache_is_bounded_by_bytes_too(self):
        refs = [self.ref(self.registry.add(f"proj/agent{i}", Image(base_layers(), [f"V{i}=" + "x" * 4000] * 10,
                                                                   arches=("amd64",)), "google")) for i in range(3)]
        self.reader.cache_bytes = 100_000  # two of these images
        for ref in refs:
            self.reader.read_image(ref)
        self.reader.read_image(refs[0])
        self.assertEqual((self.reader.hits, self.reader.misses), (0, 4), "the oldest left the cache by size")
        self.reader.read_image(refs[2])
        self.assertEqual(self.reader.hits, 1)


class ImageFieldsTest(RegistryTestCase):
    def test_the_deleted_secret_file_with_both_layer_indexes_and_no_content(self):
        image_id = self.registry.add("proj/agent", Image(base_layers(), TEST_ENV), "google")
        attribute = self.attributes(agent_pod(image_id))["in_layer_deleted_secrets"]
        self.assertEqual(attribute["status"], "ANSWERED")
        self.assertEqual(attribute["value"], {"layers": 3, "layers_read": 3, "deleted": [
            {"path": "/opt/railtest/deleted-secret.env", "added_in_layer": 1, "deleted_in_layer": 2,
             "size": len(DELETED_CONTENT)}]})
        self.assertNotIn("railtest-not-a-real-token", json.dumps(attribute))

    def test_user_follows_the_container_then_the_pod_then_the_image(self):
        image_id = self.registry.add("proj/agent", Image(base_layers(), TEST_ENV, user="node"), "google")
        cases = [
            (agent_pod(image_id, {"runAsUser": 1000}, {"runAsUser": 2000}), "1000", "the agent container's"),
            (agent_pod(image_id, {"allowPrivilegeEscalation": False}, {"runAsUser": 2000}), "2000", "the pod's"),
            (agent_pod(image_id, {}, {}), "node", "the image config's User"),
            (agent_pod(image_id, {"runAsUser": 0}), "root", "the agent container's"),
        ]
        for pod, value, source in cases:
            with self.subTest(value=value):
                attribute = self.attributes(pod)["user"]
                self.assertEqual((attribute["status"], attribute["value"]), ("ANSWERED", value))
                self.assertIn(source, attribute["method"])
        rootless = self.registry.add("proj/root", Image(base_layers(), TEST_ENV, user=""), "google")
        attribute = self.attributes(agent_pod(rootless))["user"]
        self.assertEqual(attribute["value"], "root")
        self.assertIn("an empty User is root", attribute["note"])

    def test_user_with_no_run_as_user_and_a_private_image_is_blind(self):
        private = self.public.add("someone/agent", Image(base_layers()), "private")
        attribute = self.attributes(agent_pod(private))["user"]
        self.assertEqual((attribute["status"], attribute["reason"]), ("BLIND", "PRIVATE_STORE"))
        attribute = self.attributes(agent_pod(private, {"runAsUser": 10000}))["user"]
        self.assertEqual((attribute["status"], attribute["value"]), ("ANSWERED", "10000"))

    def test_framework_identity_from_the_test_image(self):
        image_id = self.registry.add("proj/agent", Image(base_layers(), TEST_ENV), "google")
        attribute = self.attributes(agent_pod(image_id))["framework_identity"]
        self.assertEqual(attribute["value"], {"node": "v24.18.1", "yarn": "1.22.22"})
        bare = self.registry.add("proj/bare", Image(base_layers(), ["PATH=/bin"]), "google")
        self.assertEqual(self.attributes(agent_pod(bare))["framework_identity"]["status"], "ABSENT")
        python = self.registry.add("proj/py", Image(base_layers(), ["PYTHON_VERSION=3.14.9"]), "google")
        self.assertEqual(self.attributes(agent_pod(python))["framework_identity"]["value"], {"python": "Python 3.14.9"})

    def test_credential_provenance_baked_and_injected_by_name_only(self):
        image_id = self.registry.add("proj/agent", Image(base_layers(), TEST_ENV + [
            f"DATABASE_URL=postgres://agent:{URL_PASSWORD}@db.internal:5432/app"]), "google")
        pod = agent_pod(image_id, env=[
            {"name": "AGENT_LLM_API_KEY", "valueFrom": {"secretKeyRef": {"name": "agent-llm", "key": "api-key"}}},
            {"name": "OPENCLAW_GATEWAY_TOKEN", "value": SECRET_VALUE},
            {"name": "RAIL_TEST_BAKED_API_KEY", "valueFrom": {"secretKeyRef": {"name": "override", "key": "k"}}},
            {"name": "AGENT_LLM_MAX_TOKENS", "value": "4096"},
            {"name": "LOG_LEVEL", "value": "debug"},
        ])
        attribute = self.attributes(pod)["credential_provenance"]
        self.assertEqual(attribute["status"], "ANSWERED")
        found = {(c["name"], c["provenance"]): c for c in attribute["value"]["credentials"]}
        self.assertEqual(found[("AGENT_LLM_API_KEY", "injected")]["source"], {"secret": "agent-llm", "key": "api-key"})
        self.assertEqual(found[("OPENCLAW_GATEWAY_TOKEN", "injected")]["source"], "the pod spec's value")
        self.assertEqual(found[("RAIL_TEST_BAKED_API_KEY", "baked")]["source"], "the image config's Env")
        self.assertTrue(found[("RAIL_TEST_BAKED_API_KEY", "baked")]["overridden"],
                        "still in the image, though the pod sets it")
        url = found[("DATABASE_URL", "baked")]["url"]
        self.assertNotIn(URL_PASSWORD, url)
        self.assertIn("db.internal", url)
        self.assertNotIn(("AGENT_LLM_MAX_TOKENS", "injected"), found, "a token budget isn't a credential")
        self.assertNotIn(("LOG_LEVEL", "injected"), found)

    def test_env_from_a_whole_secret_is_partial_naming_it(self):
        image_id = self.registry.add("proj/agent", Image(base_layers(), TEST_ENV), "google")
        pod = agent_pod(image_id, env_from=[{"secretRef": {"name": "agent-llm"}},
                                            {"configMapRef": {"name": "agent-settings"}, "prefix": "APP_"}])
        attribute = self.attributes(pod)["credential_provenance"]
        self.assertEqual((attribute["status"], attribute["reason"]), ("PARTIAL", "NO_SOURCE_ACCESS"))
        self.assertIn("Secret agent-llm", attribute["note"])
        self.assertEqual(attribute["value"]["unlisted_sources"],
                         [{"kind": "secret", "name": "agent-llm"},
                          {"kind": "config_map", "name": "agent-settings", "prefix": "APP_"}])

    def test_no_env_value_appears_in_the_bundle(self):
        image_id = self.registry.add("proj/agent", Image(base_layers(), TEST_ENV + [
            f"DATABASE_URL=postgres://agent:{URL_PASSWORD}@db.internal/app"]), "google")
        pod = agent_pod(image_id, {"runAsUser": 1000}, env=[
            {"name": "OPENCLAW_GATEWAY_TOKEN", "value": SECRET_VALUE},
            {"name": "AGENT_LLM_API_KEY", "valueFrom": {"secretKeyRef": {"name": "agent-llm", "key": "api-key"}}}],
            env_from=[{"secretRef": {"name": "agent-llm"}}])
        text = json.dumps(bundle(self.attributes(pod)))
        for value in (BAKED_VALUE, SECRET_VALUE, URL_PASSWORD, "railtest-not-a-real-token", GOOGLE_TOKEN, ANON_TOKEN):
            self.assertNotIn(value, text)

    def test_no_registry_access_gives_the_image_fields_blind(self):
        image_id = self.registry.add("proj/agent", Image(base_layers(), TEST_ENV), "google")
        attributes = self.attributes(agent_pod(image_id, {"runAsUser": 1000},
                                               env=[{"name": "A_TOKEN", "value": "x" * 20}]), registry_access=False)
        for name in ("framework_identity", "in_layer_deleted_secrets"):
            self.assertEqual((attributes[name]["status"], attributes[name]["reason"]), ("BLIND", "NO_SOURCE_ACCESS"), name)
        self.assertEqual(attributes["user"]["value"], "1000", "a runAsUser needs no registry")
        provenance = attributes["credential_provenance"]
        self.assertEqual((provenance["status"], provenance["reason"]), ("PARTIAL", "NO_SOURCE_ACCESS"))
        self.assertEqual([c["name"] for c in provenance["value"]["credentials"]], ["A_TOKEN"])
        self.assertIn("--no-registry-access", provenance["note"])
        self.assertEqual(self.registry.requests, [], "nothing is read with --no-registry-access")

    def test_no_image_digest_yet(self):
        pod = agent_pod("")
        attributes = self.attributes(pod)
        self.assertEqual(attributes["in_layer_deleted_secrets"]["status"], "BLIND")
        self.assertIn("no image digest yet", attributes["in_layer_deleted_secrets"]["note"])


if __name__ == "__main__":
    unittest.main()
