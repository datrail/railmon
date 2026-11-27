"""gke-scan's registry reader (RC-553): an image's manifest, config and
layers, read by digest, for the image fields (image_fields.py).

An image is read by the digest the kubelet pulled (the agent container's
status `imageID`), never by tag, so what is read is what runs.

* **Artifact Registry and Container Registry** (`*-docker.pkg.dev`, `gcr.io`,
  `*.gcr.io`) are read with gke-scan's Google identity: an access token from
  the metadata server, which Workload Identity maps to gke-scan's Google
  service account. It needs `roles/artifactregistry.reader` on each
  repository (the setup script, RC-557).
* **Any other registry** is read as the public does: the registry's
  `WWW-Authenticate` challenge names a token endpoint, which gives an
  anonymous pull token. A registry that still refuses (401 or 403) holds a
  private image, reported PRIVATE_STORE.
* `read_manifest` follows an image index (multi-arch) to the manifest for the
  node's OS and architecture; `read_config` reads the config blob;
  `stream_layers` reads each layer, gzip, zstd or uncompressed, through
  image_layers.layer_entries as it arrives, so a layer is never held whole.
* Manifests and configs get 10 seconds and 4 MiB each; a layer gets 120
  seconds, and an image's layers 10 minutes in all. Those are deadlines, not
  socket timeouts: when one passes, the read's sockets are shut down (a server
  sending a byte at a time ends then) and decompression stops (a layer that
  takes long to inflate ends then too). A connection's name lookup and its
  connect attempts (at most 4 addresses) get only what is left of the
  deadline, so a name with many unreachable addresses can't stretch it. A manifest or config past its
  deadline is NO_SOURCE_ACCESS, tried again on a read 5 minutes later or
  more, as is any read the network cuts off or ends short; a layer past
  its deadline is SIZE_CAP_EXCEEDED, keeping the layers read before it. The
  layers of one image together get `--layer-budget` bytes (2 GiB):
  a layer that would pass it isn't read, and the result says so
  (SIZE_CAP_EXCEEDED). A manifest or config with more than 262,144 values
  isn't parsed (SIZE_CAP_EXCEEDED). A zstd layer is decompressed no faster
  than it is read, every frame of it, with a window of at most 32 MiB (a
  frame asking for more is SIZE_CAP_EXCEEDED), and a layer whose tar headers
  or kept names pass image_layers' caps is SIZE_CAP_EXCEEDED too, so a
  hostile layer can't grow memory. Every
  manifest and config is checked against its digest, and so is every layer
  read to its end.
* A blob's redirect (to the registry's storage) is followed, at most 5 times,
  over https only, without reading the redirect's body, and the registry's
  credential is never sent to another host.
* The registry's host comes from the imageID only when it is a host name
  (letters, digits, dots, dashes and a port), and gke-scan's Google token is
  sent only where the request's own URL is a Google registry.
* A token endpoint or a redirect a registry names can be any URL, so neither
  is followed to a loopback, private, link-local or otherwise non-public
  address unless it is the registry's own host. The name is resolved once
  and only its public addresses are connected to, so nothing is ever sent to
  a refused address (not even a TCP handshake that would tell an open port
  from a closed one), and a name that resolves differently the second time
  can't get past it. Google's registries, read with gke-scan's identity, are
  not checked: Private Service Connect gives them private addresses. Behind
  an https proxy (HTTPS_PROXY) the proxy resolves the name, so the check is
  the proxy's to make.
* The metadata server is asked for gke-scan's token directly, never through
  a proxy (which would see the token in clear) and never following a
  redirect.
* What was read is kept in an LRU cache of 256 images (and 32 MiB, estimated),
  by registry, repository, digest and platform (so what one registry answers
  for a digest is never what another's image gets): of a config, only the
  User and the first 1,024 entries or 128 KiB of the Env the image fields
  read, and at most 1,024 deleted files. Past its size, a registry host
  holding more than a quarter of the cache gives up its oldest images first.
* A failure for want of the registry (NO_SOURCE_ACCESS), or one nothing
  anticipated, is kept for 5 minutes, and a refusal (PRIVATE_STORE) for 30,
  before the image is read again. One image is read by one thread at a time;
  another asking for it waits up to 60 seconds for that answer.

Nothing here reads file content: the layers give only names, sizes and
layer indexes. Like the other central_service modules, it uses only the
standard library.
"""

from __future__ import annotations

import functools
import gzip
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import math
import re
import socket
import sys
import threading
import time
import zlib
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import IO, Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPHandler, HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

MANIFEST_TIMEOUT_SECONDS = 10.0
LAYER_TIMEOUT_SECONDS = 120.0
LAYERS_TIMEOUT_SECONDS = 600.0
# A zstd frame's window is memory the decompressor holds whole: 2**25 is
# 32 MiB, enough for every compression level short of --ultra and --long.
MAX_ZSTD_WINDOW_LOG = 25
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
DEFAULT_LAYER_BUDGET = 2 * 1024 ** 3
CACHE_IMAGES = 256
# What the cache may hold in all, estimated per image from what it keeps (the
# config's Env and User, and the deleted files), so a few hostile images can't
# fill memory however few they are.
CACHE_BYTES = 32 * 1024 * 1024
# How long a read that failed for want of the registry (NO_SOURCE_ACCESS: the
# network, a 404, a token endpoint that failed) is kept before it is tried
# again: soon enough for a blip, and no more often than this however often
# the image is asked for, so a registry that always fails a read halfway
# can't have every scan download the image again.
RETRY_SECONDS = 300.0
# A refusal (PRIVATE_STORE) is kept longer, but not for good: a permission
# granted later (roles/artifactregistry.reader, RC-557) is seen within this.
PRIVATE_RETRY_SECONDS = 1800.0
# What one registry host's images may hold of the cache, so that one
# registry's images, however large, never push out another's.
CACHE_HOST_SHARE = 4  # a quarter of CACHE_BYTES
# Of an image config's Env, what is kept: the image fields read no more, and
# past it the field says so (credential_provenance PARTIAL).
MAX_ENV = 1024
MAX_ENV_BYTES = 128 * 1024
# A User longer than this is no user or uid:gid: kept just past it, so the
# image field can tell it was longer and say so.
MAX_USER = 256
# How long a read waits for another thread's read of the same image before
# answering NO_SOURCE_ACCESS (not cached), so a slow registry holds one
# thread, not every thread that asks for its image.
WAIT_SECONDS = 60.0
# The addresses a connection tries, each with what is left of the read's
# deadline: a name with many unreachable addresses can't multiply it.
MAX_ADDRESSES = 4
# The deleted files an image keeps; the field lists 256 (image_fields.MAX_LIST).
MAX_DELETED = 1024
# Values a manifest or config may hold, counted before parsing: 4 MiB of
# `[{},{},...]` parses to over 200 MiB of objects.
MAX_JSON_VALUES = 1 << 18
MAX_REDIRECTS = 5
METADATA_TOKEN_URL = ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
                      "default/token")
DOCKER_HUB = "docker.io"
DOCKER_HUB_API = "registry-1.docker.io"
MANIFEST_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
INDEX_TYPES = MANIFEST_TYPES[:2]
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
# A registry as an imageID names it: a host name and an optional port, and
# nothing urllib would read as a userinfo, path, query or fragment.
REGISTRY_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*(?::[0-9]{1,5})?")
# A bearer token as a header can carry it: printable ASCII, no spaces.
BEARER_TOKEN = re.compile(r"[!-~]{1,8192}")
# Anonymous tokens kept, one per registry host and repository: past this the
# expired ones go, then the oldest, so a registry naming many repositories
# can't grow it.
MAX_TOKENS = 256
MAX_TOKEN_LIFETIME = 86400.0


def _image_layers() -> ModuleType:
    """tools/scan/image_layers.py, loaded by path once."""
    module = sys.modules.get("image_layers")
    if module is None:
        spec = importlib.util.spec_from_file_location(
            "image_layers", Path(__file__).resolve().parent.parent.parent / "image_layers.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules["image_layers"] = module
        spec.loader.exec_module(module)
    return module


class RegistryError(Exception):
    """The registry couldn't be read: `reason` is the bundle's reason code
    (PRIVATE_STORE, NO_SOURCE_ACCESS, PARSE_FAILED, SIZE_CAP_EXCEEDED)."""

    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


class BudgetExceeded(RegistryError):
    def __init__(self, detail: str):
        super().__init__("SIZE_CAP_EXCEEDED", detail)


class ReadTimedOut(RegistryError):
    """A read past its deadline (NO_SOURCE_ACCESS; a layer's is
    SIZE_CAP_EXCEEDED, given by stream_layers)."""

    def __init__(self, detail: str):
        super().__init__("NO_SOURCE_ACCESS", detail)


class ZstdWindowTooLarge(Exception):
    """A zstd frame whose window is over MAX_ZSTD_WINDOW_LOG."""


@dataclass(frozen=True)
class ImageRef:
    registry: str      # as the image names it: docker.io, us-central1-docker.pkg.dev, ...
    repository: str    # library/python, project/repo/image, ...
    digest: str        # sha256:...

    @property
    def api_host(self) -> str:
        return DOCKER_HUB_API if self.registry == DOCKER_HUB else self.registry

    @property
    def google(self) -> bool:
        return _google_host(self.registry.split(":")[0])

    def __str__(self) -> str:
        return f"{self.registry}/{self.repository}@{self.digest}"


def _google_host(host: str) -> bool:
    """Artifact Registry's or Container Registry's host name."""
    return host.endswith("-docker.pkg.dev") or host == "gcr.io" or host.endswith(".gcr.io")


def _token_lifetime(value: Any, default: float) -> float:
    """A token's `expires_in` in seconds: `default` when it isn't a positive
    finite number, and at most a day."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return default
    try:
        seconds = float(value)
    except (ValueError, OverflowError):  # an int past a float's range is OverflowError
        return default
    return min(seconds, MAX_TOKEN_LIFETIME) if math.isfinite(seconds) and seconds > 0 else default


def parse_image_id(image_id: Any) -> ImageRef | None:
    """The registry, repository and digest of a container status's imageID
    (`registry/repo@sha256:...`, with or without `docker-pullable://`); None
    when it names no digest, or a registry that isn't a host name."""
    if not isinstance(image_id, str):
        return None
    text = image_id.strip()
    for prefix in ("docker-pullable://", "docker://"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    name, sep, digest = text.partition("@")
    if not sep or not DIGEST.match(digest) or not name:
        return None
    first, slash, rest = name.partition("/")
    if slash and ("." in first or ":" in first or first == "localhost"):
        registry, repository = first.lower(), rest
        if not REGISTRY_HOST.fullmatch(registry):
            return None
    else:
        registry, repository = DOCKER_HUB, name
    if registry == DOCKER_HUB and "/" not in repository:
        repository = f"library/{repository}"
    if not repository or not re.fullmatch(r"[a-z0-9][a-z0-9._/-]*", repository):
        return None
    return ImageRef(registry, repository, digest)


@dataclass
class ImageReport:
    """What was read of one image: its config, and the deleted secret files
    across its layers. An error says why a part couldn't be read."""

    ref: ImageRef
    platform: str
    manifest_digest: str | None = None
    config: dict[str, Any] | None = None
    config_error: RegistryError | None = None
    layers: int = 0
    layers_read: int = 0
    deleted: list[dict[str, Any]] = field(default_factory=list)
    deleted_total: int = 0  # how many there were, of which `deleted` keeps MAX_DELETED
    layers_error: RegistryError | None = None
    bytes_read: int = 0


def _kept_config(config: dict[str, Any]) -> dict[str, Any]:
    """Of an image config, the Env and User the image fields read: all a
    cached image keeps of it. Env is kept up to MAX_ENV entries and
    MAX_ENV_BYTES, in order, and `EnvTruncated` says when more was left out."""
    inner = config.get("config") if isinstance(config.get("config"), dict) else {}
    env = [e for e in inner.get("Env") if isinstance(e, str)] if isinstance(inner.get("Env"), list) else []
    kept: list[str] = []
    size = 0
    for entry in env:
        size += len(entry)
        if len(kept) >= MAX_ENV or size > MAX_ENV_BYTES:
            break
        kept.append(entry)
    user = inner.get("User") if isinstance(inner.get("User"), str) else ""
    return {"config": {"Env": kept, "User": user[:MAX_USER + 1],
                       **({"EnvTruncated": True} if len(kept) < len(env) else {})}}


def _retry_after(report: "ImageReport", unexpected: bool = False) -> float | None:
    """How long a report is kept before its image is read again: RETRY_SECONDS
    for a failure for want of the registry (or one nothing anticipated),
    PRIVATE_RETRY_SECONDS for a refusal, and None (until it leaves the cache)
    for what the image itself is: read, bad, or past a cap."""
    reasons = {error.reason for error in (report.config_error, report.layers_error) if error is not None}
    if unexpected or "NO_SOURCE_ACCESS" in reasons:
        return RETRY_SECONDS
    if "PRIVATE_STORE" in reasons:
        return PRIVATE_RETRY_SECONDS
    return None


def _report_bytes(report: "ImageReport") -> int:
    """What a cached report holds, roughly: its config's Env and User, and its deleted files."""
    config = (report.config or {}).get("config") or {}
    return (1024 + sum(len(e) + 64 for e in config.get("Env") or []) + len(config.get("User") or "")
            + sum(len(str(d.get("path"))) + 256 for d in report.deleted))


class _Deadline:
    """One read's time limit, across every connection it makes (a redirect's,
    a token endpoint's): when it passes, each of their sockets is shut down,
    which ends a blocked handshake or read however slowly the server sends,
    and `check` stops work in between (decompressing, say). A connection's
    name lookup and connect attempts get only what is left of it
    (_create_connection)."""

    def __init__(self, seconds: float):
        self.seconds = seconds
        self.at = time.monotonic() + seconds
        self.sockets: list[socket.socket] = []
        self.lock = threading.Lock()
        self.expired = False
        self.timer = threading.Timer(seconds, self._expire)
        self.timer.daemon = True
        self.timer.start()

    @property
    def passed(self) -> bool:
        return self.expired or time.monotonic() >= self.at

    def left(self) -> float:
        """For a socket timeout: what is left, never zero (which would make the socket non-blocking)."""
        return max(self.at - time.monotonic(), 0.001)

    def watch(self, sock: socket.socket) -> None:
        with self.lock:
            self.sockets.append(sock)
            expired = self.expired
        if expired:
            self._shut(sock)

    def check(self, what: str) -> None:
        if self.passed:
            raise ReadTimedOut(f"{what} took over {self.seconds:g} seconds")

    def _expire(self) -> None:
        with self.lock:
            self.expired = True
            sockets = list(self.sockets)
        for sock in sockets:
            self._shut(sock)

    @staticmethod
    def _shut(sock: socket.socket) -> None:
        try:  # the plain socket's shutdown, also for an SSLSocket another thread is reading
            socket.socket.shutdown(sock, socket.SHUT_RDWR)
        except OSError:
            pass  # closed already, or detached into the SSLSocket that wraps it

    def close(self) -> None:
        self.timer.cancel()

    def __enter__(self) -> "_Deadline":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class NonPublicAddress(OSError):
    """A token endpoint or redirect whose host has no public address."""


def _public_address(address: str) -> bool:
    """Whether an IP address is a public one: not loopback, private,
    link-local, shared or reserved, an IPv4 address mapped into IPv6 judged
    as itself."""
    ip = ipaddress.ip_address(address.split("%")[0])
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global


def _resolve(host: str, port: int, deadline: "_Deadline | None") -> list[Any]:
    """getaddrinfo, within what is left of `deadline`: the resolver can't be
    interrupted, so it runs on a thread of its own that is left to finish
    (within the resolver's own timeouts) when the deadline passes first."""
    try:
        ipaddress.ip_address(host.split("%")[0])
        literal = True
    except ValueError:
        literal = False
    def lookup() -> list[Any]:
        # A name the registry gives (a token realm, a redirect) can be one the
        # resolver won't encode ("a..b", a label past 63 characters): that is
        # UnicodeError, a ValueError; as an OSError it is a read that failed.
        try:
            return socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        except OSError:
            raise
        except Exception as exc:  # noqa: BLE001 - any lookup failure is the name's, not the reader's
            raise OSError(f"{host!r} can't be resolved ({exc.__class__.__name__})") from None

    if deadline is None or literal:
        return lookup()
    result: dict[str, Any] = {}

    def resolve() -> None:
        try:
            result["infos"] = lookup()
        except OSError as exc:
            result["error"] = exc

    thread = threading.Thread(target=resolve, name="gke-scan-resolve", daemon=True)
    thread.start()
    thread.join(deadline.left())
    if thread.is_alive():
        raise TimeoutError(f"resolving {host} ran past the read's deadline")
    if "error" in result:
        raise result["error"]
    return result["infos"]


def _create_connection(address: tuple[str, int], timeout: Any, source_address: Any,
                       private_ok: frozenset[str] | None, deadline: "_Deadline | None" = None) -> socket.socket:
    """socket.create_connection, connecting only to the host's public
    addresses unless the host is one of `private_ok` (None: any). The name is
    resolved once, here, and a refused address is never connected to, so the
    refusal says nothing about what listens there. Within `deadline`: the
    lookup, and each of at most MAX_ADDRESSES attempts, gets only what is
    left of it, so however many addresses a name has, the read still ends
    at its deadline."""
    host, port = address
    infos = _resolve(host, port, deadline)
    if not (private_ok is None or host in private_ok):
        infos = [info for info in infos if _public_address(info[4][0])]
        if not infos:
            raise NonPublicAddress(f"{host} is at a non-public address")
    error: OSError | None = None
    for family, kind, proto, _, sockaddr in infos[:MAX_ADDRESSES]:
        attempt = timeout
        if deadline is not None:
            if deadline.passed:
                break
            left = deadline.left()
            attempt = left if attempt is None or attempt is socket._GLOBAL_DEFAULT_TIMEOUT else min(attempt, left)  # type: ignore[attr-defined]
        sock = socket.socket(family, kind, proto)
        try:
            if attempt is not socket._GLOBAL_DEFAULT_TIMEOUT:  # type: ignore[attr-defined]
                sock.settimeout(attempt)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            error = exc
            sock.close()
    if deadline is not None and deadline.passed:
        raise TimeoutError(f"connecting to {host} ran past the read's deadline")
    raise error or OSError(f"{host} has no address to connect to")


class _CheckedConnect:
    """http.client's connection, creating its socket with _create_connection.
    Behind an https proxy the socket goes to the proxy, which resolves the
    registry's name itself, so there is nothing here to check."""

    private_ok: frozenset[str] | None
    deadline: "_Deadline | None"
    _tunnel_host: str | None

    def _checked_connection(self, address: tuple[str, int], timeout: Any = socket._GLOBAL_DEFAULT_TIMEOUT,  # type: ignore[attr-defined]
                            source_address: Any = None) -> socket.socket:
        return _create_connection(address, timeout, source_address, None if self._tunnel_host else self.private_ok,
                                  self.deadline)


class _WatchedHTTPConnection(_CheckedConnect, http.client.HTTPConnection):
    def __init__(self, *args: Any, deadline: _Deadline | None = None, private_ok: frozenset[str] | None = frozenset(),
                 **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.deadline = deadline
        self.private_ok = private_ok
        self._create_connection = self._checked_connection

    def connect(self) -> None:
        super().connect()
        if self.deadline is not None:
            self.deadline.watch(self.sock)


class _WatchedHTTPSConnection(_CheckedConnect, http.client.HTTPSConnection):
    """HTTPSConnection.connect, with the socket watched before the TLS
    handshake, so a server that is slow to finish one is cut off too."""

    def __init__(self, *args: Any, deadline: _Deadline | None = None, private_ok: frozenset[str] | None = frozenset(),
                 **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.deadline = deadline
        self.private_ok = private_ok
        self._create_connection = self._checked_connection

    def connect(self) -> None:
        http.client.HTTPConnection.connect(self)
        if self.deadline is None:
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self._tunnel_host or self.host)
            return
        self.deadline.watch(self.sock)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self._tunnel_host or self.host,
                                              do_handshake_on_connect=False)
        self.deadline.watch(self.sock)
        self.sock.do_handshake()


class _WatchedHTTPHandler(HTTPHandler):
    def http_open(self, req: Request) -> Any:
        return self.do_open(functools.partial(_WatchedHTTPConnection, deadline=getattr(req, "deadline", None),
                                              private_ok=getattr(req, "private_ok", frozenset())), req)


class _WatchedHTTPSHandler(HTTPSHandler):
    def https_open(self, req: Request) -> Any:
        return self.do_open(functools.partial(_WatchedHTTPSConnection, deadline=getattr(req, "deadline", None),
                                              private_ok=getattr(req, "private_ok", frozenset())),
                            req, context=self._context)


def _request(url: str, headers: dict[str, str], deadline: _Deadline, private_ok: frozenset[str] | None) -> Request:
    """A request read within `deadline`, which may connect to a non-public
    address only for the hosts in `private_ok` (None: any)."""
    request = Request(url, headers=headers)
    request.deadline = deadline  # type: ignore[attr-defined]
    request.private_ok = private_ok  # type: ignore[attr-defined]
    return request


class _Unread:
    """A redirect's response, closed without reading its body: urllib reads
    a 3xx body whole before following it, and the registry sets its size."""

    def __init__(self, fp: Any):
        self.fp = fp

    def read(self, *args: Any) -> bytes:
        return b""

    def close(self) -> None:
        self.fp.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.fp, name)


class _Redirects(HTTPRedirectHandler):
    """Follow a blob's redirect over https only, without the registry's
    credential when the host changes, and without reading the redirect's
    body."""

    max_redirections = MAX_REDIRECTS

    def __init__(self, plain_http_hosts: frozenset[str]):
        self.plain_http_hosts = plain_http_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        if target.scheme != "https" and target.hostname not in self.plain_http_hosts:
            raise HTTPError(newurl, code, f"refused a redirect to {target.scheme}", headers, fp)
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.deadline = getattr(req, "deadline", None)  # the redirect is part of the same read
            new.private_ok = getattr(req, "private_ok", frozenset())
            if urlsplit(req.full_url).netloc != target.netloc:
                new.remove_header("Authorization")
        return new

    def http_error_302(self, req, fp, code, msg, headers):
        return super().http_error_302(req, _Unread(fp), code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


class _Counted:
    """A stream that counts, hashes and bounds what it reads, and stops at
    its deadline."""

    def __init__(self, raw: IO[bytes], limit: int, on_bytes: Callable[[int], None],
                 deadline: _Deadline | None = None, what: str = "the layer"):
        self.raw, self.limit, self.on_bytes = raw, limit, on_bytes
        self.deadline, self.what = deadline, what
        self.read_bytes = 0
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        if self.deadline is not None:
            self.deadline.check(self.what)
        want = 65536 if size is None or size < 0 else size
        try:
            data = self.raw.read(want)
        except (OSError, http.client.HTTPException) as exc:
            # The network, not the image: NO_SOURCE_ACCESS, tried again after
            # RETRY_SECONDS, rather than a bad layer that stays cached.
            if self.deadline is not None:
                self.deadline.check(self.what)
            raise RegistryError("NO_SOURCE_ACCESS", f"{self.what}: the connection failed "
                                                    f"({exc.__class__.__name__})") from None
        if not data and want and self.read_bytes < self.limit:
            if self.deadline is not None:
                self.deadline.check(self.what)  # a socket shut at the deadline ends a read short
            raise RegistryError("NO_SOURCE_ACCESS", f"{self.what} ended after {self.read_bytes} of "
                                                    f"{self.limit} bytes")
        self.read_bytes += len(data)
        if self.read_bytes > self.limit:
            raise RegistryError("PARSE_FAILED", f"the layer is larger than its descriptor's {self.limit} bytes")
        self.digest.update(data)
        self.on_bytes(len(data))
        return data

    def drain(self) -> None:
        while self.read(1 << 20):
            pass


class _Timed:
    """A decompressed layer as tarfile reads it, stopping at the deadline:
    a small compressed read can stand for gigabytes to inflate and skip."""

    def __init__(self, raw: IO[bytes], deadline: _Deadline, what: str):
        self.raw, self.deadline, self.what = raw, deadline, what

    def read(self, size: int = -1) -> bytes:
        self.deadline.check(self.what)
        return self.raw.read(size)


class _Zstd:
    """A zstd layer, decompressed as it is read (Python 3.14's
    compression.zstd), never more than one read asks for at a time: a small
    zstd chunk can stand for gigabytes. A layer can be several frames, one
    after another, and is read to the end of the last (as containerd reads
    it); one that ends inside a frame is an EOFError."""

    def __init__(self, raw: IO[bytes]):
        from compression import zstd  # type: ignore[import-not-found]

        options = {zstd.DecompressionParameter.window_log_max: MAX_ZSTD_WINDOW_LOG}
        self.raw, self.error = raw, zstd.ZstdError
        self.new = lambda: zstd.ZstdDecompressor(options=options)
        self.decompressor, self.pending, self.buffer = self.new(), b"", bytearray()

    def read(self, size: int = -1) -> bytes:
        want = 65536 if size is None or size < 0 else size
        while len(self.buffer) < want:
            if self.decompressor.eof:
                rest = self.decompressor.unused_data or self.raw.read(65536)
                if not rest:
                    break  # the end of the last frame
                self.decompressor, self.pending = self.new(), rest
            if self.pending:
                chunk, self.pending = self.pending, b""
            elif self.decompressor.needs_input:
                chunk = self.raw.read(65536)
                if not chunk:
                    raise EOFError("the zstd layer ends inside a frame")
            else:
                chunk = b""
            try:
                self.buffer += self.decompressor.decompress(chunk, max_length=want - len(self.buffer))
            except self.error as exc:  # not an OSError or ValueError
                if "too much memory" in str(exc):
                    raise ZstdWindowTooLarge(f"a zstd frame's window is over {1 << MAX_ZSTD_WINDOW_LOG} bytes") from None
                raise ValueError(f"zstd: {exc}") from None
        data = bytes(self.buffer[:want])
        del self.buffer[:want]
        return data


def zstd_supported() -> bool:
    try:
        from compression import zstd  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        return False
    return True


def _challenge(header: str | None) -> dict[str, str]:
    """A WWW-Authenticate Bearer challenge's parameters."""
    if not header or not header.lower().startswith("bearer "):
        return {}
    return {key.lower(): value for key, value in re.findall(r'(\w+)="([^"]*)"', header[7:])}


class _NoRedirect(HTTPRedirectHandler):
    """No redirect is followed: the 3xx is the answer (an HTTPError)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# The metadata server is link-local: never through an HTTP proxy, which would
# see the minted token in clear, and never following a redirect away from it
# (as the scanner's own metadata reads, scan_agent_environment._METADATA_OPENER).
_METADATA_OPENER = build_opener(ProxyHandler({}), _NoRedirect)


def google_token_from_metadata(opener: Any = None, timeout: float = MANIFEST_TIMEOUT_SECONDS) -> tuple[str, float]:
    """gke-scan's Google access token and its lifetime in seconds, from the
    metadata server (Workload Identity's)."""
    opener = opener or _METADATA_OPENER
    request = Request(METADATA_TOKEN_URL, headers={"Metadata-Flavor": "Google"})
    with opener.open(request, timeout=timeout) as resp:
        body = json.loads(resp.read(65536))
    return str(body["access_token"]), _token_lifetime(body.get("expires_in"), 300)


class RegistryReader:
    def __init__(self, layer_budget: int = DEFAULT_LAYER_BUDGET,
                 google_token: Callable[[], tuple[str, float]] = google_token_from_metadata,
                 cache_size: int = CACHE_IMAGES, clock: Callable[[], float] = time.monotonic,
                 plain_http_hosts: frozenset[str] = frozenset(), google_hosts: frozenset[str] = frozenset()):
        """`plain_http_hosts` lets a registry on those hosts be read over
        plain http, and `google_hosts` reads those with the Google identity:
        tests' local registry only."""
        self.layer_budget = layer_budget
        self.google_token = google_token
        self.cache_size = cache_size
        self.clock = clock
        self.plain_http_hosts = plain_http_hosts
        self.google_hosts = google_hosts
        self._opener = build_opener(_Redirects(plain_http_hosts), _WatchedHTTPHandler(), _WatchedHTTPSHandler())
        self._tokens: dict[tuple[str, str], tuple[str, float]] = {}
        self._tokens_lock = threading.Lock()
        self._google: tuple[str, float] | None = None
        self._cache: OrderedDict[tuple[str, str, str, str], ImageReport] = OrderedDict()
        self._cache_bytes = 0
        self._retry_at: dict[tuple[str, str, str, str], float] = {}  # when a failed read is tried again
        self._host_bytes: dict[str, int] = {}  # what each registry host's images hold of the cache
        self._reading: dict[tuple[str, str, str, str], threading.Event] = {}  # reads in flight
        self.cache_bytes = CACHE_BYTES
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    # ── HTTP ──

    def _url(self, ref: ImageRef, kind: str, reference: str) -> str:
        host = ref.api_host
        scheme = "http" if host.split(":")[0] in self.plain_http_hosts else "https"
        return f"{scheme}://{host}/v2/{ref.repository}/{kind}/{reference}"

    def _google_credential(self) -> str:
        now = self.clock()
        if self._google is None or now >= self._google[1]:
            try:
                token, lifetime = self.google_token()
            except Exception as exc:  # noqa: BLE001 - no identity: the image can't be read
                raise RegistryError("NO_SOURCE_ACCESS", f"gke-scan's Google identity gave no token: "
                                                        f"{exc.__class__.__name__}") from None
            self._google = (token, now + max(lifetime - 60, 30))
        return self._google[0]

    def _private_ok(self, ref: ImageRef, google: bool) -> frozenset[str] | None:
        """The hosts this image's reads may reach at a non-public address: any
        for Google's registries, else only the registry's own (and the tests'
        plain-http hosts)."""
        return None if google else frozenset({ref.api_host.split(":")[0]}) | self.plain_http_hosts

    def _anonymous_token(self, ref: ImageRef, challenge: dict[str, str], deadline: _Deadline) -> str:
        realm = challenge.get("realm")
        try:
            target = urlsplit(realm) if realm else None
            target_host = target.hostname if target else None
        except ValueError:  # an unparsable realm, as a hostile registry can send
            target = target_host = None
        if target is None or target.scheme != "https" and target_host not in self.plain_http_hosts:
            raise RegistryError("PRIVATE_STORE", f"{ref.registry} asked for credentials without a token endpoint")
        key = (ref.api_host, ref.repository)
        with self._tokens_lock:
            cached = self._tokens.get(key)
        if cached and self.clock() < cached[1]:
            return cached[0]
        query = {"scope": challenge.get("scope") or f"repository:{ref.repository}:pull"}
        if challenge.get("service"):
            query["service"] = challenge["service"]
        request = _request(f"{realm}?{urlencode(query)}", {"Accept": "application/json"}, deadline,
                           self._private_ok(ref, google=False))
        try:
            with self._opener.open(request, timeout=deadline.left()) as resp:
                body = json.loads(resp.read(65536))
        except HTTPError as exc:
            if exc.code in (401, 403):
                raise RegistryError("PRIVATE_STORE", f"{ref.registry} gives no anonymous pull token "
                                                     f"(HTTP {exc.code})") from None
            raise RegistryError("NO_SOURCE_ACCESS", f"{ref.registry}'s token endpoint: HTTP {exc.code}") from None
        except (URLError, TimeoutError, OSError, ValueError, RecursionError, http.client.HTTPException) as exc:
            deadline.check(f"{ref.registry}'s token endpoint")
            raise RegistryError("NO_SOURCE_ACCESS", f"{ref.registry}'s token endpoint: "
                                                    f"{exc.__class__.__name__}") from None
        # The token endpoint is the registry's to name, so its answer can be
        # anything: only a JSON object with a token a header can carry is used.
        token = (body.get("token") or body.get("access_token")) if isinstance(body, dict) else None
        if not isinstance(token, str) or not BEARER_TOKEN.fullmatch(token):
            raise RegistryError("NO_SOURCE_ACCESS", f"{ref.registry}'s token endpoint gave no usable token")
        now = self.clock()
        with self._tokens_lock:
            self._tokens.pop(key, None)
            self._tokens[key] = (token, now + max(_token_lifetime(body.get("expires_in"), 60) - 10, 10))
            if len(self._tokens) > MAX_TOKENS:
                for stale in [k for k, (_, expires) in self._tokens.items() if now >= expires]:
                    del self._tokens[stale]
                while len(self._tokens) > MAX_TOKENS:
                    del self._tokens[next(iter(self._tokens))]
        return token

    def _open(self, ref: ImageRef, kind: str, reference: str, accept: str | None, deadline: _Deadline) -> Any:
        """The response for a manifest or blob, authenticated as the registry
        needs, within `deadline` (ReadTimedOut past it); RegistryError when it
        can't be read."""
        url = self._url(ref, kind, reference)
        # Google's token goes only where this URL itself points to a Google registry.
        google = _google_host(urlsplit(url).hostname or "") or ref.registry in self.google_hosts
        private_ok = self._private_ok(ref, google)
        credential = f"Bearer {self._google_credential()}" if google else None
        for attempt in (1, 2):
            headers = {**({"Accept": accept} if accept else {}), **({"Authorization": credential} if credential else {})}
            try:
                return self._opener.open(_request(url, headers, deadline, private_ok), timeout=deadline.left())
            except HTTPError as exc:
                challenge = _challenge(exc.headers.get("WWW-Authenticate") if exc.headers else None)
                exc.close()
                if exc.code == 401 and attempt == 1 and not google and challenge:
                    credential = f"Bearer {self._anonymous_token(ref, challenge, deadline)}"
                    continue
                if exc.code in (401, 403):
                    who = "gke-scan's Google identity" if google else "an anonymous pull"
                    raise RegistryError("PRIVATE_STORE", f"{ref.registry} refused {who} for {ref.repository} "
                                                         f"(HTTP {exc.code})") from None
                if exc.code == 404:
                    raise RegistryError("NO_SOURCE_ACCESS", f"{ref.registry} has no {kind[:-1]} {reference}") from None
                raise RegistryError("NO_SOURCE_ACCESS", f"{ref.registry}: {kind} {reference}: HTTP {exc.code}") from None
            except (URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
                deadline.check(f"{ref.registry}: {kind} {reference}")
                raise RegistryError("NO_SOURCE_ACCESS", f"{ref.registry}: {exc.__class__.__name__}: "
                                                        f"{getattr(exc, 'reason', exc)}") from None
            except ValueError:  # a redirect or header urllib can't use; its text may carry the registry's values
                deadline.check(f"{ref.registry}: {kind} {reference}")
                raise RegistryError("NO_SOURCE_ACCESS", f"{ref.registry}: {kind} {reference}: "
                                                        f"a response that couldn't be followed") from None
        raise AssertionError("unreachable")

    def _json_blob(self, ref: ImageRef, kind: str, digest: str, accept: str | None) -> tuple[dict[str, Any], str]:
        """A manifest or config, read whole (at most 4 MiB), checked against
        its digest; the body and its media type."""
        what = f"{kind[:-1]} {digest}"
        with _Deadline(MANIFEST_TIMEOUT_SECONDS) as deadline:
            try:
                with self._open(ref, kind, digest, accept, deadline) as resp:
                    body = resp.read(MAX_MANIFEST_BYTES + 1)
                    media_type = (resp.headers.get("Content-Type") or "").split(";")[0].strip()
                    # What its Content-Length said was still to come: a body the
                    # network ended short, not one that fails its digest.
                    cut_short = isinstance(resp.length, int) and resp.length > 0 and len(body) <= MAX_MANIFEST_BYTES
            except (OSError, http.client.HTTPException) as exc:
                deadline.check(what)
                raise RegistryError("NO_SOURCE_ACCESS", f"{ref.registry}: reading {what}: "
                                                        f"{exc.__class__.__name__}") from None
            deadline.check(what)  # a socket shut at the deadline ends a read short
        if cut_short:
            raise RegistryError("NO_SOURCE_ACCESS", f"{ref.registry}: {what} ended after {len(body)} bytes")
        if len(body) > MAX_MANIFEST_BYTES:
            raise RegistryError("SIZE_CAP_EXCEEDED", f"{kind[:-1]} {digest} is over {MAX_MANIFEST_BYTES} bytes")
        if "sha256:" + hashlib.sha256(body).hexdigest() != digest:
            raise RegistryError("PARSE_FAILED", f"{kind[:-1]} {digest} doesn't match its digest")
        values = body.count(b",") + body.count(b"[") + body.count(b"{")
        if values > MAX_JSON_VALUES:
            raise RegistryError("SIZE_CAP_EXCEEDED", f"{kind[:-1]} {digest} has over {MAX_JSON_VALUES} values")
        try:
            parsed = json.loads(body)
        except (ValueError, RecursionError):
            raise RegistryError("PARSE_FAILED", f"{kind[:-1]} {digest} isn't JSON") from None
        if not isinstance(parsed, dict):
            raise RegistryError("PARSE_FAILED", f"{kind[:-1]} {digest} isn't a JSON object")
        return parsed, parsed.get("mediaType") or media_type

    # ── the reads ──

    def read_manifest(self, ref: ImageRef, os: str = "linux", arch: str = "amd64",
                      variant: str | None = None) -> tuple[dict[str, Any], str]:
        """The image manifest for this platform (following an index), and its digest."""
        manifest, media_type = self._json_blob(ref, "manifests", ref.digest, ",".join(MANIFEST_TYPES))
        digest = ref.digest
        entries = manifest.get("manifests")
        if media_type in INDEX_TYPES or isinstance(entries, list):
            if not isinstance(entries, list):
                raise RegistryError("PARSE_FAILED", f"index {digest} has no list of manifests")
            choices = [m for m in entries if isinstance(m, dict)
                       and isinstance(m.get("platform"), dict) and m["platform"].get("os") == os
                       and m["platform"].get("architecture") == arch
                       and (variant is None or m["platform"].get("variant") in (None, variant))]
            if not choices or not DIGEST.match(str(choices[0].get("digest"))):
                raise RegistryError("NO_SOURCE_ACCESS", f"{ref} has no {os}/{arch} image in its index")
            digest = choices[0]["digest"]
            manifest, media_type = self._json_blob(ref, "manifests", digest, ",".join(MANIFEST_TYPES[2:]))
        if not isinstance(manifest.get("config"), dict) or not isinstance(manifest.get("layers"), list):
            raise RegistryError("PARSE_FAILED", f"manifest {digest} has no config or layers")
        return manifest, digest

    def read_config(self, ref: ImageRef, manifest: dict[str, Any]) -> dict[str, Any]:
        digest = str(manifest["config"].get("digest"))
        if not DIGEST.match(digest):
            raise RegistryError("PARSE_FAILED", "the manifest's config has no sha256 digest")
        config, _ = self._json_blob(ref, "blobs", digest, None)
        return config

    def stream_layers(self, ref: ImageRef, manifest: dict[str, Any], report: ImageReport) -> None:
        """Each layer, in order, through image_layers.layer_entries; the
        deleted secret files across them into `report`. Stops at the budget,
        or at the first layer that can't be read, keeping what was read."""
        layers_module = _image_layers()
        descriptors = [d for d in manifest["layers"] if isinstance(d, dict)]
        report.layers = len(descriptors)
        entries: list[Any] = []
        kept = 0
        layers_end = time.monotonic() + LAYERS_TIMEOUT_SECONDS
        try:
            for index, descriptor in enumerate(descriptors):
                digest = str(descriptor.get("digest"))
                size = descriptor.get("size")
                media_type = str(descriptor.get("mediaType") or "")
                if not DIGEST.match(digest) or not isinstance(size, int) or size < 0:
                    raise RegistryError("PARSE_FAILED", f"layer {index} has no digest or size")
                if report.bytes_read + size > self.layer_budget:
                    raise BudgetExceeded(f"layer {index} ({size} bytes) would pass the {self.layer_budget}-byte "
                                         f"layer budget after {report.bytes_read} bytes; layers {index} to "
                                         f"{len(descriptors) - 1} not read")
                if "zstd" in media_type and not zstd_supported():
                    raise RegistryError("NO_SOURCE_ACCESS", f"layer {index} is zstd, which this Python can't read")
                not_read = f"layers {index} to {len(descriptors) - 1} not read"
                left = layers_end - time.monotonic()
                if left <= 0:
                    raise RegistryError("SIZE_CAP_EXCEEDED", f"the layers took over {LAYERS_TIMEOUT_SECONDS:g} "
                                                             f"seconds; {not_read}")
                try:
                    with _Deadline(min(LAYER_TIMEOUT_SECONDS, left)) as deadline:
                        found = self._read_layer(ref, index, digest, size, media_type, deadline, report,
                                                 layers_module.MAX_KEPT_BYTES - kept)
                except ReadTimedOut as exc:
                    raise RegistryError("SIZE_CAP_EXCEEDED", f"layer {index}: {exc.detail}; {not_read}") from None
                except (layers_module.LayerCapExceeded, ZstdWindowTooLarge) as exc:
                    raise RegistryError("SIZE_CAP_EXCEEDED", f"layer {index}: {exc}; {not_read}") from None
                if found is None:
                    raise RegistryError("PARSE_FAILED", f"layer {index} isn't a tar")
                entries.append(found)
                kept += layers_module.kept_bytes(found)
                report.layers_read = index + 1
        except RegistryError as exc:
            report.layers_error = exc
        except (URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
            report.layers_error = RegistryError("NO_SOURCE_ACCESS", f"reading the layers: {exc.__class__.__name__}")
        finally:
            # What the layers read show, however the reading ended: an image
            # can't hide a secret it adds and deletes behind a later layer
            # that fails (read_image's catch-all sets that layer's error).
            deleted = layers_module.deleted_across(entries)["deleted"]
            report.deleted_total = len(deleted)
            report.deleted = deleted[:MAX_DELETED]

    def _read_layer(self, ref: ImageRef, index: int, digest: str, size: int, media_type: str,
                    deadline: _Deadline, report: ImageReport, max_kept_bytes: int) -> Any:
        """One layer's entries (image_layers.layer_entries), read to its end
        and checked against its digest, within `deadline`."""
        layers_module = _image_layers()
        what = f"layer {index}"
        with self._open(ref, "blobs", digest, None, deadline) as resp:
            def count(n: int) -> None:
                report.bytes_read += n

            counted = _Counted(resp, size, count, deadline, what)
            if "gzip" in media_type:
                stream: Any = gzip.GzipFile(fileobj=counted, mode="rb")
            elif "zstd" in media_type:
                stream = _Zstd(counted)
            else:
                stream = counted
            try:
                found = layers_module.layer_entries(_Timed(stream, deadline, what), max_kept_bytes)
            except (OSError, EOFError, zlib.error, ValueError, http.client.HTTPException) as exc:
                deadline.check(what)
                raise RegistryError("PARSE_FAILED", f"layer {index} couldn't be decompressed: "
                                                    f"{exc.__class__.__name__}") from None
            try:
                counted.drain()
            except (OSError, http.client.HTTPException):
                deadline.check(what)
                raise
            deadline.check(what)  # a socket shut at the deadline ends a read short
            if counted.read_bytes != size or "sha256:" + counted.digest.hexdigest() != digest:
                raise RegistryError("PARSE_FAILED", f"layer {index} doesn't match its digest or size")
        return found

    def read_image(self, ref: ImageRef, os: str = "linux", arch: str = "amd64", layers: bool = True) -> ImageReport:
        """The image's config and deleted secret files, from the cache when
        this digest and platform were read before."""
        # By registry and repository too: what a hostile registry answers for a
        # popular image's digest (a refusal, a slow read) is its own, never
        # what the same digest from another registry gets.
        key = (ref.api_host, ref.repository, ref.digest + ("+layers" if layers else ""), f"{os}/{arch}")
        while True:
            with self._lock:
                cached = self._cache.get(key)
                if cached is not None and self.clock() >= self._retry_at.get(key, float("inf")):
                    self._evict(key)  # a failed read, due to be tried again
                    cached = None
                if cached is not None:
                    self._cache.move_to_end(key)
                    self.hits += 1
                    return cached
                pending = self._reading.get(key)
                if pending is None:
                    self._reading[key] = threading.Event()
                    self.misses += 1
                    break
            # Another thread is reading this image: wait for its answer
            # rather than read it again alongside, but not for longer than
            # WAIT_SECONDS, so a slow registry holds one thread, not all.
            if not pending.wait(WAIT_SECONDS):
                report = ImageReport(ref, f"{os}/{arch}")
                report.config_error = RegistryError(
                    "NO_SOURCE_ACCESS", f"another read of this image was still running after {WAIT_SECONDS:g} seconds")
                return report
        try:
            unexpected = False
            report = ImageReport(ref, f"{os}/{arch}")
            try:
                self._read_image(report, os, arch, layers)
            except Exception as exc:  # noqa: BLE001 - nothing an image holds may raise out of the reader
                # What was read before it is kept: a config read, then a layer
                # that failed unexpectedly, is a config and a failed layer.
                unexpected = True
                error = RegistryError("PARSE_FAILED", f"the image couldn't be read ({exc.__class__.__name__})")
                if report.config is None:
                    report.config_error = error
                else:
                    report.layers_error = error
            retry = _retry_after(report, unexpected)
            host = key[0]
            with self._lock:
                self._evict(key)
                self._cache[key] = report
                size = _report_bytes(report)
                self._cache_bytes += size
                self._host_bytes[host] = self._host_bytes.get(host, 0) + size
                if retry is not None:
                    self._retry_at[key] = self.clock() + retry
                # Past the cache's size, a registry host holding more than its
                # share gives up its oldest images first, so one registry's
                # images, however large, never push out another's.
                while len(self._cache) > self.cache_size or (self._cache_bytes > self.cache_bytes and len(self._cache) > 1):
                    share = self.cache_bytes // CACHE_HOST_SHARE
                    victim = next((k for k in self._cache if k != key and self._host_bytes.get(k[0], 0) > share), None)
                    self._evict(victim if victim is not None else next(iter(self._cache)))
            return report
        finally:
            with self._lock:
                self._reading.pop(key).set()

    def _evict(self, key: tuple[str, str, str, str]) -> None:
        """Drop one image from the cache, with its bytes (under the lock)."""
        report = self._cache.pop(key, None)
        if report is not None:
            size = _report_bytes(report)
            self._cache_bytes -= size
            self._host_bytes[key[0]] -= size
            if not self._host_bytes[key[0]]:
                del self._host_bytes[key[0]]
        self._retry_at.pop(key, None)

    def _read_image(self, report: ImageReport, os: str, arch: str, layers: bool) -> None:
        """Fill `report` with what can be read of its image."""
        ref = report.ref
        try:
            manifest, report.manifest_digest = self.read_manifest(ref, os, arch)
            report.config = _kept_config(self.read_config(ref, manifest))
        except RegistryError as exc:
            report.config_error = exc
            manifest = None
        if manifest is not None and layers:
            self.stream_layers(ref, manifest, report)
