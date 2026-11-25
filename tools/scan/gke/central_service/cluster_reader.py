"""gke-scan's cluster reader (RC-550): list and watch what gke-scan reads
about the agent pods in its enrolled namespaces, keep a copy in memory, and
say which workloads each change affects.

What it reads, in each enrolled namespace (or across all of them, for `*`):

| Kind | Kept as |
|---|---|
| Pods | agent pods (those `--label-selector` matches) and MCP server pods (labeled `rail.datrail.io/mcp-server=true` or annotated `rail.datrail.io/source`); other pods are dropped |
| Services, NetworkPolicies, PersistentVolumeClaims | all of them |
| The enrolled Namespaces | each one, for its owner label |

Each kind in each namespace is one stream, on its own thread: list it, then
watch from the list's resourceVersion with bookmarks, a watch the API server
ends after 5 minutes, and watch again from the last resourceVersion seen.
A 410 Gone (the resourceVersion is too old) lists again, and so does every
`--interval`. Listing again compares the new list with the copy, so a change
missed between two watches is still reported. Pods are listed without a
label selector, since an MCP server may be found by its annotation, which a
selector can't match, and the selector is applied here.

A 403 (gke-scan's role doesn't allow the read) is logged, and that stream
tries again after an interval; every other stream carries on. Any other
error is logged and tried again with backoff (1 second, doubling, up to a
minute); 429 and 5xx are first retried in KubeClient itself. The backoff,
and the 403's one log line, start over only once a watch has run to its
end, so a stream whose list works and whose watch keeps failing still backs
off rather than listing again every second.

Each change to the copy is a ChangeEvent naming the workloads it affects
(`namespace/workload`, as the sidecar keys it and workload.py checks it):

| A change to | Affects |
|---|---|
| An agent pod | its workload |
| A Service | every workload in its namespace, and those that name it in an env URL elsewhere |
| A NetworkPolicy, or the Namespace | every workload in its namespace |
| A PersistentVolumeClaim | the workloads whose pods mount it |
| An MCP server pod | the workloads that name it: an env URL in their pods whose host is one of the Services that select it |

A pod's workload comes from workload.py, which reads its owners from the API,
and is cached by the pod's UID and owner references. A pod whose owners can't
be read now is tried again on its next change. Those reads are made before
the copy's lock is taken, and the affected workloads are worked out from the
cache alone, so a slow API server never holds up the intake's `cached_pod`.

The intake's pod check answers from this copy (`cached_pod`) once the pod's
namespace has been listed, and reads the API for a pod the copy doesn't have
with the token's UID: a pod just created, before its watch event arrives,
or a namespace not listed yet. A stream that fails stops answering until it
has listed again.

Like the other central_service modules, it uses only the standard library.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Iterable, Protocol
from urllib.parse import urlsplit

ALL_NAMESPACES = "*"
SCAN_LABEL = "rail.datrail.io/scan"
DEFAULT_LABEL_SELECTOR = f"{SCAN_LABEL}=true"
MCP_SERVER_LABEL = "rail.datrail.io/mcp-server"
SOURCE_ANNOTATION = "rail.datrail.io/source"
CLUSTER_DOMAIN = "cluster.local"
DEFAULT_INTERVAL_SECONDS = 3600
ERROR_BACKOFF_START_SECONDS = 1.0
ERROR_BACKOFF_MAX_SECONDS = 60.0

AGENT_PODS = "agent_pods"
MCP_SERVERS = "mcp_servers"
SERVICES = "services"
NETWORK_POLICIES = "networkpolicies"
CLAIMS = "persistentvolumeclaims"
NAMESPACES = "namespaces"
STORES = (AGENT_PODS, MCP_SERVERS, SERVICES, NETWORK_POLICIES, CLAIMS, NAMESPACES)

URL_IN_TEXT = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>,;]+")


def _workload_module() -> ModuleType:
    """workload.py beside this file, loaded by path once (shared with intake.py)."""
    module = sys.modules.get("gke_scan_workload")
    if module is None:
        spec = importlib.util.spec_from_file_location("gke_scan_workload", Path(__file__).with_name("workload.py"))
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules["gke_scan_workload"] = module
        spec.loader.exec_module(module)
    return module


def log(message: str) -> None:
    print(f"gke-scan: reader: {message}", file=sys.stderr, flush=True)


# ── label selectors ─────────────────────────────────────────────────────────

_KEY = re.compile(r"^([a-z0-9]([-a-z0-9.]*[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$")
_VALUE = re.compile(r"^([A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?)?$")


@dataclass(frozen=True)
class Requirement:
    key: str
    op: str  # "=", "!=", "in", "notin", "exists", "!exists"
    values: frozenset[str] = frozenset()

    def matches(self, labels: dict[str, str]) -> bool:
        present = self.key in labels
        value = labels.get(self.key)
        if self.op == "=":
            return present and value in self.values
        if self.op == "!=":
            return not present or value not in self.values
        if self.op == "in":
            return present and value in self.values
        if self.op == "notin":
            return not present or value not in self.values
        if self.op == "exists":
            return present
        return not present


def _split_requirements(text: str) -> list[str]:
    parts, depth, current = [], 0, []
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return [part.strip() for part in parts]


def parse_selector(text: str) -> tuple[Requirement, ...]:
    """A Kubernetes label selector string (`a=b,c!=d,e in (f,g),!h`). Raises
    ValueError for one Kubernetes wouldn't take. An empty one matches every pod."""
    if not text.strip():
        return ()
    requirements = []
    for part in _split_requirements(text):
        if not part:
            raise ValueError(f"an empty requirement in label selector {text!r}")
        match = re.fullmatch(r"(?P<key>[^\s!=()]+)\s+(?P<op>in|notin)\s*\((?P<values>[^()]*)\)", part)
        if match:
            values = frozenset(v.strip() for v in match["values"].split(","))
            requirement = Requirement(match["key"], match["op"], values)
        elif part.startswith("!"):
            requirement = Requirement(part[1:].strip(), "!exists")
        elif "!=" in part:
            key, _, value = part.partition("!=")
            requirement = Requirement(key.strip(), "!=", frozenset([value.strip()]))
        elif "==" in part or "=" in part:
            key, _, value = part.partition("==") if "==" in part else part.partition("=")
            requirement = Requirement(key.strip(), "=", frozenset([value.strip()]))
        else:
            requirement = Requirement(part, "exists")
        if not _KEY.match(requirement.key) or not all(_VALUE.match(v) for v in requirement.values) \
                or (requirement.op in ("in", "notin") and not all(requirement.values)):
            raise ValueError(f"{part!r} isn't a valid requirement in label selector {text!r}")
        requirements.append(requirement)
    return tuple(requirements)


def selector_matches(requirements: Iterable[Requirement], labels: dict[str, str]) -> bool:
    return all(requirement.matches(labels) for requirement in requirements)


# ── object helpers ──────────────────────────────────────────────────────────

def _metadata(obj: dict[str, Any]) -> dict[str, Any]:
    metadata = obj.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _labels(obj: dict[str, Any]) -> dict[str, str]:
    labels = _metadata(obj).get("labels")
    return labels if isinstance(labels, dict) else {}


def _key(obj: dict[str, Any], namespace: str | None = None) -> tuple[str, str] | None:
    metadata = _metadata(obj)
    name = metadata.get("name")
    ns = metadata.get("namespace") if namespace is None else namespace
    if not isinstance(name, str) or not name:
        return None
    return (ns if isinstance(ns, str) else "", name)


def _spec(obj: dict[str, Any]) -> dict[str, Any]:
    spec = obj.get("spec")
    return spec if isinstance(spec, dict) else {}


def _slim(obj: dict[str, Any]) -> dict[str, Any]:
    """The object without its managedFields, which nothing reads."""
    metadata = _metadata(obj)
    if "managedFields" not in metadata:
        return obj
    return {**obj, "metadata": {k: v for k, v in metadata.items() if k != "managedFields"}}


def is_mcp_server(pod: dict[str, Any]) -> bool:
    annotations = _metadata(pod).get("annotations")
    annotated = isinstance(annotations, dict) and bool(str(annotations.get(SOURCE_ANNOTATION) or "").strip())
    return _labels(pod).get(MCP_SERVER_LABEL) == "true" or annotated


def claims_mounted(pod: dict[str, Any]) -> set[str]:
    volumes = _spec(pod).get("volumes")
    names = set()
    for volume in volumes if isinstance(volumes, list) else []:
        claim = volume.get("persistentVolumeClaim") if isinstance(volume, dict) else None
        name = claim.get("claimName") if isinstance(claim, dict) else None
        if isinstance(name, str) and name:
            names.add(name)
    return names


def env_url_hosts(pod: dict[str, Any]) -> set[str]:
    """The hosts of URL-shaped literal env values in the pod's containers,
    lowercased. Values from Secrets or ConfigMaps aren't in the pod spec, and
    aren't read."""
    hosts = set()
    spec = _spec(pod)
    for group in ("initContainers", "containers"):
        containers = spec.get(group)
        for container in containers if isinstance(containers, list) else []:
            env = container.get("env") if isinstance(container, dict) else None
            for var in env if isinstance(env, list) else []:
                value = var.get("value") if isinstance(var, dict) else None
                if not isinstance(value, str):
                    continue
                for url in URL_IN_TEXT.findall(value):
                    try:
                        host = urlsplit(url).hostname
                    except ValueError:
                        continue
                    if host:
                        hosts.add(host.lower().rstrip("."))
    return hosts


def service_hosts(service: dict[str, Any], same_namespace: bool) -> set[str]:
    """The names a pod can reach a Service by: from its own namespace, the
    bare name too."""
    key = _key(service)
    if key is None:
        return set()
    namespace, name = key
    hosts = {f"{name}.{namespace}", f"{name}.{namespace}.svc", f"{name}.{namespace}.svc.{CLUSTER_DOMAIN}"}
    if same_namespace:
        hosts.add(name)
    return hosts


def service_selects(service: dict[str, Any], pod: dict[str, Any]) -> bool:
    """A Service's selector (a plain map) against a pod in its namespace.
    A Service without a selector selects no pod."""
    selector = _spec(service).get("selector")
    if not isinstance(selector, dict) or not selector:
        return False
    if _metadata(service).get("namespace") != _metadata(pod).get("namespace"):
        return False
    labels = _labels(pod)
    return all(labels.get(k) == v for k, v in selector.items())


# ── the reader ──────────────────────────────────────────────────────────────

class KubeLister(Protocol):
    def list_objects(self, api_version: str, plural: str, namespace: str | None = None,
                     label_selector: str | None = None, field_selector: str | None = None) -> dict[str, Any]: ...

    def watch(self, api_version: str, plural: str, namespace: str | None, resource_version: str,
              label_selector: str | None = None, field_selector: str | None = None) -> Iterable[dict[str, Any]]: ...

    def get_object(self, api_version: str, plural: str, namespace: str, name: str) -> dict[str, Any] | None: ...


@dataclass(frozen=True)
class ChangeEvent:
    """One change to the copy: `kind` is one of STORES; `type` ADDED,
    MODIFIED or DELETED; `workloads` the `namespace/workload` keys it affects."""

    kind: str
    namespace: str
    name: str
    type: str
    workloads: frozenset[str]


@dataclass(frozen=True)
class StreamSpec:
    api_version: str
    plural: str
    namespace: str | None  # None: across all namespaces, or a cluster-scoped kind
    field_selector: str | None = None

    @property
    def label(self) -> str:
        if self.plural == "namespaces":
            return f"namespaces {self.field_selector or '(all)'}"
        return f"{self.plural} in {self.namespace if self.namespace is not None else 'all namespaces'}"


@dataclass
class StreamState:
    synced: bool = False
    forbidden: bool = False
    failures: int = 0  # errors since a watch last ran to its end
    listed_at: float | None = None
    last_error: str | None = None
    relists: int = 0
    watches: int = 0


def stream_specs(namespaces: tuple[str, ...]) -> list[StreamSpec]:
    """One stream per kind per enrolled namespace, or one per kind across
    every namespace for `*`."""
    scopes: list[str | None] = [None] if namespaces == (ALL_NAMESPACES,) else list(namespaces)
    specs = []
    for scope in scopes:
        specs += [StreamSpec("v1", "pods", scope), StreamSpec("v1", "services", scope),
                  StreamSpec("networking.k8s.io/v1", "networkpolicies", scope),
                  StreamSpec("v1", "persistentvolumeclaims", scope),
                  StreamSpec("v1", "namespaces", None,
                             None if scope is None else f"metadata.name={scope}")]
    return specs


class ClusterReader:
    """The copy of what gke-scan reads, kept by one thread per stream."""

    def __init__(self, kube: KubeLister, namespaces: Iterable[str], label_selector: str = DEFAULT_LABEL_SELECTOR,
                 interval: float = DEFAULT_INTERVAL_SECONDS,
                 on_change: Callable[[ChangeEvent], None] | None = None,
                 workload_of: Callable[[str, dict[str, Any]], str | None] | None = None,
                 clock: Callable[[], float] = time.monotonic, log: Callable[[str], None] = log):
        self.kube = kube
        self.namespaces = tuple(namespaces)
        self.selector = parse_selector(label_selector)
        self.interval = interval
        self.on_change = on_change or (lambda event: None)
        self._resolve = workload_of or self._api_workload
        self.clock = clock
        self.log = log
        self._lock = threading.RLock()
        self._stores: dict[str, dict[tuple[str, str], dict[str, Any]]] = {kind: {} for kind in STORES}
        self._workloads: dict[str, tuple[str, str | None]] = {}  # pod UID -> (owners, workload)
        self._workloads_lock = threading.Lock()  # held only around the dict, never across an API read
        self.specs = stream_specs(self.namespaces)
        self.states: dict[StreamSpec, StreamState] = {spec: StreamState() for spec in self.specs}
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    # ── lifecycle ──

    def start(self) -> None:
        for spec in self.specs:
            thread = threading.Thread(target=self.run_stream, args=(spec,), name=f"gke-scan-{spec.label}",
                                      daemon=True)
            thread.start()
            self._threads.append(thread)

    def stop(self) -> None:
        self._stop.set()

    def run_stream(self, spec: StreamSpec) -> None:
        """List, watch, watch again, list again: until stop()."""
        state = self.states[spec]
        while not self._stop.is_set():
            try:
                version = self.relist(spec)
                version = self.watch_until_relist(spec, version)
            except Exception as exc:  # noqa: BLE001 - one stream's trouble never stops the others
                state.last_error = str(exc)
                # The copy isn't kept up to date until the next list, so the
                # intake reads the API for this namespace's pods meanwhile.
                state.synced = False
                if getattr(exc, "status", None) == 403:
                    if not state.forbidden:
                        self.log(f"{spec.label}: {exc}; trying again in {int(self.interval)}s, "
                                 "the other reads carry on")
                    state.forbidden = True
                    self._stop.wait(self.interval)
                else:
                    state.failures += 1
                    delay = min(ERROR_BACKOFF_START_SECONDS * 2 ** (state.failures - 1), ERROR_BACKOFF_MAX_SECONDS)
                    self.log(f"{spec.label}: {exc}; trying again in {delay:g}s")
                    self._stop.wait(delay)

    def watch_until_relist(self, spec: StreamSpec, version: str) -> str:
        """Watch from `version`, and again each time the API server ends a
        watch, until the interval is up or a 410 says to list again."""
        state = self.states[spec]
        while not self._stop.is_set():
            if state.listed_at is not None and self.clock() - state.listed_at >= self.interval:
                return version
            state.watches += 1
            try:
                for event in self.kube.watch(spec.api_version, spec.plural, spec.namespace, version,
                                             field_selector=spec.field_selector):
                    if self._stop.is_set():
                        return version
                    version = self.apply(spec, event) or version
                # The API server ended the watch: the stream is healthy again.
                state.failures, state.forbidden = 0, False
            except Exception as exc:
                if getattr(exc, "status", None) == 410:
                    self.log(f"{spec.label}: {exc}; listing again")
                    return version
                raise
        return version

    # ── the copy ──

    def relist(self, spec: StreamSpec) -> str:
        """List the stream's kind, bring the copy in line with it (reporting
        each difference as a change), and return the list's resourceVersion."""
        found = self.kube.list_objects(spec.api_version, spec.plural, spec.namespace,
                                       field_selector=spec.field_selector)
        items = [_slim(item) for item in found.get("items") or [] if isinstance(item, dict)]
        version = str(_metadata(found).get("resourceVersion") or "")
        state = self.states[spec]
        if spec.plural == "pods":
            self._read_workloads(items)
        events = []
        with self._lock:
            current = {}
            for item in items:
                if spec.plural == "pods":
                    # A list's items have no kind; the namespace is the item's own.
                    store = self._pod_store(item)
                    if store is None:
                        continue
                else:
                    store = self._store_of(spec)
                key = _key(item, "" if spec.plural == "namespaces" else None)
                if key is not None:
                    current[(store, key)] = item
            previous = {(store, key): obj for store in self._stores_of(spec)
                        for key, obj in self._stores[store].items() if self._in_scope(spec, key)}
            for (store, key), obj in previous.items():
                if (store, key) not in current or self._uid(current[(store, key)]) != self._uid(obj):
                    events.append(self._remove(store, key, obj))
            for (store, key), obj in current.items():
                old = self._stores[store].get(key)
                if old is None:
                    events.append(self._put(store, key, obj, "ADDED", None))
                elif _metadata(old).get("resourceVersion") != _metadata(obj).get("resourceVersion"):
                    events.append(self._put(store, key, obj, "MODIFIED", old))
            state.synced, state.last_error = True, None
            state.listed_at = self.clock()
            state.relists += 1
        self.log(f"{spec.label}: listed, {len(current)} kept" + (f", {len(events)} changed" if state.relists > 1 else ""))
        self._emit(events)
        return version

    def apply(self, spec: StreamSpec, event: dict[str, Any]) -> str | None:
        """One watch event into the copy; the resourceVersion it brings."""
        kind = event.get("type")
        obj = event.get("object")
        if not isinstance(obj, dict):
            return None
        version = _metadata(obj).get("resourceVersion")
        version = str(version) if version else None
        if kind == "BOOKMARK" or kind not in ("ADDED", "MODIFIED", "DELETED"):
            return version
        obj = _slim(obj)
        key = _key(obj, "" if spec.plural == "namespaces" else None)
        if key is None:
            return version
        if spec.plural == "pods" and kind != "DELETED":
            self._read_workloads([obj])
        events = []
        with self._lock:
            stores = self._stores_of(spec)
            old_store = next((s for s in stores if key in self._stores[s]), None)
            old = self._stores[old_store].get(key) if old_store else None
            new_store = None
            if kind != "DELETED":
                new_store = self._pod_store(obj) if spec.plural == "pods" else self._store_of(spec)
            if old_store is not None and (new_store != old_store or kind == "DELETED"
                                          or self._uid(old) != self._uid(obj)):
                events.append(self._remove(old_store, key, old))
                old = None
            if new_store is not None:
                current = self._stores[new_store].get(key)
                if current is None:
                    events.append(self._put(new_store, key, obj, "ADDED", None))
                elif _metadata(current).get("resourceVersion") != _metadata(obj).get("resourceVersion"):
                    events.append(self._put(new_store, key, obj, "MODIFIED", current))
        self._emit(events)
        return version

    def _store_of(self, spec: StreamSpec) -> str:
        return {"services": SERVICES, "networkpolicies": NETWORK_POLICIES,
                "persistentvolumeclaims": CLAIMS, "namespaces": NAMESPACES}[spec.plural]

    def _stores_of(self, spec: StreamSpec) -> tuple[str, ...]:
        return (AGENT_PODS, MCP_SERVERS) if spec.plural == "pods" else (self._store_of(spec),)

    def _in_scope(self, spec: StreamSpec, key: tuple[str, str]) -> bool:
        if spec.plural == "namespaces":
            return spec.field_selector is None or spec.field_selector == f"metadata.name={key[1]}"
        return spec.namespace is None or key[0] == spec.namespace

    def _pod_store(self, pod: dict[str, Any]) -> str | None:
        if selector_matches(self.selector, _labels(pod)):
            return AGENT_PODS
        if is_mcp_server(pod):
            return MCP_SERVERS
        return None

    @staticmethod
    def _uid(obj: dict[str, Any] | None) -> Any:
        return _metadata(obj).get("uid") if isinstance(obj, dict) else None

    def _put(self, store: str, key: tuple[str, str], obj: dict[str, Any], kind: str,
             old: dict[str, Any] | None) -> ChangeEvent:
        """Store obj; the change, its workloads worked out from both versions."""
        before = self._affected(store, old) if old is not None else set()
        self._stores[store][key] = obj
        return ChangeEvent(store, key[0], key[1], kind, frozenset(before | self._affected(store, obj)))

    def _remove(self, store: str, key: tuple[str, str], obj: dict[str, Any]) -> ChangeEvent:
        workloads = self._affected(store, obj)
        del self._stores[store][key]
        if store == AGENT_PODS:
            with self._workloads_lock:
                self._workloads.pop(str(self._uid(obj)), None)
        return ChangeEvent(store, key[0], key[1], "DELETED", frozenset(workloads))

    def _emit(self, events: list[ChangeEvent]) -> None:
        for event in events:
            try:
                self.on_change(event)
            except Exception as exc:  # noqa: BLE001 - a consumer's bug doesn't stop the reader
                self.log(f"a change consumer failed on {event.kind} {event.namespace}/{event.name}: {exc}")

    # ── affected workloads ──

    def _api_workload(self, namespace: str, pod: dict[str, Any]) -> str | None:
        name, _ = _workload_module().sandbox_name(self.kube, namespace, pod)
        return name

    def _read_workloads(self, pods: Iterable[dict[str, Any]]) -> None:
        """Read the workload of each agent pod the cache doesn't have yet.
        Called before the copy's lock is taken, never under it."""
        for pod in pods:
            if self._pod_store(pod) == AGENT_PODS:
                self.workload_of(pod)

    def workload_of(self, pod: dict[str, Any]) -> str | None:
        """The pod's `namespace/workload`, checked through the API once per
        pod UID and owner references; None when it can't be confirmed. It may
        read the API, so it is never called while the copy's lock is held."""
        metadata = _metadata(pod)
        uid, namespace = metadata.get("uid"), metadata.get("namespace")
        if not isinstance(uid, str) or not isinstance(namespace, str):
            return None
        owners = repr(metadata.get("ownerReferences"))
        with self._workloads_lock:
            cached = self._workloads.get(uid)
        if cached is not None and cached[0] == owners:
            return cached[1]
        try:
            name = self._resolve(namespace, pod)
        except Exception as exc:  # noqa: BLE001 - tried again on the pod's next change
            self.log(f"pod {namespace}/{metadata.get('name')}: its workload can't be read now: {exc}")
            return None
        with self._workloads_lock:
            self._workloads[uid] = (owners, name)
        return name

    def _known_workload(self, pod: dict[str, Any]) -> str | None:
        """The pod's workload from the cache alone, with no API read: safe
        under the copy's lock. None when it hasn't been read, or couldn't be."""
        metadata = _metadata(pod)
        with self._workloads_lock:
            cached = self._workloads.get(str(metadata.get("uid")))
        return cached[1] if cached is not None and cached[0] == repr(metadata.get("ownerReferences")) else None

    def _workloads_where(self, test: Callable[[dict[str, Any]], bool]) -> set[str]:
        found = set()
        for pod in list(self._stores[AGENT_PODS].values()):
            if test(pod):
                name = self._known_workload(pod)
                if name:
                    found.add(name)
        return found

    def _naming(self, hosts_of: Callable[[str], set[str]]) -> set[str]:
        """Workloads whose pods' env URLs name one of hosts_of(the pod's namespace)."""
        return self._workloads_where(lambda pod: bool(env_url_hosts(pod) & hosts_of(_metadata(pod).get("namespace"))))

    def _affected(self, store: str, obj: dict[str, Any]) -> set[str]:
        namespace = _metadata(obj).get("namespace")
        if store == AGENT_PODS:
            name = self._known_workload(obj)
            return {name} if name else set()
        if store == NAMESPACES:
            name = _metadata(obj).get("name")
            return self._workloads_where(lambda pod: _metadata(pod).get("namespace") == name)
        in_namespace = self._workloads_where(lambda pod: _metadata(pod).get("namespace") == namespace)
        if store == NETWORK_POLICIES:
            return in_namespace
        if store == SERVICES:
            return in_namespace | self._naming(lambda ns: service_hosts(obj, ns == namespace))
        if store == CLAIMS:
            claim = _metadata(obj).get("name")
            return self._workloads_where(lambda pod: _metadata(pod).get("namespace") == namespace
                                         and claim in claims_mounted(pod))
        if store == MCP_SERVERS:
            services = [svc for svc in self._stores[SERVICES].values() if service_selects(svc, obj)]
            return self._naming(lambda ns: set().union(*(service_hosts(svc, ns == namespace) for svc in services)))
        return set()

    # ── reads ──

    def objects(self, store: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._stores[store].values())

    def synced(self, namespace: str | None = None) -> bool:
        """Every stream listed at least once, or, given a namespace, its pods'."""
        if namespace is None:
            return all(state.synced for state in self.states.values())
        return any(state.synced for spec, state in self.states.items()
                   if spec.plural == "pods" and spec.namespace in (namespace, None))

    def cached_pod(self, namespace: str, name: str, uid: str) -> dict[str, Any] | None:
        """The agent pod from the copy when the copy has it with this UID and
        its namespace's pods have been listed; else None, and the caller reads
        the API."""
        if not self.synced(namespace):
            return None
        with self._lock:
            pod = self._stores[AGENT_PODS].get((namespace, name))
        return pod if pod is not None and self._uid(pod) == uid else None
