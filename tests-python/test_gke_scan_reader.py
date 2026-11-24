"""RC-550: gke-scan reads its full configuration, and lists and watches the
cluster.

The ticket's exit criteria, against a fake Kubernetes API on loopback (list,
watch with bookmarks, 410, 403 and 5xx):

* A missing required flag exits 2 naming it; env variables override defaults.
* 5xx backs off; a watch timeout re-watches; 410 relists.
* Each kind's change maps to the right workloads.
* A 403 in one namespace leaves the others readable.
* The intake's tests still pass with the pod check on the watched copy
  (test_gke_scan_intake.py, and the watched-copy tests here).
"""

from __future__ import annotations

import importlib.util
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
CENTRAL = ROOT / "tools" / "scan" / "gke" / "central_service"


def _load(name: str, path: Path):
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


gke_scan = _load("gke_scan_entry", CENTRAL / "gke_scan.py")
kube = gke_scan.kube_module()
reader_mod = gke_scan.reader_module()
intake = gke_scan.intake_module()

REQUIRED_ENV = {"RAIL_CLUSTER_NAME": "gke-test", "RAIL_CENTER_URL": "https://rail-center.example.com",
                "RAIL_INTAKE_TLS_CERT_FILE": "/etc/rail/intake/tls.crt",
                "RAIL_INTAKE_TLS_KEY_FILE": "/etc/rail/intake/tls.key", "RAIL_NAMESPACES": "agents"}


def meta(name: str, namespace: str | None, uid: str | None = None, rv: str = "1",
         labels: dict[str, str] | None = None, **extra: Any) -> dict[str, Any]:
    metadata: dict[str, Any] = {"name": name, "uid": uid or f"uid-{name}", "resourceVersion": rv,
                                "labels": labels or {}, **extra}
    if namespace is not None:
        metadata["namespace"] = namespace
    return metadata


def agent_pod(name: str, namespace: str = "agents", rv: str = "1", uid: str | None = None,
              env: dict[str, str] | None = None, claims: list[str] | None = None,
              labels: dict[str, str] | None = None) -> dict[str, Any]:
    return {"metadata": meta(name, namespace, uid, rv, labels if labels is not None
                             else {"rail.datrail.io/scan": "true", "app": name.rsplit("-", 2)[0]}),
            "spec": {"containers": [{"name": "agent", "env": [{"name": k, "value": v}
                                                              for k, v in (env or {}).items()]}],
                     "volumes": [{"name": c, "persistentVolumeClaim": {"claimName": c}} for c in claims or []]}}


def mcp_pod(name: str, namespace: str = "agents", rv: str = "1", app: str = "finretail-mcp",
            annotated: bool = False) -> dict[str, Any]:
    labels = {"app": app}
    extra = {}
    if annotated:
        extra["annotations"] = {"rail.datrail.io/source": "github.com/example/finretail-mcp"}
    else:
        labels["rail.datrail.io/mcp-server"] = "true"
    return {"metadata": meta(name, namespace, None, rv, labels, **extra), "spec": {"containers": []}}


def service(name: str, namespace: str = "agents", rv: str = "1", selector: dict[str, str] | None = None):
    return {"metadata": meta(name, namespace, None, rv), "spec": {"selector": selector or {}}}


def simple(name: str, namespace: str | None, rv: str = "1", labels: dict[str, str] | None = None):
    return {"metadata": meta(name, namespace, None, rv, labels), "spec": {}}


def workload_by_name(namespace: str, pod: dict[str, Any]) -> str | None:
    """A Deployment's pod <deployment>-<hash>-<suffix>: its workload, without the API."""
    return f"{namespace}/{pod['metadata']['name'].rsplit('-', 2)[0]}"


# ── a fake Kubernetes API with list and watch ──────────────────────────────

class FakeAPI:
    """Objects by (plural, namespace or None); a list answers them, a watch
    streams what `send` pushes until `end_watches` or `watch_seconds`."""

    def __init__(self) -> None:
        self.objects: dict[tuple[str, str | None], list[dict[str, Any]]] = {}
        self.version = 100
        self.requests: list[dict[str, Any]] = []
        self.forbidden: set[tuple[str, str | None]] = set()
        self.fail_lists: list[tuple[int, dict[str, str]]] = []  # status, headers for the next lists
        self.gone_next_watch: str | None = None  # the plural whose next watch gets 410
        self.fail_watches: dict[str, int] = {}  # plural -> the status every watch of it gets
        self.watch_seconds = 30.0
        self.watches: list[queue.Queue] = []
        self.lock = threading.Lock()
        api = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args: Any) -> None:
                return

            def _json(self, code: int, body: Any, headers: dict[str, str] | None = None) -> None:
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                parts = urlsplit(self.path)
                query = {k: v[0] for k, v in parse_qs(parts.query).items()}
                segments = parts.path.strip("/").split("/")
                namespace = None
                if "namespaces" in segments[:-1]:
                    namespace = segments[segments.index("namespaces") + 1]
                plural = segments[-1]
                watching = query.get("watch") == "true"
                with api.lock:
                    api.requests.append({"plural": plural, "namespace": namespace, "query": query,
                                         "auth": self.headers.get("Authorization")})
                if (plural, namespace) in api.forbidden:
                    self._json(403, {"kind": "Status", "code": 403})
                    return
                if not watching:
                    with api.lock:
                        failure = api.fail_lists.pop(0) if api.fail_lists else None
                    if failure:
                        self._json(failure[0], {"kind": "Status", "code": failure[0]}, failure[1])
                        return
                    items = api.items(plural, namespace, query.get("fieldSelector"))
                    self._json(200, {"kind": "List", "metadata": {"resourceVersion": str(api.version)},
                                     "items": items})
                    return
                if plural in api.fail_watches:
                    code = api.fail_watches[plural]
                    self._json(code, {"kind": "Status", "code": code})
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                if api.gone_next_watch == plural:
                    api.gone_next_watch = None
                    self.wfile.write(json.dumps({"type": "ERROR", "object": {
                        "kind": "Status", "code": 410, "reason": "Expired"}}).encode() + b"\n")
                    return
                events: queue.Queue = queue.Queue()
                events.plural, events.namespace = plural, namespace  # type: ignore[attr-defined]
                with api.lock:
                    api.watches.append(events)
                deadline = time.monotonic() + api.watch_seconds
                try:
                    while time.monotonic() < deadline:
                        try:
                            event = events.get(timeout=0.05)
                        except queue.Empty:
                            continue
                        if event is None:
                            break
                        self.wfile.write(json.dumps(event).encode() + b"\n")
                        self.wfile.flush()
                finally:
                    with api.lock:
                        api.watches.remove(events)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()

    def items(self, plural: str, namespace: str | None, field_selector: str | None) -> list[dict[str, Any]]:
        with self.lock:
            if namespace is None and plural != "namespaces":
                found = [o for (p, _), objs in self.objects.items() if p == plural for o in objs]
            else:
                found = list(self.objects.get((plural, namespace), []))
        if field_selector and field_selector.startswith("metadata.name="):
            name = field_selector.split("=", 1)[1]
            found = [o for o in found if o["metadata"]["name"] == name]
        return found

    def put(self, plural: str, namespace: str | None, obj: dict[str, Any]) -> None:
        with self.lock:
            key = (plural, None if plural == "namespaces" else namespace)
            objs = [o for o in self.objects.get(key, []) if o["metadata"]["name"] != obj["metadata"]["name"]]
            self.objects[key] = objs + [obj]

    def send(self, plural: str, namespace: str | None, kind: str, obj: dict[str, Any]) -> None:
        with self.lock:
            self.version += 1
            obj["metadata"]["resourceVersion"] = str(self.version)
            for events in self.watches:
                if events.plural == plural and events.namespace in (namespace, None):  # type: ignore[attr-defined]
                    events.put({"type": kind, "object": obj})

    def end_watches(self) -> None:
        with self.lock:
            for events in self.watches:
                events.put(None)

    def watching(self, plural: str, namespace: str | None = "agents") -> bool:
        """A watch of the kind is open and will get what `send` pushes."""
        with self.lock:
            return any(w.plural == plural and w.namespace == namespace for w in self.watches)  # type: ignore[attr-defined]

    def watch_requests(self, plural: str, namespace: str | None = "agents") -> list[dict[str, Any]]:
        with self.lock:
            return [r for r in self.requests if r["plural"] == plural and r["namespace"] == namespace
                    and r["query"].get("watch") == "true"]

    def list_requests(self, plural: str, namespace: str | None = "agents") -> list[dict[str, Any]]:
        with self.lock:
            return [r for r in self.requests if r["plural"] == plural and r["namespace"] == namespace
                    and r["query"].get("watch") != "true"]

    def close(self) -> None:
        self.end_watches()
        self.server.shutdown()
        self.server.server_close()


def wait_for(test, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if test():
            return
        time.sleep(0.02)
    raise AssertionError("timed out waiting")


class APITestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.api = FakeAPI()
        self.addCleanup(self.api.close)
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        token = Path(folder.name) / "token"
        token.write_text("gke-scan-sa-token\n")
        self.sleeps: list[float] = []
        self.client = kube.KubeClient(self.api.url, str(token), str(Path(folder.name) / "ca.crt"),
                                      sleep=self.sleeps.append)
        self.logs: list[str] = []
        self.events: list[Any] = []

    def reader(self, namespaces=("agents",), interval: float = 3600, **kwargs: Any):
        reader = reader_mod.ClusterReader(self.client, namespaces, interval=interval, on_change=self.events.append,
                                          workload_of=workload_by_name, log=self.logs.append, **kwargs)
        self.addCleanup(reader.stop)
        return reader


# ── configuration ───────────────────────────────────────────────────────────

class ConfigTest(unittest.TestCase):
    def test_a_missing_required_flag_exits_2_naming_it(self):
        env = {"PATH": os.environ.get("PATH", ""), **{k: v for k, v in REQUIRED_ENV.items()
                                                      if k != "RAIL_NAMESPACES"}}
        done = subprocess.run([sys.executable, str(CENTRAL / "gke_scan.py")], capture_output=True, text=True, env=env)
        self.assertEqual(done.returncode, 2)
        self.assertIn("--namespaces/RAIL_NAMESPACES required", done.stderr)
        self.assertNotIn("--cluster-name", done.stderr)

    def test_the_defaults(self):
        config = gke_scan.parse_config([], REQUIRED_ENV)
        self.assertEqual(config.namespaces, ("agents",))
        self.assertEqual(config.label_selector, "rail.datrail.io/scan=true")
        self.assertEqual((config.interval, config.sidecar_interval), (3600, 3600))
        self.assertEqual(config.layer_budget, 2 * 1024 ** 3)
        self.assertTrue(config.registry_access)
        self.assertFalse(config.probe_external)
        self.assertFalse(config.register_without_sidecar)
        self.assertIsNone(config.data_guardrail_url)
        self.assertEqual(config.listen, ("0.0.0.0", 8443))

    def test_env_variables_override_defaults(self):
        config = gke_scan.parse_config([], {
            **REQUIRED_ENV, "RAIL_NAMESPACES": "agents, gke-test,agents", "RAIL_LABEL_SELECTOR": "team in (a,b)",
            "RAIL_INTERVAL_SECONDS": "600", "RAIL_REGISTRY_ACCESS": "false", "RAIL_LAYER_BUDGET": "512Mi",
            "RAIL_PROBE_EXTERNAL": "yes", "RAIL_DATA_GUARDRAIL_URL": "https://rail-center.example.com/data-guardrail",
            "RAIL_SIDECAR_INTERVAL_SECONDS": "120", "RAIL_REGISTER_WITHOUT_SIDECAR": "1"})
        self.assertEqual(config.namespaces, ("agents", "gke-test"))
        self.assertEqual(config.label_selector, "team in (a,b)")
        self.assertEqual((config.interval, config.sidecar_interval), (600, 120))
        self.assertFalse(config.registry_access)
        self.assertEqual(config.layer_budget, 512 * 1024 ** 2)
        self.assertTrue(config.probe_external)
        self.assertTrue(config.register_without_sidecar)
        self.assertEqual(config.data_guardrail_url, "https://rail-center.example.com/data-guardrail")

    def test_a_flag_overrides_its_env_variable(self):
        config = gke_scan.parse_config(
            ["--namespaces", "*", "--interval", "900", "--no-probe-external", "--registry-access", "--layer-budget", "1G"],
            {**REQUIRED_ENV, "RAIL_INTERVAL_SECONDS": "60", "RAIL_PROBE_EXTERNAL": "true",
             "RAIL_REGISTRY_ACCESS": "false"})
        self.assertEqual(config.namespaces, ("*",))
        self.assertEqual(config.interval, 900)
        self.assertFalse(config.probe_external)
        self.assertTrue(config.registry_access)
        self.assertEqual(config.layer_budget, 10 ** 9)

    def test_a_value_that_doesnt_parse_names_its_flag(self):
        for variable, value, named in (
                ("RAIL_NAMESPACES", "agents,*", "--namespaces/RAIL_NAMESPACES"),
                ("RAIL_NAMESPACES", "Agents", "--namespaces/RAIL_NAMESPACES"),
                ("RAIL_INTERVAL_SECONDS", "0", "--interval/RAIL_INTERVAL_SECONDS"),
                ("RAIL_SIDECAR_INTERVAL_SECONDS", "2m", "--sidecar-interval/RAIL_SIDECAR_INTERVAL_SECONDS"),
                ("RAIL_LAYER_BUDGET", "2TB", "--layer-budget/RAIL_LAYER_BUDGET"),
                ("RAIL_PROBE_EXTERNAL", "maybe", "--probe-external/RAIL_PROBE_EXTERNAL"),
                ("RAIL_LABEL_SELECTOR", "a=b=c", "--label-selector/RAIL_LABEL_SELECTOR"),
                ("RAIL_DATA_GUARDRAIL_URL", "ftp://x", "--data-guardrail-url/RAIL_DATA_GUARDRAIL_URL"),
                ("RAIL_INTAKE_LISTEN", "8443", "--listen/RAIL_INTAKE_LISTEN")):
            with self.subTest(variable=variable, value=value):
                with self.assertRaises(gke_scan.ConfigError) as raised:
                    gke_scan.parse_config([], {**REQUIRED_ENV, variable: value})
                self.assertIn(named, str(raised.exception))

    def test_a_bad_value_exits_2(self):
        env = {"PATH": os.environ.get("PATH", ""), **REQUIRED_ENV, "RAIL_INTERVAL_SECONDS": "soon"}
        done = subprocess.run([sys.executable, str(CENTRAL / "gke_scan.py")], capture_output=True, text=True, env=env)
        self.assertEqual(done.returncode, 2)
        self.assertIn("--interval/RAIL_INTERVAL_SECONDS", done.stderr)


class SelectorTest(unittest.TestCase):
    def test_equality_set_and_existence_requirements(self):
        selector = reader_mod.parse_selector("rail.datrail.io/scan=true,tier!=test,team in (a, b),!legacy,app")
        match = reader_mod.selector_matches
        self.assertTrue(match(selector, {"rail.datrail.io/scan": "true", "team": "a", "app": "x"}))
        self.assertFalse(match(selector, {"rail.datrail.io/scan": "true", "team": "c", "app": "x"}))
        self.assertFalse(match(selector, {"rail.datrail.io/scan": "true", "team": "a", "app": "x", "legacy": ""}))
        self.assertFalse(match(selector, {"rail.datrail.io/scan": "true", "team": "a", "app": "x", "tier": "test"}))
        self.assertFalse(match(selector, {"rail.datrail.io/scan": "true", "team": "a"}))
        self.assertTrue(match(reader_mod.parse_selector("a==b,c notin (d)"), {"a": "b"}))

    def test_an_invalid_selector_is_refused(self):
        for text in ("a=b=c", "a in ()", ",", "bad key=x", "a in (b"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                reader_mod.parse_selector(text)


# ── KubeClient: list, watch, backoff ────────────────────────────────────────

class KubeListWatchTest(APITestCase):
    def test_a_list_sends_gke_scans_credential_and_the_selectors(self):
        self.api.put("pods", "agents", agent_pod("agent-a-1-x"))
        found = self.client.list_objects("v1", "pods", "agents", label_selector="a=b", field_selector="x=y")
        self.assertEqual([i["metadata"]["name"] for i in found["items"]], ["agent-a-1-x"])
        self.assertEqual(found["metadata"]["resourceVersion"], "100")
        sent = self.api.requests[-1]
        self.assertEqual(sent["auth"], "Bearer gke-scan-sa-token")
        self.assertEqual(sent["query"], {"labelSelector": "a=b", "fieldSelector": "x=y"})

    def test_5xx_backs_off_then_succeeds(self):
        self.api.fail_lists = [(500, {}), (503, {}), (429, {"Retry-After": "3"})]
        found = self.client.list_objects("v1", "services", "agents")
        self.assertEqual(found["items"], [])
        self.assertEqual(self.sleeps, [1.0, 2.0, 3.0])

    def test_5xx_past_the_retries_is_a_kube_error_with_its_status(self):
        self.api.fail_lists = [(500, {})] * kube.RETRY_ATTEMPTS
        with self.assertRaises(kube.KubeError) as raised:
            self.client.list_objects("v1", "services", "agents")
        self.assertEqual(raised.exception.status, 500)
        self.assertEqual(len(self.sleeps), kube.RETRY_ATTEMPTS - 1)

    def test_403_and_410_are_their_own_errors_and_not_retried(self):
        self.api.forbidden.add(("services", "agents"))
        with self.assertRaises(kube.KubeForbidden):
            self.client.list_objects("v1", "services", "agents")
        self.api.gone_next_watch = "pods"
        with self.assertRaises(kube.KubeGone):
            list(self.client.watch("v1", "pods", "agents", "5"))
        self.assertEqual(self.sleeps, [])

    def test_a_watch_streams_events_with_bookmarks_and_a_timeout(self):
        events = []
        done = threading.Event()

        def run():
            events.extend(self.client.watch("v1", "pods", "agents", "100", timeout_seconds=300))
            done.set()

        threading.Thread(target=run, daemon=True).start()
        wait_for(lambda: self.api.watches)
        self.api.send("pods", "agents", "ADDED", agent_pod("agent-a-1-x"))
        self.api.send("pods", "agents", "BOOKMARK", {"metadata": {"resourceVersion": "150"}})
        self.api.end_watches()
        self.assertTrue(done.wait(5))
        self.assertEqual([e["type"] for e in events], ["ADDED", "BOOKMARK"])
        query = self.api.watch_requests("pods")[0]["query"]
        self.assertEqual(query["resourceVersion"], "100")
        self.assertEqual(query["allowWatchBookmarks"], "true")
        self.assertEqual(query["timeoutSeconds"], "300")

    def test_a_cluster_wide_list_and_a_namespace_by_name(self):
        self.api.put("pods", "agents", agent_pod("agent-a-1-x"))
        self.api.put("pods", "other", agent_pod("agent-b-1-x", "other"))
        self.assertEqual(len(self.client.list_objects("v1", "pods")["items"]), 2)
        self.api.put("namespaces", None, simple("agents", None))
        self.api.put("namespaces", None, simple("other", None))
        found = self.client.list_objects("v1", "namespaces", field_selector="metadata.name=agents")
        self.assertEqual([i["metadata"]["name"] for i in found["items"]], ["agents"])


# ── the reader against the fake API ─────────────────────────────────────────

class ReaderStreamTest(APITestCase):
    def test_the_reader_lists_then_watches_from_the_lists_version(self):
        self.api.put("pods", "agents", agent_pod("agent-a-1-x"))
        reader = self.reader()
        reader.start()
        wait_for(lambda: reader.synced())
        wait_for(lambda: self.api.watch_requests("pods"))
        self.assertEqual(self.api.watch_requests("pods")[0]["query"]["resourceVersion"], "100")
        self.assertEqual([p["metadata"]["name"] for p in reader.objects("agent_pods")], ["agent-a-1-x"])
        added = [e for e in self.events if e.kind == "agent_pods"]
        self.assertEqual(added[0].workloads, frozenset({"agents/agent-a"}))

    def test_a_watch_timeout_re_watches_from_the_last_version_seen(self):
        reader = self.reader()
        reader.start()
        wait_for(lambda: self.api.watching("pods"))
        self.api.send("pods", "agents", "ADDED", agent_pod("agent-a-1-x"))
        self.api.send("pods", "agents", "BOOKMARK", {"metadata": {"resourceVersion": "0"}})
        wait_for(lambda: reader.objects("agent_pods"))
        self.api.end_watches()  # the API server ends the watch, as it does after timeoutSeconds
        wait_for(lambda: len(self.api.watch_requests("pods")) >= 2)
        self.assertEqual(self.api.watch_requests("pods")[1]["query"]["resourceVersion"], "102")
        self.assertEqual(len(self.api.list_requests("pods")), 1, "a timed-out watch doesn't relist")

    def test_410_relists_and_reports_what_changed_meanwhile(self):
        self.api.put("pods", "agents", agent_pod("agent-a-1-x"))
        reader = self.reader()
        reader.start()
        wait_for(lambda: self.api.watch_requests("pods"))
        # Missed while no watch ran: a deletes, b arrives.
        self.api.objects[("pods", "agents")] = [agent_pod("agent-b-1-x")]
        self.api.gone_next_watch = "pods"
        self.api.end_watches()
        wait_for(lambda: len(self.api.list_requests("pods")) >= 2)
        wait_for(lambda: [p["metadata"]["name"] for p in reader.objects("agent_pods")] == ["agent-b-1-x"])
        changes = {(e.name, e.type) for e in self.events if e.kind == "agent_pods"}
        self.assertIn(("agent-a-1-x", "DELETED"), changes)
        self.assertIn(("agent-b-1-x", "ADDED"), changes)
        self.assertTrue(any("listing again" in line for line in self.logs))

    def test_every_interval_relists(self):
        reader = self.reader(interval=0.3)
        self.api.watch_seconds = 0.1
        reader.start()
        wait_for(lambda: len(self.api.list_requests("services")) >= 3)

    def test_a_403_in_one_namespace_leaves_the_others_readable(self):
        self.api.forbidden.add(("pods", "locked"))
        self.api.put("pods", "agents", agent_pod("agent-a-1-x"))
        reader = self.reader(namespaces=("agents", "locked"))
        reader.start()
        wait_for(lambda: reader.synced("agents"))
        wait_for(lambda: any("pods in locked" in line and "403" in line for line in self.logs))
        self.assertFalse(reader.synced("locked"))
        self.assertTrue(reader.cached_pod("agents", "agent-a-1-x", "uid-agent-a-1-x"))
        wait_for(lambda: self.api.watch_requests("services", "locked"))  # the namespace's other kinds carry on
        wait_for(lambda: self.api.watching("pods"))
        self.api.send("pods", "agents", "ADDED", agent_pod("agent-c-1-x"))
        wait_for(lambda: len(reader.objects("agent_pods")) == 2)
        self.assertEqual(sum("pods in locked" in line for line in self.logs), 1, "logged once, not per retry")

    def test_a_stream_that_fails_stops_answering_the_intake_until_it_lists_again(self):
        self.api.put("pods", "agents", agent_pod("agent-a-1-x"))
        reader = self.reader()
        reader.start()
        wait_for(lambda: reader.cached_pod("agents", "agent-a-1-x", "uid-agent-a-1-x"))
        self.api.forbidden.add(("pods", "agents"))
        self.api.gone_next_watch = "pods"
        self.api.end_watches()
        wait_for(lambda: not reader.synced("agents"))
        self.assertIsNone(reader.cached_pod("agents", "agent-a-1-x", "uid-agent-a-1-x"))

    def test_all_namespaces_reads_cluster_wide(self):
        self.api.put("pods", "agents", agent_pod("agent-a-1-x"))
        self.api.put("pods", "other", agent_pod("agent-b-1-x", "other"))
        reader = self.reader(namespaces=("*",))
        reader.start()
        wait_for(lambda: len(reader.objects("agent_pods")) == 2)
        self.assertTrue(self.api.list_requests("pods", None))
        self.assertTrue(reader.synced("other"))

    def test_a_kind_that_lists_but_cant_be_watched_still_backs_off(self):
        self.api.fail_watches["pods"] = 500
        reader = self.reader()
        reader.start()
        # Each list succeeds; the backoff grows anyway rather than starting over at 1s.
        wait_for(lambda: any("pods in agents" in line and "trying again in 2s" in line for line in self.logs))
        self.assertGreaterEqual(len(self.api.list_requests("pods")), 2)
        self.assertFalse(any("services in agents" in line and "trying again" in line for line in self.logs))

    def test_a_forbidden_watch_is_logged_once_across_relists(self):
        self.api.fail_watches["pods"] = 403
        reader = self.reader(interval=0.1)
        reader.start()
        wait_for(lambda: len(self.api.list_requests("pods")) >= 3)
        forbidden = [line for line in self.logs if "pods in agents" in line and "403" in line]
        self.assertEqual(len(forbidden), 1, forbidden)

    def test_an_unreachable_api_backs_off(self):
        self.api.close()
        reader = self.reader()
        reader.start()
        wait_for(lambda: any("trying again in 1s" in line for line in self.logs))
        self.assertFalse(reader.synced())


# ── affected workloads ──────────────────────────────────────────────────────

class StubKube:
    def __init__(self) -> None:
        self.lists: dict[tuple[str, str | None, str | None], list[dict[str, Any]]] = {}

    def list_objects(self, api_version, plural, namespace=None, label_selector=None, field_selector=None):
        return {"metadata": {"resourceVersion": "1"}, "items": self.lists.get((plural, namespace, field_selector), [])}

    def watch(self, *args, **kwargs):
        return iter(())

    def get_object(self, *args):
        return None


class AffectedWorkloadsTest(unittest.TestCase):
    """Each kind's change maps to the right workloads."""

    def setUp(self) -> None:
        self.kube = StubKube()
        self.events: list[Any] = []
        self.reader = reader_mod.ClusterReader(self.kube, ("agents", "tools"), on_change=self.events.append,
                                               workload_of=workload_by_name, log=lambda line: None)
        self.spec = {(s.plural, s.namespace if s.plural != "namespaces" else s.field_selector): s
                     for s in self.reader.specs}
        mcp_url = {"AGENT_MCP_URL": "http://finretail-mcp.tools.svc.cluster.local:8080/mcp"}
        self.kube.lists[("pods", "agents", None)] = [
            agent_pod("payments-6d9f-a", env=mcp_url, claims=["payments-data"]),
            agent_pod("payments-6d9f-b", env=mcp_url, claims=["payments-data"]),
            agent_pod("support-77aa-c", env={"AGENT_MCP_URL": "http://helpdesk:9000"}),
            {"metadata": meta("unlabeled-1-x", "agents"), "spec": {}},
        ]
        self.kube.lists[("pods", "tools", None)] = [agent_pod("research-55bb-d", "tools",
                                                              env={"AGENT_MCP_URL": "http://finretail-mcp:8080"}),
                                                    mcp_pod("finretail-mcp-0", "tools")]
        self.kube.lists[("services", "tools", None)] = [service("finretail-mcp", "tools",
                                                                selector={"app": "finretail-mcp"})]
        for spec in self.reader.specs:
            self.reader.relist(spec)
        self.events.clear()

    def change(self, plural: str, scope: str | None, kind: str, obj: dict[str, Any]):
        self.events.clear()
        self.reader.apply(self.spec[(plural, scope)], {"type": kind, "object": obj})
        return self.events

    def test_unlabeled_pods_are_dropped_and_mcp_servers_kept_apart(self):
        names = sorted(p["metadata"]["name"] for p in self.reader.objects("agent_pods"))
        self.assertEqual(names, ["payments-6d9f-a", "payments-6d9f-b", "research-55bb-d", "support-77aa-c"])
        self.assertEqual([p["metadata"]["name"] for p in self.reader.objects("mcp_servers")], ["finretail-mcp-0"])

    def test_a_pod_affects_its_workload(self):
        events = self.change("pods", "agents", "MODIFIED", agent_pod("payments-6d9f-a", rv="2"))
        self.assertEqual([(e.kind, e.type, e.workloads) for e in events],
                         [("agent_pods", "MODIFIED", frozenset({"agents/payments"}))])
        events = self.change("pods", "agents", "DELETED", agent_pod("payments-6d9f-b", rv="3"))
        self.assertEqual(events[0].type, "DELETED")
        self.assertEqual(events[0].workloads, frozenset({"agents/payments"}))

    def test_a_pod_that_loses_its_label_leaves_the_copy(self):
        relabeled = agent_pod("support-77aa-c", rv="2", labels={"app": "support"})
        events = self.change("pods", "agents", "MODIFIED", relabeled)
        self.assertEqual([(e.type, e.workloads) for e in events], [("DELETED", frozenset({"agents/support"}))])

    def test_an_unchanged_resource_version_is_no_change(self):
        self.assertEqual(self.change("pods", "agents", "MODIFIED", agent_pod("payments-6d9f-a")), [])

    def test_a_service_affects_its_namespace_and_those_that_name_it(self):
        events = self.change("services", "tools", "MODIFIED",
                             service("finretail-mcp", "tools", rv="2", selector={"app": "finretail-mcp"}))
        # tools/research by its namespace (and by name); agents/payments by its env URL's full name.
        self.assertEqual(events[0].workloads, frozenset({"tools/research", "agents/payments"}))
        events = self.change("services", "agents", "ADDED", service("helpdesk", "agents", rv="3"))
        self.assertEqual(events[0].workloads, frozenset({"agents/payments", "agents/support"}))

    def test_a_network_policy_or_the_namespace_affects_every_workload_in_it(self):
        events = self.change("networkpolicies", "agents", "ADDED", simple("deny-egress", "agents", rv="2"))
        self.assertEqual(events[0].workloads, frozenset({"agents/payments", "agents/support"}))
        events = self.change("namespaces", "metadata.name=tools", "MODIFIED",
                             simple("tools", None, rv="2", labels={"rail.datrail.io/owner": "research"}))
        self.assertEqual(events[0].workloads, frozenset({"tools/research"}))

    def test_a_claim_affects_the_workloads_that_mount_it(self):
        events = self.change("persistentvolumeclaims", "agents", "ADDED", simple("payments-data", "agents", rv="2"))
        self.assertEqual(events[0].workloads, frozenset({"agents/payments"}))
        events = self.change("persistentvolumeclaims", "agents", "ADDED", simple("unused", "agents", rv="3"))
        self.assertEqual(events[0].workloads, frozenset())

    def test_an_mcp_server_affects_the_workloads_that_name_it(self):
        events = self.change("pods", "tools", "MODIFIED", mcp_pod("finretail-mcp-0", "tools", rv="2"))
        self.assertEqual([(e.kind, e.workloads) for e in events],
                         [("mcp_servers", frozenset({"agents/payments", "tools/research"}))])

    def test_an_mcp_server_found_by_its_source_annotation(self):
        events = self.change("pods", "tools", "ADDED", mcp_pod("finretail-mcp-1", "tools", annotated=True))
        self.assertEqual(events[0].kind, "mcp_servers")
        self.assertEqual(events[0].workloads, frozenset({"agents/payments", "tools/research"}))

    def test_a_bare_service_name_only_counts_in_its_own_namespace(self):
        self.kube.lists[("services", "agents", None)] = [service("finretail-mcp", "agents",
                                                                 selector={"app": "finretail-mcp"})]
        self.reader.relist(self.spec[("services", "agents")])
        events = self.change("pods", "agents", "ADDED", mcp_pod("finretail-mcp-9", "agents", rv="5"))
        # research (in tools) names "finretail-mcp" bare: that's tools' Service, not this one.
        self.assertEqual(events[0].workloads, frozenset())

    def test_a_pods_workload_is_read_once_per_uid_and_owners(self):
        calls = []

        def counting(namespace, pod):
            calls.append(pod["metadata"]["name"])
            return workload_by_name(namespace, pod)

        reader = reader_mod.ClusterReader(self.kube, ("agents",), workload_of=counting, log=lambda line: None)
        for spec in reader.specs:
            reader.relist(spec)
        spec = next(s for s in reader.specs if s.plural == "networkpolicies")
        reader.apply(spec, {"type": "ADDED", "object": simple("p", "agents", rv="9")})
        self.assertEqual(sorted(calls), ["payments-6d9f-a", "payments-6d9f-b", "support-77aa-c"])

    def test_a_workload_that_cant_be_read_now_is_tried_again(self):
        attempts = []

        def flaky(namespace, pod):
            attempts.append(1)
            if len(attempts) == 1:
                raise kube.KubeError("GET replicasets: HTTP 500", 500)
            return workload_by_name(namespace, pod)

        logs: list[str] = []
        reader = reader_mod.ClusterReader(StubKube(), ("agents",), workload_of=flaky, log=logs.append)
        pods = next(s for s in reader.specs if s.plural == "pods")
        events: list[Any] = []
        reader.on_change = events.append
        reader.apply(pods, {"type": "ADDED", "object": agent_pod("payments-6d9f-a", rv="2")})
        reader.apply(pods, {"type": "MODIFIED", "object": agent_pod("payments-6d9f-a", rv="3")})
        self.assertEqual([e.workloads for e in events], [frozenset(), frozenset({"agents/payments"})])
        self.assertTrue(any("can't be read now" in line for line in logs))

    def test_a_slow_workload_read_doesnt_hold_up_the_intake(self):
        release, reading = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def slow(namespace, pod):
            if pod["metadata"]["name"].startswith("slow-"):
                reading.set()
                release.wait(5)
            return workload_by_name(namespace, pod)

        reader = reader_mod.ClusterReader(StubKube(), ("agents",), workload_of=slow, log=lambda line: None)
        reader.kube.lists[("pods", "agents", None)] = [agent_pod("payments-6d9f-a")]
        for spec in reader.specs:
            reader.relist(spec)
        pods = next(s for s in reader.specs if s.plural == "pods")
        services = next(s for s in reader.specs if s.plural == "services")
        adding = threading.Thread(target=reader.apply, daemon=True,
                                  args=(pods, {"type": "ADDED", "object": agent_pod("slow-6d9f-b", rv="2")}))
        adding.start()
        self.assertTrue(reading.wait(5))
        # While that pod's owners are being read: the intake's check and the other streams go on.
        answered: list[Any] = []
        checking = threading.Thread(daemon=True, target=lambda: (
            answered.append(reader.cached_pod("agents", "payments-6d9f-a", "uid-payments-6d9f-a")),
            reader.apply(services, {"type": "ADDED", "object": service("helpdesk", rv="3")})))
        checking.start()
        checking.join(2)
        self.assertFalse(checking.is_alive(), "the intake waited on a workload read")
        self.assertEqual(answered[0]["metadata"]["name"], "payments-6d9f-a")
        release.set()
        adding.join(5)
        self.assertEqual(sorted(p["metadata"]["name"] for p in reader.objects("agent_pods")),
                         ["payments-6d9f-a", "slow-6d9f-b"])

    def test_a_consumer_that_fails_doesnt_stop_the_reader(self):
        logs: list[str] = []
        reader = reader_mod.ClusterReader(StubKube(), ("agents",), on_change=lambda e: 1 / 0,
                                          workload_of=workload_by_name, log=logs.append)
        pods = next(s for s in reader.specs if s.plural == "pods")
        reader.apply(pods, {"type": "ADDED", "object": agent_pod("payments-6d9f-a", rv="2")})
        self.assertEqual(len(reader.objects("agent_pods")), 1)
        self.assertTrue(any("consumer failed" in line for line in logs))


class EnvHostsTest(unittest.TestCase):
    def test_hosts_from_literal_url_values_only(self):
        pod = {"spec": {"initContainers": [{"env": [{"name": "A", "value": "https://Init.Example.com./x"}]}],
                        "containers": [{"env": [
                            {"name": "MCP", "value": "http://finretail-mcp.tools:8080/mcp"},
                            {"name": "LIST", "value": "http://a:1, https://b.svc/x"},
                            {"name": "PLAIN", "value": "finretail-mcp"},
                            {"name": "SECRET", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}]}]}}
        self.assertEqual(reader_mod.env_url_hosts(pod), {"init.example.com", "finretail-mcp.tools", "a", "b.svc"})


# ── the intake's pod check on the watched copy ──────────────────────────────

class WatchedPodCheckTest(unittest.TestCase):
    """The intake answers from the copy when it has the token's pod with its
    UID, and reads the API otherwise."""

    def setUp(self) -> None:
        self.reader = reader_mod.ClusterReader(StubKube(), ("agents",), workload_of=workload_by_name,
                                               log=lambda line: None)

    def sync(self, pods: list[dict[str, Any]]) -> None:
        self.reader.kube.lists[("pods", "agents", None)] = pods
        for spec in self.reader.specs:
            self.reader.relist(spec)

    def test_the_copy_answers_only_with_the_tokens_uid_once_listed(self):
        self.assertIsNone(self.reader.cached_pod("agents", "payments-6d9f-a", "uid-payments-6d9f-a"))
        self.sync([agent_pod("payments-6d9f-a")])
        self.assertEqual(self.reader.cached_pod("agents", "payments-6d9f-a", "uid-payments-6d9f-a")["metadata"]["name"],
                         "payments-6d9f-a")
        self.assertIsNone(self.reader.cached_pod("agents", "payments-6d9f-a", "uid-of-a-new-pod"))
        self.assertIsNone(self.reader.cached_pod("other", "payments-6d9f-a", "uid-payments-6d9f-a"))

    def test_the_intake_uses_the_copy_and_falls_back_to_the_api(self):
        api_reads = []

        class Kube:
            def get_pod(self, namespace, name):
                api_reads.append(name)
                return {"metadata": {"name": name, "uid": "uid-new", "labels": {}}}

        identity = kube.TokenIdentity("agents", "default", "payments-6d9f-a", "uid-payments-6d9f-a")
        check = intake.Intake(Kube(), lambda data, uid: None, "gke-test", "gke-scan", pods=self.reader)
        self.sync([agent_pod("payments-6d9f-a")])
        self.assertEqual(check.watched_pod(identity)["metadata"]["uid"], "uid-payments-6d9f-a")
        newer = kube.TokenIdentity("agents", "default", "payments-6d9f-a", "uid-new")
        self.assertIsNone(check.watched_pod(newer))
        # check_bundle reads the API for the pod the copy doesn't have: here unlabeled, so 403.
        bundle = {"bundle_version": 1, "host_id": "gke-test", "sandbox_name": "agents/payments",
                  "attributes": {"agent_instance": {"value": {"pod": {"uid": "uid-new"}}}}}
        answer = check.check_bundle(newer, json.dumps(bundle).encode())
        self.assertEqual(answer.status, 403)
        self.assertEqual(api_reads, ["payments-6d9f-a"])


if __name__ == "__main__":
    unittest.main()
