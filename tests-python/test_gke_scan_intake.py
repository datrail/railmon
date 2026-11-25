"""RC-515: gke-scan's sidecar intake relays the sidecar's bundle.

The intake (tools/scan/gke/central_service/intake.py) runs on loopback with a
mocked TokenReview and pod read, and relays through the real relay
(gke_scan.make_relay) to a fake Rail Center, so what is asserted is what
reached Rail Center and what the sidecar got back. The ticket's exit
criteria are the first three tests: a valid bundle is relayed byte for byte
with the headers; another pod's token gives 403; Rail Center's 401 reaches
the sidecar as 503. KubeClient is tested against a fake Kubernetes API.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
CENTRAL = ROOT / "tools" / "scan" / "gke" / "central_service"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gke_scan = _load("gke_scan_entry", CENTRAL / "gke_scan.py")
intake = gke_scan.intake_module()
kube = gke_scan.kube_module()

CLUSTER = "gke-test"
AUDIENCE = "gke-scan"
CENTER_TOKEN = "center-credential-of-gke-scan"
SIDECAR_TOKEN = "sidecar-token-pod-1"
OTHER_POD_TOKEN = "sidecar-token-pod-2"
OTHER_NAMESPACE_TOKEN = "sidecar-token-other-namespace"
UNBOUND_TOKEN = "service-account-token-no-pod"


def bundle_bytes(**overrides: Any) -> bytes:
    """A v1 bundle as the sidecar writes it. Indented and unsorted on purpose,
    so a relay that re-serialized it would change the bytes."""
    bundle: dict[str, Any] = {
        "bundle_version": 1,
        "bundle_id": "bnd-0123456789ab",
        "host_id": CLUSTER,
        "sandbox_name": "agents/agent-finretail",
        "collected_at": "2026-11-19T15:00:00+00:00",
        "rule_pack_version": "16",
        "inputs_attempted": [],
        "attestations": [],
        "attributes": {"agent_instance": {"status": "ANSWERED", "tier": "observed",
                                          "value": {"pod": {"name": "agent-finretail-58cd78b55d-48jcw",
                                                            "uid": "uid-1", "node": "node-a"}}}},
    }
    bundle.update(overrides)
    return json.dumps(bundle, indent=1).encode() + b"\n"


def pod(name: str, uid: str, labeled: bool = True, owner: dict[str, Any] | None = None,
        labels: dict[str, str] | None = None) -> dict[str, Any]:
    """A Deployment's pod by default: <deployment>-<hash>-<suffix>, owned by
    the ReplicaSet <deployment>-<hash>."""
    base, template_hash, _ = name.rsplit("-", 2)
    all_labels = {"app": base, "pod-template-hash": template_hash} if labels is None else dict(labels)
    if labeled:
        all_labels[intake.SCAN_LABEL] = "true"
    if owner is None:
        owner = {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": f"{base}-{template_hash}",
                 "uid": f"rs-uid-{base}", "controller": True}
    return {"metadata": {"name": name, "namespace": "agents", "uid": uid, "labels": all_labels,
                         "ownerReferences": [owner] if owner else []}}


def obj(name: str, uid: str, selector: dict[str, Any] | None = None,
        owner: dict[str, Any] | None = None, labels: dict[str, str] | None = None) -> dict[str, Any]:
    return {"metadata": {"name": name, "uid": uid, "labels": labels or {},
                         "ownerReferences": [owner] if owner else []},
            "spec": {"selector": selector} if selector is not None else {}}


def deployment(base: str) -> dict[str, Any]:
    return obj(base, f"dep-uid-{base}", {"matchLabels": {"app": base}})


def replicaset(base: str, template_hash: str) -> dict[str, Any]:
    return obj(f"{base}-{template_hash}", f"rs-uid-{base}",
               {"matchLabels": {"app": base, "pod-template-hash": template_hash}},
               {"apiVersion": "apps/v1", "kind": "Deployment", "name": base, "uid": f"dep-uid-{base}",
                "controller": True})


class FakeKube:
    """TokenReview and the pod read, mocked."""

    def __init__(self) -> None:
        self.identities = {
            SIDECAR_TOKEN: kube.TokenIdentity("agents", "default", "agent-finretail-58cd78b55d-48jcw", "uid-1"),
            OTHER_POD_TOKEN: kube.TokenIdentity("agents", "default", "agent-other-7d9f-xk2p", "uid-2"),
            OTHER_NAMESPACE_TOKEN: kube.TokenIdentity("elsewhere", "default", "agent-finretail-58cd78b55d-48jcw",
                                                      "uid-1"),
            UNBOUND_TOKEN: kube.TokenIdentity("agents", "default", None, None),
        }
        self.pods = {("agents", "agent-finretail-58cd78b55d-48jcw"): pod("agent-finretail-58cd78b55d-48jcw", "uid-1"),
                     ("agents", "agent-other-7d9f-xk2p"): pod("agent-other-7d9f-xk2p", "uid-2")}
        self.reviews: list[tuple[str, str]] = []
        self.fail: str | None = None
        # The two pods' Deployments and ReplicaSets.
        self.objects: dict[tuple[str, str, str], dict[str, Any]] = {}
        for base, template_hash in (("agent-finretail", "58cd78b55d"), ("agent-other", "7d9f")):
            self.add("deployments", deployment(base))
            self.add("replicasets", replicaset(base, template_hash))

    def add(self, plural: str, obj: dict[str, Any], namespace: str = "agents") -> None:
        self.objects[(plural, namespace, obj["metadata"]["name"])] = obj

    def get_object(self, api_version: str, plural: str, namespace: str, name: str) -> dict[str, Any] | None:
        if self.fail == "owners":
            raise kube.KubeError(f"GET {plural}: timed out")
        if plural == "pods":
            return self.get_pod(namespace, name)
        return self.objects.get((plural, namespace, name))

    def token_review(self, token: str, audience: str) -> Any:
        self.reviews.append((token, audience))
        if self.fail == "review":
            raise kube.KubeError("TokenReview: connection refused")
        return self.identities.get(token)

    def get_pod(self, namespace: str, name: str) -> dict[str, Any] | None:
        if self.fail == "pod":
            raise kube.KubeError("GET pod: timed out")
        return self.pods.get((namespace, name))


class FakeCenter:
    """Rail Center's register route: records each request, answers as set."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.status = 200
        self.body = b'{"status": "registered", "agent_id": "agt-1"}'
        self.headers: dict[str, str] = {}
        self.hold: threading.Event | None = None
        self.entered = threading.Event()
        center = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                return

            def do_POST(self) -> None:
                data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                center.requests.append({"path": self.path, "body": data,
                                        "headers": {k.lower(): v for k, v in self.headers.items()}})
                center.entered.set()
                if center.hold is not None:
                    center.hold.wait(10)
                self.send_response(center.status)
                self.send_header("Content-Type", "application/json")
                for key, value in center.headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(center.body)))
                self.end_headers()
                self.wfile.write(center.body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class IntakeTestCase(unittest.TestCase):
    max_bytes = intake.MAX_BUNDLE_BYTES

    def setUp(self) -> None:
        env = mock.patch.dict(os.environ, {"RAIL_AUTH_MODE": "bearer", "RAIL_AUTH_TOKEN": CENTER_TOKEN})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("RAIL_AUTH_TOKEN_FILE", None)
        self.kube = FakeKube()
        self.center = FakeCenter()
        self.addCleanup(self.center.close)
        self.logs: list[str] = []
        patcher = mock.patch.object(intake, "log", self.logs.append)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.intake = intake.Intake(self.kube, gke_scan.make_relay(self.center.url, timeout=5),
                                    CLUSTER, AUDIENCE, max_bytes=self.max_bytes)
        self.server = intake.IntakeServer(("127.0.0.1", 0), self.intake, None)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}{intake.REGISTER_PATH}"

    def post(self, data: bytes, token: str | None = SIDECAR_TOKEN, url: str | None = None,
             method: str = "POST") -> tuple[int, bytes, Any]:
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        req = Request(url or self.url, data=data if method == "POST" else None, headers=headers, method=method)
        try:
            with urlopen(req, timeout=10) as resp:
                return resp.status, resp.read(), resp.headers
        except HTTPError as exc:
            return exc.code, exc.read(), exc.headers


class ExitCriteriaTest(IntakeTestCase):
    def test_a_valid_bundle_is_relayed_byte_for_byte_with_the_headers(self):
        data = bundle_bytes()
        status, body, _ = self.post(data)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"status": "registered", "agent_id": "agt-1"})
        self.assertEqual(len(self.center.requests), 1)
        sent = self.center.requests[0]
        self.assertEqual(sent["body"], data)
        self.assertEqual(sent["path"], intake.REGISTER_PATH)
        self.assertEqual(sent["headers"]["x-rail-source"], "sidecar")
        self.assertEqual(sent["headers"]["x-rail-pod-uid"], "uid-1")
        # gke-scan's own credential, never the sidecar's token.
        self.assertEqual(sent["headers"]["authorization"], f"Bearer {CENTER_TOKEN}")
        self.assertNotIn(SIDECAR_TOKEN, json.dumps(sent["headers"]))
        self.assertEqual(self.kube.reviews, [(SIDECAR_TOKEN, AUDIENCE)])

    def test_another_pods_token_gives_403(self):
        status, body, _ = self.post(bundle_bytes(), token=OTHER_POD_TOKEN)
        self.assertEqual(status, 403)
        self.assertIn("pod UID", json.loads(body)["error"])
        self.assertEqual(self.center.requests, [])

    def test_rail_centers_401_reaches_the_sidecar_as_503(self):
        self.center.status, self.center.body = 401, b'{"error": "unauthorized"}'
        status, _, _ = self.post(bundle_bytes())
        self.assertEqual(status, 503)
        self.assertEqual(len(self.center.requests), 1)


class TokenTest(IntakeTestCase):
    def test_no_token_is_401_and_never_reviewed(self):
        status, _, _ = self.post(bundle_bytes(), token=None)
        self.assertEqual(status, 401)
        self.assertEqual(self.kube.reviews, [])

    def test_a_token_the_review_rejects_is_401(self):
        status, _, _ = self.post(bundle_bytes(), token="expired-or-wrong-audience")
        self.assertEqual(status, 401)
        self.assertEqual(self.center.requests, [])

    def test_a_token_bound_to_no_pod_is_403(self):
        status, _, _ = self.post(bundle_bytes(), token=UNBOUND_TOKEN)
        self.assertEqual(status, 403)
        self.assertEqual(self.center.requests, [])

    def test_a_token_from_another_namespace_is_403(self):
        status, body, _ = self.post(bundle_bytes(), token=OTHER_NAMESPACE_TOKEN)
        self.assertEqual(status, 403)
        self.assertIn("namespace", json.loads(body)["error"])

    def test_an_unreachable_api_server_is_503(self):
        self.kube.fail = "review"
        status, _, _ = self.post(bundle_bytes())
        self.assertEqual(status, 503)
        self.assertEqual(self.center.requests, [])

    def test_the_token_is_never_logged(self):
        self.post(bundle_bytes())
        self.post(bundle_bytes(), token=OTHER_POD_TOKEN)
        self.assertTrue(self.logs)
        for line in self.logs:
            self.assertNotIn("sidecar-token", line)


class BundleTest(IntakeTestCase):
    def test_only_v1_is_relayed(self):
        for version in (2, "1", True):
            status, _, _ = self.post(bundle_bytes(bundle_version=version))
            self.assertEqual(status, 422, version)
        self.assertEqual(self.center.requests, [])

    def test_a_body_that_isnt_a_json_object_is_422(self):
        for data in (b"not json", b"[1, 2]"):
            status, _, _ = self.post(data)
            self.assertEqual(status, 422)
        self.assertEqual(self.center.requests, [])

    def test_another_clusters_host_id_is_403(self):
        status, _, _ = self.post(bundle_bytes(host_id="other-cluster"))
        self.assertEqual(status, 403)

    def test_a_bundle_with_no_pod_uid_is_403(self):
        status, _, _ = self.post(bundle_bytes(attributes={"agent_instance": {"status": "BLIND", "value": None}}))
        self.assertEqual(status, 403)
        self.assertEqual(self.center.requests, [])


class WorkloadCheckTest(IntakeTestCase):
    """RC-515 rail review: with no agent_key, sandbox_name decides where Rail
    Center files the bundle, so the workload half is checked against the API,
    and nothing the pod says about itself is taken as given."""

    POD = ("agents", "agent-finretail-58cd78b55d-48jcw")

    def set_pod(self, **kwargs: Any) -> None:
        self.kube.pods[self.POD] = pod(self.POD[1], "uid-1", **kwargs)

    def test_another_workload_in_the_same_namespace_is_403(self):
        status, body, _ = self.post(bundle_bytes(sandbox_name="agents/agent-billing"))
        self.assertEqual(status, 403)
        self.assertIn("workload", json.loads(body)["error"])
        self.assertEqual(self.center.requests, [])

    def test_a_sandbox_name_without_exactly_one_workload_is_403(self):
        for name in ("agents", "agents/", "agents/agent-finretail/extra", "agents/agent-finretail-58cd78b55d"):
            status, _, _ = self.post(bundle_bytes(sandbox_name=name))
            self.assertEqual(status, 403, name)
        self.assertEqual(self.center.requests, [])

    def test_a_bare_pod_named_after_a_deployment_is_403(self):
        # The reviewer's case: no forgery, just a bare pod named payments-api.
        self.kube.add("deployments", deployment("payments-api"))
        self.kube.pods[("agents", "payments-api")] = {"metadata": {
            "name": "payments-api", "uid": "uid-1", "labels": {intake.SCAN_LABEL: "true"}, "ownerReferences": []}}
        self.kube.identities[SIDECAR_TOKEN] = kube.TokenIdentity("agents", "default", "payments-api", "uid-1")
        status, _, _ = self.post(bundle_bytes(sandbox_name="agents/payments-api"))
        self.assertEqual(status, 403)
        self.assertEqual(self.center.requests, [])

    def test_a_bare_pod_with_a_name_of_its_own_is_relayed(self):
        self.kube.pods[("agents", "debug-agent")] = {"metadata": {
            "name": "debug-agent", "uid": "uid-1", "labels": {intake.SCAN_LABEL: "true"}}}
        self.kube.identities[SIDECAR_TOKEN] = kube.TokenIdentity("agents", "default", "debug-agent", "uid-1")
        status, _, _ = self.post(bundle_bytes(sandbox_name="agents/debug-agent"))
        self.assertEqual(status, 200)

    def test_an_owner_that_doesnt_exist_is_403(self):
        self.set_pod(owner={"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "agent-billing-58cd78b55d",
                            "uid": "made-up", "controller": True},
                     labels={"app": "agent-billing", "pod-template-hash": "58cd78b55d"})
        status, _, _ = self.post(bundle_bytes(sandbox_name="agents/agent-billing"))
        self.assertEqual(status, 403)

    def test_a_real_owner_with_another_uid_is_403(self):
        self.set_pod(owner={"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "agent-finretail-58cd78b55d",
                            "uid": "copied-wrong", "controller": True})
        status, _, _ = self.post(bundle_bytes())
        self.assertEqual(status, 403)

    def test_a_real_owner_that_doesnt_select_the_pod_is_403(self):
        # The right ReplicaSet and UID, but the pod's labels aren't its.
        self.set_pod(labels={"app": "something-else", "pod-template-hash": "58cd78b55d"})
        status, _, _ = self.post(bundle_bytes())
        self.assertEqual(status, 403)

    def test_a_controller_kind_gke_scan_cant_check_is_403(self):
        self.set_pod(owner={"apiVersion": "example.com/v1", "kind": "AgentSet", "name": "agent-billing",
                            "uid": "u", "controller": True})
        status, _, _ = self.post(bundle_bytes(sandbox_name="agents/agent-billing"))
        self.assertEqual(status, 403)

    def test_a_pod_with_two_controllers_is_403(self):
        two = pod(self.POD[1], "uid-1")
        two["metadata"]["ownerReferences"].append({"apiVersion": "apps/v1", "kind": "StatefulSet", "name": "x",
                                                   "uid": "x", "controller": True})
        self.kube.pods[self.POD] = two
        status, _, _ = self.post(bundle_bytes())
        self.assertEqual(status, 403)

    def test_an_unreadable_owner_is_503(self):
        self.kube.fail = "owners"
        status, _, _ = self.post(bundle_bytes())
        self.assertEqual(status, 503)
        self.assertEqual(self.center.requests, [])


workload = sys.modules.get("gke_scan_workload") or intake._workload()


def ref(kind: str, name: str, api_version: str = "apps/v1") -> dict[str, Any]:
    return {"apiVersion": api_version, "kind": kind, "name": name, "uid": f"uid-{kind}-{name}", "controller": True}


class Cluster:
    """Objects for workload.workload, by (plural, name)."""

    def __init__(self, *objects: tuple[str, dict[str, Any]]):
        self.objects = {(plural, o["metadata"]["name"]): o for plural, o in objects}

    def get_object(self, api_version: str, plural: str, namespace: str, name: str) -> dict[str, Any] | None:
        return self.objects.get((plural, name))


def case(pod_name: str, labels: dict[str, str], owner_ref: dict[str, Any] | None,
         *objects: tuple[str, dict[str, Any]]) -> tuple[Cluster, dict[str, Any]]:
    return Cluster(*objects), {"metadata": {"name": pod_name, "labels": labels,
                                            "ownerReferences": [owner_ref] if owner_ref else []}}


def cronjob(name: str, *active_uids: str) -> dict[str, Any]:
    found = obj(name, f"uid-CronJob-{name}")
    found["status"] = {"active": [{"kind": "Job", "uid": uid} for uid in active_uids]}
    return found


def owned_by(kind: str, name: str, selector: dict[str, str], up: dict[str, Any] | None = None,
             labels: dict[str, str] | None = None) -> dict[str, Any]:
    return obj(name, f"uid-{kind}-{name}", {"matchLabels": selector}, up, labels)


# (the case, the workload as both the sidecar and gke-scan key it)
WORKLOADS = [
    (case("agent-finretail-58cd78b55d-48jcw", {"app": "fr", "pod-template-hash": "58cd78b55d"},
          ref("ReplicaSet", "agent-finretail-58cd78b55d"),
          ("replicasets", owned_by("ReplicaSet", "agent-finretail-58cd78b55d", {"app": "fr"},
                                   ref("Deployment", "agent-finretail"))),
          ("deployments", owned_by("Deployment", "agent-finretail", {"app": "fr"}))), "agent-finretail"),
    (case("canary-agent-6f9c7b-zx81q", {"app": "c", "rollouts-pod-template-hash": "6f9c7b"},
          ref("ReplicaSet", "canary-agent-6f9c7b"),
          ("replicasets", owned_by("ReplicaSet", "canary-agent-6f9c7b", {"app": "c"},
                                   ref("Rollout", "canary-agent", "argoproj.io/v1alpha1"))),
          ("rollouts", owned_by("Rollout", "canary-agent", {"app": "c"}))), "canary-agent"),
    # Rail review: a ReplicaSet no Deployment owns; the sidecar keeps the pod's name.
    (case("bare-rs-q2w3e", {"app": "b"}, ref("ReplicaSet", "bare-rs"),
          ("replicasets", owned_by("ReplicaSet", "bare-rs", {"app": "b"}))), "bare-rs-q2w3e"),
    (case("agent-db-0", {"app": "db", "statefulset.kubernetes.io/pod-name": "agent-db-0"},
          ref("StatefulSet", "agent-db"), ("statefulsets", owned_by("StatefulSet", "agent-db", {"app": "db"}))),
     "agent-db-0"),
    (case("node-agent-k2x9p", {"app": "n", "controller-revision-hash": "5d8f"}, ref("DaemonSet", "node-agent"),
          ("daemonsets", owned_by("DaemonSet", "node-agent", {"app": "n"}))), "node-agent"),
    (case("nightly-29100000-abcde", {"batch.kubernetes.io/job-name": "nightly-29100000", "j": "1"},
          ref("Job", "nightly-29100000", "batch/v1"),
          ("jobs", owned_by("Job", "nightly-29100000", {"j": "1"}, ref("CronJob", "nightly", "batch/v1"))),
          ("cronjobs", cronjob("nightly", "uid-Job-nightly-29100000"))), "nightly"),
    (case("backfill-2026-q8w7e", {"batch.kubernetes.io/job-name": "backfill-2026", "j": "2"},
          ref("Job", "backfill-2026", "batch/v1"), ("jobs", owned_by("Job", "backfill-2026", {"j": "2"}))),
     "backfill-2026"),
    (case("debug-agent", {}, None), "debug-agent"),
]


class WorkloadTest(unittest.TestCase):
    def test_each_kind_of_workload(self):
        for (cluster, pod_obj), expected in WORKLOADS:
            self.assertEqual(workload.workload(cluster, "agents", pod_obj), (expected, mock.ANY),
                             pod_obj["metadata"]["name"])

    def test_the_sidecar_works_out_the_same_name(self):
        # gke-scan's checked workload and the sidecar's (from its pod name and
        # labels) must agree for real workloads, or their bundles are refused.
        pod_mode = gke_scan.scanner()._pod_mode()
        for (_, pod_obj), expected in WORKLOADS:
            meta = pod_obj["metadata"]
            self.assertEqual(pod_mode.workload_name(meta["name"], meta["labels"])[0], expected, meta["name"])

    def test_claims_that_dont_hold_up(self):
        refused = {
            "a StatefulSet pod named as another's": case(
                "agent-billing-0", {"app": "db"}, ref("StatefulSet", "agent-db"),
                ("statefulsets", owned_by("StatefulSet", "agent-db", {"app": "db"}))),
            "a ReplicaSet controlled by something else": case(
                "x-abc12", {"app": "x"}, ref("ReplicaSet", "x"),
                ("replicasets", owned_by("ReplicaSet", "x", {"app": "x"}, ref("StatefulSet", "s"))),
                ("statefulsets", owned_by("StatefulSet", "s", {"app": "x"}))),
            "a Job under a CronJob, not named as its runs": case(
                "evil-abcde", {"j": "1"}, ref("Job", "evil", "batch/v1"),
                ("jobs", owned_by("Job", "evil", {"j": "1"}, ref("CronJob", "nightly", "batch/v1"))),
                ("cronjobs", cronjob("nightly", "uid-Job-evil"))),
            "a bare pod named as a StatefulSet's pod": case(
                "agent-db-3", {}, None, ("statefulsets", owned_by("StatefulSet", "agent-db", {"app": "db"}))),
            "a bare pod named as a CronJob": case("nightly", {}, None, ("cronjobs", cronjob("nightly"))),
            # Rail review: a Job of one's own, named as a CronJob's run and
            # naming it as controller, that the CronJob never made.
            "a made-up Job under someone's CronJob": case(
                "nightly-29000000-zzzzz", {"j": "x"}, ref("Job", "nightly-29000000", "batch/v1"),
                ("jobs", owned_by("Job", "nightly-29000000", {"j": "x"}, ref("CronJob", "nightly", "batch/v1"))),
                ("cronjobs", cronjob("nightly", "uid-Job-nightly-29100000"))),
            # Rail review: a ReplicaSet of one's own selecting a pod named as
            # someone's Deployment.
            "a ReplicaSet's pod named as a Deployment": case(
                "payments-api", {"app": "mine"}, ref("ReplicaSet", "mine"),
                ("replicasets", owned_by("ReplicaSet", "mine", {"app": "mine"})),
                ("deployments", owned_by("Deployment", "payments-api", {"app": "payments"}))),
            "a DaemonSet named as a Deployment": case(
                "payments-api-k2x9p", {"app": "mine"}, ref("DaemonSet", "payments-api"),
                ("daemonsets", owned_by("DaemonSet", "payments-api", {"app": "mine"})),
                ("deployments", owned_by("Deployment", "payments-api", {"app": "payments"}))),
            "a Job named as a CronJob": case(
                "nightly-abcde", {"j": "1"}, ref("Job", "nightly", "batch/v1"),
                ("jobs", owned_by("Job", "nightly", {"j": "1"})), ("cronjobs", cronjob("nightly"))),
            "a StatefulSet's pod named as another's": case(
                "agent-db-0", {"app": "x"}, ref("StatefulSet", "agent-db-0x"),
                ("statefulsets", owned_by("StatefulSet", "agent-db-0x", {"app": "x"}))),
            "a StatefulSet named so its pod is a Deployment's key": case(
                "web-1", {"app": "s"}, ref("StatefulSet", "web"),
                ("statefulsets", owned_by("StatefulSet", "web", {"app": "s"})),
                ("deployments", owned_by("Deployment", "web-1", {"app": "d"}))),
            "an empty selector": case("e-abcde", {"app": "e"}, ref("ReplicaSet", "e"),
                                      ("replicasets", obj("e", "uid-ReplicaSet-e", {}))),
        }
        for what, (cluster, pod_obj) in refused.items():
            self.assertIsNone(workload.workload(cluster, "agents", pod_obj)[0], what)

    def test_a_rollout_and_the_deployment_its_workload_ref_names_are_one_workload(self):
        # Rail review: Argo's migration keeps the Deployment, often scaled to 0,
        # under the Rollout's name.
        def rollout(workload_ref: dict[str, Any] | None) -> dict[str, Any]:
            found = owned_by("Rollout", "payments-api", {"app": "p"})
            if workload_ref is not None:
                found["spec"]["workloadRef"] = workload_ref
            return found

        to_deployment = {"apiVersion": "apps/v1", "kind": "Deployment", "name": "payments-api"}
        rollout_pod = ("payments-api-6f9c7b-zx81q", {"app": "p", "rollouts-pod-template-hash": "6f9c7b"},
                       ref("ReplicaSet", "payments-api-6f9c7b"))
        deployment_pod = ("payments-api-58cd78b55d-48jcw", {"app": "p", "pod-template-hash": "58cd78b55d"},
                          ref("ReplicaSet", "payments-api-58cd78b55d"))
        objects = [
            ("replicasets", owned_by("ReplicaSet", "payments-api-6f9c7b", {"app": "p"},
                                     ref("Rollout", "payments-api", "argoproj.io/v1alpha1"))),
            ("replicasets", owned_by("ReplicaSet", "payments-api-58cd78b55d", {"app": "p"},
                                     ref("Deployment", "payments-api"))),
            ("deployments", owned_by("Deployment", "payments-api", {"app": "p"})),
        ]
        for pod_args in (rollout_pod, deployment_pod):
            cluster, pod_obj = case(*pod_args, *objects, ("rollouts", rollout(to_deployment)))
            self.assertEqual(workload.workload(cluster, "agents", pod_obj)[0], "payments-api", pod_args[0])
        # A Rollout that names no Deployment, or another one, is still a collision.
        for other in (None, {"apiVersion": "apps/v1", "kind": "Deployment", "name": "something-else"}):
            for pod_args in (rollout_pod, deployment_pod):
                cluster, pod_obj = case(*pod_args, *objects, ("rollouts", rollout(other)))
                self.assertIsNone(workload.workload(cluster, "agents", pod_obj)[0], (pod_args[0], other))

    def test_selectors(self):
        labels = {"app": "a", "tier": "web"}
        self.assertTrue(workload.selects({"matchLabels": {"app": "a"}}, labels))
        self.assertFalse(workload.selects({"matchLabels": {"app": "b"}}, labels))
        self.assertTrue(workload.selects({"matchExpressions": [{"key": "tier", "operator": "In", "values": ["web"]}]}, labels))
        self.assertFalse(workload.selects({"matchExpressions": [{"key": "tier", "operator": "NotIn", "values": ["web"]}]}, labels))
        self.assertTrue(workload.selects({"matchExpressions": [{"key": "x", "operator": "DoesNotExist"}]}, labels))
        self.assertFalse(workload.selects({"matchExpressions": [{"key": "x", "operator": "Exists"}]}, labels))
        self.assertFalse(workload.selects({}, labels))
        self.assertFalse(workload.selects(None, labels))

    def test_a_long_key_is_cut_as_the_sidecar_cuts_it(self):
        cluster, pod_obj = case("p" * 100, {}, None)
        name, _ = workload.sandbox_name(cluster, "n" * 200, pod_obj)
        self.assertEqual(len(name), workload.SANDBOX_NAME_MAX)


class PodTest(IntakeTestCase):
    def test_a_pod_without_the_scan_label_is_403(self):
        self.kube.pods[("agents", "agent-finretail-58cd78b55d-48jcw")] = pod(
            "agent-finretail-58cd78b55d-48jcw", "uid-1", labeled=False)
        status, body, _ = self.post(bundle_bytes())
        self.assertEqual(status, 403)
        self.assertIn(intake.SCAN_LABEL, json.loads(body)["error"])

    def test_a_deleted_pod_is_403(self):
        del self.kube.pods[("agents", "agent-finretail-58cd78b55d-48jcw")]
        status, _, _ = self.post(bundle_bytes())
        self.assertEqual(status, 403)

    def test_a_pod_recreated_under_the_same_name_is_403(self):
        self.kube.pods[("agents", "agent-finretail-58cd78b55d-48jcw")] = pod(
            "agent-finretail-58cd78b55d-48jcw", "uid-new")
        status, _, _ = self.post(bundle_bytes())
        self.assertEqual(status, 403)

    def test_an_unreadable_pod_is_503(self):
        self.kube.fail = "pod"
        status, _, _ = self.post(bundle_bytes())
        self.assertEqual(status, 503)
        self.assertEqual(self.center.requests, [])


class SizeTest(IntakeTestCase):
    max_bytes = 1024

    def test_a_bundle_over_the_limit_is_413_and_the_sidecar_gets_the_answer(self):
        data = bundle_bytes(padding="x" * 4096)
        status, _, _ = self.post(data)
        self.assertEqual(status, 413)
        self.assertEqual(self.center.requests, [])

    def test_the_default_limit_is_4_mb(self):
        self.assertEqual(intake.MAX_BUNDLE_BYTES, 4 * 1024 * 1024)


class RailCenterAnswerTest(IntakeTestCase):
    def test_403_and_5xx_become_503_and_retry_after_is_kept(self):
        for code in (403, 500, 502, 503):
            self.center.status = code
            self.center.headers = {"Retry-After": "30"} if code >= 500 else {}
            status, _, headers = self.post(bundle_bytes())
            self.assertEqual(status, 503, code)
            if code >= 500:
                self.assertEqual(headers.get("Retry-After"), "30")

    def test_no_answer_becomes_503(self):
        self.center.close()
        status, _, _ = self.post(bundle_bytes())
        self.assertEqual(status, 503)

    def test_other_answers_pass_through_as_is(self):
        for code, body in ((200, b'{"duplicate": true}'), (409, b'{"error": "bundle_id reused"}'),
                           (413, b'{"error": "too large"}'), (422, b'{"error": "schema"}'),
                           (429, b'{"error": "slow down"}')):
            self.center.status, self.center.body = code, body
            self.center.headers = {"Retry-After": "7"} if code == 429 else {}
            status, answered, headers = self.post(bundle_bytes())
            self.assertEqual((status, answered), (code, body))
            if code == 429:
                self.assertEqual(headers.get("Retry-After"), "7")

    def test_a_redirect_is_not_followed(self):
        self.center.status, self.center.headers = 302, {"Location": self.center.url + "/elsewhere"}
        status, _, _ = self.post(bundle_bytes())
        self.assertEqual(status, 302)
        self.assertEqual(len(self.center.requests), 1)

    def test_a_credential_gke_scan_cant_get_is_503(self):
        with mock.patch.dict(os.environ, {"RAIL_AUTH_MODE": "gcp"}):
            os.environ.pop("RAIL_AUTH_TOKEN", None)
            os.environ.pop("RAIL_AUTH_AUDIENCE", None)
            status, _, _ = self.post(bundle_bytes())
        self.assertEqual(status, 503)
        self.assertEqual(self.center.requests, [])

    def test_no_agent_key_is_ever_relayed(self):
        self.post(bundle_bytes())
        self.assertEqual(self.center.requests[0]["path"], intake.REGISTER_PATH)


class AgentKeyTest(IntakeTestCase):
    """RC-515 rail review: a pod with a valid token must not choose the key
    Rail Center files its bundle under, since Rail Center files a v1 bundle
    under the ?agent_key= it comes with."""

    def test_a_post_naming_another_agents_key_is_422_and_never_relayed(self):
        for query in ("?agent_key=payments%2Fagent-billing", "?agent_key=agents%2Fagent-finretail",
                      "?agent_key=", "?x=1&agent_key=other"):
            status, body, _ = self.post(bundle_bytes(), url=self.url + query)
            self.assertEqual(status, 422, query)
            self.assertIn("agent_key", json.loads(body)["error"])
        self.assertEqual(self.center.requests, [])

    def test_the_relay_has_no_way_to_send_a_key(self):
        import inspect
        self.assertEqual(list(inspect.signature(gke_scan.make_relay(self.center.url)).parameters),
                         ["data", "pod_uid"])


class OneAtATimeTest(IntakeTestCase):
    def test_a_second_bundle_from_the_same_pod_in_flight_is_409(self):
        self.center.hold = threading.Event()
        first: list[int] = []
        thread = threading.Thread(target=lambda: first.append(self.post(bundle_bytes())[0]))
        thread.start()
        self.assertTrue(self.center.entered.wait(5))
        status, _, _ = self.post(bundle_bytes())
        self.assertEqual(status, 409)
        self.center.hold.set()
        thread.join(10)
        self.assertEqual(first, [200])
        self.assertEqual(len(self.center.requests), 1)
        # Once the first is done, the pod can post again.
        self.center.hold = None
        self.assertEqual(self.post(bundle_bytes())[0], 200)

    def test_drain_waits_for_relays_in_flight(self):
        self.center.hold = threading.Event()
        thread = threading.Thread(target=lambda: self.post(bundle_bytes()))
        thread.start()
        self.assertTrue(self.center.entered.wait(5))
        self.assertEqual(self.server.drain(grace=0.2), 1)
        self.center.hold.set()
        thread.join(10)
        self.assertEqual(self.server.drain(grace=1), 0)


class RouteTest(IntakeTestCase):
    def test_another_path_is_404_and_another_method_405(self):
        status, _, _ = self.post(bundle_bytes(), url=self.url.replace("/register", "/other"))
        self.assertEqual(status, 404)
        status, _, headers = self.post(b"", method="GET")
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "POST")
        self.assertEqual(self.kube.reviews, [])


class FakeKubeAPI:
    """The Kubernetes API's TokenReview and pod routes, on loopback."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.review_status: dict[str, Any] = {}
        self.pod_status = 200
        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                return

            def _answer(self, code: int, body: Any) -> None:
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self) -> None:
                data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                api.requests.append({"method": "POST", "path": self.path, "auth": self.headers.get("Authorization"),
                                     "body": json.loads(data)})
                self._answer(201, {"kind": "TokenReview", "status": api.review_status})

            def do_GET(self) -> None:
                api.requests.append({"method": "GET", "path": self.path, "auth": self.headers.get("Authorization")})
                self._answer(api.pod_status, pod("agent-finretail-58cd78b55d-48jcw", "uid-1")
                             if api.pod_status == 200 else {"kind": "Status"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class KubeClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self.api = FakeKubeAPI()
        self.addCleanup(self.api.close)
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.token_file = Path(folder.name) / "token"
        self.token_file.write_text("gke-scan-sa-token\n")
        self.client = kube.KubeClient(self.api.url, str(self.token_file), str(Path(folder.name) / "ca.crt"))

    def authenticated(self, **user: Any) -> dict[str, Any]:
        return {"authenticated": True, "audiences": [AUDIENCE],
                "user": {"username": "system:serviceaccount:agents:default",
                         "extra": {kube.POD_NAME_CLAIM: ["agent-finretail-58cd78b55d-48jcw"],
                                   kube.POD_UID_CLAIM: ["uid-1"]}, **user}}

    def test_token_review_sends_the_token_and_audience_with_gke_scans_own_credential(self):
        self.api.review_status = self.authenticated()
        identity = self.client.token_review(SIDECAR_TOKEN, AUDIENCE)
        self.assertEqual(identity, kube.TokenIdentity("agents", "default", "agent-finretail-58cd78b55d-48jcw", "uid-1"))
        sent = self.api.requests[0]
        self.assertEqual(sent["path"], "/apis/authentication.k8s.io/v1/tokenreviews")
        self.assertEqual(sent["auth"], "Bearer gke-scan-sa-token")
        self.assertEqual(sent["body"]["spec"], {"token": SIDECAR_TOKEN, "audiences": [AUDIENCE]})

    def test_a_rotated_token_file_is_read_again(self):
        self.api.review_status = self.authenticated()
        self.client.token_review(SIDECAR_TOKEN, AUDIENCE)
        self.token_file.write_text("rotated")
        self.client.token_review(SIDECAR_TOKEN, AUDIENCE)
        self.assertEqual(self.api.requests[1]["auth"], "Bearer rotated")

    def test_a_review_read_strictly(self):
        cases = {
            "not authenticated": {"authenticated": False},
            "no audiences": {k: v for k, v in self.authenticated().items() if k != "audiences"},
            "another audience": {**self.authenticated(), "audiences": ["https://kubernetes.default.svc"]},
            "a user, not a service account": self.authenticated(username="alice@example.com"),
            "an error": {**self.authenticated(), "error": "token expired"},
        }
        for name, status in cases.items():
            self.api.review_status = status
            self.assertIsNone(self.client.token_review(SIDECAR_TOKEN, AUDIENCE), name)

    def test_a_token_with_no_pod_claims_has_no_pod(self):
        self.api.review_status = self.authenticated(extra={})
        identity = self.client.token_review(SIDECAR_TOKEN, AUDIENCE)
        self.assertEqual((identity.pod_name, identity.pod_uid), (None, None))

    def test_get_pod(self):
        self.assertEqual(self.client.get_pod("agents", "agent-finretail-58cd78b55d-48jcw")["metadata"]["uid"], "uid-1")
        self.assertEqual(self.api.requests[0]["path"], "/api/v1/namespaces/agents/pods/agent-finretail-58cd78b55d-48jcw")
        self.api.pod_status = 404
        self.assertIsNone(self.client.get_pod("agents", "gone"))
        self.api.pod_status = 500
        with self.assertRaises(kube.KubeError):
            self.client.get_pod("agents", "agent-finretail-58cd78b55d-48jcw")

    def test_get_object_reads_a_namespaced_object(self):
        self.client.get_object("apps/v1", "replicasets", "agents", "agent-finretail-58cd78b55d")
        self.assertEqual(self.api.requests[-1]["path"], "/apis/apps/v1/namespaces/agents/replicasets/agent-finretail-58cd78b55d")

    def test_a_refused_read_names_the_missing_permission(self):
        # Rail review: without a rollouts rule the API answers 403, even where
        # Argo isn't installed, and the log must say what to grant.
        self.api.pod_status = 403
        with self.assertRaises(kube.KubeError) as raised:
            self.client.get_object("argoproj.io/v1alpha1", "rollouts", "agents", "payments-api")
        self.assertIn("rollouts", str(raised.exception))
        self.assertIn("doesn't allow", str(raised.exception))

    def test_an_unreachable_api_is_a_kube_error(self):
        self.api.close()
        with self.assertRaises(kube.KubeError):
            self.client.token_review(SIDECAR_TOKEN, AUDIENCE)


@unittest.skipUnless(shutil.which("openssl"), "needs openssl to make a test certificate")
class TLSTest(unittest.TestCase):
    def test_the_intake_serves_https_with_the_charts_certificate(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        cert, key = Path(folder.name) / "tls.crt", Path(folder.name) / "tls.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=gke-scan.rail-system.svc", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
        center = FakeCenter()
        self.addCleanup(center.close)
        with mock.patch.dict(os.environ, {"RAIL_AUTH_MODE": "bearer", "RAIL_AUTH_TOKEN": CENTER_TOKEN}), \
                mock.patch.object(intake, "log", lambda line: None):
            server = intake.IntakeServer(("127.0.0.1", 0), intake.Intake(
                FakeKube(), gke_scan.make_relay(center.url, timeout=5), CLUSTER, AUDIENCE),
                intake.server_tls_context(str(cert), str(key)))
            threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            context = ssl.create_default_context(cafile=str(cert))
            req = Request(f"https://127.0.0.1:{server.server_address[1]}{intake.REGISTER_PATH}",
                          data=bundle_bytes(), method="POST", headers={"Authorization": f"Bearer {SIDECAR_TOKEN}"})
            with urlopen(req, timeout=10, context=context) as resp:
                self.assertEqual(resp.status, 200)

            # The chart signs a new certificate on every render; sidecars
            # trusting the new CA reach the running intake without a restart.
            renewed = Path(folder.name) / "renewed"
            renewed.mkdir()
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=gke-scan.rail-system.svc", "-addext", "subjectAltName=IP:127.0.0.1",
                            "-keyout", str(renewed / "tls.key"), "-out", str(renewed / "tls.crt")],
                           check=True, capture_output=True)
            shutil.copy(renewed / "tls.key", key)
            shutil.copy(renewed / "tls.crt", cert)
            req = Request(f"https://127.0.0.1:{server.server_address[1]}{intake.REGISTER_PATH}",
                          data=bundle_bytes(), method="POST", headers={"Authorization": f"Bearer {SIDECAR_TOKEN}"})
            with urlopen(req, timeout=10, context=ssl.create_default_context(cafile=str(renewed / "tls.crt"))) as resp:
                self.assertIn(resp.status, (200, 409))
        self.assertEqual(center.requests[0]["body"], bundle_bytes())


class EntryPointTest(unittest.TestCase):
    def test_missing_configuration_exits_2_naming_it(self):
        with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(None):
            stderr = subprocess.run([sys.executable, str(CENTRAL / "gke_scan.py")], capture_output=True,
                                    text=True, env={"PATH": os.environ.get("PATH", "")})
        self.assertEqual(stderr.returncode, 2)
        self.assertIn("--cluster-name/RAIL_CLUSTER_NAME", stderr.stderr)
        self.assertIn("--tls-cert-file", stderr.stderr)
        self.assertIn("--namespaces/RAIL_NAMESPACES", stderr.stderr)

    def test_sigterm_stops_the_service(self):
        if not shutil.which("openssl"):
            self.skipTest("needs openssl to make a test certificate")
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        cert, key, token = (Path(folder.name) / n for n in ("tls.crt", "tls.key", "token"))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=t",
                        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
        token.write_text("t")
        proc = subprocess.Popen(
            [sys.executable, str(CENTRAL / "gke_scan.py"), "--cluster-name", CLUSTER, "--center-url",
             "http://127.0.0.1:9", "--tls-cert-file", str(cert), "--tls-key-file", str(key), "--listen",
             "127.0.0.1:0", "--kube-api-url", "http://127.0.0.1:9", "--kube-token-file", str(token),
             "--namespaces", "agents"],
            stderr=subprocess.PIPE, text=True)
        try:
            line = proc.stderr.readline()
            self.assertIn("intake listening", line)
            proc.terminate()
            self.assertEqual(proc.wait(10), 0)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.stderr.close()


if __name__ == "__main__":
    unittest.main()
