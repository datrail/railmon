"""RC-551: gke-scan's workload key, agent container, revision and sidecar,
agent_type, and the fields read from the pod spec and the objects around it
(tools/scan/gke/central_service/pod_fields.py).

The ticket's exit criteria:

* Every workload kind gives the same key as the sidecar's `workload_name`.
* The annotation wins; several candidates with no annotation pick the first
  container, with a note.
* The agent-type label gives `agent_type`, and no label gives none.
* Each field matches what `central_v3.py` produced; mutable tags give
  PARTIAL; a pod not yet Ready contributes nothing.
* matchExpressions In, NotIn, Exists and DoesNotExist select correctly; an
  empty podSelector selects all; an unevaluable selector gives PARTIAL naming
  the policy.

The recorded pods are research phase 15's, from 11/4 and 11/5 on gke-test,
gke-auto and gke-sandbox (tests-python/fixtures/gke-scan/): the pod fields
the collectors read, and env names with every value left out (the recorded
sidecar env held literal tokens), with the project ID and the owner label
replaced and the node name dropped. Each fixture keeps
central_v3.py's output for its pod, which the Service and NetworkPolicy
results are compared with; the Service and policies are the research's own
manifests (k8s/phase11/test-objects.yaml and the recorded egress policy).
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CENTRAL = ROOT / "tools" / "scan" / "gke" / "central_service"
FIXTURES = ROOT / "tests-python" / "fixtures" / "gke-scan"
CLUSTERS = ("gke-test", "gke-auto", "gke-sandbox")


def _load(name: str, path: Path):
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


fields = _load("gke_scan_pod_fields", CENTRAL / "pod_fields.py")
workload = _load("gke_scan_workload", CENTRAL / "workload.py")
pod_mode = _load("gke_pod_mode", ROOT / "tools" / "scan" / "gke" / "sidecar" / "pod_mode.py")
evidence = _load("evidence_bundle", ROOT / "tools" / "scan" / "evidence_bundle.py")

B = {"answered": evidence._answered, "partial": evidence._partial,
     "blind": evidence._blind, "absent": evidence._absent}


def recorded(cluster: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{cluster}.json").read_text())


def ready(pod: dict[str, Any], is_ready: bool = True) -> dict[str, Any]:
    pod = copy.deepcopy(pod)
    pod.setdefault("status", {})["conditions"] = [{"type": "Ready", "status": "True" if is_ready else "False"}]
    return pod


def make_pod(name: str = "agent-6d9f8c7b5-x2x4z", namespace: str = "agents", labels: dict[str, str] | None = None,
             containers: list[dict[str, Any]] | None = None, annotations: dict[str, str] | None = None,
             image_id: str | None = "registry.example.com/agent@sha256:" + "a" * 64, **spec: Any) -> dict[str, Any]:
    containers = containers if containers is not None else [{"name": "agent", "image": "registry.example.com/agent:1"}]
    pod = {"metadata": {"name": name, "namespace": namespace, "uid": f"uid-{name}",
                        "labels": labels if labels is not None else {"app": "agent", "pod-template-hash": "6d9f8c7b5"},
                        **({"annotations": annotations} if annotations else {})},
           "spec": {"containers": containers, **spec},
           "status": {"containerStatuses": [{"name": c["name"], "imageID": image_id} for c in containers]}}
    return ready(pod)


def policy(name: str, pod_selector: Any, namespace: str = "agents", **spec: Any) -> dict[str, Any]:
    return {"metadata": {"name": name, "namespace": namespace}, "spec": {"podSelector": pod_selector, **spec}}


# ── the workload key ────────────────────────────────────────────────────────

class FakeObjects:
    def __init__(self, *objects: tuple[str, dict[str, Any]]):
        self.objects = {(plural, obj["metadata"]["name"]): obj for plural, obj in objects}

    def get_object(self, api_version: str, plural: str, namespace: str, name: str):
        return self.objects.get((plural, name))


def ref(kind: str, name: str, api_version: str = "apps/v1") -> dict[str, Any]:
    return {"apiVersion": api_version, "kind": kind, "name": name, "uid": f"uid-{kind}-{name}", "controller": True}


def owner_obj(kind: str, name: str, match: dict[str, str], up: dict[str, Any] | None = None, **extra: Any):
    obj = {"kind": kind, "metadata": {"name": name, "namespace": "agents", "uid": f"uid-{kind}-{name}",
                                      "labels": dict(match), "ownerReferences": [up] if up else []},
           "spec": {"selector": {"matchLabels": match}}}
    obj.update(extra)
    return obj


def kind_cases() -> list[tuple[str, dict[str, Any], FakeObjects]]:
    cases = []
    labels = {"app": "payments", "pod-template-hash": "6d9f8c7b5"}
    rs = owner_obj("ReplicaSet", "payments-6d9f8c7b5", labels, ref("Deployment", "payments"))
    dep = owner_obj("Deployment", "payments", {"app": "payments"})
    pod = make_pod("payments-6d9f8c7b5-x2x4z", labels=labels)
    pod["metadata"]["ownerReferences"] = [ref("ReplicaSet", "payments-6d9f8c7b5")]
    cases.append(("Deployment", pod, FakeObjects(("replicasets", rs), ("deployments", dep))))

    labels = {"app": "canary", "rollouts-pod-template-hash": "77bf9c4d8"}
    rs = owner_obj("ReplicaSet", "canary-77bf9c4d8", labels, ref("Rollout", "canary", "argoproj.io/v1alpha1"))
    rollout = owner_obj("Rollout", "canary", {"app": "canary"})
    pod = make_pod("canary-77bf9c4d8-qq7lp", labels=labels)
    pod["metadata"]["ownerReferences"] = [ref("ReplicaSet", "canary-77bf9c4d8")]
    cases.append(("Argo Rollout", pod, FakeObjects(("replicasets", rs), ("rollouts", rollout))))

    labels = {"app": "ledger", "statefulset.kubernetes.io/pod-name": "ledger-2", "controller-revision-hash": "ledger-5c9"}
    sts = owner_obj("StatefulSet", "ledger", {"app": "ledger"})
    pod = make_pod("ledger-2", labels=labels)
    pod["metadata"]["ownerReferences"] = [ref("StatefulSet", "ledger")]
    cases.append(("StatefulSet", pod, FakeObjects(("statefulsets", sts))))

    labels = {"app": "node-agent", "controller-revision-hash": "7c8d9"}
    ds = owner_obj("DaemonSet", "node-agent", {"app": "node-agent"})
    pod = make_pod("node-agent-k2p9q", labels=labels)
    pod["metadata"]["ownerReferences"] = [ref("DaemonSet", "node-agent")]
    cases.append(("DaemonSet", pod, FakeObjects(("daemonsets", ds))))

    labels = {"batch.kubernetes.io/job-name": "backfill", "job-name": "backfill"}
    job = owner_obj("Job", "backfill", labels)
    pod = make_pod("backfill-7xq2m", labels=labels)
    pod["metadata"]["ownerReferences"] = [ref("Job", "backfill", "batch/v1")]
    cases.append(("Job", pod, FakeObjects(("jobs", job))))

    run = "nightly-29012345"
    labels = {"batch.kubernetes.io/job-name": run, "job-name": run}
    job = owner_obj("Job", run, labels, ref("CronJob", "nightly", "batch/v1"))
    cron = owner_obj("CronJob", "nightly", {}, status={"active": [{"uid": f"uid-Job-{run}"}]})
    pod = make_pod(f"{run}-4kq8s", labels=labels)
    pod["metadata"]["ownerReferences"] = [ref("Job", run, "batch/v1")]
    cases.append(("CronJob", pod, FakeObjects(("jobs", job), ("cronjobs", cron))))

    pod = make_pod("debug-agent", labels={"app": "debug"})
    cases.append(("bare pod", pod, FakeObjects()))
    return cases


class WorkloadKeyTest(unittest.TestCase):
    def test_every_workload_kind_gives_the_sidecars_key(self):
        for kind, pod, objects in kind_cases():
            with self.subTest(kind=kind):
                checked, how = workload.sandbox_name(objects, "agents", pod)
                sidecar, source = pod_mode.workload_name(pod["metadata"]["name"], pod["metadata"]["labels"])
                self.assertIsNotNone(checked, how)
                self.assertEqual(checked, f"agents/{sidecar}", f"gke-scan: {how}; sidecar: {source}")
                self.assertEqual(fields.workload_key("gke-test", checked), ("gke-test", checked))

    def test_the_recorded_pods_key_as_the_sidecar_keys_them(self):
        for cluster in CLUSTERS:
            pod = recorded(cluster)["pods"][0]
            owner = pod["metadata"]["ownerReferences"][0]
            labels = pod["metadata"]["labels"]
            rs = {"kind": "ReplicaSet", "metadata": {"name": owner["name"], "uid": owner["uid"], "labels": labels,
                                                     "ownerReferences": [ref("Deployment", "agent-finretail")]},
                  "spec": {"selector": {"matchLabels": {"app": "agent-finretail",
                                                        "pod-template-hash": labels["pod-template-hash"]}}}}
            dep = owner_obj("Deployment", "agent-finretail", {"app": "agent-finretail"})
            with self.subTest(cluster=cluster):
                checked, _ = workload.sandbox_name(FakeObjects(("replicasets", rs), ("deployments", dep)),
                                                   "gke-test", pod)
                sidecar, _ = pod_mode.workload_name(pod["metadata"]["name"], labels)
                self.assertEqual(checked, f"gke-test/{sidecar}")
                self.assertEqual(checked, "gke-test/agent-finretail")


# ── the agent container, revision, sidecar and agent_type ──────────────────

class ResolverTest(unittest.TestCase):
    def test_the_annotation_wins(self):
        pod = make_pod(containers=[{"name": "proxy-helper"}, {"name": "agent"}],
                       annotations={fields.AGENT_CONTAINER_ANNOTATION: "agent"})
        container, note = fields.agent_container(pod)
        self.assertEqual((container["name"], note), ("agent", None))

    def test_several_candidates_pick_the_first_with_a_note(self):
        pod = make_pod(containers=[{"name": "rail-proxy"}, {"name": "worker"}, {"name": "agent"},
                                   {"name": "rail-scan"}])
        container, note = fields.agent_container(pod)
        self.assertEqual(container["name"], "worker")
        self.assertIn("'worker', 'agent'", note)
        self.assertIn(fields.AGENT_CONTAINER_ANNOTATION, note)

    def test_an_annotation_naming_no_container_falls_back_with_a_note(self):
        pod = make_pod(containers=[{"name": "agent"}], annotations={fields.AGENT_CONTAINER_ANNOTATION: "missing"})
        container, note = fields.agent_container(pod)
        self.assertEqual(container["name"], "agent")
        self.assertIn("'missing', which the pod doesn't have; using 'agent'", note)

    def test_the_sidecar_and_proxy_are_never_the_agent(self):
        pod = make_pod(containers=[{"name": "rail-proxy"}, {"name": "railmon-scan", "args": ["scan", "--mode", "pod"]}])
        self.assertEqual(fields.agent_container(pod), (None, "the pod has no container other than the scan "
                                                              "sidecar and rail-proxy"))

    def test_the_recorded_pods_agent_container_revision_and_sidecar(self):
        for cluster in CLUSTERS:
            pod = recorded(cluster)["pods"][0]
            with self.subTest(cluster=cluster):
                self.assertEqual(fields.agent_container(pod)[0]["name"], "agent")
                self.assertEqual(fields.pod_revision(pod), pod["metadata"]["labels"]["pod-template-hash"])
                self.assertTrue(fields.has_sidecar(pod), "railmon-scan runs scan --mode pod")
                self.assertTrue(fields.is_ready(pod))

    def test_a_sidecar_is_found_by_the_webhooks_annotation_a_native_sidecar_or_its_name(self):
        self.assertFalse(fields.has_sidecar(make_pod()))
        self.assertTrue(fields.has_sidecar(make_pod(annotations={fields.SIDECAR_INJECTED_ANNOTATION: "img"})))
        self.assertTrue(fields.has_sidecar(make_pod(initContainers=[
            {"name": "rail-scan", "restartPolicy": "Always", "args": ["scan", "--mode", "pod", "--register"]}])))
        self.assertFalse(fields.has_sidecar(make_pod(initContainers=[{"name": "rail-scan"}])),
                         "an init container that runs to completion isn't a sidecar")
        self.assertTrue(fields.has_sidecar(make_pod(containers=[{"name": "agent"}, {"name": "rail-scan"}])))

    def test_revisions_of_each_controller(self):
        self.assertEqual(fields.pod_revision(make_pod(labels={"rollouts-pod-template-hash": "77bf"})), "77bf")
        self.assertEqual(fields.pod_revision(make_pod(labels={"controller-revision-hash": "ledger-5c9"})), "ledger-5c9")
        self.assertIsNone(fields.pod_revision(make_pod(labels={"app": "x"})))

    def test_the_agent_type_label(self):
        labeled = make_pod(labels={"app": "x", fields.AGENT_TYPE_LABEL: "service"})
        self.assertEqual(fields.agent_type(labeled), ("service", None))
        attribute = fields.agent_type_attribute([labeled], B)
        self.assertEqual((attribute["status"], attribute["value"], attribute["tier"]), ("ANSWERED", "service", "declared"))
        self.assertEqual(fields.agent_type(make_pod()), (None, None))
        self.assertIsNone(fields.agent_type_attribute([make_pod()], B))
        value, note = fields.agent_type(make_pod(labels={fields.AGENT_TYPE_LABEL: "robot"}))
        self.assertIsNone(value)
        self.assertIn("'robot'", note)


# ── the fields against what central_v3.py produced ──────────────────────────

GATEWAY = {"metadata": {"name": "agent-finretail-gateway", "namespace": "gke-test"},
           "spec": {"type": "ClusterIP", "selector": {"app": "agent-finretail"},
                    "ports": [{"name": "gateway", "port": 18789, "targetPort": 18789}]}}
OTHER_SERVICE = {"metadata": {"name": "finretail-mcp", "namespace": "gke-test"},
                 "spec": {"selector": {"app": "finretail-mcp-server"}, "ports": [{"port": 23004}]}}


def recorded_policies(cluster: str) -> list[dict[str, Any]]:
    selecting = recorded(cluster)["central_v3"]["network_policies_selecting_agent"]
    policies = [policy(p["name"], {"matchLabels": {"app": "agent-finretail"}}, "gke-test",
                       policyTypes=p["policyTypes"], egress=p["egress"]) for p in selecting]
    # In another namespace, and one selecting other pods: neither counts.
    policies.append(policy("other-pods-only", {"matchLabels": {"app": "finretail-data-service"}}, "gke-test",
                           policyTypes=["Ingress"]))
    policies.append(policy("elsewhere", {}, "another-namespace"))
    return policies


class RecordedFieldsTest(unittest.TestCase):
    def attributes(self, cluster: str) -> dict[str, Any]:
        pods = recorded(cluster)["pods"]
        return fields.pod_spec_attributes(pods, [GATEWAY, OTHER_SERVICE], [], recorded_policies(cluster), B)

    def test_image_digest_is_the_agent_containers_status_image_id(self):
        for cluster in CLUSTERS:
            pod = recorded(cluster)["pods"][0]
            status = next(s for s in pod["status"]["containerStatuses"] if s["name"] == "agent")
            with self.subTest(cluster=cluster):
                attribute = self.attributes(cluster)["image_digest"]
                self.assertEqual(attribute["status"], "ANSWERED")
                self.assertEqual(attribute["value"], status["imageID"].split("@")[-1])
                self.assertTrue(attribute["value"].startswith("sha256:"))

    def test_mounts_are_the_agents_less_the_token_with_their_volumes(self):
        for cluster in CLUSTERS:
            pod = recorded(cluster)["pods"][0]
            agent = pod["spec"]["containers"][0]
            # compare15.py's value: the agent's mounts, ro or rw, but the service account's.
            research = sorted((m["mountPath"], "ro" if m.get("readOnly") else "rw") for m in agent["volumeMounts"]
                              if "serviceaccount" not in m["mountPath"])
            with self.subTest(cluster=cluster):
                attribute = self.attributes(cluster)["mounts"]
                self.assertEqual(attribute["status"], "ANSWERED")
                self.assertEqual(sorted((m["target"], m["mode"]) for m in attribute["value"]), research)
                types = {m["target"]: m["type"] for m in attribute["value"]}
                self.assertEqual(types, {"/rail-agent": "configMap", "/rail-policy": "configMap",
                                         "/root/.openclaw": "emptyDir"})

    def test_permissions_from_the_security_contexts_and_host_settings(self):
        for cluster in CLUSTERS:
            with self.subTest(cluster=cluster):
                value = self.attributes(cluster)["permissions"]["value"]
                self.assertEqual((value["privileged"], value["cap_add"], value["cap_drop"]), (False, [], ["ALL"]))
                self.assertIs(value["allow_privilege_escalation"], False)
                self.assertEqual(value["seccomp_profile"], {"type": "RuntimeDefault"})
                self.assertIsNone(value["run_as_user"], "nothing in the pod sets it: the image's user (RC-553)")
                self.assertEqual((value["host_network"], value["host_pid"], value["host_ipc"]), (False, False, False))
                self.assertEqual(value["service_account"], "agent-finretail")
                self.assertEqual(value["runtime_class"], "gvisor" if cluster == "gke-sandbox" else None)

    def test_declared_ports(self):
        for cluster in CLUSTERS:
            with self.subTest(cluster=cluster):
                self.assertEqual(self.attributes(cluster)["declared_ports"]["value"],
                                 [{"port": 18789, "protocol": "TCP"}])

    def test_services_exposing_agent_match_central_v3(self):
        for cluster in CLUSTERS:
            research = recorded(cluster)["central_v3"]["services_exposing_agent"]
            with self.subTest(cluster=cluster):
                value = self.attributes(cluster)["services_exposing_agent"]["value"]
                self.assertEqual([{"name": s["name"], "type": s["type"],
                                   "ports": [{"port": p["port"], "targetPort": p["target_port"]} for p in s["ports"]]}
                                  for s in value], research)

    def test_sandbox_network_policy_matches_central_v3(self):
        for cluster in CLUSTERS:
            research = recorded(cluster)["central_v3"]["network_policies_selecting_agent"]
            with self.subTest(cluster=cluster):
                attribute = self.attributes(cluster)["sandbox_network_policy"]
                self.assertEqual(attribute["status"], "ANSWERED")
                self.assertEqual([(p["name"], p["policy_types"], p["egress"]) for p in attribute["value"]],
                                 [(p["name"], p["policyTypes"], p["egress"]) for p in research])
                self.assertIn("1 of 2 in its namespace", attribute["method"])

    def test_the_attributes_verify_as_the_scanners_and_carry_no_env_value(self):
        for cluster in CLUSTERS:
            attributes = self.attributes(cluster)
            text = json.dumps(attributes)
            with self.subTest(cluster=cluster):
                self.assertNotIn("recorded value left out", text)
                self.assertNotIn("AGENT_MCP_URL", text)
                for name, attribute in attributes.items():
                    self.assertIn(attribute["status"], ("ANSWERED", "PARTIAL", "BLIND", "ABSENT"), name)
                    self.assertIn(attribute["tier"], ("declared", "observed"), name)


class ReadinessAndDigestTest(unittest.TestCase):
    def test_a_mutable_tag_that_moved_gives_partial_with_every_digest(self):
        a = make_pod("agent-6d9f8c7b5-aaaaa", image_id="r/agent@sha256:" + "a" * 64)
        b = make_pod("agent-6d9f8c7b5-bbbbb", image_id="r/agent@sha256:" + "b" * 64)
        attribute = fields.pod_spec_attributes([a, b], [], [], [], B)["image_digest"]
        self.assertEqual(attribute["status"], "PARTIAL")
        self.assertEqual(attribute["value"], ["sha256:" + "a" * 64, "sha256:" + "b" * 64])
        self.assertIn("agent-6d9f8c7b5-aaaaa", attribute["note"])
        self.assertIn("agent-6d9f8c7b5-bbbbb", attribute["note"])

    def test_a_pod_not_yet_ready_contributes_nothing(self):
        starting = ready(make_pod("agent-6d9f8c7b5-new", image_id="r/agent@sha256:" + "b" * 64), is_ready=False)
        running = make_pod("agent-6d9f8c7b5-old", image_id="r/agent@sha256:" + "a" * 64)
        attribute = fields.pod_spec_attributes([starting, running], [], [], [], B)["image_digest"]
        self.assertEqual((attribute["status"], attribute["value"]), ("ANSWERED", "sha256:" + "a" * 64))
        self.assertIsNone(fields.pod_spec_attributes([starting], [], [], [], B))
        terminating = make_pod("agent-6d9f8c7b5-bye")
        terminating["metadata"]["deletionTimestamp"] = "2026-11-24T00:00:00Z"
        self.assertFalse(fields.is_ready(terminating))

    def test_no_image_id_yet_is_blind(self):
        attribute = fields.pod_spec_attributes([make_pod(image_id=None)], [], [], [], B)["image_digest"]
        self.assertEqual((attribute["status"], attribute["reason"]), ("BLIND", "NO_SOURCE_ACCESS"))


class MountsTest(unittest.TestCase):
    def test_a_claim_gives_its_class_modes_and_size_and_a_secret_only_its_name(self):
        pod = make_pod(containers=[{"name": "agent", "volumeMounts": [
            {"name": "data", "mountPath": "/data"},
            {"name": "creds", "mountPath": "/etc/creds", "readOnly": True},
            {"name": "cfg", "mountPath": "/etc/agent/config.yaml", "subPath": "config.yaml", "readOnly": True},
            {"name": "kube-api-access-x", "mountPath": fields.SERVICE_ACCOUNT_TOKEN_PATH}]}],
            volumes=[{"name": "data", "persistentVolumeClaim": {"claimName": "agent-data"}},
                     {"name": "creds", "secret": {"secretName": "agent-llm", "items": [{"key": "k", "path": "p"}]}},
                     {"name": "cfg", "configMap": {"name": "agent-config"}},
                     {"name": "kube-api-access-x", "projected": {"sources": [{"serviceAccountToken": {}}]}}])
        claim = {"metadata": {"name": "agent-data", "namespace": "agents"},
                 "spec": {"storageClassName": "premium-rwo", "accessModes": ["ReadWriteOnce"],
                          "resources": {"requests": {"storage": "10Gi"}}},
                 "status": {"accessModes": ["ReadWriteOnce"], "capacity": {"storage": "10Gi"}}}
        attribute = fields.mounts_attribute([pod], [claim], B)
        self.assertEqual(attribute["status"], "ANSWERED")
        self.assertEqual(attribute["value"], [
            {"target": "/data", "mode": "rw", "volume": "data", "type": "persistentVolumeClaim", "source": "agent-data",
             "storage_class": "premium-rwo", "access_modes": ["ReadWriteOnce"], "capacity": "10Gi"},
            {"target": "/etc/agent/config.yaml", "mode": "ro", "sub_path": "config.yaml", "volume": "cfg",
             "type": "configMap", "source": "agent-config"},
            {"target": "/etc/creds", "mode": "ro", "volume": "creds", "type": "secret", "source": "agent-llm"},
        ])

    def test_a_claim_not_in_the_copy_is_partial(self):
        pod = make_pod(containers=[{"name": "agent", "volumeMounts": [{"name": "data", "mountPath": "/data"}]}],
                       volumes=[{"name": "data", "persistentVolumeClaim": {"claimName": "gone"}}])
        attribute = fields.mounts_attribute([pod], [], B)
        self.assertEqual((attribute["status"], attribute["reason"]), ("PARTIAL", "NO_SOURCE_ACCESS"))
        self.assertIn("claim gone", attribute["note"])

    def test_no_mounts_is_an_answered_empty_list(self):
        attribute = fields.mounts_attribute([make_pod()], [], B)
        self.assertEqual((attribute["status"], attribute["value"]), ("ANSWERED", []))


class ServicesAndPermissionsTest(unittest.TestCase):
    def test_a_service_in_another_namespace_or_without_a_selector_doesnt_expose_the_pod(self):
        pod = make_pod(labels={"app": "agent"})
        services = [
            {"metadata": {"name": "same", "namespace": "agents"},
             "spec": {"type": "LoadBalancer", "selector": {"app": "agent"},
                      "ports": [{"port": 443, "targetPort": "https", "nodePort": 31443}]},
             "status": {"loadBalancer": {"ingress": [{"ip": "203.0.113.7"}]}}},
            {"metadata": {"name": "elsewhere", "namespace": "other"}, "spec": {"selector": {"app": "agent"}}},
            {"metadata": {"name": "headless-manual", "namespace": "agents"}, "spec": {"ports": [{"port": 80}]}},
        ]
        value = fields.services_exposing_attribute([pod], services, B)["value"]
        self.assertEqual(value, [{"name": "same", "type": "LoadBalancer",
                                  "ports": [{"port": 443, "target_port": "https", "protocol": "TCP", "node_port": 31443}],
                                  "load_balancer_ingress": ["203.0.113.7"]}])

    def test_the_containers_settings_win_over_the_pods(self):
        pod = make_pod(containers=[{"name": "agent", "securityContext": {"runAsUser": 1000, "privileged": True,
                                                                        "capabilities": {"add": ["NET_ADMIN"]}}}],
                       securityContext={"runAsUser": 0, "runAsGroup": 3000, "runAsNonRoot": False},
                       hostNetwork=True, hostPID=True, runtimeClassName="gvisor")
        value = fields.permissions_attribute([pod], B)["value"]
        self.assertEqual((value["run_as_user"], value["run_as_group"], value["run_as_non_root"]), (1000, 3000, False))
        self.assertEqual((value["privileged"], value["cap_add"]), (True, ["NET_ADMIN"]))
        self.assertEqual((value["host_network"], value["host_pid"], value["runtime_class"]), (True, True, "gvisor"))
        self.assertEqual(value["service_account"], "default")


# ── NetworkPolicy selection ─────────────────────────────────────────────────

class PolicySelectionTest(unittest.TestCase):
    LABELS = {"app": "agent", "tier": "prod"}

    def matches(self, selector: Any) -> bool | None:
        return fields.label_selector_matches(selector, self.LABELS)

    def test_match_expressions_select_correctly(self):
        def expr(key: str, op: str, *values: str) -> dict[str, Any]:
            return {"matchExpressions": [{"key": key, "operator": op, **({"values": list(values)} if values else {})}]}

        self.assertTrue(self.matches(expr("tier", "In", "prod", "staging")))
        self.assertFalse(self.matches(expr("tier", "In", "staging")))
        self.assertFalse(self.matches(expr("missing", "In", "x")))
        self.assertTrue(self.matches(expr("tier", "NotIn", "staging")))
        self.assertFalse(self.matches(expr("tier", "NotIn", "prod")))
        self.assertTrue(self.matches(expr("missing", "NotIn", "x")))
        self.assertTrue(self.matches(expr("app", "Exists")))
        self.assertFalse(self.matches(expr("missing", "Exists")))
        self.assertTrue(self.matches(expr("missing", "DoesNotExist")))
        self.assertFalse(self.matches(expr("app", "DoesNotExist")))
        both = {"matchLabels": {"app": "agent"}, "matchExpressions": [{"key": "tier", "operator": "In", "values": ["dev"]}]}
        self.assertFalse(self.matches(both), "matchLabels and matchExpressions are ANDed")

    def test_an_empty_pod_selector_selects_every_pod(self):
        self.assertTrue(self.matches({}))
        self.assertTrue(self.matches(None))
        pod = make_pod(labels=self.LABELS)
        selecting, _ = fields.selecting_policies(pod, [policy("default-deny", {}, policyTypes=["Ingress", "Egress"])])
        self.assertEqual([p["name"] for p in selecting], ["default-deny"])

    def test_an_unevaluable_selector_gives_partial_naming_the_policy(self):
        pod = make_pod(labels=self.LABELS)
        policies = [policy("odd", {"matchExpressions": [{"key": "tier", "operator": "Gt", "values": ["1"]}]}),
                    policy("broken", {"matchExpressions": [{"key": "tier", "operator": "In"}]}),
                    policy("allow-dns", {"matchLabels": {"app": "agent"}}, egress=[{"ports": [{"port": 53}]}])]
        attribute = fields.sandbox_network_policy_attribute([pod], policies, B)
        self.assertEqual((attribute["status"], attribute["reason"]), ("PARTIAL", "PARSE_FAILED"))
        self.assertIn("broken, odd", attribute["note"])
        self.assertEqual([p["name"] for p in attribute["value"]], ["allow-dns"])

    def test_peers_are_kept_as_written_and_policy_types_defaulted(self):
        egress = [{"to": [{"namespaceSelector": {"matchLabels": {"team": "data"}}},
                          {"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8"]}}]}]
        pod = make_pod(labels=self.LABELS)
        value = fields.sandbox_network_policy_attribute(
            [pod], [policy("egress-only-rules", {"matchLabels": {"app": "agent"}}, egress=egress),
                    policy("ingress-default", {"matchLabels": {"app": "agent"}})], B)["value"]
        self.assertEqual(value[0], {"name": "egress-only-rules", "policy_types": ["Ingress", "Egress"],
                                    "ingress": [], "egress": egress})
        self.assertEqual(value[1]["policy_types"], ["Ingress"])

    def test_no_selecting_policy_is_answered_empty(self):
        attribute = fields.sandbox_network_policy_attribute([make_pod()], [], B)
        self.assertEqual((attribute["status"], attribute["value"]), ("ANSWERED", []))
        self.assertIn("allows all its traffic", attribute["note"])


if __name__ == "__main__":
    unittest.main()
