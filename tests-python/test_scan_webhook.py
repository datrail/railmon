"""RC-518: the admission webhook adds the scan sidecar to labeled pods.

The ticket's exit criteria are the first three tests, on the JSON patch: a
plain pod gets the sidecar with RAIL_SANDBOX_TYPE kubernetes; a gVisor pod
gets gvisor; a pod that already has the sidecar gets no patch. The rest
cover the per-pod parts (config mounts, UID and GID), failing open, and the
HTTPS server with a real AdmissionReview.
"""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import os
import posixpath
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock
from typing import Any
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
WEBHOOK = ROOT / "tools" / "scan" / "gke" / "webhook"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


scan_webhook = _load("scan_webhook_entry", WEBHOOK / "scan_webhook.py")
patch = scan_webhook.patch_module()

IMAGE = "us-docker.pkg.dev/datrail/railmon/scan-sidecar:1.2.3"

# What the chart renders into its ConfigMap with its default values
# (deploy/helm/railmon-gke/templates/sidecar-spec.yaml).
SPEC: dict[str, Any] = {
    "containerName": "rail-scan",
    "configPath": "/root/.openclaw",
    "nativeSidecar": True,
    "container": {
        "image": IMAGE,
        "args": ["scan", "--mode", "pod", "--register", "--no-feature-file"],
        "workingDir": "/tmp",
        "env": [
            {"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
            {"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}},
            {"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}},
            {"name": "NODE_NAME", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}},
            {"name": "RAIL_OWNER", "valueFrom": {"fieldRef": {"fieldPath": "metadata.labels['rail.datrail.io/owner']"}}},
            {"name": "RAIL_HOST_ID", "value": "gke-test"},
            {"name": "RAIL_CENTER_URL", "value": "https://gke-scan.rail-system.svc:8443"},
            {"name": "RAIL_AUTH_MODE", "value": "bearer"},
            {"name": "RAIL_AUTH_TOKEN_FILE", "value": "/var/run/rail/token"},
            {"name": "RAIL_CENTER_CA_FILE", "value": "/etc/rail/ca/ca.crt"},
            {"name": "RAIL_SCAN_INTERVAL_IN_SECONDS", "value": "3600"},
            {"name": "RAIL_POD_INFO_DIR", "value": "/etc/podinfo"},
        ],
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "readOnlyRootFilesystem": True,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "volumeMounts": [
            {"name": "rail-scan-podinfo", "mountPath": "/etc/podinfo", "readOnly": True},
            {"name": "rail-scan-token", "mountPath": "/var/run/rail", "readOnly": True},
            {"name": "rail-scan-ca", "mountPath": "/etc/rail/ca", "readOnly": True},
            {"name": "rail-scan-tmp", "mountPath": "/tmp"},
        ],
    },
    "volumes": [
        {"name": "rail-scan-podinfo", "downwardAPI": {"items": [{"path": "labels", "fieldRef": {"fieldPath": "metadata.labels"}}]}},
        {"name": "rail-scan-token", "projected": {"sources": [{"serviceAccountToken": {"audience": "gke-scan", "expirationSeconds": 3600, "path": "token"}}]}},
        {"name": "rail-scan-ca", "configMap": {"name": "rail-scan-ca"}},
        {"name": "rail-scan-tmp", "emptyDir": {"sizeLimit": "64Mi"}},
    ],
}


# CI renders the chart and sets RAILMON_SIDECAR_SPEC to its sidecar.json, so
# these tests also run against the spec the chart really produces.
if os.environ.get("RAILMON_SIDECAR_SPEC"):
    with open(os.environ["RAILMON_SIDECAR_SPEC"], encoding="utf-8") as _handle:
        SPEC = json.load(_handle)
    IMAGE = SPEC["container"]["image"]


def agent_pod(**spec_overrides: Any) -> dict[str, Any]:
    """An OpenClaw agent's pod as its ReplicaSet creates it, before admission."""
    pod: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "generateName": "agent-finretail-58cd78b55d-",
            "namespace": "gke-test",
            "labels": {"app": "agent-finretail", "pod-template-hash": "58cd78b55d", "rail.datrail.io/scan": "true"},
        },
        "spec": {
            "containers": [{
                "name": "agent",
                "image": "ghcr.io/nvidia/nemoclaw:latest",
                "securityContext": {"runAsUser": 0, "runAsGroup": 0},
                "volumeMounts": [{"name": "openclaw-config", "mountPath": "/root/.openclaw"}],
            }],
            "volumes": [{"name": "openclaw-config", "persistentVolumeClaim": {"claimName": "openclaw"}}],
        },
    }
    pod["spec"].update(spec_overrides)
    return pod


def patched(pod: dict[str, Any], spec: dict[str, Any] = SPEC) -> tuple[dict[str, Any], Any]:
    result = patch.sidecar_patch(pod, spec)
    return patch.apply_patch(pod, result.patch), result


def sidecar_of(pod: dict[str, Any]) -> dict[str, Any]:
    found = [c for key in ("initContainers", "containers") for c in pod["spec"].get(key) or [] if c["name"] == "rail-scan"]
    assert len(found) == 1, found
    return found[0]


def env_of(container: dict[str, Any]) -> dict[str, Any]:
    return {e["name"]: e.get("value", e.get("valueFrom")) for e in container.get("env") or []}


class ExitCriteriaTest(unittest.TestCase):
    def test_plain_pod_gets_the_sidecar(self) -> None:
        pod = agent_pod()
        after, result = patched(pod)
        self.assertIsNone(result.skipped)
        self.assertEqual(result.warnings, [])
        sidecar = sidecar_of(after)
        self.assertEqual(sidecar["image"], IMAGE)
        self.assertEqual(sidecar["restartPolicy"], "Always")
        self.assertEqual(env_of(sidecar)["RAIL_SANDBOX_TYPE"], "kubernetes")
        self.assertEqual(sidecar["args"][-2:], ["--config-path", "/root/.openclaw"])
        self.assertIn({"name": "openclaw-config", "mountPath": "/root/.openclaw", "readOnly": True}, sidecar["volumeMounts"])
        self.assertTrue(after["spec"]["shareProcessNamespace"])
        # A root agent with the runtime's default capabilities: the sidecar
        # gets the same default set, which reading the agent's process needs.
        expected = {**SPEC["container"]["securityContext"], "runAsUser": 0, "runAsGroup": 0, "runAsNonRoot": False}
        expected.pop("capabilities")
        self.assertEqual(sidecar["securityContext"], expected)
        names = [v["name"] for v in after["spec"]["volumes"]]
        self.assertEqual(names, ["openclaw-config"] + [v["name"] for v in SPEC["volumes"]])
        self.assertEqual(set(names[1:]), {"rail-scan-podinfo", "rail-scan-token", "rail-scan-ca", "rail-scan-tmp"})
        self.assertTrue(after["spec"]["containers"][0]["volumeMounts"])
        self.assertEqual(env_of(sidecar)["POD_UID"], {"fieldRef": {"fieldPath": "metadata.uid"}})
        self.assertEqual(env_of(sidecar)["RAIL_AUTH_TOKEN_FILE"], "/var/run/rail/token")
        self.assertTrue(sidecar["securityContext"]["readOnlyRootFilesystem"])
        token = next(v for v in after["spec"]["volumes"] if v["name"] == "rail-scan-token")
        self.assertEqual(token["projected"]["sources"][0]["serviceAccountToken"], {"audience": "gke-scan", "expirationSeconds": 3600, "path": "token"})
        self.assertEqual(after["metadata"]["annotations"], {"rail.datrail.io/scan-sidecar": IMAGE})
        # The agent itself is untouched.
        self.assertEqual(after["spec"]["containers"], pod["spec"]["containers"])

    def test_gvisor_pod_gets_gvisor(self) -> None:
        after, result = patched(agent_pod(runtimeClassName="gvisor"))
        self.assertIsNone(result.skipped)
        self.assertEqual(env_of(sidecar_of(after))["RAIL_SANDBOX_TYPE"], "gvisor")

    def test_pod_with_the_sidecar_gets_no_patch(self) -> None:
        once, _ = patched(agent_pod())
        result = patch.sidecar_patch(once, SPEC)
        self.assertEqual(result.patch, [])
        self.assertIn("already has a container named rail-scan", result.skipped)
        # Added by hand as a regular container: the same.
        by_hand = agent_pod()
        by_hand["spec"]["containers"].append({"name": "rail-scan", "image": IMAGE})
        self.assertEqual(patch.sidecar_patch(by_hand, SPEC).patch, [])


class PatchTest(unittest.TestCase):
    def test_other_runtime_class_is_kubernetes(self) -> None:
        after, _ = patched(agent_pod(runtimeClassName="kata"))
        self.assertEqual(env_of(sidecar_of(after))["RAIL_SANDBOX_TYPE"], "kubernetes")

    def test_sandbox_type_in_the_spec_is_replaced_not_duplicated(self) -> None:
        spec = copy.deepcopy(SPEC)
        spec["container"]["env"].append({"name": "RAIL_SANDBOX_TYPE", "value": "docker"})
        after, _ = patched(agent_pod(runtimeClassName="gvisor"), spec)
        names = [e["name"] for e in sidecar_of(after)["env"]]
        self.assertEqual(names.count("RAIL_SANDBOX_TYPE"), 1)
        self.assertEqual(env_of(sidecar_of(after))["RAIL_SANDBOX_TYPE"], "gvisor")

    def test_patch_paths_for_a_pod_with_no_volumes_or_annotations(self) -> None:
        pod = agent_pod()
        del pod["spec"]["volumes"]
        pod["spec"]["containers"][0].pop("volumeMounts")
        result = patch.sidecar_patch(pod, SPEC)
        paths = [op["path"] for op in result.patch]
        self.assertEqual(paths, ["/spec/shareProcessNamespace", "/spec/volumes", "/spec/initContainers", "/metadata/annotations"])
        self.assertTrue(any("can't read the agent's config" in w for w in result.warnings))

    def test_patch_appends_to_existing_lists_and_escapes_the_annotation(self) -> None:
        pod = agent_pod(initContainers=[{"name": "setup", "image": "busybox"}])
        pod["metadata"]["annotations"] = {"a": "b"}
        result = patch.sidecar_patch(pod, SPEC)
        paths = [op["path"] for op in result.patch]
        self.assertIn("/spec/initContainers/-", paths)
        self.assertIn("/spec/volumes/-", paths)
        self.assertIn("/metadata/annotations/rail.datrail.io~1scan-sidecar", paths)
        after = patch.apply_patch(pod, result.patch)
        # After the agent's own init containers, so their setup is done when it starts.
        self.assertEqual([c["name"] for c in after["spec"]["initContainers"]], ["setup", "rail-scan"])

    def test_share_process_namespace_false_is_replaced(self) -> None:
        result = patch.sidecar_patch(agent_pod(shareProcessNamespace=False), SPEC)
        self.assertIn({"op": "replace", "path": "/spec/shareProcessNamespace", "value": True}, result.patch)
        result = patch.sidecar_patch(agent_pod(shareProcessNamespace=True), SPEC)
        self.assertFalse(any(op["path"] == "/spec/shareProcessNamespace" for op in result.patch))

    def test_regular_container_when_native_sidecars_are_off(self) -> None:
        spec = {**SPEC, "nativeSidecar": False}
        after, _ = patched(agent_pod(), spec)
        self.assertEqual([c["name"] for c in after["spec"]["containers"]], ["agent", "rail-scan"])
        self.assertNotIn("restartPolicy", after["spec"]["containers"][1])

    def test_host_pid_pod_skips_with_a_warning(self) -> None:
        # The API server refuses shareProcessNamespace with hostPID ("cannot
        # both be enabled"), so a patch would stop the pod; it starts without
        # the sidecar instead.
        result = patch.sidecar_patch(agent_pod(hostPID=True), SPEC)
        self.assertEqual(result.patch, [])
        self.assertIn("hostPID", result.skipped)
        self.assertTrue(any("hostPID" in w for w in result.warnings))
        # hostPID false is any other pod.
        self.assertTrue(patch.sidecar_patch(agent_pod(hostPID=False), SPEC).patch)

    def test_volume_name_clash_skips_with_a_warning(self) -> None:
        pod = agent_pod()
        pod["spec"]["volumes"].append({"name": "rail-scan-tmp", "emptyDir": {}})
        result = patch.sidecar_patch(pod, SPEC)
        self.assertEqual(result.patch, [])
        self.assertTrue(result.warnings)

    def test_config_mounts_above_and_below_the_config_path(self) -> None:
        agent = {"volumeMounts": [
            {"name": "home", "mountPath": "/root"},
            {"name": "openclaw", "mountPath": "/root/.openclaw", "subPath": "oc"},
            {"name": "state", "mountPath": "/root/.openclaw/state"},
            {"name": "other", "mountPath": "/data"},
            {"name": "prefix-trap", "mountPath": "/root/.openclaw-old"},
        ]}
        mounts = patch.config_mounts(agent, "/root/.openclaw/")
        self.assertEqual(mounts, [
            {"name": "openclaw", "mountPath": "/root/.openclaw", "readOnly": True, "subPath": "oc"},
            {"name": "state", "mountPath": "/root/.openclaw/state", "readOnly": True},
        ])
        # A config path inside a volume mounted higher up.
        self.assertEqual(patch.config_mounts({"volumeMounts": [{"name": "home", "mountPath": "/root", "readOnly": False}]}, "/root/.openclaw"),
                         [{"name": "home", "mountPath": "/root", "readOnly": True}])

    def test_config_mount_at_a_sidecar_mount_path_is_dropped_with_a_warning(self) -> None:
        # A hardened agent with HOME=/tmp on an emptyDir: its config volume is
        # at /tmp, where the sidecar mounts its own. Two mounts at one path
        # would make the API server refuse the pod.
        pod = agent_pod()
        agent = pod["spec"]["containers"][0]
        agent["volumeMounts"] = [{"name": "home", "mountPath": "/tmp/"},
                                 {"name": "state", "mountPath": "/tmp/.openclaw/state"}]
        pod["spec"]["volumes"] = [{"name": "home", "emptyDir": {}}, {"name": "state", "emptyDir": {}}]
        pod["metadata"]["annotations"] = {"rail.datrail.io/scan-config-path": "/tmp/.openclaw"}
        after, result = patched(pod)
        paths = [posixpath.normpath(m["mountPath"]) for m in sidecar_of(after)["volumeMounts"]]
        self.assertEqual(len(paths), len(set(paths)), paths)
        names = [m["name"] for m in sidecar_of(after)["volumeMounts"]]
        self.assertNotIn("home", names)
        self.assertIn("state", names)  # under the clash, so still copied
        self.assertTrue(any("home" in w and "BLIND" in w for w in result.warnings))
        self.assertFalse(any("no volume of the agent's container" in w for w in result.warnings))

    def test_config_path_and_agent_container_from_annotations(self) -> None:
        pod = agent_pod()
        pod["spec"]["containers"].insert(0, {"name": "proxy", "image": "envoy", "securityContext": {"runAsUser": 101}})
        pod["spec"]["containers"][1]["volumeMounts"].append({"name": "claude", "mountPath": "/home/node/.claude"})
        pod["spec"]["volumes"].append({"name": "claude", "emptyDir": {}})
        pod["metadata"]["annotations"] = {
            "rail.datrail.io/scan-agent-container": "agent",
            "rail.datrail.io/scan-config-path": "/home/node/.claude",
        }
        after, result = patched(pod)
        sidecar = sidecar_of(after)
        self.assertEqual(sidecar["args"][-2:], ["--config-path", "/home/node/.claude"])
        self.assertIn({"name": "claude", "mountPath": "/home/node/.claude", "readOnly": True}, sidecar["volumeMounts"])
        self.assertEqual(sidecar["securityContext"]["runAsUser"], 0)  # the agent's, not the proxy's
        self.assertEqual(result.warnings, [])

    def split_pod(self, annotation: str) -> dict[str, Any]:
        """An agent whose files sit on two volumes (RC-549)."""
        pod = agent_pod()
        agent = pod["spec"]["containers"][0]
        agent["volumeMounts"] = [{"name": "config", "mountPath": "/data/openclaw"},
                                 {"name": "state", "mountPath": "/root/.openclaw"}]
        pod["spec"]["volumes"] = [{"name": "config", "emptyDir": {}}, {"name": "state", "emptyDir": {}}]
        pod["metadata"]["annotations"] = {"rail.datrail.io/scan-config-path": annotation}
        return pod

    def test_two_config_paths_on_two_volumes_give_two_arguments_and_both_mounts(self) -> None:
        after, result = patched(self.split_pod("/data/openclaw, /root/.openclaw"))
        sidecar = sidecar_of(after)
        self.assertEqual(sidecar["args"][-4:], ["--config-path", "/data/openclaw", "--config-path", "/root/.openclaw"])
        mounts = [m for m in sidecar["volumeMounts"] if m["name"] in ("config", "state")]
        self.assertEqual(mounts, [{"name": "config", "mountPath": "/data/openclaw", "readOnly": True},
                                  {"name": "state", "mountPath": "/root/.openclaw", "readOnly": True}])
        self.assertEqual(result.warnings, [])

    def test_two_config_paths_on_one_volume_mount_it_once(self) -> None:
        pod = self.split_pod("/root/.claude,/root/work,/root/.claude")
        pod["spec"]["containers"][0]["volumeMounts"] = [{"name": "home", "mountPath": "/root"}]
        pod["spec"]["volumes"] = [{"name": "home", "emptyDir": {}}]
        after, result = patched(pod)
        sidecar = sidecar_of(after)
        self.assertEqual(sidecar["args"][-4:], ["--config-path", "/root/.claude", "--config-path", "/root/work"])
        self.assertEqual([m["name"] for m in sidecar["volumeMounts"]].count("home"), 1)
        self.assertEqual(result.warnings, [])

    def test_a_path_no_volume_holds_warns_for_that_path_only(self) -> None:
        after, result = patched(self.split_pod("/root/.openclaw,/workspace"))
        self.assertIn("state", [m["name"] for m in sidecar_of(after)["volumeMounts"]])
        no_volume = [w for w in result.warnings if "no volume of the agent's container" in w]
        self.assertEqual(len(no_volume), 1)
        self.assertIn("/workspace", no_volume[0])
        self.assertNotIn("/root/.openclaw", no_volume[0])

    def test_one_path_is_unchanged_and_the_chart_may_give_a_list(self) -> None:
        one, one_result = patched(self.split_pod("/root/.openclaw"))
        self.assertEqual(sidecar_of(one)["args"][-2:], ["--config-path", "/root/.openclaw"])
        self.assertEqual([m["name"] for m in sidecar_of(one)["volumeMounts"] if m["name"] in ("config", "state")], ["state"])
        self.assertEqual(one_result.warnings, [])
        pod = self.split_pod("")
        del pod["metadata"]["annotations"]
        listed, _ = patched(pod, dict(SPEC, configPath=["/data/openclaw", "/root/.openclaw"]))
        self.assertEqual(sidecar_of(listed)["args"][-4:], ["--config-path", "/data/openclaw", "--config-path", "/root/.openclaw"])
        self.assertEqual(patch.config_paths(" , ", None), [])

    def test_unknown_agent_container_annotation_falls_back_with_a_warning(self) -> None:
        pod = agent_pod()
        pod["metadata"]["annotations"] = {"rail.datrail.io/scan-agent-container": "nope"}
        _, result = patched(pod)
        self.assertTrue(any("doesn't have" in w for w in result.warnings))


class RunAsTest(unittest.TestCase):
    def sc(self, pod: dict[str, Any], spec: dict[str, Any] = SPEC) -> tuple[dict[str, Any], list[str]]:
        after, result = patched(pod, spec)
        return sidecar_of(after)["securityContext"], result.warnings

    def test_pod_security_context_when_the_container_has_none(self) -> None:
        pod = agent_pod(securityContext={"runAsUser": 1000, "runAsGroup": 2000})
        pod["spec"]["containers"][0].pop("securityContext")
        sc, warnings = self.sc(pod)
        self.assertEqual((sc["runAsUser"], sc["runAsGroup"], sc["runAsNonRoot"]), (1000, 2000, True))
        self.assertEqual(warnings, [])

    def test_container_wins_over_pod(self) -> None:
        pod = agent_pod(securityContext={"runAsUser": 1000, "runAsGroup": 1000})
        sc, _ = self.sc(pod)
        self.assertEqual((sc["runAsUser"], sc["runAsGroup"]), (0, 0))

    def test_annotation_when_the_spec_has_none(self) -> None:
        pod = agent_pod()
        pod["spec"]["containers"][0].pop("securityContext")
        pod["metadata"]["annotations"] = {"rail.datrail.io/scan-run-as-user": "1001", "rail.datrail.io/scan-run-as-group": "1001"}
        sc, warnings = self.sc(pod)
        self.assertEqual((sc["runAsUser"], sc["runAsGroup"], sc["runAsNonRoot"]), (1001, 1001, True))
        self.assertEqual(warnings, [])

    def test_gid_defaults_to_uid_with_a_warning(self) -> None:
        pod = agent_pod()
        pod["spec"]["containers"][0]["securityContext"] = {"runAsUser": 1000}
        sc, warnings = self.sc(pod)
        self.assertEqual(sc["runAsGroup"], 1000)
        self.assertTrue(any("GID" in w for w in warnings))

    def test_no_uid_anywhere_leaves_the_image_user_and_warns(self) -> None:
        pod = agent_pod()
        pod["spec"]["containers"][0].pop("securityContext")
        pod["metadata"]["annotations"] = {"rail.datrail.io/scan-run-as-user": "root"}
        sc, warnings = self.sc(pod)
        self.assertNotIn("runAsUser", sc)
        # The image's user isn't root, and Pod Security `restricted` needs this.
        self.assertIs(sc["runAsNonRoot"], True)
        self.assertTrue(any("isn't a UID" in w for w in warnings))
        self.assertTrue(any("65532" in w for w in warnings))
        # The chart's default fills the gap when set.
        sc, _ = self.sc(pod, {**SPEC, "runAsUser": 0, "runAsGroup": 0})
        self.assertEqual((sc["runAsUser"], sc["runAsNonRoot"]), (0, False))


class CapabilitiesTest(unittest.TestCase):
    """Reading another process's environment and root needs the caller's
    permitted capabilities to include the target's, even at the same UID."""

    def caps(self, pod: dict[str, Any]) -> Any:
        after, _ = patched(pod)
        return sidecar_of(after)["securityContext"].get("capabilities", "runtime default")

    def test_non_root_agent_keeps_none(self) -> None:
        pod = agent_pod()
        pod["spec"]["containers"][0]["securityContext"] = {
            "runAsUser": 1000, "runAsGroup": 1000, "capabilities": {"add": ["NET_ADMIN"]}}
        self.assertEqual(self.caps(pod), {"drop": ["ALL"]})

    def test_root_agent_capabilities_are_mirrored(self) -> None:
        pod = agent_pod()
        caps = {"drop": ["ALL"], "add": ["CHOWN", "SETUID"]}
        pod["spec"]["containers"][0]["securityContext"]["capabilities"] = caps
        self.assertEqual(self.caps(pod), caps)
        self.assertIsNot(self.caps(pod), caps)

    def test_root_agent_that_drops_all_gets_a_sidecar_with_none(self) -> None:
        pod = agent_pod()
        pod["spec"]["containers"][0]["securityContext"]["capabilities"] = {"drop": ["ALL"]}
        self.assertEqual(self.caps(pod), {"drop": ["ALL"]})

    def test_root_agent_without_capabilities_gets_the_runtime_default(self) -> None:
        self.assertEqual(self.caps(agent_pod()), "runtime default")

    def test_unknown_uid_keeps_none(self) -> None:
        pod = agent_pod()
        pod["spec"]["containers"][0].pop("securityContext")
        self.assertEqual(self.caps(pod), {"drop": ["ALL"]})


class WarningsAnnotationTest(unittest.TestCase):
    def test_warnings_are_kept_on_the_pod(self) -> None:
        pod = agent_pod()
        pod["spec"]["containers"][0].pop("securityContext")
        after, result = patched(pod)
        self.assertEqual(after["metadata"]["annotations"]["rail.datrail.io/scan-sidecar-warnings"],
                         "\n".join(result.warnings))
        pod["metadata"]["annotations"] = {"x": "y"}
        after, _ = patched(pod)
        self.assertIn("rail.datrail.io/scan-sidecar-warnings", after["metadata"]["annotations"])

    def test_no_annotation_without_warnings(self) -> None:
        after, _ = patched(agent_pod())
        self.assertNotIn("rail.datrail.io/scan-sidecar-warnings", after["metadata"]["annotations"])


class ReviewTest(unittest.TestCase):
    def review(self, pod: dict[str, Any], **request: Any) -> dict[str, Any]:
        body = {"uid": "req-1", "kind": {"group": "", "version": "v1", "kind": "Pod"}, "operation": "CREATE",
                "namespace": "gke-test", "object": pod}
        body.update(request)
        return {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": body}

    def test_review_carries_the_patch(self) -> None:
        answer = scan_webhook.review_response(self.review(agent_pod()), SPEC)
        response = answer["response"]
        self.assertEqual((response["uid"], response["allowed"], response["patchType"]), ("req-1", True, "JSONPatch"))
        ops = json.loads(base64.b64decode(response["patch"]))
        self.assertEqual(ops, patch.sidecar_patch(agent_pod(), SPEC).patch)

    def test_fails_open_on_a_broken_spec(self) -> None:
        answer = scan_webhook.review_response(self.review(agent_pod()), {"volumes": []})  # no container
        self.assertEqual(answer["response"], {"uid": "req-1", "allowed": True})

    def test_fails_open_on_a_strange_pod(self) -> None:
        answer = scan_webhook.review_response(self.review({"spec": {"containers": "nope", "volumes": 7}}), SPEC)
        self.assertTrue(answer["response"]["allowed"])

    def test_only_pod_creation_is_patched(self) -> None:
        for request in ({"operation": "UPDATE"}, {"kind": {"kind": "Deployment"}}, {"subResource": "ephemeralcontainers"}):
            answer = scan_webhook.review_response(self.review(agent_pod(), **request), SPEC)
            self.assertNotIn("patch", answer["response"])
            self.assertTrue(answer["response"]["allowed"])
        self.assertTrue(scan_webhook.review_response({"request": None}, SPEC)["response"]["allowed"])

    def test_warnings_reach_the_response(self) -> None:
        pod = agent_pod()
        pod["spec"]["containers"][0].pop("securityContext")
        response = scan_webhook.review_response(self.review(pod), SPEC)["response"]
        self.assertIn("patch", response)
        self.assertTrue(response["warnings"][0].startswith("rail scan sidecar: "))


@unittest.skipUnless(shutil.which("openssl"), "needs openssl for a test certificate")
class ServerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        cert, key = os.path.join(self.tmp, "tls.crt"), os.path.join(self.tmp, "tls.key")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", key, "-out", cert],
            check=True, capture_output=True,
        )
        self.server = scan_webhook.WebhookServer(("127.0.0.1", 0), SPEC, scan_webhook.server_tls_context(cert, key))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.cert, self.key = cert, key
        self.context = ssl.create_default_context(cafile=cert)
        self.base = f"https://localhost:{self.server.server_address[1]}"

    def test_a_renewed_certificate_is_served_without_a_restart(self) -> None:
        # The chart signs a new certificate on every render; the running
        # webhook must serve it, or the API server (trusting the new CA)
        # stops calling it and labeled pods start without the sidecar.
        renewed = os.path.join(self.tmp, "renewed")
        os.mkdir(renewed)
        new_cert, new_key = os.path.join(renewed, "tls.crt"), os.path.join(renewed, "tls.key")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", new_key, "-out", new_cert],
            check=True, capture_output=True,
        )
        shutil.copy(new_key, self.key)
        shutil.copy(new_cert, self.cert)
        with mock.patch.object(scan_webhook, "log", lambda line: None):
            with urlopen(self.base + "/healthz", context=ssl.create_default_context(cafile=new_cert), timeout=5) as answer:
                self.assertEqual(answer.status, 200)

    def test_mutate_over_https(self) -> None:
        review = ReviewTest().review(agent_pod(runtimeClassName="gvisor"))
        request = Request(self.base + "/mutate", data=json.dumps(review).encode(), headers={"Content-Type": "application/json"})
        with urlopen(request, context=self.context, timeout=5) as answer:
            body = json.loads(answer.read())
        ops = json.loads(base64.b64decode(body["response"]["patch"]))
        after = patch.apply_patch(review["request"]["object"], ops)
        self.assertEqual(env_of(sidecar_of(after))["RAIL_SANDBOX_TYPE"], "gvisor")

    def test_healthz(self) -> None:
        with urlopen(self.base + "/healthz", context=self.context, timeout=5) as answer:
            self.assertEqual(answer.status, 200)

    def test_a_silent_client_does_not_hold_up_other_requests(self) -> None:
        # A connection that never starts its TLS handshake (a port scan, a
        # half-open connection) must not stop the webhook answering others.
        silent = socket.create_connection(("127.0.0.1", self.server.server_address[1]))
        self.addCleanup(silent.close)
        with urlopen(self.base + "/healthz", context=self.context, timeout=5) as answer:
            self.assertEqual(answer.status, 200)

    def test_a_stalled_client_is_dropped_after_the_read_timeout(self) -> None:
        self.assertIsNotNone(scan_webhook.WebhookHandler.timeout)
        self.assertLessEqual(scan_webhook.WebhookHandler.timeout, scan_webhook.REQUEST_READ_TIMEOUT_SECONDS)

    def test_main_needs_its_settings(self) -> None:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("RAIL_WEBHOOK_", "RAIL_SCAN_SIDECAR_"))}
        run = subprocess.run([sys.executable, str(WEBHOOK / "scan_webhook.py")], env=env, capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertIn("--sidecar-spec", run.stderr)


if __name__ == "__main__":
    unittest.main()
