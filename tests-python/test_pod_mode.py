"""RC-504: `railmon scan --mode pod` names the agent from the downward API.

As a sidecar in a Kubernetes pod, the scanner learns which pod it is in from
the downward API (POD_NAME, POD_NAMESPACE, POD_UID, NODE_NAME and the labels
file in RAIL_POD_INFO_DIR), files the agent under namespace/workload, and
never guesses an owner from git or the login user.

The name-derivation tests call the functions directly. The bundle tests run
the real scanner as a subprocess, so what is asserted is what it wrote or sent.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCANNER_DIR = ROOT / "tools" / "scan"
SCANNER = SCANNER_DIR / "scan_agent_environment.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


scanner = _load("scan_agent_environment", SCANNER)
evidence_bundle = _load("evidence_bundle", SCANNER_DIR / "evidence_bundle.py")
pod_mode = scanner._pod_mode()   # tools/scan/gke/pod_mode.py


def collect_pod_context(config_paths=()):
    """Pod mode's context, as scan() builds it."""
    return pod_mode.collect_context(scanner.collect_self_context(), list(config_paths), scanner.redact_cmdline,
                                   scanner.container_id_from_cgroup)

POD = {
    "POD_NAME": "agent-finretail-58cd78b55d-48jcw",
    "POD_NAMESPACE": "gke-test",
    "POD_UID": "f3fe5e58-b328-40cb-9b03-1acf558d773d",
    "NODE_NAME": "gke-gke-test-default-pool-1c6529e9-aqik",
}
DEPLOYMENT_LABELS = 'app="agent-finretail"\npod-template-hash="58cd78b55d"\n'


class WorkloadNameTest(unittest.TestCase):
    def test_a_deployment_pod_loses_its_template_hash_and_suffix(self):
        name, source = pod_mode.workload_name(
            "agent-finretail-58cd78b55d-48jcw", {"pod-template-hash": "58cd78b55d"})
        self.assertEqual(name, "agent-finretail")
        self.assertEqual(source, "pod name without its pod-template-hash")

    def test_two_replicas_and_a_restart_get_the_same_name(self):
        labels = {"pod-template-hash": "58cd78b55d"}
        names = {pod_mode.workload_name(pod, labels)[0]
                 for pod in ("agent-finretail-58cd78b55d-48jcw", "agent-finretail-58cd78b55d-x7k2p")}
        self.assertEqual(names, {"agent-finretail"})

    def test_a_statefulset_pod_name_is_already_stable(self):
        for pod in ("db-0", "db-1"):
            name, source = pod_mode.workload_name(pod, {"statefulset.kubernetes.io/pod-name": pod})
            self.assertEqual(name, pod)
            self.assertEqual(source, "statefulset pod name")

    def test_a_bare_pod_keeps_its_name(self):
        # `-agent` looks like a generated five-character suffix; it isn't one.
        self.assertEqual(pod_mode.workload_name("debug-agent", {}), ("debug-agent", "pod name"))

    def test_a_job_pod_is_named_after_its_job(self):
        name, source = pod_mode.workload_name(
            "nightly-scan-7xk2p", {"batch.kubernetes.io/job-name": "nightly-scan"})
        self.assertEqual(name, "nightly-scan")
        self.assertEqual(source, "label batch.kubernetes.io/job-name")

    def test_a_cronjob_pod_keeps_one_name_across_runs(self):
        names = {pod_mode.workload_name(f"nightly-scan-{run}-7xk2p",
                                       {"batch.kubernetes.io/job-name": f"nightly-scan-{run}"})
                 for run in ("29630880", "29632320")}
        self.assertEqual(names, {("nightly-scan", "label batch.kubernetes.io/job-name without its CronJob run number")})

    def test_a_job_named_by_date_or_unix_seconds_keeps_its_name(self):
        for job in ("report-20240115", "backup-1700000000"):
            name, source = pod_mode.workload_name(f"{job}-abcde", {"job-name": job})
            self.assertEqual((name, source), (job, "label job-name"))

    def test_a_long_deployment_whose_pod_name_was_cut_derives_nothing(self):
        # Kubernetes cuts <deployment>-<hash>- to 58 characters. A 57-character
        # Deployment and a longer one with a dash at character 58 then give
        # the same pod name, so neither is guessed.
        for deployment in ("a" * 46 + "z", "a" * 56 + "z", "a" * 57 + "-bc", "a" * 60):
            pod = f"{deployment}-58cd78b55d-"[:58] + "48jcw"
            self.assertEqual(pod_mode.workload_name(pod, {"pod-template-hash": "58cd78b55d"}),
                             (None, "pod-template-hash not found in the pod name"), deployment)

    def test_the_longest_deployment_whose_hash_fits_is_still_named(self):
        deployment = "a" * 45 + "z"   # 46 + 12 = 58: the whole -<hash>- fits
        pod = f"{deployment}-58cd78b55d-" + "48jcw"
        self.assertEqual(pod_mode.workload_name(pod, {"pod-template-hash": "58cd78b55d"})[0], deployment)

    def test_a_hash_label_the_pod_name_doesnt_carry_derives_nothing(self):
        self.assertEqual(pod_mode.workload_name("finretail", {"pod-template-hash": "58cd78b55d"}),
                         (None, "pod-template-hash not found in the pod name"))

    def test_an_argo_rollout_pod_loses_its_template_hash(self):
        name, source = pod_mode.workload_name(
            "agent-finretail-6f9c7d8b4-x7k2p", {"rollouts-pod-template-hash": "6f9c7d8b4"})
        self.assertEqual((name, source),
                         ("agent-finretail", "pod name without its rollouts-pod-template-hash"))

    def test_a_daemonset_pod_keeps_one_name_across_restarts(self):
        labels = {"controller-revision-hash": "7d4f8b9c6", "pod-template-generation": "3"}
        names = {pod_mode.workload_name(f"node-agent-{suffix}", labels) for suffix in ("x7k2p", "4mzqd")}
        self.assertEqual(names, {("node-agent", "DaemonSet pod name without its generated suffix")})

    def test_a_daemonset_pod_name_kubernetes_may_have_cut_derives_nothing(self):
        # 63 characters: a 57-character DaemonSet, or a longer one cut to 58.
        labels = {"controller-revision-hash": "7d4f8b9c6"}
        for daemonset in ("a" * 57, "a" * 70):
            pod = f"{daemonset}-"[:58] + "x7k2p"
            self.assertEqual(pod_mode.workload_name(pod, labels),
                             (None, "DaemonSet pod name cut by Kubernetes"), daemonset)

    def test_a_short_name_with_a_daemonset_label_derives_nothing_and_does_not_crash(self):
        for pod in ("a", "ab-cd", "abcdef", "abcdefg"):
            self.assertEqual(pod_mode.workload_name(pod, {"controller-revision-hash": "7d4f8b9c6"}),
                             (None, "controller-revision-hash on a pod name no DaemonSet generates"), pod)

    def test_a_statefulset_pod_is_not_taken_for_a_daemonset(self):
        labels = {"controller-revision-hash": "db-6c5d8", "statefulset.kubernetes.io/pod-name": "db-0"}
        self.assertEqual(pod_mode.workload_name("db-0", labels), ("db-0", "statefulset pod name"))

    def test_a_job_name_ending_in_a_short_number_is_kept(self):
        name, _ = pod_mode.workload_name("migrate-2-abcde", {"job-name": "migrate-2"})
        self.assertEqual(name, "migrate-2")

    def test_no_pod_name_is_no_workload(self):
        self.assertEqual(pod_mode.workload_name(None, {"pod-template-hash": "x"}), (None, "unset"))


class LabelsFileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_quoted_values_are_unquoted(self):
        path = self.tmp / "labels"
        path.write_text('app="agent-finretail"\nrail.datrail.io/owner="support-platform"\n'
                        'note="say \\"hi\\""\n')
        self.assertEqual(pod_mode.read_downward_api_labels(path), ({
            "app": "agent-finretail",
            "rail.datrail.io/owner": "support-platform",
            "note": 'say "hi"',
        }, False))

    def test_a_missing_file_is_unknown_labels_not_no_labels(self):
        self.assertEqual(pod_mode.read_downward_api_labels(self.tmp / "labels"), (None, False))

    def test_an_empty_file_is_a_pod_with_no_labels(self):
        (self.tmp / "labels").write_text("")
        self.assertEqual(pod_mode.read_downward_api_labels(self.tmp / "labels"), ({}, False))

    def test_a_file_over_the_cap_keeps_whole_lines_and_says_so(self):
        line = 'k{}="' + "v" * 90 + '"\n'
        (self.tmp / "labels").write_text("".join(line.format(i) for i in range(1000)))
        labels, truncated = pod_mode.read_downward_api_labels(self.tmp / "labels")
        self.assertTrue(truncated)
        self.assertGreater(len(labels), 0)
        self.assertLess(len(labels), 1000)
        self.assertTrue(all(value == "v" * 90 for value in labels.values()))

    def test_a_cut_labels_file_without_a_workload_label_derives_nothing(self):
        # The kubelet sorts by key, so pod-template-hash lands after the cut.
        filler = "".join(f'a{i:04}="' + "v" * 90 + '"\n' for i in range(1000))
        (self.tmp / "labels").write_text(filler + 'pod-template-hash="58cd78b55d"\n')
        pod = pod_mode.read_pod_metadata(POD, self.tmp)
        self.assertTrue(pod["labels_truncated"])
        self.assertEqual((pod["workload"], pod["workload_source"]),
                         (None, "labels file over the cap, before any workload label"))

    def test_a_cut_labels_file_with_its_workload_label_still_names_it(self):
        filler = "".join(f'z{i:04}="' + "v" * 90 + '"\n' for i in range(1000))
        (self.tmp / "labels").write_text('pod-template-hash="58cd78b55d"\n' + filler)
        pod = pod_mode.read_pod_metadata(POD, self.tmp)
        self.assertTrue(pod["labels_truncated"])
        self.assertEqual(pod["workload"], "agent-finretail")

    def test_a_cut_pod_name_says_to_set_sandbox_name(self):
        (self.tmp / "labels").write_text('pod-template-hash="58cd78b55d"\n')
        env = {**POD, "POD_NAME": ("a" * 60)[:58] + "48jcw", "RAIL_POD_INFO_DIR": str(self.tmp)}
        with mock.patch.dict(os.environ, env, clear=False), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            pod = collect_pod_context()["pod"]
        self.assertIsNone(pod["workload"])
        self.assertIn("set --sandbox-name to namespace/<workload>", err.getvalue())

    def test_without_the_labels_file_no_workload_is_guessed(self):
        env = {**POD, "RAIL_POD_INFO_DIR": str(self.tmp)}
        with mock.patch.dict(os.environ, env, clear=False), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            pod = collect_pod_context()["pod"]
        self.assertIsNone(pod["workload"])
        self.assertEqual(pod["workload_source"], "no labels file")
        self.assertIn("missing the labels file", err.getvalue())

    def test_the_labels_are_read_from_rail_pod_info_dir(self):
        (self.tmp / "labels").write_text(DEPLOYMENT_LABELS)
        env = {**POD, "RAIL_POD_INFO_DIR": str(self.tmp)}
        with mock.patch.dict(os.environ, env, clear=False):
            context = collect_pod_context()
        pod = context["pod"]
        self.assertEqual(context["mode"], "pod")
        # pod-template-hash changes with each rollout, so it is left out.
        self.assertEqual(pod["labels"], {"app": "agent-finretail"})
        self.assertEqual(pod["workload"], "agent-finretail")
        self.assertEqual((pod["name"], pod["namespace"], pod["uid"], pod["node"]),
                         (POD["POD_NAME"], POD["POD_NAMESPACE"], POD["POD_UID"], POD["NODE_NAME"]))

    def test_without_rail_pod_info_dir_the_default_folder_is_read(self):
        read = []
        with mock.patch.dict(os.environ, {}, clear=False), \
                mock.patch.object(pod_mode, "read_downward_api_labels",
                                  side_effect=lambda path: read.append(path) or ({}, False)), \
                contextlib.redirect_stderr(io.StringIO()):
            os.environ.pop("RAIL_POD_INFO_DIR", None)
            collect_pod_context()
        self.assertEqual(read, [Path("/etc/podinfo/labels")])


class FakeCenter:
    """A loopback rail-center that records every POST."""

    def __init__(self):
        center = self
        self.requests: list[bytes] = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                center.requests.append(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                data = json.dumps({"agent": {"id": "a-1"}, "evidence_bundle_id": "eb-1",
                                   "duplicate": False}).encode()
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)


class PodModeScanTest(unittest.TestCase):
    """The real scanner in pod mode, as a subprocess."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.podinfo = self.tmp / "podinfo"
        self.podinfo.mkdir()
        # A home of its own, so no real ~/.gitconfig or ~/.openclaw is read.
        self.home = self.tmp / "home"
        self.home.mkdir()

    def env(self, downward_api: bool = True, **extra: str) -> dict[str, str]:
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("RAIL_", "GCE_", "POD_", "GIT_"))
               and key not in ("NODE_NAME", "USER", "LOGNAME")}
        env.update(HOME=str(self.home), RAIL_POD_INFO_DIR=str(self.podinfo))
        if downward_api:
            env.update(POD)
            (self.podinfo / "labels").write_text(DEPLOYMENT_LABELS)
        env.update(extra)
        return env

    def run_scan(self, args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCANNER), "--mode", "pod", "--config-path", str(self.tmp / "config"),
             "--feature-output", str(self.tmp / "features.json"),
             "--evidence-bundle-output", str(self.tmp / "bundle.json"),
             "--output", str(self.tmp / "payload.json")] + args,
            cwd=self.tmp, capture_output=True, text=True, env=env, timeout=120,
        )

    def bundle(self) -> dict[str, Any]:
        return json.loads((self.tmp / "bundle.json").read_text())

    def test_the_bundle_names_the_agent_and_passes_verify_bundle(self):
        proc = self.run_scan(["--host-id", "gke-test"], self.env(RAIL_OWNER="support-platform"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        bundle = self.bundle()
        evidence_bundle.verify_bundle(bundle)

        self.assertEqual(bundle["host_id"], "gke-test")
        self.assertEqual(bundle["sandbox_name"], "gke-test/agent-finretail")
        attributes = bundle["attributes"]
        self.assertEqual(attributes["agent_instance"]["status"], "ANSWERED")
        self.assertEqual(attributes["agent_instance"]["value"], {"pod": {
            "name": POD["POD_NAME"], "uid": POD["POD_UID"], "node": POD["NODE_NAME"]}})
        self.assertEqual(attributes["agent_instance"]["authored_by"], "platform")
        self.assertEqual(attributes["deployment"]["status"], "ANSWERED")
        self.assertEqual(attributes["deployment"]["value"],
                         {"RAIL_DEPLOYMENT": "agent-finretail", "RAIL_NAMESPACE": "gke-test"})
        self.assertEqual(attributes["deployment"]["authored_by"], "platform")
        self.assertEqual(attributes["deployment"]["method"],
                         "RAIL_DEPLOYMENT from the downward API (the pod name without its "
                         "pod-template-hash); RAIL_NAMESPACE from the downward API (POD_NAMESPACE)")
        self.assertEqual(attributes["owner"]["status"], "ANSWERED")
        self.assertEqual(attributes["owner"]["value"],
                         {"owner": "support-platform", "source": "RAIL_OWNER"})
        self.assertEqual(attributes["container_identity"]["value"],
                         {"host_id": "gke-test", "sandbox_name": "gke-test/agent-finretail"})
        self.assertEqual(attributes["sandbox_type"]["value"], "kubernetes")

    def test_a_restarted_pod_gets_the_same_key_and_a_new_instance(self):
        first = self.run_scan(["--host-id", "gke-test"], self.env())
        self.assertEqual(first.returncode, 0, first.stderr)
        before = self.bundle()
        restarted = self.env(POD_NAME="agent-finretail-58cd78b55d-x7k2p", POD_UID="0b1c2d3e")
        second = self.run_scan(["--host-id", "gke-test"], restarted)
        self.assertEqual(second.returncode, 0, second.stderr)
        after = self.bundle()
        self.assertEqual(after["sandbox_name"], before["sandbox_name"])
        self.assertEqual(after["attributes"]["deployment"]["value"],
                         before["attributes"]["deployment"]["value"])
        self.assertNotEqual(after["attributes"]["agent_instance"]["value"],
                            before["attributes"]["agent_instance"]["value"])

    def test_an_explicit_deployment_pair_wins_and_the_method_says_so(self):
        env = self.env(downward_api=False, RAIL_DEPLOYMENT="finretail", RAIL_NAMESPACE="prod")
        proc = self.run_scan(["--host-id", "gke-test", "--sandbox-name", "prod/finretail"], env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        deployment = self.bundle()["attributes"]["deployment"]
        self.assertEqual(deployment["value"], {"RAIL_DEPLOYMENT": "finretail", "RAIL_NAMESPACE": "prod"})
        self.assertEqual(deployment["method"],
                         "RAIL_DEPLOYMENT from the environment; RAIL_NAMESPACE from the environment")
        self.assertNotIn("downward API", deployment["method"])
        self.assertNotIn("unset", deployment["method"])

    def test_an_explicit_key_and_the_downward_api_are_each_credited(self):
        proc = self.run_scan(["--host-id", "gke-test"], self.env(RAIL_DEPLOYMENT="finretail"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        deployment = self.bundle()["attributes"]["deployment"]
        self.assertEqual(deployment["value"], {"RAIL_DEPLOYMENT": "finretail", "RAIL_NAMESPACE": "gke-test"})
        self.assertEqual(deployment["method"],
                         "RAIL_DEPLOYMENT from the environment; "
                         "RAIL_NAMESPACE from the downward API (POD_NAMESPACE)")

    def test_no_downward_api_gives_blind_with_no_source_access(self):
        proc = self.run_scan(["--host-id", "gke-test", "--sandbox-name", "gke-test/agent-finretail"],
                             self.env(downward_api=False))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        bundle = self.bundle()
        evidence_bundle.verify_bundle(bundle)
        for name in ("agent_instance", "deployment", "owner"):
            field = bundle["attributes"][name]
            self.assertEqual(field["status"], "BLIND", name)
            self.assertEqual(field["reason"], "NO_SOURCE_ACCESS", name)
            self.assertIsNone(field["value"], name)
        # The design's failure table: scan the rest, and log it.
        self.assertIn("pod mode: the downward API is missing POD_NAME, POD_NAMESPACE, POD_UID, "
                      "NODE_NAME, the labels file", proc.stderr)

    def test_a_full_downward_api_logs_nothing_about_it(self):
        proc = self.run_scan(["--host-id", "gke-test"], self.env())
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("downward API is missing", proc.stderr)

    def test_no_user_or_git_owner_fallback_in_pod_mode(self):
        (self.home / ".gitconfig").write_text("[user]\n\temail = someone@example.com\n\tname = Someone\n")
        env = self.env(USER="root", LOGNAME="root", GIT_AUTHOR_EMAIL="author@example.com")
        proc = self.run_scan(["--host-id", "gke-test"], env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        bundle = self.bundle()
        owner = bundle["attributes"]["owner"]
        self.assertEqual(owner["status"], "BLIND")
        self.assertEqual(owner["reason"], "NO_SOURCE_ACCESS")
        written = (self.tmp / "bundle.json").read_text()
        for guess in ("author@example.com", "someone@example.com"):
            self.assertNotIn(guess, written)
        # Without a readable agent process user_info is BLIND (RC-509); with
        # one, it is the agent's user. Either way, never the sidecar's git.
        user_info = bundle["attributes"]["user_info"]["value"] or {}
        self.assertNotIn("git_user_email", user_info)
        self.assertNotIn("git_user_name", user_info)

    def test_self_mode_still_falls_back_to_the_login_user(self):
        env = self.env(USER="ops-user")
        proc = subprocess.run(
            [sys.executable, str(SCANNER), "--mode", "self", "--host-id", "h-1",
             "--feature-output", str(self.tmp / "features.json"),
             "--evidence-bundle-output", str(self.tmp / "bundle.json"),
             "--output", str(self.tmp / "payload.json")],
            cwd=self.tmp, capture_output=True, text=True, env=env, timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.bundle()["attributes"]["owner"]["value"],
                         {"owner": "ops-user", "source": "USER"})

    def assert_nothing_sent_or_written(self, args: list[str], env: dict[str, str], missing: str):
        center = FakeCenter()
        self.addCleanup(center.close)
        proc = self.run_scan(args + ["--register", "--center-url", center.url], env)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn(f"--mode pod cannot name the agent: no {missing}", proc.stderr)
        self.assertEqual(center.requests, [])
        for name in ("bundle.json", "payload.json", "features.json"):
            self.assertFalse((self.tmp / name).exists(), name)

    def test_no_sandbox_name_sends_nothing(self):
        self.assert_nothing_sent_or_written(["--host-id", "gke-test"],
                                            self.env(downward_api=False), "sandbox_name")

    def test_no_labels_file_sends_nothing_rather_than_an_unstable_key(self):
        env = self.env()
        (self.podinfo / "labels").unlink()
        self.assert_nothing_sent_or_written(["--host-id", "gke-test"], env, "sandbox_name")

    def test_no_labels_file_with_sandbox_name_still_scans(self):
        env = self.env()
        (self.podinfo / "labels").unlink()
        proc = self.run_scan(["--host-id", "gke-test", "--sandbox-name", "gke-test/agent-finretail"], env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        bundle = self.bundle()
        evidence_bundle.verify_bundle(bundle)
        self.assertEqual(bundle["sandbox_name"], "gke-test/agent-finretail")
        # The pod's own fields still come from the variables.
        self.assertEqual(bundle["attributes"]["agent_instance"]["status"], "ANSWERED")

    def test_no_host_id_sends_nothing(self):
        self.assert_nothing_sent_or_written([], self.env(), "host_id")

    def test_with_the_key_the_bundle_is_sent(self):
        center = FakeCenter()
        self.addCleanup(center.close)
        proc = self.run_scan(["--host-id", "gke-test", "--register", "--center-url", center.url],
                             self.env())
        self.assertEqual(proc.returncode, 0, proc.stderr)
        [body] = center.requests
        self.assertEqual(body, (self.tmp / "bundle.json").read_bytes())
        self.assertEqual(json.loads(body)["sandbox_name"], "gke-test/agent-finretail")


if __name__ == "__main__":
    unittest.main()
