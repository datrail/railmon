"""Tests for the v1 evidence bundle: the closed-set contract and the write path.

The bundle is the profile brain's input, so two invariants matter. First,
its closed sets: the six statuses, the thirteen reason codes, the three
tiers and the four authored_by values are mirrored from the published
contract, and a field outside them is a collector bug, not a value.
Second, the write path: the bundle is written from the scanner's `finally`,
so it lands even when the registration fails, and a write failure is
reported without changing the exit code - the feature file owns that.

Stdlib only, to match the scanner itself - `make test-python` runs this
with no dependencies to install.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from argparse import Namespace
from pathlib import Path
from types import ModuleType
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCANNER_DIR = ROOT / "tools" / "agent-environment-scanner"
SCANNER = SCANNER_DIR / "scan_agent_environment.py"

_spec = importlib.util.spec_from_file_location("scan_agent_environment", SCANNER)
scanner = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(scanner)
# The bundle module imports the scanner lazily under its canonical name, so
# register the object under that name: the lazy import then resolves to the
# same module this file tested, not a second copy.
sys.modules.setdefault("scan_agent_environment", scanner)

_bundle_spec = importlib.util.spec_from_file_location(
    "evidence_bundle", SCANNER_DIR / "evidence_bundle.py"
)
evidence_bundle = importlib.util.module_from_spec(_bundle_spec)
assert _bundle_spec.loader is not None
_bundle_spec.loader.exec_module(evidence_bundle)


def build_args(**overrides) -> Namespace:
    kwargs = {
        "config_path": [],
        "mcp_config": [],
        "evidence_bundle_output": None,
        "compact": False,
    }
    kwargs.update(overrides)
    return Namespace(**kwargs)


def docker_context(**overrides) -> dict:
    base = {
        "mode": "docker",
        "env": {},
        "hostname": "host-from-label",
        "image": "sha256:deadbeef",
        "container_name": "agent-container",
        "container_id": "cid",
        "proc1_cmdline": "",
        "docker_inspect": {
            "Image": "sha256:deadbeef",
            "HostConfig": {"Privileged": False, "CapAdd": [], "User": "root"},
            "Config": {"Labels": {"com.docker.compose.project": "rail", "com.docker.compose.service": "agent"}},
        },
    }
    base.update(overrides)
    return base


def self_context(**overrides) -> dict:
    base = {
        "mode": "self",
        "env": {},
        "hostname": "host-from-hostname",
        "image": None,
        "container_name": None,
        "container_id": None,
        "proc1_cmdline": "",
        "docker_inspect": None,
    }
    base.update(overrides)
    return base


def identity(**overrides) -> dict:
    base = {
        "host_id": "h-1",
        "host_id_source": "container_env",
        "sandbox_name": "agent-container",
        "sandbox_name_source": "container_name",
        "host_class": "container",
        "registration_status": "unregistered",
        "mcp_servers": [],
        "observed_reach": None,
    }
    base.update(overrides)
    return base


def build_bundle(**overrides):
    mode = overrides.pop("mode", "docker")
    context = docker_context() if mode == "docker" else self_context()
    payload = {"host_id": "h-1", "sandbox_name": "agent-container"}
    return evidence_bundle.build_evidence_bundle(build_args(), context, payload, identity())


class BundleContractTest(unittest.TestCase):
    """The emitted bundle stays inside the closed sets, and the check rejects a broken one."""

    def test_every_emitted_field_is_inside_the_closed_sets(self):
        bundle = build_bundle()
        for name, field in bundle["attributes"].items():
            self.assertIn(field.get("status"), evidence_bundle.STATUSES, name)
            self.assertIn(field.get("tier"), evidence_bundle.TIERS, name)
            self.assertIn(
                field.get("authored_by"), (*evidence_bundle.AUTHORED_BY, None), name
            )
            self.assertIn(field.get("reason"), (*evidence_bundle.REASONS, None), name)
            if field["status"] == "ABSENT":
                self.assertTrue(field.get("method"), f"{name}: ABSENT without method")
        self.assertEqual(evidence_bundle.contract_problems(bundle), [])

    def test_an_unknown_status_is_a_problem(self):
        bundle = build_bundle()
        bundle["attributes"]["tool_names"] = {"value": None, "status": "MAYBE", "tier": "observed"}
        problems = evidence_bundle.contract_problems(bundle)
        self.assertTrue(any("MAYBE" in p for p in problems), problems)

    def test_an_unknown_reason_is_a_problem(self):
        bundle = build_bundle()
        bundle["attributes"]["user"] = {"value": None, "status": "BLIND", "reason": "WHY_NOT", "tier": "observed"}
        problems = evidence_bundle.contract_problems(bundle)
        self.assertTrue(any("WHY_NOT" in p for p in problems), problems)

    def test_an_absent_without_method_is_a_problem(self):
        bundle = build_bundle()
        bundle["attributes"]["user"] = {"value": None, "status": "ABSENT", "tier": "observed"}
        problems = evidence_bundle.contract_problems(bundle)
        self.assertTrue(any("ABSENT without method" in p for p in problems), problems)

    def test_an_attestation_ref_pointing_at_nothing_is_a_problem(self):
        bundle = build_bundle()
        bundle["attributes"]["user"] = {
            "value": "root",
            "status": "ANSWERED",
            "tier": "observed",
            "attestation_ref": "att-1",
        }
        problems = evidence_bundle.contract_problems(bundle)
        self.assertTrue(any("att-1" in p for p in problems), problems)

    def test_verify_rejects_a_broken_bundle(self):
        bundle = build_bundle()
        bundle["attributes"]["user"] = {"value": None, "status": "MAYBE", "tier": "observed"}
        with self.assertRaises(scanner.ScannerError):
            evidence_bundle.verify_bundle(bundle)
        # A clean bundle passes.
        evidence_bundle.verify_bundle(build_bundle())


class BundlePermissionsTest(unittest.TestCase):
    """The declared-tier permission and approval attribute the containment category reads."""

    def test_privileged_hostconfig_lands_in_the_permissions_value(self):
        context = docker_context(
            docker_inspect={
                "Image": "sha256:deadbeef",
                "HostConfig": {"Privileged": True, "CapAdd": ["SYS_PTRACE"], "User": "app"},
                "Config": {"Labels": {}},
            }
        )
        bundle = evidence_bundle.build_evidence_bundle(
            build_args(), context, {"host_id": None, "sandbox_name": None}, identity(host_id=None, sandbox_name=None)
        )
        field = bundle["attributes"]["permissions"]
        self.assertEqual(field["status"], "ANSWERED")
        self.assertEqual(field["tier"], "declared")
        self.assertTrue(field["value"]["privileged"])
        self.assertEqual(field["value"]["cap_add"], ["SYS_PTRACE"])

    def test_no_harness_keys_keeps_the_hostconfig_value_in_docker_mode(self):
        bundle = build_bundle(mode="docker")
        field = bundle["attributes"]["permissions"]
        self.assertEqual(field["status"], "ANSWERED")
        self.assertFalse(field["value"]["privileged"])
        self.assertFalse(field["value"].get("harness"))
        self.assertIn("no permission-shaped keys", field.get("note") or "")

    def test_harness_permission_keys_join_the_value(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "harness-config.json"
            config.write_text(
                json.dumps(
                    {
                        "permissions": {"allow": ["read"], "deny": ["write"]},
                        "approvalPolicy": {"requireApproval": True},
                        "model": {"name": "not-a-permission"},
                    }
                ),
                encoding="utf-8",
            )
            args = build_args(config_path=[str(config)])
            bundle = evidence_bundle.build_evidence_bundle(
                args, docker_context(), {"host_id": "h-1", "sandbox_name": "agent-container"}, identity()
            )
            value = bundle["attributes"]["permissions"]["value"]
            self.assertEqual(value["harness"]["harness-config.json:permissions"], {"allow": ["read"], "deny": ["write"]})
            self.assertEqual(value["harness"]["harness-config.json:approvalPolicy"], {"requireApproval": True})
            self.assertNotIn("model", json.dumps(value["harness"]))

    def test_approval_policy_is_blind_without_approval_keys(self):
        bundle = build_bundle(mode="docker")
        field = bundle["attributes"]["approval_policy"]
        self.assertEqual(field["status"], "BLIND")
        self.assertEqual(field["reason"], "GATEWAY_MANAGED")

    def test_approval_keys_move_the_approval_policy_to_answered(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "approval-config.json"
            config.write_text(json.dumps({"approvalPolicy": {"requireApproval": True}}), encoding="utf-8")
            args = build_args(config_path=[str(config)])
            bundle = evidence_bundle.build_evidence_bundle(
                args, docker_context(), {"host_id": "h-1", "sandbox_name": "agent-container"}, identity()
            )
            field = bundle["attributes"]["approval_policy"]
            self.assertEqual(field["status"], "ANSWERED")
            self.assertEqual(field["value"], {"approvalPolicy": {"requireApproval": True}})

    def test_self_mode_is_blind_with_a_reason(self):
        bundle = build_bundle(mode="self")
        field = bundle["attributes"]["permissions"]
        self.assertEqual(field["status"], "BLIND")
        self.assertEqual(field["reason"], "NO_SOURCE_ACCESS")
        self.assertEqual(evidence_bundle.contract_problems(bundle), [])

    def test_a_malformed_config_does_not_crash_the_scan(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "harness-config.json"
            config.write_text("not json", encoding="utf-8")
            args = build_args(config_path=[str(config)])
            bundle = evidence_bundle.build_evidence_bundle(
                args, docker_context(), {"host_id": "h-1", "sandbox_name": "agent-container"}, identity()
            )
            field = bundle["attributes"]["permissions"]
            self.assertEqual(field["status"], "ANSWERED")
            self.assertFalse(field["value"].get("harness"))
            self.assertIn("no permission-shaped keys", field.get("note") or "")

    def test_a_directory_root_reads_its_json_children(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "agent-a.json").write_text(
                json.dumps({"permissions": {"allow": ["read"]}}), encoding="utf-8"
            )
            (root / "agent-b.json").write_text(
                json.dumps({"model": {"name": "not-a-permission"}}), encoding="utf-8"
            )
            args = build_args(config_path=[str(root)])
            bundle = evidence_bundle.build_evidence_bundle(
                args, docker_context(), {"host_id": "h-1", "sandbox_name": "agent-container"}, identity()
            )
            value = bundle["attributes"]["permissions"]["value"]
            self.assertEqual(value["harness"]["agent-a.json:permissions"], {"allow": ["read"]})
            self.assertNotIn("agent-b.json", json.dumps(value))

    def test_credential_shaped_values_are_redacted(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "harness-config.json"
            config.write_text(
                json.dumps(
                    {
                        "permissions": {"allow": ["read"]},
                        "security": {
                            "env": {"OPENAI_API_KEY": "sk-abcdef1234567890"},
                            "apiKey": "ghp_ABCDEFGHIJKLmnop",
                            "apiToken": "sm://vault/agent",
                        },
                    }
                ),
                encoding="utf-8",
            )
            args = build_args(config_path=[str(config)])
            bundle = evidence_bundle.build_evidence_bundle(
                args, docker_context(), {"host_id": "h-1", "sandbox_name": "agent-container"}, identity()
            )
            harness = bundle["attributes"]["permissions"]["value"]["harness"]
            self.assertEqual(harness["harness-config.json:permissions"], {"allow": ["read"]})
            self.assertEqual(
                harness["harness-config.json:security"],
                {
                    "env": {"OPENAI_API_KEY": "[redacted]"},
                    "apiKey": "[redacted]",
                    "apiToken": "[redacted]",
                },
            )
            self.assertEqual(evidence_bundle.contract_problems(bundle), [])

    def test_a_name_only_image_is_blind(self):
        context = docker_context(
            docker_inspect={
                "Image": "ghcr.io/datrail/agent:latest",
                "HostConfig": {"Privileged": False, "CapAdd": [], "User": "app"},
                "Config": {"Labels": {}},
            }
        )
        bundle = evidence_bundle.build_evidence_bundle(
            build_args(), context, {"host_id": "h-1", "sandbox_name": "agent-container"}, identity()
        )
        field = bundle["attributes"]["image_digest"]
        self.assertEqual(field["status"], "BLIND")
        self.assertEqual(field["reason"], "NO_SOURCE_ACCESS")
        self.assertEqual(evidence_bundle.contract_problems(bundle), [])

    def test_self_mode_user_is_blind_with_a_reason(self):
        bundle = build_bundle(mode="self")
        field = bundle["attributes"]["user"]
        self.assertEqual(field["status"], "BLIND")
        self.assertEqual(field["reason"], "NOT_COLLECTED_BY_PACK")
        self.assertIn("user_info", field.get("note") or "")
        self.assertEqual(evidence_bundle.contract_problems(bundle), [])

    def test_the_default_config_roots_are_consulted_when_none_given(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".openclaw").mkdir(parents=True)
            (home / ".openclaw" / "agent.json").write_text(
                json.dumps({"permissions": {"allow": ["read"]}}), encoding="utf-8"
            )
            with mock.patch.object(Path, "cwd", create=True, return_value=Path(tmp)):
                context = docker_context(env={"HOME": str(home)})
                bundle = evidence_bundle.build_evidence_bundle(
                    build_args(), context, {"host_id": "h-1", "sandbox_name": "agent-container"}, identity()
                )
            harness = bundle["attributes"]["permissions"]["value"].get("harness")
            self.assertEqual(harness, {"agent.json:permissions": {"allow": ["read"]}})

    def test_deployment_labels_lands_in_the_deployment_attribute(self):
        bundle = build_bundle(mode="docker")
        field = bundle["attributes"]["deployment"]
        self.assertEqual(field["status"], "ANSWERED")
        self.assertEqual(
            field["value"],
            {"com.docker.compose.project": "rail", "com.docker.compose.service": "agent"},
        )


class BundleWritePathTest(unittest.TestCase):
    """The write path reports failures rather than raising, and honours the output location."""

    def test_a_blocked_path_is_reported_not_raised(self):
        with mock.patch.object(
            scanner, "store_json", side_effect=scanner.ScannerError("could not write x: blocked")
        ):
            self.assertFalse(evidence_bundle.write_evidence_bundle(build_args(), docker_context(), {}, identity()))

    def test_a_clean_build_verifies_and_stores(self):
        with mock.patch.object(scanner, "store_json") as store:
            self.assertTrue(
                evidence_bundle.write_evidence_bundle(build_args(), docker_context(), {}, identity())
            )
            bundle = store.call_args.args[1]
            self.assertEqual(bundle["bundle_version"], 1)
            self.assertIn("permissions", bundle["attributes"])

    def test_the_env_var_selects_the_output_path(self):
        args = build_args()
        with mock.patch.dict(os.environ, {"RAIL_EVIDENCE_BUNDLE_OUTPUT": "/tmp/env-bundle.json"}):
            self.assertEqual(evidence_bundle.evidence_bundle_output_path(args), Path("/tmp/env-bundle.json"))
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(evidence_bundle.evidence_bundle_output_path(args), evidence_bundle.DEFAULT_EVIDENCE_BUNDLE_OUTPUT)


class ScannerWiringTest(unittest.TestCase):
    """Subprocess runs mirroring the registration/feature-file guarantees."""

    def run_scan(self, tmp: str, extra: list[str], env_cwd: str):
        import subprocess

        argv = ["python3", str(SCANNER)] + extra
        return subprocess.run(
            argv,
            cwd=env_cwd,
            capture_output=True,
            text=True,
            env={k: v for k, v in os.environ.items() if not k.startswith("RAIL_")},
            timeout=120,
        )

    def test_a_failed_registration_still_writes_the_bundle(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_scan(
                tmp,
                [
                    "--mode", "self",
                    "--feature-output", f"{tmp}/features.json",
                    "--register",
                    "--center-url", "http://127.0.0.1:1",
                    "--evidence-bundle-output", f"{tmp}/bundle.json",
                ],
                tmp,
            )
            self.assertEqual(proc.returncode, 2, proc.stderr)
            feature = json.loads(Path(tmp, "features.json").read_text())
            self.assertEqual(feature["scan"]["registration_status"], "registration_failed")
            bundle = json.loads(Path(tmp, "bundle.json").read_text())
            self.assertEqual(bundle["host_id"], feature["host_and_identity"]["host_id"])
            self.assertEqual(bundle["sandbox_name"], feature["host_and_identity"]["sandbox_name"])
            self.assertEqual(bundle["bundle_version"], 1)

    def test_no_evidence_bundle_skips_the_write(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_scan(
                tmp,
                [
                    "--mode", "self",
                    "--feature-output", f"{tmp}/features.json",
                    "--evidence-bundle-output", f"{tmp}/bundle.json",
                    "--no-evidence-bundle",
                ],
                tmp,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertFalse(Path(tmp, "bundle.json").exists())
            # The feature file is unrelated to the bundle flag: it is still written.
            self.assertTrue(Path(tmp, "features.json").exists())

    def test_the_default_bundle_path_is_respected(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_scan(
                tmp,
                [
                    "--mode", "self",
                    "--feature-output", f"{tmp}/features.json",
                ],
                tmp,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            default = Path(tmp, ".rail", "railscan", "evidence-bundle.json")
            self.assertTrue(default.exists())
            self.assertEqual(json.loads(default.read_text())["bundle_version"], 1)

if __name__ == "__main__":
    unittest.main()
