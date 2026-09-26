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

import contextlib
import importlib.util
import io
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

# The published v1 schema, RailMon's single canonical copy — loaded here
# independently of `evidence_bundle` itself, so the assertions below anchor on
# the file, not on whatever the module happens to compute from it.
SCHEMA = json.loads((ROOT / "schemas" / "evidence-bundle-v1.schema.json").read_text())
_ATTR = SCHEMA["$defs"]["attribute"]
_SOURCE = SCHEMA["$defs"]["source"]


def schema_enum(*path) -> frozenset:
    """The literal enum at a dotted path inside the vendored schema."""
    node = SCHEMA
    for key in path:
        node = node[key]
    return frozenset(node["enum"])


# "remove this key" in the mutation table, distinct from a legitimate None.
_DROP = object()


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


# The pair the schema requires in the envelope; a scan that cannot derive one
# is a refused write, not a bundle with a null owner.
HOST_PAIR = {"host_id": "h-1", "sandbox_name": "agent-container"}


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
    payload = dict(HOST_PAIR)
    return evidence_bundle.build_evidence_bundle(build_args(), context, payload, identity())


class BundleContractTest(unittest.TestCase):
    """The emitted bundle stays inside the closed sets, and the check rejects a broken one."""

    def test_the_module_loads_the_one_canonical_schema_file(self):
        # There is one copy of this contract now, not a mirror of it: the
        # module reads `schemas/evidence-bundle-v1.schema.json` at import
        # time, and every closed set below (STATUSES, TIERS, ...) is derived
        # from that object rather than a second hand-typed copy that could
        # drift from it. This just confirms it is the same file this test
        # loads independently.
        self.assertEqual(evidence_bundle.SCHEMA_PATH, ROOT / "schemas" / "evidence-bundle-v1.schema.json")
        self.assertEqual(evidence_bundle.SCHEMA, SCHEMA)

    def test_deployment_keys_match_the_schemas_closed_set(self):
        # DEPLOYMENT_ENV_KEYS/DEPLOYMENT_LABEL_KEYS are the builder's own
        # source of truth (they also carry the env-over-Compose precedence
        # order, so they stay hand-written tuples, not schema-derived). The
        # schema's `deployment_value` closed set is a separate, hand-written
        # copy of the same four names for exactly the reason this branch
        # exists to fix elsewhere — so it gets the cross-check the others get
        # for free from being schema-derived.
        self.assertEqual(
            set(evidence_bundle.DEPLOYMENT_KEYS),
            set(SCHEMA["$defs"]["deployment_value"]["properties"]),
        )

    def test_schema_restricts_window_seconds_to_runtime(self):
        source_schemas = SCHEMA["properties"]["inputs_attempted"]["properties"]
        self.assertEqual(source_schemas["runtime"], {"$ref": "#/$defs/source"})
        for source_name in ("image", "manifest", "repo"):
            self.assertEqual(
                source_schemas[source_name],
                {"$ref": "#/$defs/non_runtime_source"},
            )
        self.assertIn(
            {"not": {"required": ["window_seconds"]}},
            SCHEMA["$defs"]["non_runtime_source"]["allOf"],
        )

    def test_every_emitted_field_is_inside_the_closed_sets(self):
        bundle = build_bundle()
        for name, field in bundle["attributes"].items():
            self.assertIn(field.get("status"), schema_enum("$defs", "attribute", "properties", "status"), name)
            self.assertIn(field.get("tier"), schema_enum("$defs", "attribute", "properties", "tier"), name)
            self.assertIn(field.get("reason"), (*schema_enum("$defs", "reason"), None), name)
            # authored_by is stated exactly when there is a value to attribute.
            if field["status"] in ("ANSWERED", "PARTIAL", "TEMPLATED"):
                self.assertIn(field.get("authored_by"), schema_enum("$defs", "attribute", "properties", "authored_by"), name)
            else:
                self.assertNotIn("authored_by", field, name)
            if field["status"] == "ABSENT":
                self.assertTrue(field.get("method"), f"{name}: ABSENT without method")
            # The attribute is closed to the schema's field set, so a stray
            # key is a consumer-visible contract break, not a harmless extra.
            self.assertLessEqual(set(field), set(_ATTR["properties"]), name)
        # Docker mode with an empty reach cannot reach its runtime source, so
        # that entry carries the reason the schema demands with it.
        runtime = bundle["inputs_attempted"]["runtime"]
        self.assertEqual(set(runtime), {"attempted", "reached", "reason"})
        # The envelope names exactly the four sources, never the `config` key.
        self.assertEqual(set(bundle["inputs_attempted"]), set(evidence_bundle.INPUT_SOURCES))
        self.assertEqual(evidence_bundle.contract_problems(bundle), [])

    def test_every_emitted_bundle_passes_the_vendored_schema(self):
        # The point of the branch: the emitted envelope is one the published
        # schema accepts. `contract_problems` is now the schema walked
        # directly (see evidence_bundle.py), so this exercises the real
        # production check rather than a second copy of it.
        for mode in ("docker", "self"):
            with self.subTest(mode=mode):
                self.assertEqual(evidence_bundle.contract_problems(build_bundle(mode=mode)), [])

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
        self.assertTrue(any("user.method" in p for p in problems), problems)

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

    def test_every_contract_branch_rejects_what_it_must(self):
        # Every branch of `contract_problems` has at least one row, each proved
        # by mutation: the bundle is broken in exactly that way and the check
        # must name it. A branch that stops firing is the guard failing open,
        # which is why each assertion also demands the problem text names the
        # field. Mutation-verified by neutralizing each `problems.append` in
        # turn: with the table as written, none stays green.

        def envelope(bundle, key, value):
            if value is _DROP:
                bundle.pop(key, None)
            else:
                bundle[key] = value

        def source(bundle, name, key, value):
            entry = bundle["inputs_attempted"][name]
            if value is _DROP:
                entry.pop(key, None)
            else:
                entry[key] = value

        def attribute(bundle, name, key, value):
            field = bundle["attributes"]["user"]
            if value is _DROP:
                field.pop(key, None)
            else:
                field[key] = value

        def replace_user(status=None, **fields):
            def mutate(bundle):
                field = {"value": "root", "status": status or "ANSWERED", "tier": "observed"}
                if status is None:
                    field["authored_by"] = "none"
                field.update(fields)
                for key, value in list(field.items()):
                    if value is _DROP:
                        del field[key]
                bundle["attributes"]["user"] = field

            return mutate

        cases = {
            "envelope: required key missing": (lambda b: envelope(b, "collected_at", _DROP), "collected_at"),
            "envelope: unknown key": (lambda b: envelope(b, "agent_id", "a"), "agent_id"),
            "envelope: wrong bundle_version": (lambda b: envelope(b, "bundle_version", 2), "bundle_version"),
            "envelope: empty host_id": (lambda b: envelope(b, "host_id", "  "), "host_id"),
            "envelope: null sandbox_name": (lambda b: envelope(b, "sandbox_name", None), "sandbox_name"),
            "envelope: host_id past its cap": (
                lambda b: envelope(b, "host_id", "h" * (evidence_bundle.HOST_ID_MAX + 1)),
                "host_id",
            ),
            "envelope: sandbox_name past its cap": (
                lambda b: envelope(b, "sandbox_name", "s" * (evidence_bundle.SANDBOX_NAME_MAX + 1)),
                "sandbox_name",
            ),
            "source: one of the four missing": (
                lambda b: b["inputs_attempted"].pop("manifest"),
                "manifest",
            ),
            "source: an extra key": (lambda b: b["inputs_attempted"].__setitem__("config", {"attempted": False, "reason": "NO_SOURCE_ACCESS"}), "config"),
            "source: attempted not boolean": (lambda b: source(b, "manifest", "attempted", "yes"), "attempted"),
            "source: unknown reason": (lambda b: source(b, "manifest", "reason", "WHY_NOT"), "WHY_NOT"),
            "source: attempted without reached": (lambda b: source(b, "manifest", "reached", _DROP), "reached"),
            "source: not attempted without reason": (
                lambda b: (source(b, "manifest", "attempted", False), source(b, "manifest", "reason", _DROP)),
                "reason",
            ),
            "source: not reached without reason": (
                lambda b: (source(b, "manifest", "reached", False), source(b, "manifest", "reason", _DROP)),
                "reason",
            ),
            "source: window_seconds off runtime": (
                lambda b: source(b, "manifest", "window_seconds", 60),
                "window_seconds",
            ),
            "source: not an object": (lambda b: b.__setitem__("inputs_attempted", []), "inputs_attempted"),
            "source: an entry that is not an object": (
                lambda b: b["inputs_attempted"].__setitem__("manifest", "yes"),
                "must be an object",
            ),
            "source: an entry field that is not a source field": (
                lambda b: source(b, "manifest", "count", 3),
                "count",
            ),
            "attribute: unknown field": (lambda b: attribute(b, "user", "score", 1), "score"),
            "attribute: value missing": (lambda b: attribute(b, "user", "value", _DROP), "value"),
            "attribute: unknown tier": (lambda b: attribute(b, "user", "tier", "guessed"), "tier"),
            "attribute: unknown authored_by": (lambda b: attribute(b, "user", "authored_by", "vendor"), "vendor"),
            "attribute: unknown status": (
                lambda b: replace_user("NOT_A_STATUS")(b),
                "NOT_A_STATUS",
            ),
            "attribute: unknown reason": (
                lambda b: replace_user("BLIND", reason="WHY_NOT", authored_by=_DROP)(b),
                "WHY_NOT",
            ),
            "attribute: attestation_ref pointing at nothing": (
                lambda b: replace_user("ANSWERED", authored_by="none", attestation_ref="att-missing")(b),
                "attestation_ref",
            ),
            "attribute: ANSWERED without authored_by": (
                lambda b: replace_user("ANSWERED", authored_by=_DROP)(b),
                "authored_by",
            ),
            "attribute: PARTIAL without authored_by": (
                lambda b: replace_user("PARTIAL", authored_by=_DROP)(b),
                "authored_by",
            ),
            "attribute: BLIND carrying authored_by": (
                lambda b: replace_user("BLIND", reason="NO_SOURCE_ACCESS", authored_by="none")(b),
                "must not have authored_by",
            ),
            "attribute: BLIND without reason": (
                lambda b: replace_user("BLIND", authored_by=_DROP)(b),
                "user.reason",
            ),
            "attribute: FAILED without reason": (
                lambda b: replace_user("FAILED", authored_by=_DROP)(b),
                "user.reason",
            ),
            "attribute: ANSWERED with a reason": (
                lambda b: replace_user("ANSWERED", authored_by="none", reason="NO_SOURCE_ACCESS")(b),
                "must not have reason",
            ),
            "attribute: ABSENT without method": (lambda b: replace_user("ABSENT")(b), "user.method"),
            "attribute: not an object": (lambda b: b["attributes"].__setitem__("user", "root"), "user"),
        }
        for name, (mutate, needle) in cases.items():
            with self.subTest(case=name):
                bundle = build_bundle()
                mutate(bundle)
                problems = evidence_bundle.contract_problems(bundle)
                self.assertTrue(
                    any(needle in problem for problem in problems),
                    f"{name}: expected a problem naming {needle!r}, got {problems}",
                )
        # The unmutated bundle is the control: no branch fires on a clean one.
        self.assertEqual(evidence_bundle.contract_problems(build_bundle()), [])


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
            build_args(), context, {"host_id": "h-1", "sandbox_name": "agent-container"}, identity()
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
            self.assertEqual(field["value"], {"approval-config.json:approvalPolicy": {"requireApproval": True}})

    def test_self_mode_is_blind_with_a_reason(self):
        bundle = build_bundle(mode="self")
        field = bundle["attributes"]["permissions"]
        self.assertEqual(field["status"], "BLIND")
        self.assertEqual(field["reason"], "NO_SOURCE_ACCESS")
        self.assertEqual(evidence_bundle.contract_problems(bundle), [])

    def test_a_malformed_config_records_a_failure(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "harness-config.json"
            config.write_text("not json", encoding="utf-8")
            args = build_args(config_path=[str(config)])
            bundle = evidence_bundle.build_evidence_bundle(
                args, docker_context(), {"host_id": "h-1", "sandbox_name": "agent-container"}, identity()
            )
            field = bundle["attributes"]["permissions"]
            self.assertEqual(field["status"], "PARTIAL")
            self.assertEqual(field["reason"], "PARSE_FAILED")
            self.assertFalse(field["value"].get("harness"))
            self.assertIn("harness-config.json", field.get("note") or "")
            self.assertEqual(evidence_bundle.contract_problems(bundle), [])

    def test_a_misnamed_root_is_a_no_source_access_failure(self):
        args = build_args(config_path=["/tmp/missing-config-dir-dl08.json"])
        bundle = evidence_bundle.build_evidence_bundle(
            args, docker_context(), {"host_id": "h-1", "sandbox_name": "agent-container"}, identity()
        )
        field = bundle["attributes"]["permissions"]
        self.assertEqual(field["status"], "PARTIAL")
        self.assertEqual(field["reason"], "NO_SOURCE_ACCESS")
        self.assertIn("missing-config-dir-dl08.json", field.get("note") or "")

    def test_an_oversized_config_is_a_size_cap_failure(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "harness-config.json"
            payload = json.dumps({"permissions": {"allow": ["read"]}, "pad": "x" * 65_000})
            config.write_text(payload, encoding="utf-8")
            args = build_args(config_path=[str(config)])
            bundle = evidence_bundle.build_evidence_bundle(
                args, docker_context(), {"host_id": "h-1", "sandbox_name": "agent-container"}, identity()
            )
            field = bundle["attributes"]["permissions"]
            self.assertEqual(field["status"], "PARTIAL")
            self.assertEqual(field["reason"], "SIZE_CAP_EXCEEDED")
            self.assertIn("harness-config.json", field.get("note") or "")

    def test_two_roots_with_a_shared_basename_keep_both(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root_a = Path(tmp) / "dirA"
            root_b = Path(tmp) / "dirB"
            root_a.mkdir()
            root_b.mkdir()
            (root_a / "agent.json").write_text(
                json.dumps({"permissions": {"allow": ["read"]}}), encoding="utf-8"
            )
            (root_b / "agent.json").write_text(
                json.dumps({"permissions": {"allow": ["write"]}}), encoding="utf-8"
            )
            args = build_args(config_path=[str(root_a), str(root_b)])
            bundle = evidence_bundle.build_evidence_bundle(
                args, docker_context(), {"host_id": "h-1", "sandbox_name": "agent-container"}, identity()
            )
            harness = bundle["attributes"]["permissions"]["value"]["harness"]
            self.assertEqual(harness[f"{root_a}/agent.json:permissions"], {"allow": ["read"]})
            self.assertEqual(harness[f"{root_b}/agent.json:permissions"], {"allow": ["write"]})
            self.assertEqual(len(harness), 2)

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

    def test_deployment_environment_pair_is_emitted_before_compose_fallback(self):
        context = docker_context(
            env={
                "RAIL_DEPLOYMENT": "payments-agent",
                "RAIL_NAMESPACE": "production",
                "IGNORED_DEPLOYMENT_KEY": "not-in-the-contract",
            }
        )
        bundle = evidence_bundle.build_evidence_bundle(
            build_args(), context, dict(HOST_PAIR), identity()
        )

        field = bundle["attributes"]["deployment"]
        self.assertEqual(field["status"], "ANSWERED")
        self.assertEqual(
            field["value"],
            {
                "RAIL_DEPLOYMENT": "payments-agent",
                "RAIL_NAMESPACE": "production",
                "com.docker.compose.project": "rail",
                "com.docker.compose.service": "agent",
            },
        )
        self.assertIn("environment pair takes precedence", field["note"])

    def test_half_environment_pair_does_not_hide_complete_compose_pair(self):
        context = docker_context(env={"RAIL_DEPLOYMENT": "payments-agent"})
        bundle = evidence_bundle.build_evidence_bundle(
            build_args(), context, dict(HOST_PAIR), identity()
        )

        field = bundle["attributes"]["deployment"]
        self.assertEqual(
            field["value"],
            {
                "RAIL_DEPLOYMENT": "payments-agent",
                "com.docker.compose.project": "rail",
                "com.docker.compose.service": "agent",
            },
        )
        self.assertIn("half-pair supplies no deployment key", field["note"])

    def test_self_mode_emits_environment_deployment_pair(self):
        context = self_context(
            env={"RAIL_DEPLOYMENT": "local-agent", "RAIL_NAMESPACE": "developer"}
        )
        bundle = evidence_bundle.build_evidence_bundle(
            build_args(), context, dict(HOST_PAIR), identity()
        )

        field = bundle["attributes"]["deployment"]
        self.assertEqual(field["status"], "ANSWERED")
        self.assertEqual(
            field["value"],
            {"RAIL_DEPLOYMENT": "local-agent", "RAIL_NAMESPACE": "developer"},
        )
        self.assertEqual(field["authored_by"], "subject")

    def test_readable_environment_without_deployment_keys_is_absent(self):
        bundle = build_bundle(mode="self")

        field = bundle["attributes"]["deployment"]
        self.assertEqual(field["status"], "ABSENT")
        self.assertIn("environment", field["method"])

    def test_deployment_values_follow_the_published_byte_bound(self):
        bundle = build_bundle()
        bundle["attributes"]["deployment"]["value"] = {
            "RAIL_DEPLOYMENT": "é" * 126 + "a",
            "RAIL_NAMESPACE": "é" * 126 + "a",
        }
        self.assertEqual(evidence_bundle.contract_problems(bundle), [])

        bundle["attributes"]["deployment"]["value"]["RAIL_DEPLOYMENT"] += "a"
        problems = evidence_bundle.contract_problems(bundle)
        self.assertTrue(
            any(
                "RAIL_DEPLOYMENT" in problem and "253-byte" in problem
                for problem in problems
            )
        )

    def test_deployment_contract_rejects_unknown_or_empty_keys(self):
        bundle = build_bundle()
        bundle["attributes"]["deployment"]["value"] = {
            "RAIL_DEPLOYMENT": "",
            "unexpected": "agent",
        }

        problems = evidence_bundle.contract_problems(bundle)
        self.assertTrue(
            any(
                "RAIL_DEPLOYMENT" in problem and "non-empty" in problem
                for problem in problems
            )
        )
        self.assertTrue(
            any(
                "unexpected" in problem and "not a field of the schema" in problem
                for problem in problems
            )
        )

    def test_deployment_contract_rejects_whitespace_only_values(self):
        # A blank host_id/sandbox_name is rejected by a `pattern` rule, not
        # just `minLength` (a whitespace-only string still has length >= 1).
        # The four deployment keys feed the same "no blank claims" rule.
        bundle = build_bundle()
        bundle["attributes"]["deployment"]["value"] = {"RAIL_DEPLOYMENT": "   "}
        problems = evidence_bundle.contract_problems(bundle)
        self.assertTrue(
            any("RAIL_DEPLOYMENT" in problem for problem in problems), problems
        )

    def test_credential_classes_match_the_profiler_contract(self):
        with mock.patch.object(
            scanner,
            "collect_secret_hygiene",
            return_value=[
                {"key": "API_TOKEN", "secret_class": "plaintext", "secret_type": "token"},
                {"key": "CLIENT_SECRET_FILE", "secret_class": "mount", "secret_type": "secret"},
                {"key": "REMOTE_KEY", "secret_class": "reference", "secret_type": "key"},
                {"key": "EMPTY_PASSWORD", "secret_class": "empty", "secret_type": "password"},
            ],
        ):
            bundle = build_bundle()

        credentials = bundle["attributes"]["credential_inventory"]["value"]
        self.assertEqual(
            credentials,
            [
                {"name": "API_TOKEN", "class": "secret_plaintext", "type": "token"},
                {"name": "CLIENT_SECRET_FILE", "class": "mount", "type": "secret"},
                {"name": "REMOTE_KEY", "class": "secret_ref", "type": "key"},
            ],
        )

    def test_empty_secret_markers_do_not_become_credentials(self):
        with mock.patch.object(
            scanner,
            "collect_secret_hygiene",
            return_value=[
                {"key": "EMPTY_PASSWORD", "secret_class": "empty", "secret_type": "password"}
            ],
        ):
            bundle = build_bundle()

        field = bundle["attributes"]["credential_inventory"]
        self.assertEqual(field["status"], "ANSWERED")
        self.assertEqual(field["value"], [])
        self.assertEqual(field["method"], "env scan; no credential material found")


class BundleWritePathTest(unittest.TestCase):
    """The write path reports failures rather than raising, and honours the output location."""

    def test_a_blocked_path_is_reported_not_raised(self):
        with mock.patch.object(
            scanner, "store_json", side_effect=scanner.ScannerError("could not write x: blocked")
        ):
            self.assertFalse(evidence_bundle.write_evidence_bundle(build_args(), docker_context(), HOST_PAIR, identity()))

    def test_a_clean_build_verifies_and_stores(self):
        with mock.patch.object(scanner, "store_json") as store:
            self.assertTrue(
                evidence_bundle.write_evidence_bundle(build_args(), docker_context(), HOST_PAIR, identity())
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

    def test_a_null_host_pair_refuses_the_write_without_a_file(self):
        # A scan with no host identity produces no bundle at all: the write is
        # refused and the reason is reported, never a bundle with a null owner.
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            args = build_args()
            args.evidence_bundle_output = f"{tmp}/bundle.json"
            stderr = io.StringIO()
            with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(stderr):
                self.assertFalse(
                    evidence_bundle.write_evidence_bundle(
                        args, docker_context(), {"host_id": None, "sandbox_name": None}, identity()
                    )
                )
            self.assertFalse(Path(tmp, "bundle.json").exists())
            self.assertIn("host_id", stderr.getvalue())

    def test_the_flag_beats_the_env_var_for_the_output_path(self):
        # Precedence, not just each side alone: a stale RAIL_EVIDENCE_BUNDLE_OUTPUT
        # must not redirect a run that named its output explicitly.
        args = build_args()
        args.evidence_bundle_output = "/tmp/flag-bundle.json"
        with mock.patch.dict(os.environ, {"RAIL_EVIDENCE_BUNDLE_OUTPUT": "/tmp/env-bundle.json"}):
            self.assertEqual(evidence_bundle.evidence_bundle_output_path(args), Path("/tmp/flag-bundle.json"))

    def test_a_credential_carrying_value_is_redacted(self):
        # Every credential shape the key-name check cannot see, including the
        # empty-side DSN forms and a bare-token userinfo.
        redacted = "[redacted]"
        for value in (
            "postgres://u:p@h/db",
            "redis://:hunter2@cache.internal:6379/0",
            "postgres://admin:@db.internal/db",
            "https://token@api.internal/v1",
            "Basic dXNlcjpwYXNz",
            # A password may contain the URL separators. These are the shapes
            # a narrower password class silently stopped redacting.
            "postgres://svc:aB3/xY9+q@db.internal/prod",
            "https://svc:a?b@api.internal/v1",
            "redis://u:a#b@cache.internal:6379",
            # Surrounding whitespace is not a way past the shape check.
            " redis://:hunter2@cache.internal",
            "\tpostgres://u:p@db.internal\n",
            # An Authorization header value, under a key the scanner does not
            # name secret ("authorization" carries no marker it recognizes).
            "Bearer eyJhbGciOiJIUzI1NiJ9.abc.def",
        ):
            with self.subTest(value=value):
                self.assertEqual(evidence_bundle._redact_harness_values(value, "auth"), redacted)
        # And it stays off a plain declarative value under a neutral key.
        self.assertEqual(evidence_bundle._redact_harness_values("read-only", "mode"), "read-only")

    def test_a_nested_but_parseable_config_is_read_not_a_failure(self):
        # A JSON `null` is valid: it must read as "nothing here", not as a
        # failure whose empty reason poisons the whole bundle's contract.
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            null_file = Path(tmp, "null.json")
            null_file.write_text("null")
            found, failures = evidence_bundle.read_harness_permission_config([null_file])
            self.assertEqual(failures, {})
            self.assertEqual(found, {})

    def test_a_top_level_list_config_is_read_like_an_object(self):
        # `_permission_keys` walks lists at any depth, so a JSON array of
        # permission blocks holds keys: a bare-list config must land in the
        # attribute, not be silently dropped as a non-object.
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            list_file = Path(tmp, "list.json")
            list_file.write_text(json.dumps([{"permissions": {"deny": ["write"]}}, {"note": "x"}]))
            found, failures = evidence_bundle.read_harness_permission_config([list_file])
            self.assertEqual(failures, {})
            self.assertEqual(found, {str(list_file): {"permissions": {"deny": ["write"]}}})

    def test_a_deeply_nested_config_is_a_parse_failure_not_a_crash(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            nested = Path(tmp, "nested.json")
            nested.write_text("[" * 20_000)
            data, reason = evidence_bundle._read_json_capped(nested)
            self.assertIsNone(data)
            self.assertEqual(reason, "PARSE_FAILED")

    def test_the_source_filename_does_not_shape_the_block(self):
        # A block's shape is its own key's, never the file it was read from:
        # `permissions.json` must not turn an approval block into allow/deny.
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp, "permissions.json")
            conf.write_text(json.dumps({"approvalPolicy": {"requireApproval": True}}))
            args = build_args()
            args.config_path = [Path(tmp)]
            bundle = evidence_bundle.build_evidence_bundle(
                args, self_context(), dict(HOST_PAIR), identity()
            )
            attrs = bundle["attributes"]
            # The approval block is the approval gate and only that.
            self.assertEqual(attrs["approval_policy"]["status"], "ANSWERED")
            # And the allow/deny gate stays unanswered: nothing in this file
            # is shaped like it, so it must not inherit the approval block.
            self.assertEqual(attrs["tool_allow_deny"]["status"], "BLIND")
            # The control: a neutral filename with the same content lands the
            # same way, which is the behaviour the filename was overriding.
            neutral = Path(tmp, "settings.json")
            neutral.write_text(json.dumps({"approvalPolicy": {"requireApproval": True}}))
            control_args = build_args()
            control_args.config_path = [neutral]
            control = evidence_bundle.build_evidence_bundle(
                control_args, self_context(), dict(HOST_PAIR), identity()
            )
            self.assertEqual(control["attributes"]["approval_policy"]["status"], "ANSWERED")
            self.assertEqual(control["attributes"]["tool_allow_deny"]["status"], "BLIND")
            # The symmetric direction: a filename carrying the *approval*
            # token must not turn an allow/deny block into an approval gate.
            notes = Path(tmp, "my-approval-notes.json")
            notes.write_text(json.dumps({"permissions": {"allow": ["read"], "deny": ["write"]}}))
            notes_args = build_args()
            notes_args.config_path = [notes]
            notes_bundle = evidence_bundle.build_evidence_bundle(
                notes_args, self_context(), dict(HOST_PAIR), identity()
            )
            notes_attrs = notes_bundle["attributes"]
            self.assertEqual(notes_attrs["tool_allow_deny"]["status"], "ANSWERED")
            self.assertEqual(notes_attrs["approval_policy"]["status"], "BLIND")


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
                    "--host-id", "h-1",
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
                    "--host-id", "h-1",
                ],
                tmp,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            default = Path(tmp, ".rail", "railscan", "evidence-bundle.json")
            self.assertTrue(default.exists())
            self.assertEqual(json.loads(default.read_text())["bundle_version"], 1)

if __name__ == "__main__":
    unittest.main()
