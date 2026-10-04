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
import copy
import importlib.util
import io
import json
import os
import sys
import time
import unittest
from argparse import Namespace
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCANNER_DIR = ROOT / "tools" / "scan"
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

    def test_walker_handles_a_boolean_not_schema(self):
        # `_schema_problems` supports boolean schemas (`true`/`false`) for
        # `"value": true` in $defs/attribute. A `"not"` keyword can just as
        # legally hold a bare boolean instead of an object — `{"not": true}`
        # rejects everything — and the message branch must not assume
        # `schema["not"]` is a dict when it isn't.
        self.assertEqual(
            evidence_bundle._schema_problems("x", {"not": True}, "bundle"),
            ["bundle: matches an excluded shape"],
        )
        self.assertEqual(evidence_bundle._schema_problems("x", {"not": False}, "bundle"), [])

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

    def test_deployment_contract_reports_a_non_object_value_instead_of_crashing(self):
        # `_semantic_problems`'s byte-cap loop iterates `.value.items()`; a
        # non-dict ANSWERED value must be reported by the schema walker, not
        # reach that loop and raise.
        bundle = build_bundle()
        bundle["attributes"]["deployment"]["value"] = "not-a-dict"
        problems = evidence_bundle.contract_problems(bundle)
        self.assertTrue(any("deployment.value" in p for p in problems), problems)

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


class ObservedListenersBundleTest(unittest.TestCase):
    """The listening half of observed reach in the bundle (DR-125)."""

    LISTENER = {"protocol": "tcp", "addr": "0.0.0.0", "port": 4444, "process": "python3"}

    def bundle(self, listening):
        return evidence_bundle.build_evidence_bundle(
            build_args(), self_context(), dict(HOST_PAIR), identity(observed_listeners=listening)
        )

    @staticmethod
    def listening(listeners=(), **counts):
        base = {"source": "listensnoop", "listeners": list(listeners), "lost": 0,
                "unlisted": 0, "malformed": 0, "outside_namespace": 0,
                "starts": 1, "restarted": False, "stale": False}
        base.update(counts)
        return base

    def attribute(self, listening):
        bundle = self.bundle(listening)
        self.assertEqual(evidence_bundle.contract_problems(bundle), [])
        return bundle["attributes"]["observed_listeners"]

    def test_the_rule_pack_grew(self):
        # x-rail-spec's additions-version rule: a new attribute is a new pack,
        # which RailDash shows as CONTRACT_MISMATCH rather than drift.
        # Pack 3 added observed_ingress_peers (DR-145), pack 4
        # observed_file_access (DR-154); pack 5 folds its random temp names
        # (DR-166), so a pack-4 baseline is not compared against it.
        self.assertEqual(self.bundle(None)["rule_pack_version"], 5)

    def test_without_an_event_file_the_pack_says_it_did_not_look(self):
        field = self.attribute(None)
        self.assertEqual((field["status"], field["reason"]), ("BLIND", "NOT_COLLECTED_BY_PACK"))

    def test_listeners_are_answered_as_observed(self):
        field = self.attribute(self.listening([self.LISTENER]))
        self.assertEqual((field["status"], field["tier"], field["value"]),
                         ("ANSWERED", "observed", [self.LISTENER]))

    def test_an_empty_window_is_absent_not_an_empty_answer(self):
        field = self.attribute(self.listening())
        self.assertEqual((field["status"], field["value"]), ("ABSENT", None))

    def test_a_gap_makes_the_list_partial_even_when_it_is_empty(self):
        # Lost events may have been the one listener that mattered: a gap
        # must never read as "none".
        for counts in ({"lost": 3}, {"unlisted": 2}):
            for listeners in ((), [self.LISTENER]):
                with self.subTest(counts=counts, listeners=listeners):
                    field = self.attribute(self.listening(listeners, **counts))
                    self.assertEqual((field["status"], field["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))
                    self.assertEqual(field["value"], list(listeners))
                    self.assertIn("may be missing", field["note"])

    def test_a_restarted_or_never_attached_probe_is_a_source_we_cannot_reach(self):
        # A restart is a gap the probe cannot fill (it does not report
        # sockets already listening); no start record means it never ran.
        for counts, words in (({"starts": 2, "restarted": True}, "restarted 1 time "),
                              ({"starts": 0}, "never have attached")):
            with self.subTest(counts=counts):
                field = self.attribute(self.listening([self.LISTENER], **counts))
                self.assertEqual((field["status"], field["reason"]), ("PARTIAL", "NO_SOURCE_ACCESS"))
                self.assertIn(words, field["note"])

    def test_each_restart_is_one_drift_and_the_next_is_not_hidden(self):
        # Accepting a restart (locking the PARTIAL ASP) must not hide the
        # next one: the note changes on each restart, and only then.
        once = self.attribute(self.listening([self.LISTENER], starts=2, restarted=True))
        once_later = self.attribute(self.listening([self.LISTENER], starts=2, restarted=True, malformed=9))
        twice = self.attribute(self.listening([self.LISTENER], starts=3, restarted=True))
        self.assertEqual(once["note"], once_later["note"])
        self.assertNotEqual(once["note"], twice["note"])
        self.assertIn("restarted 2 times", twice["note"])

    def test_a_stopped_probe_is_a_source_we_cannot_reach(self):
        # The agent shares the probe's PID namespace and can kill it; a dead
        # probe must not read as "no new listeners".
        field = self.attribute(self.listening([self.LISTENER], stale=True))
        self.assertEqual((field["status"], field["reason"]), ("PARTIAL", "NO_SOURCE_ACCESS"))
        self.assertIn("stopped reporting", field["note"])
        self.assertEqual(self.attribute(self.listening([self.LISTENER], stale=False))["status"], "ANSWERED")

    def test_the_gap_note_carries_no_count_so_a_growing_one_is_not_drift(self):
        # RailDash compares notes; listensnoop's lost count only grows, and
        # any process can inflate it.
        first = self.attribute(self.listening([self.LISTENER], lost=3, unlisted=1))
        later = self.attribute(self.listening([self.LISTENER], lost=3000, unlisted=50))
        self.assertEqual(first, later)
        self.assertNotRegex(first["note"], r"\d")

    def test_listeners_are_sandbox_scoped_in_a_multi_agent_bundle(self):
        # One PID namespace's events, not attributable to one agent.
        spec = importlib.util.spec_from_file_location(
            "compose_evidence_bundle_v2", ROOT / "tools/scan/compose_evidence_bundle_v2.py")
        composer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(composer)

        self.assertIn("observed_listeners", composer.SANDBOX_ATTRIBUTES)
        self.assertNotIn("observed_listeners", composer.agent_scoped_attributes(
            self.bundle(self.listening([self.LISTENER]))["attributes"]))

    def test_events_reach_the_runtime_source_in_docker_mode(self):
        bundle = evidence_bundle.build_evidence_bundle(
            build_args(), docker_context(), dict(HOST_PAIR), identity(observed_listeners=self.listening())
        )
        self.assertTrue(bundle["inputs_attempted"]["runtime"]["reached"])

    def test_a_new_listener_changes_the_value_and_nothing_else_moves(self):
        before = self.bundle(self.listening([self.LISTENER]))["attributes"]
        after = self.bundle(self.listening([self.LISTENER, dict(self.LISTENER, port="ephemeral", protocol="udp")]))["attributes"]
        changed = {name for name in before if before[name] != after[name]}
        self.assertEqual(changed, {"observed_listeners"})


class ObservedIngressPeersBundleTest(unittest.TestCase):
    """Who connected in, from listensnoop's peer events (DR-145)."""

    PEER = {"protocol": "tcp", "addr": "0.0.0.0", "port": 8080, "process": "python3",
            "peer": "8.8.4.4", "scope": "public"}

    def bundle(self, listening):
        return evidence_bundle.build_evidence_bundle(
            build_args(), self_context(), dict(HOST_PAIR), identity(observed_listeners=listening)
        )

    @staticmethod
    def listening(peers=(), reported=True, **counts):
        base = ObservedListenersBundleTest.listening(peers=list(peers), peers_reported=reported,
                                                     peers_unlisted=0)
        base.update(counts)
        return base

    def attribute(self, listening):
        bundle = self.bundle(listening)
        self.assertEqual(evidence_bundle.contract_problems(bundle), [])
        return bundle["attributes"]["observed_ingress_peers"]

    def test_without_an_event_file_the_pack_says_it_did_not_look(self):
        field = self.attribute(None)
        self.assertEqual((field["status"], field["reason"]), ("BLIND", "NOT_COLLECTED_BY_PACK"))

    def test_a_probe_that_predates_peers_is_blind_not_absent(self):
        # It never looked: "nobody connected" would be a lie.
        field = self.attribute(self.listening(reported=False))
        self.assertEqual((field["status"], field["reason"]), ("BLIND", "NOT_COLLECTED_BY_PACK"))
        self.assertIn("does not report accepted peers", field["note"])

    def test_peers_are_answered_as_observed(self):
        field = self.attribute(self.listening([self.PEER]))
        self.assertEqual((field["status"], field["tier"], field["value"]),
                         ("ANSWERED", "observed", [self.PEER]))

    def test_an_empty_window_is_absent(self):
        field = self.attribute(self.listening())
        self.assertEqual((field["status"], field["value"]), ("ABSENT", None))

    def test_probe_gaps_and_the_peer_cap_make_it_partial(self):
        for counts, reason, words in (
            ({"lost": 3}, "SIZE_CAP_EXCEEDED", "lost events"),
            ({"peers_unlisted": 2}, "SIZE_CAP_EXCEEDED", "more distinct peers"),
            ({"starts": 2, "restarted": True}, "NO_SOURCE_ACCESS", "restarted 1 time "),
            ({"stale": True}, "NO_SOURCE_ACCESS", "stopped reporting"),
        ):
            for peers in ((), [self.PEER]):
                with self.subTest(counts=counts, peers=peers):
                    field = self.attribute(self.listening(peers, **counts))
                    self.assertEqual((field["status"], field["reason"]), ("PARTIAL", reason))
                    self.assertIn(words, field["note"])
                    self.assertIn("peers may be missing", field["note"])

    def test_the_listener_cap_is_not_a_peer_gap(self):
        field = self.attribute(self.listening([self.PEER], unlisted=4))
        self.assertEqual(field["status"], "ANSWERED")

    def test_the_gap_note_carries_no_count(self):
        first = self.attribute(self.listening([self.PEER], lost=3, peers_unlisted=1))
        later = self.attribute(self.listening([self.PEER], lost=3000, peers_unlisted=90))
        self.assertEqual(first, later)
        self.assertNotRegex(first["note"], r"\d")

    def test_a_new_peer_changes_this_value_and_nothing_else_moves(self):
        before = self.bundle(self.listening([self.PEER]))["attributes"]
        after = self.bundle(self.listening([self.PEER, dict(self.PEER, peer="1.1.1.1")]))["attributes"]
        changed = {name for name in before if before[name] != after[name]}
        self.assertEqual(changed, {"observed_ingress_peers"})

    def test_peers_are_sandbox_scoped_in_a_multi_agent_bundle(self):
        spec = importlib.util.spec_from_file_location(
            "compose_evidence_bundle_v2", ROOT / "tools/scan/compose_evidence_bundle_v2.py")
        composer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(composer)
        self.assertIn("observed_ingress_peers", composer.SANDBOX_ATTRIBUTES)
        self.assertNotIn("observed_ingress_peers", composer.agent_scoped_attributes(
            self.bundle(self.listening([self.PEER]))["attributes"]))


class ObservedFileAccessBundleTest(unittest.TestCase):
    """The files the sandbox opened, from filesnoop (DR-154)."""

    WROTE = {"path": "/data/out.txt", "read": False, "write": True, "exec": False, "layer": False}
    READ = {"path": "/etc/hosts", "read": True, "write": False, "exec": False, "layer": False}

    def bundle(self, files, **identity_overrides):
        return evidence_bundle.build_evidence_bundle(
            build_args(), self_context(), dict(HOST_PAIR),
            identity(observed_file_access=files, **identity_overrides),
        )

    @staticmethod
    def files(entries=(), **counts):
        base = {"source": "filesnoop", "files": list(entries), "lost": 0, "unlisted": 0,
                "unnamed": 0, "malformed": 0, "outside_namespace": 0,
                "starts": 1, "restarted": False, "stale": False}
        base.update(counts)
        return base

    def attribute(self, files):
        bundle = self.bundle(files)
        self.assertEqual(evidence_bundle.contract_problems(bundle), [])
        return bundle["attributes"]["observed_file_access"]

    def test_without_an_event_file_the_pack_says_it_did_not_look(self):
        field = self.attribute(None)
        self.assertEqual((field["status"], field["reason"], field["tier"]),
                         ("BLIND", "NOT_COLLECTED_BY_PACK", "observed"))

    def test_files_are_answered_as_observed_and_authored_by_nobody(self):
        # Kernel-observed: never declared, and nothing the agent wrote.
        field = self.attribute(self.files([self.READ, self.WROTE]))
        self.assertEqual((field["status"], field["tier"], field["authored_by"], field["value"]),
                         ("ANSWERED", "observed", "none", [self.READ, self.WROTE]))

    def test_an_empty_window_is_absent_not_an_empty_answer(self):
        field = self.attribute(self.files())
        self.assertEqual((field["status"], field["value"]), ("ABSENT", None))

    def test_probe_gaps_the_cap_and_unnamed_paths_make_it_partial(self):
        for counts, reason, words in (
            ({"lost": 3}, "SIZE_CAP_EXCEEDED", "filesnoop reported lost events"),
            ({"unlisted": 2}, "SIZE_CAP_EXCEEDED", "more distinct files than the cap"),
            ({"unnamed": 1}, "SIZE_CAP_EXCEEDED", "could not read"),
            ({"starts": 0}, "NO_SOURCE_ACCESS", "no filesnoop start record"),
            ({"starts": 2, "restarted": True}, "NO_SOURCE_ACCESS", "filesnoop restarted 1 time "),
            ({"stale": True}, "NO_SOURCE_ACCESS", "filesnoop stopped reporting"),
        ):
            for entries in ((), [self.WROTE]):
                with self.subTest(counts=counts, entries=entries):
                    field = self.attribute(self.files(entries, **counts))
                    self.assertEqual((field["status"], field["reason"]), ("PARTIAL", reason))
                    self.assertEqual(field["value"], list(entries))
                    self.assertIn(words, field["note"])
                    self.assertIn("files may be missing", field["note"])

    def test_a_lost_write_changes_the_note_of_an_already_partial_list(self):
        # A baseline locked while reads overflowed the cap must still drift
        # when a write is what goes missing.
        reads_only = self.attribute(self.files([self.WROTE], unlisted=40))
        write_lost = self.attribute(self.files([self.WROTE], unlisted=41, unlisted_write_exec=1))
        self.assertNotEqual(reads_only["note"], write_lost["note"])
        self.assertIn("written or run files past the cap", write_lost["note"])
        unnamed = self.attribute(self.files([self.WROTE], unnamed=2))
        unnamed_write = self.attribute(self.files([self.WROTE], unnamed=3, unnamed_write_exec=1))
        self.assertNotEqual(unnamed["note"], unnamed_write["note"])
        self.assertEqual(write_lost["reason"], "SIZE_CAP_EXCEEDED")

    def test_the_gap_note_carries_no_count(self):
        first = self.attribute(self.files([self.WROTE], lost=3, unlisted=1, unnamed=1, malformed=2))
        later = self.attribute(self.files([self.WROTE], lost=3000, unlisted=90, unnamed=7, malformed=9))
        self.assertEqual(first, later)
        self.assertNotRegex(first["note"], r"\d")

    def test_the_note_says_when_temp_names_were_folded_without_a_count(self):
        # DR-166: a templated path must never pass for one opened by that
        # name, and the words, unlike a count, are the same every scan.
        temp = {"path": "/tmp/tmp*", "read": False, "write": True, "exec": False, "layer": False}
        plain = self.attribute(self.files([self.WROTE]))
        folded = self.attribute(self.files([self.WROTE, temp], collapsed=3))
        again = self.attribute(self.files([self.WROTE, temp], collapsed=40))
        self.assertNotIn("folded", plain["note"])
        self.assertIn("randomly named temp files are folded", folded["note"])
        self.assertEqual((folded["status"], folded["value"]), ("ANSWERED", [self.WROTE, temp]))
        self.assertEqual(folded, again)
        self.assertNotRegex(folded["note"], r"\d")
        self.assertEqual(folded["method"], plain["method"])
        partial = self.attribute(self.files([temp], lost=1, collapsed=2))
        self.assertEqual(partial["status"], "PARTIAL")
        self.assertIn("files may be missing", partial["note"])
        self.assertIn("randomly named temp files are folded", partial["note"])

    def test_a_newly_written_path_changes_this_value_and_nothing_else_moves(self):
        before = self.bundle(self.files([self.READ]))["attributes"]
        after = self.bundle(self.files([self.READ, self.WROTE]))["attributes"]
        changed = {name for name in before if before[name] != after[name]}
        self.assertEqual(changed, {"observed_file_access"})

    def test_listener_gaps_do_not_leak_into_file_access_or_back(self):
        listening = ObservedListenersBundleTest.listening(lost=5, starts=0)
        attrs = self.bundle(self.files([self.WROTE]), observed_listeners=listening)["attributes"]
        self.assertEqual(attrs["observed_file_access"]["status"], "ANSWERED")
        self.assertEqual(attrs["observed_listeners"]["status"], "PARTIAL")
        attrs = self.bundle(self.files([self.WROTE], lost=1),
                            observed_listeners=ObservedListenersBundleTest.listening())["attributes"]
        self.assertEqual(attrs["observed_listeners"]["status"], "ABSENT")

    def test_events_reach_the_runtime_source_in_docker_mode(self):
        bundle = evidence_bundle.build_evidence_bundle(
            build_args(), docker_context(), dict(HOST_PAIR), identity(observed_file_access=self.files())
        )
        self.assertTrue(bundle["inputs_attempted"]["runtime"]["reached"])

    def test_the_contract_holds_the_value_to_its_shape(self):
        # The published schema holds this value to `file_access_value`, and
        # verify_bundle walks that schema, so a producer bug is a failed
        # scan, not a bundle RailDash has to guess at.
        good = self.bundle(self.files([self.WROTE]))
        self.assertEqual(evidence_bundle.contract_problems(good), [])
        for broken, words in (
            ([dict(self.WROTE, process="python3")], "not a field"),
            ([dict(self.WROTE, write="yes")], "must be a boolean"),
            ([{k: v for k, v in self.WROTE.items() if k != "layer"}], "required"),
            ([dict(self.WROTE, path="")], "non-empty"),
            ([dict(self.WROTE, path="/" + "x" * 1024)], "exceeds 1024"),
            ([self.WROTE] * 513, "at most 512"),
            ([dict(self.WROTE, path=f"/{i}" + "\u00e9" * 1000) for i in range(60)], "byte bound"),
            ({"path": "/x"}, "must be an array"),
        ):
            with self.subTest(words=words):
                bundle = copy.deepcopy(good)
                bundle["attributes"]["observed_file_access"]["value"] = broken
                problems = evidence_bundle.contract_problems(bundle)
                self.assertTrue(any(words in p for p in problems), problems)

    def test_the_published_schema_carries_the_shape(self):
        # One copy: the scanner's shape is the published def, and the v1
        # schema applies it to both statuses that carry the list, so a
        # consumer validating against the published schema holds the value
        # to the same shape verify_bundle does (the byte bound stays code).
        self.assertEqual(evidence_bundle.FILE_ACCESS_VALUE_SCHEMA, SCHEMA["$defs"]["file_access_value"])
        self.assertEqual(
            SCHEMA["properties"]["attributes"]["properties"]["observed_file_access"]["allOf"][1],
            {"if": {"properties": {"status": {"enum": ["ANSWERED", "PARTIAL"]}}},
             "then": {"properties": {"value": {"$ref": "#/$defs/file_access_value"}}}})
        partial = self.bundle(self.files([self.WROTE], lost=3))
        self.assertEqual(partial["attributes"]["observed_file_access"]["status"], "PARTIAL")
        self.assertEqual(evidence_bundle.contract_problems(partial), [])
        partial["attributes"]["observed_file_access"]["value"] = [dict(self.WROTE, pid=7)]
        self.assertTrue(any("value[0].pid: not a field" in p
                            for p in evidence_bundle._schema_problems(partial, SCHEMA, "bundle")))
        absent = self.bundle(self.files([]))
        self.assertEqual(absent["attributes"]["observed_file_access"]["status"], "ABSENT")
        self.assertEqual(evidence_bundle.contract_problems(absent), [])

    def test_the_shape_check_matches_the_summarizer_bounds(self):
        self.assertEqual(evidence_bundle.FILE_ACCESS_VALUE_SCHEMA["maxItems"], scanner.FILE_ACCESS_CAP)
        self.assertEqual(evidence_bundle.FILE_ACCESS_VALUE_SCHEMA["items"]["properties"]["path"]["maxLength"],
                         scanner.FILE_PATH_MAX)
        self.assertEqual(evidence_bundle.FILE_ACCESS_VALUE_MAX_BYTES, scanner.FILE_ACCESS_BYTES)

    def test_file_access_is_sandbox_scoped_in_a_multi_agent_bundle(self):
        spec = importlib.util.spec_from_file_location(
            "compose_evidence_bundle_v2", ROOT / "tools/scan/compose_evidence_bundle_v2.py")
        composer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(composer)
        self.assertIn("observed_file_access", composer.SANDBOX_ATTRIBUTES)
        self.assertNotIn("observed_file_access", composer.agent_scoped_attributes(
            self.bundle(self.files([self.WROTE]))["attributes"]))

    def test_a_v2_bundle_holds_the_sandbox_value_to_its_shape(self):
        # The statuses v1's schema applies the shape to, so v1 and v2 agree.
        self.assertEqual(evidence_bundle.FILE_ACCESS_VALUED_STATUSES, {"ANSWERED", "PARTIAL"})
        for status in ("ANSWERED", "PARTIAL"):
            with self.subTest(status=status):
                problems = evidence_bundle._semantic_problems_v2({"sandbox": {"attributes": {
                    "observed_file_access": {"status": status, "value": [{"path": "/x"}]}}}, "agents": []})
                self.assertTrue(any("observed_file_access.value[0].read" in p for p in problems), problems)
        huge = [dict(self.WROTE, path=f"/{i}" + "\u00e9" * 1000) for i in range(60)]
        problems = evidence_bundle._semantic_problems_v2({"sandbox": {"attributes": {
            "observed_file_access": {"status": "ABSENT", "value": huge}}}, "agents": []})
        self.assertTrue(any("byte bound" in p for p in problems), problems)


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

    def test_a_listen_file_reaches_the_feature_file_and_the_bundle(self):
        import tempfile

        line = json.dumps({"kind": "listen", "pid": 7, "tid": 7, "host_pid": 7, "uid": 0,
                           "comm": "nc", "protocol": "tcp", "family": "ipv4",
                           "addr": "0.0.0.0", "port": 4444})
        for how in ("flag", "env"):
            with self.subTest(how=how), tempfile.TemporaryDirectory() as tmp:
                Path(tmp, "listen.jsonl").write_text(line + "\n", encoding="utf-8")
                argv = ["--mode", "self", "--host-id", "h-1",
                        "--feature-output", f"{tmp}/features.json",
                        "--evidence-bundle-output", f"{tmp}/bundle.json"]
                if how == "flag":
                    argv += ["--listen-file", f"{tmp}/listen.jsonl"]
                    proc = self.run_scan(tmp, argv, tmp)
                else:
                    import subprocess

                    proc = subprocess.run(
                        ["python3", str(SCANNER)] + argv, cwd=tmp, capture_output=True, text=True,
                        env={**{k: v for k, v in os.environ.items() if not k.startswith("RAIL_")},
                             "RAIL_LISTEN_FILE": f"{tmp}/listen.jsonl"},
                        timeout=120,
                    )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                features = json.loads(Path(tmp, "features.json").read_text())
                bundle = json.loads(Path(tmp, "bundle.json").read_text())
                expected = [{"protocol": "tcp", "addr": "0.0.0.0", "port": 4444, "process": "nc"}]
                self.assertEqual(features["observed_listeners"]["listeners"], expected)
                self.assertEqual(bundle["attributes"]["observed_listeners"]["value"], expected)

    def test_a_files_file_reaches_the_feature_file_and_the_bundle(self):
        import subprocess
        import tempfile

        lines = [
            json.dumps({"kind": "start", "time": "2026-10-03T08:00:00Z", "every": 0}),
            json.dumps({"timestamp_ns": 1, "kind": "open", "pid": 7, "tid": 7, "host_pid": 7, "uid": 0,
                        "comm": "sh", "path": "/tmp/out.txt", "read": False, "write": True,
                        "exec": False, "creat": True, "trunc": True, "append": False,
                        "dev": "0:1", "ino": 2}),
        ]
        for how in ("flag", "env"):
            with self.subTest(how=how), tempfile.TemporaryDirectory() as tmp:
                Path(tmp, "files.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
                argv = ["--mode", "self", "--host-id", "h-1",
                        "--feature-output", f"{tmp}/features.json",
                        "--evidence-bundle-output", f"{tmp}/bundle.json"]
                env = {k: v for k, v in os.environ.items() if not k.startswith("RAIL_")}
                if how == "flag":
                    argv += ["--files-file", f"{tmp}/files.jsonl"]
                else:
                    env["RAIL_FILES_FILE"] = f"{tmp}/files.jsonl"
                proc = subprocess.run(["python3", str(SCANNER)] + argv, cwd=tmp, capture_output=True,
                                      text=True, env=env, timeout=120)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                features = json.loads(Path(tmp, "features.json").read_text())
                bundle = json.loads(Path(tmp, "bundle.json").read_text())
                expected = [{"path": "/tmp/out.txt", "read": False, "write": True, "exec": False,
                             "layer": False}]
                self.assertEqual(features["observed_file_access"]["files"], expected)
                field = bundle["attributes"]["observed_file_access"]
                self.assertEqual((field["status"], field["tier"], field["value"]),
                                 ("ANSWERED", "observed", expected))
                self.assertEqual(evidence_bundle.contract_problems(bundle), [])

    def test_the_scanned_tmpdir_folds_its_random_names_end_to_end(self):
        # DR-166: the scanned environment's $TMPDIR is a temp dir; the count
        # goes to the feature file, the words to the bundle's note.
        import subprocess
        import tempfile

        def opened(path):
            return json.dumps({"timestamp_ns": 1, "kind": "open", "pid": 7, "tid": 7, "host_pid": 7,
                               "uid": 0, "comm": "py", "path": path, "read": False, "write": True,
                               "exec": False, "creat": True, "trunc": False, "append": False,
                               "dev": "0:1", "ino": 2})

        lines = [json.dumps({"kind": "start", "time": "2026-10-03T08:00:00Z", "every": 0}),
                 opened("/scratch/tmp/tmpk3j_9xq2"), opened("/scratch/tmp/tmp9zz8yy7x"), opened("/tmp/tmpqwertyui")]
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "files.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.startswith("RAIL_")}
            env["TMPDIR"] = "/scratch/tmp"
            proc = subprocess.run(
                ["python3", str(SCANNER), "--mode", "self", "--host-id", "h-1",
                 "--feature-output", f"{tmp}/features.json", "--evidence-bundle-output", f"{tmp}/bundle.json",
                 "--files-file", f"{tmp}/files.jsonl"],
                cwd=tmp, capture_output=True, text=True, env=env, timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            features = json.loads(Path(tmp, "features.json").read_text())["observed_file_access"]
            field = json.loads(Path(tmp, "bundle.json").read_text())["attributes"]["observed_file_access"]
        expected = [{"path": path, "read": False, "write": True, "exec": False, "layer": False}
                    for path in ("/scratch/tmp/tmp*", "/tmp/tmp*")]
        self.assertEqual((features["files"], features["collapsed"]), (expected, 3))
        self.assertEqual((field["status"], field["value"]), ("ANSWERED", expected))
        self.assertIn("randomly named temp files are folded", field["note"])

    def test_an_unreadable_files_file_fails_the_scan_loudly(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_scan(tmp, ["--mode", "self", "--host-id", "h-1",
                                       "--feature-output", f"{tmp}/features.json",
                                       "--files-file", f"{tmp}/missing.jsonl"], tmp)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("cannot read filesnoop events", proc.stderr)

    def test_an_unreadable_listen_file_fails_the_scan_loudly(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_scan(tmp, ["--mode", "self", "--host-id", "h-1",
                                       "--feature-output", f"{tmp}/features.json",
                                       "--listen-file", f"{tmp}/missing.jsonl"], tmp)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("cannot read listensnoop events", proc.stderr)

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
            default = Path(tmp, ".rail", "railmon", "evidence-bundle.json")
            self.assertTrue(default.exists())
            self.assertEqual(json.loads(default.read_text())["bundle_version"], 1)
            self.assertFalse(Path(tmp, ".rail", "railscan").exists())

    def test_a_railscan_layout_keeps_its_default_paths(self):
        """DR-161: a working directory that already has RailScan's
        `.rail/railscan/` keeps getting its feature file and bundle there, with
        a deprecation note, until the files are moved — also when
        `--register` or another output creates `.rail/railmon/` first."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".rail", "railscan").mkdir(parents=True)
            proc = self.run_scan(tmp, ["--mode", "self", "--host-id", "h-1"], tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            legacy = Path(tmp, ".rail", "railscan")
            self.assertTrue((legacy / "features.json").exists())
            self.assertEqual(json.loads((legacy / "evidence-bundle.json").read_text())["bundle_version"], 1)
            self.assertFalse(Path(tmp, ".rail", "railmon").exists())
            self.assertIn("deprecated RailScan location", proc.stderr)

            Path(tmp, ".rail", "railmon", "forward").mkdir(parents=True)
            proc = self.run_scan(tmp, ["--mode", "self", "--host-id", "h-1"], tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertFalse(Path(tmp, ".rail", "railmon", "features.json").exists())
            self.assertIn("deprecated RailScan location", proc.stderr)

            for name in ("features.json", "evidence-bundle.json"):
                (legacy / name).rename(Path(tmp, ".rail", "railmon", name))
            proc = self.run_scan(tmp, ["--mode", "self", "--host-id", "h-1"], tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(Path(tmp, ".rail", "railmon", "features.json").exists())
            self.assertTrue(Path(tmp, ".rail", "railmon", "evidence-bundle.json").exists())
            self.assertNotIn("deprecated RailScan location", proc.stderr)


class RaildashDeliveryWiringTest(unittest.TestCase):
    """DR-121: `--raildash-url` POSTs the exact evidence-bundle bytes, and is
    independent of `--register`/`--center-url`.

    A real loopback server, not a mock of `post_evidence_bundle`'s internals —
    the acceptance criterion is the actual bytes over the wire and the two
    delivery targets' independence, both wire-level claims a mocked poster
    could not verify. No live RailDash is required: `FakeRaildash` is a tiny
    stand-in, the same pattern `test_mcp_tool_discovery.py` already uses for
    a fake MCP server.
    """

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

    def start_fake_raildash(self, responses: list[tuple[int, dict]]):
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        captured: dict = {}
        remaining = list(responses)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                captured["path"] = self.path
                length = int(self.headers.get("Content-Length", 0))
                captured["body"] = self.rfile.read(length)
                captured["content_type"] = self.headers.get("Content-Type")
                status, body = remaining.pop(0)
                payload = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        return server, thread, f"http://{host}:{port}", captured

    def stop_fake_raildash(self, server, thread):
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    def test_the_posted_bytes_match_the_local_evidence_bundle_file(self):
        import tempfile

        server, thread, url, captured = self.start_fake_raildash([(202, {"asp_id": "asp-1", "duplicate": False})])
        try:
            with tempfile.TemporaryDirectory() as tmp:
                proc = self.run_scan(
                    tmp,
                    [
                        "--mode", "self",
                        "--no-feature-file",
                        "--host-id", "h-1",
                        "--evidence-bundle-output", f"{tmp}/bundle.json",
                        "--raildash-url", url,
                    ],
                    tmp,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                on_disk = Path(tmp, "bundle.json").read_bytes()
        finally:
            self.stop_fake_raildash(server, thread)

        self.assertEqual(captured["path"], "/v1/evidence-bundles")
        self.assertEqual(captured["content_type"], "application/json")
        # The identical bytes, not just an equivalent re-serialization: the
        # POST body and the file on disk share one `build_verified_bundle`
        # call, so their bundle_id (and every other byte) must match exactly.
        self.assertEqual(captured["body"], on_disk)
        self.assertIn("accepted", proc.stderr)
        self.assertIn("id=asp-1", proc.stderr)

    def test_a_duplicate_response_is_reported_as_such(self):
        """--no-evidence-bundle still allows raildash delivery: the two are
        independent controls over the same underlying bundle."""
        import tempfile

        server, thread, url, captured = self.start_fake_raildash([(202, {"asp_id": "asp-1", "duplicate": True})])
        try:
            with tempfile.TemporaryDirectory() as tmp:
                proc = self.run_scan(
                    tmp,
                    [
                        "--mode", "self",
                        "--no-feature-file",
                        "--host-id", "h-1",
                        "--no-evidence-bundle",
                        "--raildash-url", url,
                    ],
                    tmp,
                )
        finally:
            self.stop_fake_raildash(server, thread)

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("duplicate", proc.stderr)
        self.assertIn("path", captured)

    def test_raildash_delivery_is_independent_of_a_failed_registration(self):
        """--register (pointed at an unreachable port) and --raildash-url (a
        real local server) in one invocation: each target's own outcome, not
        the other's."""
        import tempfile

        server, thread, url, captured = self.start_fake_raildash([(202, {"asp_id": "asp-2", "duplicate": False})])
        try:
            with tempfile.TemporaryDirectory() as tmp:
                proc = self.run_scan(
                    tmp,
                    [
                        "--mode", "self",
                        "--feature-output", f"{tmp}/features.json",
                        "--host-id", "h-1",
                        "--evidence-bundle-output", f"{tmp}/bundle.json",
                        "--register",
                        "--center-url", "http://127.0.0.1:1",
                        "--raildash-url", url,
                    ],
                    tmp,
                )
                feature = json.loads(Path(tmp, "features.json").read_text())
        finally:
            self.stop_fake_raildash(server, thread)

        # The failed --register still sets the exit code (matching its own
        # existing behaviour), but must not prevent the RailDash delivery.
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("rail-center registration failed", proc.stderr)
        self.assertIn("delivered evidence bundle to raildash", proc.stderr)
        self.assertIn("accepted", proc.stderr)
        self.assertEqual(feature["scan"]["registration_status"], "registration_failed")
        self.assertEqual(captured["path"], "/v1/evidence-bundles")

    def test_a_non_2xx_response_is_reported_not_fatal_to_the_bundle_write(self):
        """The local bundle is still on disk, and the run does not crash — the
        failure is reported and reflected in the exit code, mirroring
        --register's existing failure handling."""
        import tempfile

        server, thread, url, captured = self.start_fake_raildash([(400, {"error": "bundle too large"})])
        try:
            with tempfile.TemporaryDirectory() as tmp:
                proc = self.run_scan(
                    tmp,
                    [
                        "--mode", "self",
                        "--no-feature-file",
                        "--host-id", "h-1",
                        "--evidence-bundle-output", f"{tmp}/bundle.json",
                        "--raildash-url", url,
                    ],
                    tmp,
                )
                bundle_exists = Path(tmp, "bundle.json").exists()
        finally:
            self.stop_fake_raildash(server, thread)

        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertTrue(bundle_exists, "the local bundle must survive a rejected delivery")
        self.assertIn("HTTP 400", proc.stderr)


class ScanExitAndConfigTest(unittest.TestCase):
    """DR-157: a bundle that fails its contract fails the scan, and
    `--observed-file` has an environment variable like `--listen-file`."""

    def run_scan(self, tmp: str, extra: list[str], env: dict | None = None):
        import subprocess

        return subprocess.run(
            ["python3", str(SCANNER)] + extra,
            cwd=tmp,
            capture_output=True,
            text=True,
            env={**{k: v for k, v in os.environ.items() if not k.startswith("RAIL_")}, **(env or {})},
            timeout=120,
        )

    def test_a_bundle_that_fails_its_contract_fails_the_scan(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            # No RAIL_HOST_ID and no --host-id: the bundle has no host_id,
            # which its schema requires.
            proc = self.run_scan(tmp, ["--mode", "self", "--no-feature-file",
                                       "--evidence-bundle-output", f"{tmp}/bundle.json"])
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertIn("evidence bundle failed its contract", proc.stderr)
            self.assertFalse(Path(tmp, "bundle.json").exists())

    def test_skipping_the_bundle_skips_its_contract(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_scan(tmp, ["--mode", "self", "--no-feature-file", "--no-evidence-bundle"])
            self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_the_observed_file_can_come_from_the_environment(self):
        import tempfile

        snapshot = {"network_targets": [{"host": "api.example.test", "path": "/v1", "count": 3}]}
        for how in ("flag", "env"):
            with self.subTest(how=how), tempfile.TemporaryDirectory() as tmp:
                Path(tmp, "snapshot.json").write_text(json.dumps(snapshot), encoding="utf-8")
                argv = ["--mode", "self", "--host-id", "h-1", "--no-evidence-bundle",
                        "--feature-output", f"{tmp}/features.json"]
                env = {}
                if how == "flag":
                    argv += ["--observed-file", f"{tmp}/snapshot.json"]
                else:
                    env["RAIL_OBSERVED_FILE"] = f"{tmp}/snapshot.json"
                proc = self.run_scan(tmp, argv, env)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                features = json.loads(Path(tmp, "features.json").read_text())
                hosts = [d["host"] for d in features["observed_reach"]["destinations"]]
                self.assertEqual(hosts, ["api.example.test"])


class UnchangedBundleReuseTest(unittest.TestCase):
    """DR-157: an interval scan of an unchanged agent re-sends the same
    bundle bytes, so RailDash (which keys an ASP on their digest) stores one
    ASP rather than one per interval."""

    def setUp(self):
        evidence_bundle._previous_bundles.clear()
        self.addCleanup(evidence_bundle._previous_bundles.clear)

    def test_unchanged_content_reuses_the_previous_bundle(self):
        first = build_bundle()
        second = build_bundle()
        self.assertNotEqual(first["bundle_id"], second["bundle_id"])
        self.assertEqual(evidence_bundle.content_fingerprint(first), evidence_bundle.content_fingerprint(second))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertIs(evidence_bundle.reuse_unchanged_bundle(first), first)
            self.assertIs(evidence_bundle.reuse_unchanged_bundle(second), first)

    def test_changed_content_is_a_new_bundle_and_the_new_reference(self):
        first = build_bundle()
        changed = build_bundle()
        changed["attributes"]["system_prompt_present"] = {"status": "ABSENT"}
        third = json.loads(json.dumps(changed))
        third["bundle_id"] = "bnd-other"
        with contextlib.redirect_stderr(io.StringIO()):
            evidence_bundle.reuse_unchanged_bundle(first)
            self.assertIs(evidence_bundle.reuse_unchanged_bundle(changed), changed)
            self.assertIs(evidence_bundle.reuse_unchanged_bundle(third), changed)

    def test_another_agent_key_never_reuses_a_bundle(self):
        first = build_bundle()
        second = build_bundle()
        with contextlib.redirect_stderr(io.StringIO()):
            evidence_bundle.reuse_unchanged_bundle(first, "agent-a")
            self.assertIs(evidence_bundle.reuse_unchanged_bundle(second, "agent-b"), second)

    def test_interval_scans_post_identical_bytes_while_nothing_changes(self):
        import tempfile
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        bodies: list[bytes] = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                duplicate = body in bodies
                bodies.append(body)
                payload = json.dumps({"accepted": True, "asp_id": "asp-1", "duplicate": duplicate}).encode()
                self.send_response(202)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        ticks = {"n": 0}

        def sleep(_seconds):
            ticks["n"] += 1
            if ticks["n"] >= 3:
                raise KeyboardInterrupt

        # Replace the scanner's `time` reference, not the shared `time`
        # module: any other `time.sleep` in the process (a polling loop left
        # over from another test) would otherwise use up the scan loop's ticks.
        scanner_time = SimpleNamespace(
            **{name: getattr(time, name) for name in dir(time) if not name.startswith("__")}
        )
        scanner_time.sleep = sleep

        try:
            with tempfile.TemporaryDirectory() as tmp:
                env = {k: v for k, v in os.environ.items() if not k.startswith("RAIL_")}
                stderr = io.StringIO()
                # The scanner imports evidence_bundle lazily; point that
                # import at the module this file loaded, for this run only.
                modules = {"evidence_bundle": evidence_bundle, "scan_agent_environment": scanner}
                with mock.patch.dict(os.environ, env, clear=True), \
                        mock.patch.dict(sys.modules, modules), \
                        mock.patch.object(scanner, "time", scanner_time), \
                        contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
                    code = scanner.main([
                        "--mode", "self", "--host-id", "h-1", "--agent-key", "a-1",
                        "--no-feature-file", "--evidence-bundle-output", f"{tmp}/bundle.json",
                        "--raildash-url", f"http://127.0.0.1:{server.server_address[1]}",
                        "--interval", "0",
                    ])
                on_disk = Path(tmp, "bundle.json").read_bytes()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(code, 0, stderr.getvalue())
        self.assertEqual(len(bodies), 3)
        self.assertEqual(len(set(bodies)), 1, "an unchanged scan must re-send the same bytes")
        self.assertEqual(bodies[0], on_disk)
        self.assertEqual(stderr.getvalue().count("duplicate"), 2)
        self.assertEqual(stderr.getvalue().count("evidence bundle unchanged since"), 2)


if __name__ == "__main__":
    unittest.main()
