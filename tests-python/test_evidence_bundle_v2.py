from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MODULE = ROOT / "tools/scan/compose_evidence_bundle_v2.py"
spec = importlib.util.spec_from_file_location("compose_evidence_bundle_v2", MODULE)
composer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(composer)

_bundle_spec = importlib.util.spec_from_file_location(
    "evidence_bundle", ROOT / "tools/scan/evidence_bundle.py"
)
evidence_bundle = importlib.util.module_from_spec(_bundle_spec)
assert _bundle_spec.loader is not None
_bundle_spec.loader.exec_module(evidence_bundle)

# The published v2 schema, RailMon's single canonical copy — loaded here
# independently of the composer, so the assertions below anchor on the file
# rather than on whatever the composer happens to produce.
V2_SCHEMA = json.loads((ROOT / "schemas" / "evidence-bundle-v2.schema.json").read_text())


def source(model: str, image: str = "sha256:abc") -> dict:
    return {
        "bundle_version": 1,
        "bundle_id": "ignored",
        "host_id": "host-01",
        "sandbox_name": "shared",
        "rule_pack_version": 1,
        "inputs_attempted": {"runtime": {"attempted": True, "reached": True}},
        "attributes": {
            "image_digest": {"value": image, "status": "ANSWERED"},
            "model_name": {"value": model, "status": "ANSWERED"},
        },
    }


class EvidenceBundleV2Test(unittest.TestCase):
    def test_shared_evidence_is_once_and_agents_are_sorted(self):
        bundle = composer.compose(
            "host-01", "shared", {"planner": source("claude"), "executor": source("gpt")}
        )
        self.assertEqual(bundle["bundle_version"], 2)
        self.assertEqual(bundle["sandbox"]["attributes"]["image_digest"]["value"], "sha256:abc")
        self.assertEqual([agent["agent_key"] for agent in bundle["agents"]], ["executor", "planner"])
        self.assertNotIn("image_digest", bundle["agents"][0]["attributes"])
        self.assertEqual(bundle["agents"][1]["attributes"]["model_name"]["value"], "claude")

    def test_disagreement_in_shared_evidence_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "disagrees"):
            composer.compose(
                "host-01", "shared", {"planner": source("claude"), "executor": source("gpt", "sha256:def")}
            )

    def test_default_key_is_not_a_multi_agent_key(self):
        with self.assertRaisesRegex(ValueError, "invalid"):
            composer.compose("host-01", "shared", {"default": source("claude")})

    def test_attestations_are_preserved_once(self):
        planner = source("claude")
        executor = source("gpt")
        attestation = {"id": "att-1", "root": "r", "claim": "c", "subject": "s", "verified_at": "2026-09-24T00:00:00Z", "verifier_version": "1"}
        for item in (planner, executor):
            item["attestations"] = [attestation]
            item["attributes"]["model_name"]["attestation_ref"] = "att-1"
        bundle = composer.compose("host-01", "shared", {"planner": planner, "executor": executor})
        self.assertEqual(bundle["attestations"], [attestation])


def full_source(model: str, image: str = "sha256:abc") -> dict:
    """A v1 source bundle complete enough to satisfy the published schema's
    `inputs_attempted`, unlike `source()` above, which only the composer's own
    (schema-independent) merge logic reads."""
    bundle = source(model, image)
    bundle["inputs_attempted"] = {
        "runtime": {"attempted": True, "reached": True},
        "image": {"attempted": False, "reason": "NO_SOURCE_ACCESS"},
        "manifest": {"attempted": False, "reason": "NO_SOURCE_ACCESS"},
        "repo": {"attempted": False, "reason": "NO_SOURCE_ACCESS"},
    }
    for attribute in bundle["attributes"].values():
        attribute.setdefault("tier", "observed")
        attribute.setdefault("authored_by", "platform")
    return bundle


class EvidenceBundleV2SchemaTest(unittest.TestCase):
    """DR-109 M1: the published v2 schema and the composer's own output agree —
    the schema accepts a real composed bundle, and refuses one broken in each
    of the ways the schema itself can express (see its top-level $comment for
    the three rules it cannot, which `EvidenceBundleV2` in rail-center's
    `profiling/bundle.py` checks instead)."""

    def build(self) -> dict:
        return composer.compose(
            "host-01", "shared", {"planner": full_source("claude"), "executor": full_source("gpt")}
        )

    def test_the_schema_is_a_draft_2020_12_document(self):
        self.assertEqual(V2_SCHEMA["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_a_composed_bundle_passes_the_vendored_schema(self):
        problems = evidence_bundle._schema_problems(self.build(), V2_SCHEMA, "bundle", V2_SCHEMA)
        self.assertEqual(problems, [])

    def test_an_empty_agents_array_is_refused(self):
        bundle = self.build()
        bundle["agents"] = []
        problems = evidence_bundle._schema_problems(bundle, V2_SCHEMA, "bundle", V2_SCHEMA)
        self.assertTrue(any("agents" in p and "at least 1" in p for p in problems), problems)

    def test_a_missing_sandbox_scope_is_refused(self):
        bundle = self.build()
        del bundle["sandbox"]
        problems = evidence_bundle._schema_problems(bundle, V2_SCHEMA, "bundle", V2_SCHEMA)
        self.assertTrue(any("sandbox" in p for p in problems), problems)

    def test_bundle_version_1_is_refused_by_the_v2_schema(self):
        bundle = self.build()
        bundle["bundle_version"] = 1
        problems = evidence_bundle._schema_problems(bundle, V2_SCHEMA, "bundle", V2_SCHEMA)
        self.assertTrue(any("bundle_version" in p for p in problems), problems)

    def test_an_unpatterned_agent_key_is_refused(self):
        bundle = self.build()
        bundle["agents"][0]["agent_key"] = "Not Valid!"
        problems = evidence_bundle._schema_problems(bundle, V2_SCHEMA, "bundle", V2_SCHEMA)
        self.assertTrue(any("agent_key" in p for p in problems), problems)

    def test_an_unknown_discovery_status_is_refused(self):
        bundle = self.build()
        bundle["agents"][0]["discovery_status"] = "vanished"
        problems = evidence_bundle._schema_problems(bundle, V2_SCHEMA, "bundle", V2_SCHEMA)
        self.assertTrue(any("discovery_status" in p for p in problems), problems)

    def test_the_schema_does_not_check_agent_key_ordering_or_uniqueness(self):
        # Named in the schema's own $comment as code-only: JSON Schema has no
        # way to compare sibling array items by a field, so two agents sharing
        # a key, or listed out of order, pass here and are refused only by
        # `EvidenceBundleV2.keys_are_sorted_and_unique` in rail-center.
        bundle = self.build()
        bundle["agents"] = [copy.deepcopy(bundle["agents"][0]), copy.deepcopy(bundle["agents"][0])]
        problems = evidence_bundle._schema_problems(bundle, V2_SCHEMA, "bundle", V2_SCHEMA)
        self.assertEqual(problems, [])


class ContractProblemsV2Test(unittest.TestCase):
    """`contract_problems_v2`/`verify_bundle_v2` catch the two rules the
    schema itself cannot express (DR-109 M2): sorted, unique `agent_key`s,
    and an `attestation_ref` naming a real attestation — unlike
    `EvidenceBundleV2SchemaTest` above, which only checks the published
    schema in isolation."""

    def build(self) -> dict:
        return composer.compose(
            "host-01", "shared", {"planner": full_source("claude"), "executor": full_source("gpt")}
        )

    def test_a_composed_bundle_has_no_contract_problems(self):
        self.assertEqual(evidence_bundle.contract_problems_v2(self.build()), [])

    def test_duplicate_agent_key_is_a_contract_problem_not_just_a_schema_gap(self):
        bundle = self.build()
        bundle["agents"] = [copy.deepcopy(bundle["agents"][0]), copy.deepcopy(bundle["agents"][0])]
        problems = evidence_bundle.contract_problems_v2(bundle)
        self.assertTrue(any("duplicate" in p for p in problems), problems)

    def test_out_of_order_agents_is_a_contract_problem(self):
        bundle = self.build()
        bundle["agents"] = list(reversed(bundle["agents"]))
        problems = evidence_bundle.contract_problems_v2(bundle)
        self.assertTrue(any("sorted" in p for p in problems), problems)

    def test_an_attestation_ref_naming_nothing_is_a_contract_problem(self):
        bundle = self.build()
        bundle["agents"][0]["attributes"]["model_name"]["attestation_ref"] = "att-does-not-exist"
        problems = evidence_bundle.contract_problems_v2(bundle)
        self.assertTrue(any("attestation_ref" in p for p in problems), problems)

    def test_verify_bundle_v2_raises_on_a_broken_bundle(self):
        # Not `scanner.ScannerError` by name: this file never registers
        # "scan_agent_environment" under `sys.modules`, so `verify_bundle_v2`'s
        # own lazy `from scan_agent_environment import ScannerError` may
        # resolve to a module object this file never loaded (whichever test
        # file claimed that name first in this `unittest discover` process) —
        # asserting the raise, not a specific class identity, is what's
        # actually load-bearing here.
        bundle = self.build()
        bundle["agents"] = [copy.deepcopy(bundle["agents"][0]), copy.deepcopy(bundle["agents"][0])]
        with self.assertRaises(Exception):
            evidence_bundle.verify_bundle_v2(bundle)


class ComposeFromScopesTest(unittest.TestCase):
    """The real `--target-manifest` collection path's own composer
    (DR-109 M2), distinct from `compose()`'s whole-bundle-merge contract:
    the caller already scoped each piece correctly, so there is nothing left
    to merge or agree on, only to validate, sort and wrap."""

    def agent(self, key: str, status: str = "available") -> dict:
        return {
            "agent_key": key,
            "discovery_status": status,
            "inputs_attempted": {"runtime": {"attempted": True, "reached": True}},
            "attributes": {"model_name": {"value": key, "status": "ANSWERED", "tier": "observed"}},
        }

    def test_agents_are_sorted_by_key(self):
        bundle = composer.compose_from_scopes(
            host_id="host-01",
            sandbox_name="shared",
            rule_pack_version=1,
            sandbox_inputs={"runtime": {"attempted": True, "reached": True}},
            sandbox_attributes={"image_digest": {"value": "sha256:abc", "status": "ANSWERED", "tier": "observed"}},
            agent_entries=[self.agent("planner"), self.agent("executor")],
        )
        self.assertEqual(bundle["bundle_version"], 2)
        self.assertEqual([a["agent_key"] for a in bundle["agents"]], ["executor", "planner"])
        self.assertEqual(bundle["sandbox"]["attributes"]["image_digest"]["value"], "sha256:abc")

    def test_at_least_one_agent_entry_is_required(self):
        with self.assertRaisesRegex(ValueError, "at least one"):
            composer.compose_from_scopes(
                host_id="host-01",
                sandbox_name="shared",
                rule_pack_version=1,
                sandbox_inputs={},
                sandbox_attributes={},
                agent_entries=[],
            )

    def test_duplicate_agent_key_is_refused(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            composer.compose_from_scopes(
                host_id="host-01",
                sandbox_name="shared",
                rule_pack_version=1,
                sandbox_inputs={},
                sandbox_attributes={},
                agent_entries=[self.agent("planner"), self.agent("planner")],
            )

    def test_the_default_key_is_refused(self):
        with self.assertRaisesRegex(ValueError, "invalid"):
            composer.compose_from_scopes(
                host_id="host-01",
                sandbox_name="shared",
                rule_pack_version=1,
                sandbox_inputs={},
                sandbox_attributes={},
                agent_entries=[self.agent("default")],
            )

    def test_a_failed_or_not_found_agent_is_still_an_entry(self):
        bundle = composer.compose_from_scopes(
            host_id="host-01",
            sandbox_name="shared",
            rule_pack_version=1,
            sandbox_inputs={},
            sandbox_attributes={},
            agent_entries=[self.agent("planner", status="not_found")],
        )
        self.assertEqual(bundle["agents"][0]["discovery_status"], "not_found")


class FailedScopeBuildersTest(unittest.TestCase):
    """`failed_inputs`/`failed_attributes` (DR-109 M2, design §5's "shared
    evidence collection fails" / "one agent collector fails" rows) —
    distinct from `unattempted_inputs`/`scope_unresolved_attributes`, which
    describe a target that was never even tried."""

    def test_failed_inputs_are_attempted_but_not_reached(self):
        inputs = evidence_bundle.failed_inputs("PARSE_FAILED")
        self.assertEqual(set(inputs), {"runtime", "image", "manifest", "repo"})
        for source in inputs.values():
            self.assertTrue(source["attempted"])
            self.assertFalse(source["reached"])
            self.assertEqual(source["reason"], "PARSE_FAILED")

    def test_failed_attributes_cover_every_template_name_outside_the_exclusion(self):
        template = {
            "image_digest": {"value": "sha256:abc", "status": "ANSWERED", "tier": "observed"},
            "model_name": {"value": "claude", "status": "ANSWERED", "tier": "declared"},
        }
        attrs = evidence_bundle.failed_attributes(template, frozenset({"image_digest"}))
        self.assertEqual(set(attrs), {"model_name"})
        self.assertEqual(attrs["model_name"]["status"], "FAILED")
        self.assertEqual(attrs["model_name"]["tier"], "declared")

    def test_an_empty_template_yields_no_attributes(self):
        self.assertEqual(evidence_bundle.failed_attributes({}, frozenset()), {})
