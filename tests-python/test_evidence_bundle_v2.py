from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "tools/agent-environment-scanner/compose_evidence_bundle_v2.py"
spec = importlib.util.spec_from_file_location("compose_evidence_bundle_v2", MODULE)
composer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(composer)


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
