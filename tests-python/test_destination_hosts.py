"""The scanner spells a destination's host as `schemas/vectors/destination-hosts.json` says.

The collector's `normalize_host` (src/observed.rs) runs the same file, so a host
declared in the configuration and the same host observed on the wire are one
destination.
"""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    """A private copy, not registered in `sys.modules`: discovery imports every
    test file before any runs, and the other files register their own copies."""
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / "scan" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


scanner = _load("scan_agent_environment")

VECTORS = json.loads((ROOT / "schemas" / "vectors" / "destination-hosts.json").read_text())


class DestinationHostTest(unittest.TestCase):
    def test_each_authority_is_spelled_as_the_vectors_say(self) -> None:
        self.assertTrue(VECTORS["cases"])
        for case in VECTORS["cases"]:
            with self.subTest(case["id"]):
                self.assertEqual(scanner.url_host(case["authority"]), case["host"])
                self.assertEqual(scanner.url_host(f"https://{case['authority']}/mcp"), case["host"])

    def test_case_ids_are_unique(self) -> None:
        ids = [case["id"] for case in VECTORS["cases"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_a_declared_host_with_a_trailing_dot_is_the_observed_one(self) -> None:
        summary = scanner.summarize_observed(
            {"network_targets": [{"host": "API.Example.com.", "path": "/v1", "count": 2}]},
            {scanner.url_host("https://api.example.com./mcp")},
        )
        self.assertEqual([d["host"] for d in summary["destinations"]], ["api.example.com"])
        self.assertEqual(summary["undeclared_destinations"], [])

    def test_a_canonical_host_with_a_trailing_dot_is_canonical(self) -> None:
        self.assertEqual(scanner.classify_base_url("https://api.anthropic.com./v1"), "canonical")
        self.assertEqual(scanner.classify_base_url("http://localhost.:11434"), "local")


if __name__ == "__main__":
    unittest.main()
