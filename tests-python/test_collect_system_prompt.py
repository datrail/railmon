"""RC-518: --collect-system-prompt (RAIL_COLLECT_SYSTEM_PROMPT) reaches the
harness reader in pod mode, so the chart's sidecar.collectSystemPrompt puts
the system prompt's text in the bundle, and nothing else does."""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    # A private name, never registered: test_evidence_bundle registers the
    # scanner under its canonical name and must be the one that does.
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scanner = _load("scan_agent_environment_prompt_test", ROOT / "tools" / "scan" / "scan_agent_environment.py")
sources = _load("gke_harness_sources_prompt_test", ROOT / "tools" / "scan" / "gke" / "sidecar" / "harness" / "harness_sources.py")


class FlagTest(unittest.TestCase):
    def test_off_by_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            args = scanner.make_parser().parse_args(["--mode", "pod"])
            self.assertFalse(scanner.collect_system_prompt(args))

    def test_flag(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            args = scanner.make_parser().parse_args(["--mode", "pod", "--collect-system-prompt"])
            self.assertTrue(scanner.collect_system_prompt(args))

    def test_environment(self) -> None:
        args = argparse.Namespace(collect_system_prompt=False)
        for value, expected in (("1", True), ("true", True), ("YES", True), ("0", False), ("no", False), ("", False)):
            with mock.patch.dict(os.environ, {"RAIL_COLLECT_SYSTEM_PROMPT": value}, clear=True):
                self.assertEqual(scanner.collect_system_prompt(args), expected, value)


class ReaderTest(unittest.TestCase):
    def read(self, context: dict) -> bool:
        reader = mock.Mock()
        reader.harness_reader_for.return_value = None
        reader.GENERIC_HARNESS = "generic"
        reader.read_harness_fields.return_value = {}
        with mock.patch.object(sources, "reader", return_value=reader), \
                mock.patch.object(sources, "agent_view", return_value={}):
            sources.read_agent_harness({"subject": {"root": "/proc/1/root"}, **context}, [Path("/cfg")], known_profiles=[])
        return reader.read_harness_fields.call_args.kwargs["collect_prompt"]

    def test_context_reaches_the_reader(self) -> None:
        self.assertFalse(self.read({}))
        self.assertTrue(self.read({"collect_system_prompt": True}))


if __name__ == "__main__":
    unittest.main()
