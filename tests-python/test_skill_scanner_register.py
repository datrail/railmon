from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "tools/skills/skill_scanner.py"


class SkillScannerDoesNotRegisterTest(unittest.TestCase):
    """DR-198: Rail Center takes one set of agent data, the scan's evidence
    bundle. The skills scanner refuses to send a second, partial copy."""

    def run_scanner(self, *args: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as root:
            return subprocess.run(
                [sys.executable, str(SCANNER), "--root", root, *args],
                capture_output=True, text=True, timeout=60,
            )

    def test_each_registration_flag_is_refused_before_anything_is_sent(self):
        for flags in (
            ("--register", "--center-url", "http://127.0.0.1:9"),
            ("--register",),
            ("--center-url", "http://127.0.0.1:9"),
            ("--output-register-response",),
        ):
            with self.subTest(flags=flags):
                result = self.run_scanner(*flags)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("railmon scan --register", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_the_local_payload_is_still_emitted(self):
        result = self.run_scanner("--payload", "--owner", "alice")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"skills"', result.stdout)
        self.assertIn('"owner": "alice"', result.stdout)
