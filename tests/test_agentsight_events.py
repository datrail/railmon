#!/usr/bin/env python3
"""Unit tests for AgentSight event normalization and command building."""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "collector"))

from collector import SslCollector, normalize_ssl_event  # noqa: E402


class NormalizeSslEventTests(unittest.TestCase):
    def test_unwrap_agentsight_envelope(self):
        wrapped = {
            "comm": "curl",
            "source": "ssl",
            "pid": 1,
            "timestamp": 123,
            "data": {
                "function": "WRITE/SEND",
                "data": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "pid": 1,
                "tid": 1,
                "timestamp_ns": 99,
                "is_handshake": False,
            },
        }
        event = normalize_ssl_event(wrapped)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["function"], "WRITE/SEND")
        self.assertTrue(event["data"].startswith("GET /"))
        self.assertEqual(event["timestamp_ns"], 99)

    def test_passthrough_flat_sslsniff(self):
        flat = {
            "function": "READ/RECV",
            "data": "HTTP/1.1 200 OK\r\n\r\n",
            "pid": 2,
            "tid": 2,
            "timestamp_ns": 1,
            "is_handshake": False,
        }
        event = normalize_ssl_event(flat)
        self.assertEqual(event, flat)

    def test_hex_payload_decode(self):
        # "GET " in hex
        wrapped = {
            "source": "ssl",
            "data": {
                "function": "WRITE/SEND",
                "data": "HEX:47455420",
                "pid": 3,
            },
        }
        event = normalize_ssl_event(wrapped)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["data"], "GET ")

    def test_banner_lines_rejected(self):
        self.assertIsNone(normalize_ssl_event({"hello": "world"}))


class BuildCmdTests(unittest.TestCase):
    def test_agentsight_cmd(self):
        c = SslCollector(agentsight_path="/opt/agentsight", binary_path="/bin/node", pid=42)
        self.assertEqual(
            c._build_cmd(),
            ["/opt/agentsight", "debug", "ssl", "--binary-path", "/bin/node", "--", "-p", "42"],
        )

    def test_bare_sslsniff_cmd(self):
        c = SslCollector(agentsight_path="/opt/sslsniff", comm="curl")
        self.assertEqual(
            c._build_cmd(),
            ["/opt/sslsniff", "--comm", "curl"],
        )


if __name__ == "__main__":
    unittest.main()
