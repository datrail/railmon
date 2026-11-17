"""`asp_redaction`: the URL redaction rule RailMon applies, for consumers that match on it.

Every expectation here is what RailMon's scanner wrote before the rule moved into this package, so
a consumer importing it redacts a URL exactly as a bundle carries it.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]


def _load(name: str):
    """A private copy of `<name>.py` beside this directory, never left in sys.modules, so the suite
    reads the file here rather than any installed one."""
    spec = importlib.util.spec_from_file_location(f"{name}_under_test", HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


redaction = _load("asp_redaction")
redact_url = redaction.redact_url
redact_path_segment = redaction.redact_path_segment


class MarkersTest(unittest.TestCase):
    def test_the_markers_are_the_strings_bundles_carry(self):
        self.assertEqual(redaction.REDACTED_SEGMENT, "[redacted]")
        self.assertEqual(redaction.REDACTED_QUERY, "?[redacted]")
        self.assertEqual(redaction.UNPARSEABLE, "[unparseable]")
        self.assertEqual(redaction.REDACTION_VERSION, 1)

    def test_a_key_shaped_segment_and_a_query_are_marked(self):
        self.assertEqual(
            redact_url("https://gw.example.com/mcp/sk-live-abc12345/sse?api_key=x"),
            "https://gw.example.com/mcp/[redacted]/sse?[redacted]",
        )

    def test_userinfo_and_fragment_are_dropped_and_the_port_kept(self):
        self.assertEqual(
            redact_url("https://user:pass@api.example.com:8443/v1/chat#access_token=abc"),
            "https://api.example.com:8443/v1/chat",
        )

    def test_a_url_without_a_scheme_or_host_is_unparseable(self):
        self.assertEqual(redact_url("api.example.com/v1"), "[unparseable]")
        self.assertEqual(redact_url("file:///etc/passwd"), "[unparseable]")

    def test_nothing_in_gives_nothing_out(self):
        self.assertIsNone(redact_url(None))
        self.assertIsNone(redact_url(""))


class ShapeTest(unittest.TestCase):
    def test_a_root_url_has_no_path(self):
        self.assertEqual(redact_url("https://api.example.com"), "https://api.example.com")
        self.assertEqual(redact_url("https://api.example.com/"), "https://api.example.com")
        self.assertEqual(redact_url("https://api.example.com/?q=1"), "https://api.example.com?[redacted]")

    def test_empty_segments_are_collapsed(self):
        self.assertEqual(redact_url("https://h.example.com//a///b/"), "https://h.example.com/a/b")

    def test_an_unbracketed_ipv6_literal_is_unparseable(self):
        self.assertEqual(redact_url("http://::1:8080/x"), "[unparseable]")

    def test_a_bracketed_ipv6_literal_stays_bracketed(self):
        self.assertEqual(redact_url("http://[::1]:8080/mcp"), "http://[::1]:8080/mcp")

    def test_the_host_is_lowercased_by_urlsplit(self):
        self.assertEqual(redact_url("https://API.Example.com/V1"), "https://api.example.com/V1")


class LengthBoundTest(unittest.TestCase):
    def test_twenty_characters_is_a_key_and_nineteen_is_not(self):
        self.assertEqual(redact_path_segment("a" * 19), "a" * 19)
        self.assertEqual(redact_path_segment("a" * 20), "[redacted]")
        self.assertTrue(redaction.looks_like_secret_segment("a" * 20))
        self.assertFalse(redaction.looks_like_secret_segment("a" * 19))


class VendorShapeTest(unittest.TestCase):
    def test_a_short_vendor_key_is_redacted(self):
        for key in ("sk-live-abc12", "ghp_abcdefghijkl", "glpat-abcdef", "xoxb-1234567890"):
            with self.subTest(key=key):
                self.assertTrue(redaction.is_secret_token(key))
                self.assertEqual(redact_path_segment(key), "[redacted]")

    def test_a_word_sharing_a_vendor_prefix_is_kept(self):
        for word in ("asian-markets", "aizawa", "akia", "sk-short", "risk-report"):
            with self.subTest(word=word):
                self.assertFalse(redaction.is_secret_token(word))
                self.assertEqual(redact_path_segment(word), word)

    def test_the_aws_key_id_needs_its_exact_shape(self):
        self.assertTrue(redaction.is_secret_token("AKIA" + "A" * 16))
        self.assertFalse(redaction.is_secret_token("AKIA" + "a" * 16))


class BracketTest(unittest.TestCase):
    def test_a_kept_segments_brackets_are_percent_encoded(self):
        self.assertEqual(redact_url("https://h.example.com/a[1]/b"), "https://h.example.com/a%5B1%5D/b")

    def test_a_literal_marker_in_the_input_stays_the_marker(self):
        self.assertEqual(redact_path_segment("[redacted]"), "[redacted]")
        self.assertEqual(redact_path_segment("%5Bredacted%5D"), "[redacted]")
        self.assertEqual(redact_path_segment("%5bredacted%5d"), "[redacted]")

    def test_the_length_bound_reads_the_decoded_segment(self):
        # 18 raw characters; encoded they are 22, which must not cross the bound on a second pass.
        segment = "[abcdefghijklmnop]"
        once = redact_path_segment(segment)
        self.assertEqual(once, "%5Babcdefghijklmnop%5D")
        self.assertEqual(redact_path_segment(once), once)


class IdempotenceTest(unittest.TestCase):
    URLS = (
        "https://gw.example.com/mcp/sk-live-abc12345/sse?api_key=x",
        "https://user:pass@api.example.com:8443/v1/chat#t=1",
        "http://[::1]:8080/a[b]/c",
        "https://h.example.com/[redacted]/x?[redacted]",
        "https://h.example.com/" + "z" * 25,
        "https://h.example.com/[abcdefghijklmnop]",
        "https://api.example.com",
        "http://::1:8080/x",
    )

    def test_redacting_twice_is_redacting_once(self):
        for url in self.URLS:
            with self.subTest(url=url):
                once = redact_url(url)
                if once == "[unparseable]":
                    continue
                self.assertEqual(redact_url(once), once)


if __name__ == "__main__":
    unittest.main()
