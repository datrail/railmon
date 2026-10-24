"""DR-249: `railmon openshell`, over OpenShell 0.1.3's own output.

The fixtures in tests/fixtures/openshell-0.1.3 were recorded on a CI host by
datrail-project's *Record OpenShell fixtures* workflow. A stand-in `openshell`
script prints them, and a local HTTP server stands in for RailDash.
"""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "openshell-0.1.3"


def _load():
    """A private copy, never put in sys.modules (see test_egress_containment)."""
    spec = importlib.util.spec_from_file_location("openshell_collector", ROOT / "tools/openshell/collector.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector = _load()
LOG = (FIXTURES / "logs-sandbox.txt").read_text()
POLICY = (FIXTURES / "policy-full.json").read_text()

FAKE_OPENSHELL = """#!/usr/bin/env python3
import json, os, sys
with open(os.environ["FAKE_ARGS"], "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
if os.environ.get("FAKE_FAIL") == sys.argv[1]:
    print("Error:   x gateway unreachable", file=sys.stderr)
    sys.exit(1)
path = os.environ["FAKE_POLICY"] if sys.argv[1] == "policy" else os.environ["FAKE_LOG"]
sys.stdout.write(open(path).read())
"""


class FakeRailDash(BaseHTTPRequestHandler):
    posts: list[tuple[str, str | None, dict]] = []
    status = 201

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).posts.append((self.path, self.headers.get("X-RailDash-Token"), body))
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


class OpenShellCliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        tmp = Path(self.tmp.name)
        self.cli = tmp / "openshell"
        self.cli.write_text(FAKE_OPENSHELL)
        self.cli.chmod(self.cli.stat().st_mode | stat.S_IEXEC)
        self.args = tmp / "args"
        self.log = tmp / "log.txt"
        self.log.write_text(LOG)
        self.policy = tmp / "policy.json"
        self.policy.write_text(POLICY)
        env = {"FAKE_ARGS": str(self.args), "FAKE_LOG": str(self.log), "FAKE_POLICY": str(self.policy)}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def calls(self):
        return [json.loads(line) for line in self.args.read_text().splitlines()] if self.args.exists() else []

    def test_only_the_allowed_subcommands_ever_run(self):
        for refused in (["policy", "set", "my-agent", "--policy", "x"], ["policy", "update", "my-agent"],
                        ["policy", "delete", "--global"], ["sandbox", "delete", "my-agent"],
                        ["provider", "get", "x"], ["policy"], [], ["settings", "set"]):
            with self.assertRaises(collector.CollectorError, msg=refused):
                collector.run_openshell(str(self.cli), refused)
        self.assertEqual(self.calls(), [])
        collector.run_openshell(str(self.cli), ["policy", "get", "my-agent", "--full", "-o", "json"])
        collector.run_openshell(str(self.cli), ["logs", "my-agent"])
        self.assertEqual([call[:2] for call in self.calls()], [["policy", "get"], ["logs", "my-agent"]])

    def test_a_failed_call_says_what_the_cli_said(self):
        with mock.patch.dict(os.environ, {"FAKE_FAIL": "logs"}):
            with self.assertRaisesRegex(collector.CollectorError, "exited 1: Error:   x gateway unreachable"):
                collector.run_openshell(str(self.cli), ["logs", "my-agent"])


class ParseLogTest(unittest.TestCase):
    def test_the_denials_of_a_real_sandbox_log(self):
        """The fixture's sandbox made four requests (attempts.py): one
        allowed, a POST its read-only rule denies at L7, a host no rule
        names, and the metadata address. Three DENIED lines; the allowed
        ones, NET:REFUSE (a DNS answer, followed by its NET:OPEN) and the
        WARN lines aren't denials."""
        stamps, denials = collector.parse_log(LOG)
        self.assertEqual(len(stamps), 28)
        self.assertEqual([{k: v for k, v in d.items() if k not in ("at", "hash")} for d in denials], [
            {"kind": "http", "host": "api.github.com", "port": 443, "method": "POST", "path": "/markdown",
             "binary": None, "policy": "github_api",
             "reason": "L7_REQUEST deny POST api.github.com:443/markdown reason=POST /markdown not permitted by policy"},
            {"kind": "net", "host": "example.org", "port": 443, "method": None, "path": None,
             "binary": "/usr/local/bin/python3.13", "policy": None, "reason": "transparent_tcp_policy_denied"},
            {"kind": "net", "host": "169.254.169.254", "port": 80, "method": None, "path": None,
             "binary": "/usr/local/bin/python3.13", "policy": None, "reason": "transparent_tcp_policy_denied"},
        ])
        self.assertEqual([d["at"] for d in denials],
                         ["2026-10-24T19:09:47.502Z", "2026-10-24T19:09:47.507Z", "2026-10-24T19:09:47.509Z"])
        self.assertEqual(len({d["hash"] for d in denials}), 3)

    def test_lines_that_dont_parse_are_skipped(self):
        stamps, denials = collector.parse_log("not a log line\n[x] [sandbox]\n\n")
        self.assertEqual((stamps, denials), ([], []))


class StripPolicyTest(unittest.TestCase):
    def test_only_what_raildash_reads_is_posted(self):
        secret = "s3cr3t-must-not-leave"
        view = json.loads((FIXTURES / "provider-github.policy-full.json").read_text())
        view["policy"]["network_middlewares"] = {"hook": {"config": {"token": secret}}}
        endpoint = view["policy"]["network_policies"]["github_api"]["endpoints"][0]
        endpoint.update(credential_signing="aws-sigv4", signing_service=secret,
                        credential_binding={"provider": secret}, password=secret,
                        rules=[{"allow": {"method": "GET", "path": "/x", "query": {"token": secret}}}],
                        deny_rules=[{"method": "DELETE", "path": "/**", "query": {"k": secret}}])
        stripped = collector.strip_policy(view)
        self.assertNotIn(secret, json.dumps(stripped))
        self.assertEqual(stripped["active_version"], 1)
        self.assertEqual(stripped["sandbox"], "fx-provider-gh")
        kept = stripped["policy"]["network_policies"]["github_api"]["endpoints"][0]
        self.assertEqual(kept["rules"], [{"allow": {"method": "GET", "path": "/x"}}])
        self.assertEqual(kept["deny_rules"], [{}])
        self.assertIn("_provider_fx_github", stripped["policy"]["network_policies"])
        self.assertEqual(stripped["policy"]["network_policies"]["_provider_fx_github"]["binaries"][0],
                         {"path": "/usr/bin/gh"})

    def test_a_view_without_a_policy_is_an_error(self):
        with self.assertRaises(collector.CollectorError):
            collector.strip_policy({"active_version": 1})


class DenialCursorTest(unittest.TestCase):
    def setUp(self):
        stamps, _ = collector.parse_log(LOG)
        self.newest = max(stamps)
        self.now = self.newest + 10

    def test_the_first_poll_is_partial_and_a_repeat_posts_nothing(self):
        cursor = collector.DenialCursor()
        self.assertEqual(cursor.window(self.now), collector.FIRST_WINDOW_SECONDS)
        first = cursor.batch(LOG, self.now)
        self.assertEqual(len(first["denials"]), 3)
        self.assertEqual(first["partial"]["reasons"], ["first_poll"])
        self.assertIsNone(first["partial"]["from"])
        # The next window reaches back past the newest line by the overlap.
        self.assertEqual(cursor.window(self.now), 10 + collector.OVERLAP_SECONDS)
        again = cursor.batch(LOG, self.now + 60)
        self.assertEqual(again, {"denials": [], "partial": None})

    def test_a_log_that_no_longer_reaches_the_last_line_seen_is_a_gap(self):
        cursor = collector.DenialCursor()
        cursor.batch(LOG, self.now)
        later = [line for line in LOG.splitlines()[-2:]]
        shifted = "\n".join(line.replace("[1792", "[1793", 1) for line in later)
        batch = cursor.batch(shifted, self.now + 10**8)
        self.assertEqual(batch["partial"]["reasons"], ["gap"])
        self.assertIsNotNone(batch["partial"]["from"])
        # An empty answer after lines were seen is a gap too (a restarted sandbox).
        self.assertEqual(cursor.batch("", self.now + 2 * 10**8)["partial"]["reasons"], ["gap"])

    def test_a_full_buffer_and_a_failed_poll_are_partial(self):
        cursor = collector.DenialCursor()
        cursor.batch(LOG, self.now)
        lines = LOG.splitlines()
        # A full buffer that still reaches the last line seen lost nothing.
        reaching = "\n".join([lines[0]] * (collector.LOG_BUFFER_LINES - 1) + lines[-1:])
        self.assertIsNone(cursor.batch(reaching, self.now + 1)["partial"])
        # One that starts after it cut older lines.
        later = lines[-1].replace("[1792", "[1793", 1)
        cut = "\n".join([later] * collector.LOG_BUFFER_LINES)
        partial = cursor.batch(cut, self.now + 10**8)["partial"]
        self.assertEqual(partial["reasons"], ["gap", "full_buffer"])
        self.assertLess(partial["from"], partial["to"])
        failed = cursor.batch(None, self.now + 2 * 10**8)
        self.assertEqual(failed["denials"], [])
        self.assertEqual(failed["partial"]["reasons"], ["poll_failed"])

    def test_an_idle_sandbox_is_partial_once(self):
        cursor = collector.DenialCursor()
        first = cursor.batch("", 1000.0)
        self.assertEqual(first["partial"]["reasons"], ["first_poll"])
        # The next windows reach back to the first poll, and say nothing new.
        self.assertEqual(cursor.window(1060.0), 60 + collector.OVERLAP_SECONDS)
        self.assertEqual(cursor.batch("", 1060.0), {"denials": [], "partial": None})


class CollectorTest(OpenShellCliTest):
    def setUp(self):
        super().setUp()
        FakeRailDash.posts = []
        FakeRailDash.status = 201
        self.server = HTTPServer(("127.0.0.1", 0), FakeRailDash)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        token = Path(self.tmp.name) / "token"
        token.write_text("-tok-en\n")
        patcher = mock.patch.dict(os.environ, {"RAIL_RAILDASH_TOKEN_FILE": str(token)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.messages: list[str] = []

    def make(self):
        stamps, _ = collector.parse_log(LOG)
        return collector.Collector("fx-base", self.url, str(self.cli), log=self.messages.append,
                                   clock=lambda: max(stamps) + 5)

    def test_a_policy_revision_is_posted_once_and_denials_once(self):
        poller = self.make()
        poller.once()
        poller.once()
        paths = [path for path, _, _ in FakeRailDash.posts]
        self.assertEqual(paths, ["/v1/openshell/sandboxes/fx-base/policy", "/v1/openshell/sandboxes/fx-base/denials"])
        self.assertEqual({token for _, token, _ in FakeRailDash.posts}, {"-tok-en"})
        policy = FakeRailDash.posts[0][2]
        self.assertEqual(policy["active_version"], 1)
        self.assertEqual(sorted(policy["policy"]["network_policies"]),
                         ["example_wildcard", "github_api", "github_uploads", "raw_content"])
        denials = FakeRailDash.posts[1][2]
        self.assertEqual([d["host"] for d in denials["denials"]], ["api.github.com", "example.org", "169.254.169.254"])
        self.assertEqual(denials["partial"]["reasons"], ["first_poll"])
        self.assertEqual([call[0] for call in self.calls()], ["policy", "logs", "policy", "logs"])
        self.assertEqual(self.calls()[1][:6], ["logs", "fx-base", "--source", "sandbox", "-n", "2000"])
        # A new revision is posted again.
        view = json.loads(POLICY)
        view["active_version"], view["hash"] = 2, "ff" * 32
        self.policy.write_text(json.dumps(view))
        poller.once()
        self.assertEqual(FakeRailDash.posts[-1][0], "/v1/openshell/sandboxes/fx-base/policy")
        self.assertEqual(FakeRailDash.posts[-1][2]["active_version"], 2)

    def test_a_failed_logs_call_posts_a_partial_span(self):
        poller = self.make()
        with mock.patch.dict(os.environ, {"FAKE_FAIL": "logs"}):
            poller.once()
        self.assertEqual(FakeRailDash.posts[-1][2]["partial"]["reasons"], ["poll_failed"])
        self.assertTrue(any("logs: openshell logs fx-base exited 1" in m for m in self.messages))

    def test_what_raildash_refused_is_posted_with_the_next_batch(self):
        """RailDash down for a poll: the cursor moves past those lines, so
        the collector keeps them, and the first poll's span, and posts them
        when RailDash is back, an hour later included."""
        stamps, _ = collector.parse_log(LOG)
        clock = [max(stamps) + 5]
        poller = collector.Collector("fx-base", self.url, str(self.cli), log=self.messages.append,
                                     clock=lambda: clock[0])
        FakeRailDash.status = 503
        poller.poll_denials()
        self.assertEqual(len(poller.pending["denials"]), 3)
        FakeRailDash.status = 201
        clock[0] += 3600
        self.log.write_text("")  # the log has moved on
        before = len(FakeRailDash.posts)
        poller.poll_denials()
        sent = FakeRailDash.posts[before][2]
        self.assertEqual(len(sent["denials"]), 3)
        self.assertEqual(sent["partial"]["reasons"], ["first_poll", "gap"])
        self.assertEqual(poller.pending, {"denials": [], "partial": None})
        self.assertTrue(any("denials post: ok again" in m for m in self.messages))

    def test_a_post_raildash_refuses_is_dropped_with_its_span_marked(self):
        poller = self.make()
        FakeRailDash.status = 422
        poller.poll_denials()
        self.assertTrue(any("RailDash refused 3 denials, dropped" in m for m in self.messages))
        # Not queued again; only its span waits, as a gap.
        self.assertEqual(poller.pending["denials"], [])
        self.assertEqual(poller.pending["partial"]["reasons"], ["first_poll", "gap"])
        FakeRailDash.status = 201
        before = len(FakeRailDash.posts)
        poller.poll_denials()
        self.assertEqual(FakeRailDash.posts[-1][2]["denials"], [])
        self.assertEqual(FakeRailDash.posts[-1][2]["partial"]["reasons"], ["first_poll", "gap"])
        self.assertEqual(len(FakeRailDash.posts), before + 1)

    def test_posts_are_cut_by_count_and_by_size(self):
        small = {"at": "2026-10-24T00:00:00.000Z", "hash": "a" * 32, "kind": "net", "path": "é" * 2048}
        cut = collector.chunks([small] * 3000)
        self.assertTrue(all(len(collector.encode({"denials": c, "partial": None})) < 2 * 1024 * 1024 for c in cut))
        self.assertTrue(all(len(c) <= collector.MAX_DENIALS_PER_POST for c in cut))
        self.assertEqual(sum(len(c) for c in cut), 3000)
        self.assertEqual(collector.chunks([]), [[]])

    def test_an_out_of_range_port_is_no_port(self):
        line = "[1792867645.652] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED /bin/x(1) -> example.org:99999 [reason:r]"
        self.assertIsNone(collector.parse_log(line)[1][0]["port"])

    def test_an_unchanged_policy_is_posted_again_before_raildash_calls_it_stale(self):
        stamps, _ = collector.parse_log(LOG)
        clock = [max(stamps)]
        poller = collector.Collector("fx-base", self.url, str(self.cli), log=self.messages.append,
                                     clock=lambda: clock[0])
        poller.poll_policy()
        poller.poll_policy()
        clock[0] += collector.POLICY_REPOST_SECONDS
        poller.poll_policy()
        self.assertEqual([p for p, _, _ in FakeRailDash.posts].count("/v1/openshell/sandboxes/fx-base/policy"), 2)
        self.assertLess(collector.POLICY_REPOST_SECONDS, 2 * 3600)

    def test_main_names_what_is_missing(self):
        with mock.patch.dict(os.environ, {"AGENT_CONTAINER": "", "RAIL_RAILDASH_URL": ""}, clear=False):
            os.environ.pop("RAIL_OPENSHELL_SANDBOX", None)
            with mock.patch("sys.stderr"):
                self.assertEqual(collector.main(["--raildash-url", self.url]), 64)
                self.assertEqual(collector.main(["--sandbox", "fx-base"]), 64)
                self.assertEqual(collector.main(["--sandbox", "bad name", "--raildash-url", self.url]), 64)
                with mock.patch.dict(os.environ, {"RAIL_OPENSHELL_INTERVAL": "soon"}):
                    self.assertEqual(collector.main(["--sandbox", "fx-base", "--raildash-url", self.url]), 64)
        with mock.patch.dict(os.environ, {"AGENT_CONTAINER": "openshell:my-agent", "RAIL_OPENSHELL_SANDBOX": ""}):
            # Set but empty, as .env.example leaves it, is unset.
            self.assertEqual(collector.sandbox_from(None), "my-agent")
        with mock.patch.dict(os.environ, {"RAIL_RAILDASH_TOKEN": "x"}):
            with self.assertRaisesRegex(collector.CollectorError, "not both"):
                collector.raildash_token()

    def test_once_runs_with_main(self):
        with mock.patch.dict(os.environ, {"RAIL_RAILDASH_URL": self.url, "OPENSHELL_CLI": str(self.cli)}):
            self.assertEqual(collector.main(["--sandbox", "fx-base", "--once"]), 0)
        self.assertEqual(len(FakeRailDash.posts), 2)


if __name__ == "__main__":
    unittest.main()
