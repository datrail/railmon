"""An interval scanner waits for RailDash before its first delivery (DR-316).

After a host reboot RailDash and railmon-scan start together, and the first
delivery used to fail with "Connection refused" while RailDash was starting.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import socket
import sys
import threading
import unittest
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
SCANNER_DIR = ROOT / "tools" / "scan"


def _load(name: str):
    """A private copy, registered only while this file's tests run (see
    test_egress_containment.py for why)."""
    spec = importlib.util.spec_from_file_location(name, SCANNER_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


scanner = _load("scan_agent_environment")
_modules = mock.patch.dict(sys.modules, {"scan_agent_environment": scanner})


def setUpModule():
    _modules.start()


def tearDownModule():
    _modules.stop()


URL = "http://raildash:8000"


def refused():
    return URLError(ConnectionRefusedError(111, "Connection refused"))


def not_resolved():
    return URLError(socket.gaierror(-2, "Name or service not known"))


def method_not_allowed():
    return HTTPError(URL + "/v1/evidence-bundles", 405, "Method Not Allowed", Message(), io.BytesIO(b""))


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class WaitForRailDashTest(unittest.TestCase):
    def wait(self, outcomes, budget=120.0):
        clock = FakeClock()
        stderr = io.StringIO()
        with mock.patch.object(scanner, "urlopen", side_effect=outcomes) as opened, \
                contextlib.redirect_stderr(stderr):
            answered = scanner.wait_for_raildash(URL, budget, sleep=clock.sleep, clock=clock)
        return answered, stderr.getvalue(), clock, opened

    def test_a_raildash_that_answers_at_once_costs_one_request_and_no_log(self):
        answered, err, clock, opened = self.wait([method_not_allowed()])
        self.assertTrue(answered)
        self.assertEqual(err, "")
        self.assertEqual(clock.sleeps, [])
        request = opened.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, URL + "/v1/evidence-bundles")

    def test_a_starting_raildash_is_waited_for_without_an_error(self):
        answered, err, clock, _ = self.wait([not_resolved(), refused(), method_not_allowed()])
        self.assertTrue(answered)
        self.assertEqual(len(clock.sleeps), 2)
        self.assertIn("isn't up yet; waiting up to 120s", err)
        self.assertEqual(err.count("isn't up yet"), 1)
        self.assertIn("RailDash is up", err)
        self.assertNotIn("failed", err)
        self.assertNotIn("Connection refused", err)

    def test_a_raildash_that_never_answers_ends_the_wait_after_the_budget(self):
        answered, err, clock, opened = self.wait(lambda *a, **k: (_ for _ in ()).throw(refused()), budget=10.0)
        self.assertFalse(answered)
        self.assertGreaterEqual(clock.now, 10.0)
        self.assertLess(clock.now, 10.0 + scanner.RAILDASH_START_POLL_SECONDS + 0.01)
        self.assertIn("still isn't answering after 10s; scanning anyway", err)

    def test_a_url_urlopen_cannot_use_is_left_to_the_delivery_to_report(self):
        answered, err, clock, _ = self.wait([ValueError("bad port")])
        self.assertTrue(answered)
        self.assertEqual(clock.sleeps, [])

    def test_any_http_answer_from_a_real_server_counts(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(405)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}"
            with mock.patch.dict("os.environ", {"NO_PROXY": "*", "no_proxy": "*"}):
                self.assertTrue(scanner.wait_for_raildash(url, 5.0, sleep=lambda s: None))
        finally:
            server.shutdown()
            server.server_close()


class IntervalModeTest(unittest.TestCase):
    def run_main(self, argv):
        calls: list[str] = []

        def scan_once(args):
            calls.append("scan")
            raise KeyboardInterrupt

        with mock.patch.object(scanner, "wait_for_raildash", side_effect=lambda url: calls.append(f"wait {url}")), \
                mock.patch.object(scanner, "run_one_scan", side_effect=scan_once), \
                mock.patch.object(scanner, "configured_target_manifest", return_value=None), \
                mock.patch.dict("os.environ", {}, clear=False) as env:
            env.pop("RAIL_RAILDASH_URL", None)
            env.pop("RAIL_SCAN_INTERVAL_IN_SECONDS", None)
            scanner.main(argv)
        return calls

    def test_an_interval_scanner_waits_before_its_first_scan(self):
        calls = self.run_main(["--raildash-url", URL, "--interval", "60"])
        self.assertEqual(calls, [f"wait {URL}", "scan"])

    def test_without_raildash_there_is_nothing_to_wait_for(self):
        self.assertEqual(self.run_main(["--interval", "60"]), ["scan"])

    def test_a_single_scan_does_not_wait(self):
        calls: list[str] = []
        with mock.patch.object(scanner, "wait_for_raildash", side_effect=lambda url: calls.append("wait")), \
                mock.patch.object(scanner, "run_one_scan", return_value=0), \
                mock.patch.object(scanner, "configured_target_manifest", return_value=None), \
                mock.patch.dict("os.environ", {}, clear=False) as env:
            env.pop("RAIL_SCAN_INTERVAL_IN_SECONDS", None)
            self.assertEqual(scanner.main(["--raildash-url", URL]), 0)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
