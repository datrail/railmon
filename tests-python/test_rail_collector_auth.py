"""RM-F2…F5: `railmon forward` presents the credential RAIL_AUTH_MODE names.

Runs the real command through the entrypoint against a local stand-in for
Rail Center's POST /v1/interactions (and for the GCP metadata server), so the
header that actually leaves the process is what gets asserted.
"""

import base64
import importlib.util
import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("rail_collector", ROOT / "rail-collector" / "rail_collector.py")
rail_collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rail_collector)

AUTH_VARS = ("RAIL_AUTH_MODE", "RAIL_AUTH_TOKEN", "RAIL_AUTH_TOKEN_FILE", "RAIL_AUTH_AUDIENCE", "GCE_METADATA_HOST")

EVENT = {
    "interaction_id": "i-1",
    "timestamp": "2026-10-02T00:00:00Z",
    "request": {"method": "POST", "path": "/v1/messages", "destination": "api.example"},
    "response": {"status": 200},
}


def jwt(exp: int) -> str:
    enc = lambda v: base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")  # noqa: E731
    return ".".join([enc('{"alg":"RS256"}'), enc(json.dumps({"exp": exp})), "sig"])


class Recorder(BaseHTTPRequestHandler):
    """Rail Center's interactions route plus the metadata identity endpoint."""

    def log_message(self, *args):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.seen.append(("POST", self.path, self.headers.get("Authorization")))
        if self.server.redirect:
            self.send_response(302)
            self.send_header("Location", self.server.redirect)
        else:
            self.send_response(202)
        self.end_headers()

    def do_GET(self):
        self.server.seen.append(("GET", self.path, self.headers.get("Metadata-Flavor"), self.headers.get("Authorization")))
        body = self.server.identity.encode()
        self.send_response(self.server.identity_status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ForwardAuthTest(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
        self.server.seen = []
        self.server.identity = jwt(int(time.time()) + 3600)
        self.server.identity_status = 200
        self.server.redirect = None
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.host = f"127.0.0.1:{self.server.server_address[1]}"
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def forward(self, **auth):
        env = {k: v for k, v in os.environ.items() if k not in AUTH_VARS}
        env.update(auth, RAILMON_ROOT=str(ROOT), RAIL_CENTER_URL=f"http://{self.host}")
        return subprocess.run(
            [str(ROOT / "entrypoint.sh"), "forward", "--spool-dir", self.tmp.name],
            input=json.dumps(EVENT) + "\n",
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def posts(self):
        return [entry[2] for entry in self.server.seen if entry[0] == "POST"]

    def test_a_redirect_is_not_followed_with_the_credential(self):
        self.server.redirect = f"http://{self.host}/elsewhere"
        result = self.forward(RAIL_AUTH_MODE="bearer", RAIL_AUTH_TOKEN="t-1")
        self.assertEqual(result.returncode, 1, result.stderr)
        # Retried by the final drain, but only ever at Rail Center's own URL.
        self.assertTrue(self.posts())
        self.assertEqual({e[1] for e in self.server.seen if e[0] == "POST"}, {"/v1/interactions"})
        self.assertEqual([e for e in self.server.seen if e[0] == "GET"], [])
        self.assertEqual(len(list((Path(self.tmp.name) / "pending").glob("*.json"))), 1)

    def test_none_is_anonymous_by_decision(self):
        result = self.forward()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.posts(), [None])

    def test_a_token_beside_none_stops_before_forwarding(self):
        result = self.forward(RAIL_AUTH_TOKEN="s3cret")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unset, which is none", result.stderr)
        self.assertNotIn("s3cret", result.stderr)
        self.assertEqual(self.posts(), [])

    def test_bearer_from_the_environment(self):
        result = self.forward(RAIL_AUTH_MODE="bearer", RAIL_AUTH_TOKEN="t-1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.posts(), ["Bearer t-1"])

    def test_bearer_from_a_file_and_an_unreadable_file_fails(self):
        token = Path(self.tmp.name) / "token"
        token.write_text("from-file\n")
        result = self.forward(RAIL_AUTH_MODE="bearer", RAIL_AUTH_TOKEN_FILE=str(token))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.posts(), ["Bearer from-file"])

        result = self.forward(RAIL_AUTH_MODE="bearer", RAIL_AUTH_TOKEN_FILE=str(token) + ".missing")
        self.assertEqual(result.returncode, 2)
        self.assertIn("RAIL_AUTH_TOKEN_FILE", result.stderr)
        self.assertEqual(len(self.posts()), 1)

    def test_gcp_mints_for_the_audience(self):
        result = self.forward(
            RAIL_AUTH_MODE="gcp", RAIL_AUTH_AUDIENCE="https://rc.example/api", GCE_METADATA_HOST=self.host
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.posts(), [f"Bearer {self.server.identity}"])
        gets = [entry[1:3] for entry in self.server.seen if entry[0] == "GET"]
        # Minted once at startup, reused for the forward while fresh.
        self.assertEqual(
            gets,
            [
                (
                    "/computeMetadata/v1/instance/service-accounts/default/identity"
                    "?audience=https%3A%2F%2Frc.example%2Fapi",
                    "Google",
                )
            ],
        )

    def test_gcp_without_an_identity_fails_rather_than_going_anonymous(self):
        self.server.identity_status = 404
        result = self.forward(RAIL_AUTH_MODE="gcp", RAIL_AUTH_AUDIENCE="aud", GCE_METADATA_HOST=self.host)
        self.assertEqual(result.returncode, 2)
        self.assertIn("returned 404", result.stderr)
        self.assertEqual(self.posts(), [])


class CredentialTest(unittest.TestCase):
    def test_rotated_file_takes_effect_and_a_lost_credential_keeps_events_spooled(self):
        with tempfile.TemporaryDirectory() as tmp:
            token = Path(tmp) / "token"
            token.write_text("first\n")
            credential = rail_collector.Credential(
                {"RAIL_AUTH_MODE": "bearer", "RAIL_AUTH_TOKEN_FILE": str(token)}
            )
            self.assertEqual(credential.headers(), {"Authorization": "Bearer first"})
            token.write_text("second\n")
            self.assertEqual(credential.headers(), {"Authorization": "Bearer second"})

            token.write_text("")
            pending = Path(tmp) / "pending"
            rail_collector.spool_event(EVENT, pending)
            sent, failed = rail_collector.drain_pending(
                pending, Path(tmp) / "sent", "http://127.0.0.1:9", 1.0, False, credential
            )
            self.assertEqual((sent, failed), (0, 1))
            self.assertEqual(len(list(pending.glob("*.json"))), 1)

    def test_refusals(self):
        cases = [
            ({"RAIL_AUTH_MODE": "basic"}, "none, bearer, gcp"),
            ({"RAIL_AUTH_MODE": "bearer"}, "requires RAIL_AUTH_TOKEN"),
            ({"RAIL_AUTH_MODE": "bearer", "RAIL_AUTH_TOKEN": "a", "RAIL_AUTH_TOKEN_FILE": "/t"}, "both are set"),
            ({"RAIL_AUTH_MODE": "bearer", "RAIL_AUTH_TOKEN": "ab\ncd"}, "U+000A at offset 2"),
            ({"RAIL_AUTH_MODE": "gcp"}, "RAIL_AUTH_AUDIENCE"),
            ({"RAIL_AUTH_MODE": "gcp", "RAIL_AUTH_AUDIENCE": "a", "RAIL_AUTH_TOKEN": "t"}, "mints its own"),
        ]
        for env, expected in cases:
            with self.subTest(env=env):
                with self.assertRaises(rail_collector.RailCollectorError) as caught:
                    rail_collector.Credential(env)
                self.assertIn(expected, str(caught.exception))
                self.assertNotIn("ab\ncd", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
