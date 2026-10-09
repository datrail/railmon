"""DR-188: `--register` sends rail-center the evidence bundle, not the payload.

Rail Center takes RailMon's evidence bundle on `POST /v1/agents/register`
(RC-387, Daniel 2026-10-09), with the same RAIL_AUTH_MODE credential. These
tests pin RailMon's side of that: the bytes sent are exactly the bytes written
locally and sent to RailDash, every target is attempted on its own, a v2
collection registers once with per-agent state, and no ticket is kept.

The wire-level tests run the real scanner as a subprocess against a loopback
fake of rail-center (and of RailDash), so what is asserted is what left the
process. The collection tests drive `run_one_collection` in process, mocking
only `scan()`, `resolve_targets` and the HTTP call, as test_agent_identity.py's
collection tests do.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCANNER_DIR = ROOT / "tools" / "scan"
SCANNER = SCANNER_DIR / "scan_agent_environment.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


scanner = _load("scan_agent_environment", SCANNER)
evidence_bundle = _load("evidence_bundle", SCANNER_DIR / "evidence_bundle.py")
composer = _load("compose_evidence_bundle_v2", SCANNER_DIR / "compose_evidence_bundle_v2.py")

# The scanner's lazy imports must resolve to the objects above, for this
# file's run only (see test_agent_identity.py's note on the same pattern).
_PATCHED_MODULES = {
    "scan_agent_environment": scanner,
    "evidence_bundle": evidence_bundle,
    "compose_evidence_bundle_v2": composer,
}
_saved_modules: dict[str, Any] = {}


def setUpModule() -> None:
    for name, module in _PATCHED_MODULES.items():
        _saved_modules[name] = sys.modules.get(name)
        sys.modules[name] = module


def tearDownModule() -> None:
    for name, original in _saved_modules.items():
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original


TOKEN = "x-rail-placeholder-token-do-not-keep"


def v1_answer(agent_id: str = "a-1", duplicate: bool = False) -> dict[str, Any]:
    """RC-387's answer to a v1 bundle: the registration plus the stored bundle."""
    return {
        "agent": {
            "id": agent_id,
            "sandbox_id": "s-1",
            "host_id": "h-1",
            "sandbox_name": "sb",
            "agent_key": "default",
            "environment_fingerprint": "fp-1",
            "provisioning_token": "x-rail-nested",
        },
        "token": TOKEN,
        "expires_at": "2026-10-10T00:00:00Z",
        "evidence_bundle_id": "eb-1",
        "duplicate": duplicate,
    }


def v2_answer(keys: list[str], duplicate: bool = False) -> dict[str, Any]:
    return {
        "agents": [
            {
                "agent": {"id": f"a-{key}", "sandbox_id": "s-1", "host_id": "host-01",
                          "sandbox_name": "shared", "agent_key": key},
                "token": TOKEN,
                "expires_at": "2026-10-10T00:00:00Z",
            }
            for key in keys
        ],
        "evidence_bundle_id": "eb-2",
        "duplicate": duplicate,
    }


class FakeServer:
    """A loopback HTTP server answering each POST from a queue, recording
    path, headers and the exact body bytes."""

    def __init__(self, responses: list[tuple[int, dict[str, Any]]]):
        server = self
        self.responses = list(responses)
        self.requests: list[dict[str, Any]] = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                server.requests.append({
                    "path": self.path,
                    "body": body,
                    "content_type": self.headers.get("Content-Type"),
                    "authorization": self.headers.get("Authorization"),
                })
                status, answer = server.responses.pop(0) if server.responses else (500, {"error": "exhausted"})
                data = json.dumps(answer).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)


def clean_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("RAIL_", "GCE_"))}
    env.update(extra)
    return env


class WireTest(unittest.TestCase):
    """The real scanner, as a subprocess, against loopback fakes."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def server(self, responses):
        server = FakeServer(responses)
        self.addCleanup(server.close)
        return server

    def run_scan(self, extra: list[str], **env: str):
        return subprocess.run(
            [sys.executable, str(SCANNER), "--mode", "self", "--host-id", "h-1",
             "--feature-output", f"{self.tmp}/features.json",
             "--evidence-bundle-output", f"{self.tmp}/bundle.json",
             "--registration-output", f"{self.tmp}/registration.json"] + extra,
            cwd=self.tmp, capture_output=True, text=True, env=clean_env(**env), timeout=120,
        )

    def read(self, name: str) -> dict[str, Any]:
        return json.loads(Path(self.tmp, name).read_text())

    def test_rail_center_gets_the_bundle_bytes_written_locally(self):
        center = self.server([(201, v1_answer())])
        proc = self.run_scan(["--register", "--center-url", center.url, "--output", f"{self.tmp}/payload.json"])
        self.assertEqual(proc.returncode, 0, proc.stderr)

        [request] = center.requests
        self.assertEqual(request["path"], "/v1/agents/register")
        self.assertEqual(request["content_type"], "application/json")
        on_disk = Path(self.tmp, "bundle.json").read_bytes()
        self.assertEqual(request["body"], on_disk)
        sent = json.loads(request["body"])
        self.assertEqual(sent["bundle_version"], 1)
        self.assertEqual(sent["attributes"]["agent_type"]["value"], "personal")
        # The payload is still the local artifact, and no longer what is sent.
        payload = self.read("payload.json")
        self.assertIn("environment", payload)
        self.assertNotIn("bundle_version", payload)

        state = self.read("registration.json")
        self.assertEqual(state["agent_id"], "a-1")
        self.assertEqual(state["evidence_bundle_id"], "eb-1")
        self.assertIs(state["duplicate"], False)
        written = Path(self.tmp, "registration.json").read_text()
        self.assertNotIn(TOKEN, written)
        self.assertNotIn("x-rail-nested", written)
        self.assertNotIn(TOKEN, proc.stdout + proc.stderr)
        self.assertIn(
            f"registered with rail-center: HTTP 201 agent_id=a-1 bundle=accepted "
            f"state_file={self.tmp}/registration.json",
            proc.stderr,
        )
        self.assertEqual(self.read("features.json")["scan"]["registration_status"], "registered")

    def test_the_bundle_is_sent_with_no_local_bundle_file(self):
        """--no-evidence-bundle skips the file, not the registration."""
        center = self.server([(200, v1_answer())])
        proc = self.run_scan(["--register", "--center-url", center.url, "--no-evidence-bundle"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(center.requests[0]["body"])["bundle_version"], 1)
        self.assertFalse(Path(self.tmp, "bundle.json").exists())

    def test_the_rail_auth_mode_credential_is_presented(self):
        center = self.server([(201, v1_answer())])
        proc = self.run_scan(["--register", "--center-url", center.url],
                             RAIL_AUTH_MODE="bearer", RAIL_AUTH_TOKEN="t-123")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(center.requests[0]["authorization"], "Bearer t-123")

    def test_a_rail_center_refusal_does_not_block_raildash_the_feature_file_or_the_bundle(self):
        center = self.server([(422, {"detail": [{"loc": ["body", "attributes", "agent_type"]}]})])
        raildash = self.server([(202, {"asp_id": "asp-1", "duplicate": False})])
        proc = self.run_scan(["--register", "--center-url", center.url, "--raildash-url", raildash.url])

        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("rail-center registration failed: HTTP 422", proc.stderr)
        on_disk = Path(self.tmp, "bundle.json").read_bytes()
        self.assertEqual(center.requests[0]["body"], on_disk)
        self.assertEqual(raildash.requests[0]["body"], on_disk)
        self.assertIn("delivered evidence bundle to raildash: HTTP 202 accepted", proc.stderr)
        self.assertEqual(self.read("features.json")["scan"]["registration_status"], "registration_failed")
        self.assertFalse(Path(self.tmp, "registration.json").exists())

    def test_a_raildash_failure_does_not_block_registration(self):
        center = self.server([(201, v1_answer())])
        raildash = self.server([(500, {"error": "down"})])
        proc = self.run_scan(["--register", "--center-url", center.url, "--raildash-url", raildash.url])

        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("raildash evidence-bundle delivery failed: HTTP 500", proc.stderr)
        self.assertEqual(center.requests[0]["body"], raildash.requests[0]["body"])
        self.assertEqual(self.read("registration.json")["agent_id"], "a-1")
        self.assertEqual(self.read("features.json")["scan"]["registration_status"], "registered")
        self.assertTrue(Path(self.tmp, "bundle.json").exists())

    def test_output_register_response_prints_the_stored_state(self):
        center = self.server([(201, v1_answer())])
        proc = self.run_scan(["--register", "--center-url", center.url, "--output-register-response"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        printed = json.loads(proc.stdout)
        self.assertEqual(printed, self.read("registration.json"))
        self.assertNotIn(TOKEN, proc.stdout)

    def test_a_keyed_v1_scan_sends_its_key_as_a_query_parameter(self):
        """A v1 bundle names no agent key, so a keyed scan names it on the URL,
        and rail-center files the registration under it (RC-387)."""
        center = self.server([(201, v1_answer())])
        proc = self.run_scan(["--register", "--center-url", f"{center.url}/?tenant=acme", "--agent-key", "planner"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        [request] = center.requests
        self.assertEqual(request["path"], "/v1/agents/register?tenant=acme&agent_key=planner")
        self.assertEqual(request["body"], Path(self.tmp, "bundle.json").read_bytes())
        self.assertNotIn("agent_key", json.loads(request["body"]))
        state = self.read("registration.json")
        self.assertEqual(state["registration_url"], f"{center.url}/v1/agents/register?tenant=acme&agent_key=planner")
        self.assertEqual(self.read("features.json")["scan"]["registration_status"], "registered")

    def test_a_key_outside_the_key_rule_is_refused_not_lowercased(self):
        """Rail Center holds ?agent_key= to the manifest key rule. Lowercasing
        here would file it under a key RailDash does not use, so it is refused,
        nothing sent, and the rest of the scan still runs."""
        center = self.server([(201, v1_answer())])
        proc = self.run_scan(["--register", "--center-url", center.url, "--agent-key", "Planner"])
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(center.requests, [])
        self.assertIn("--agent-key/RAIL_AGENT_KEY must match", proc.stderr)
        self.assertTrue(Path(self.tmp, "bundle.json").exists())
        self.assertEqual(self.read("features.json")["scan"]["registration_status"], "registration_failed")

    def test_an_unkeyed_v1_scan_sends_no_agent_key(self):
        center = self.server([(201, v1_answer())])
        proc = self.run_scan(["--register", "--center-url", center.url])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(center.requests[0]["path"], "/v1/agents/register")


class InProcessTest(unittest.TestCase):
    """`run_one_scan`/`run_one_collection` in process, the HTTP call mocked."""

    def setUp(self):
        self.saved_env = {k: v for k, v in os.environ.items() if k.startswith(("RAIL_", "GCE_"))}
        for key in self.saved_env:
            os.environ.pop(key)
        self.addCleanup(os.environ.update, self.saved_env)
        evidence_bundle._previous_bundles.clear()
        self.addCleanup(evidence_bundle._previous_bundles.clear)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        stderr = io.StringIO()
        self.stderr = stderr
        redirect = contextlib.redirect_stderr(stderr)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        cwd = contextlib.chdir(self.tmp)
        cwd.__enter__()
        self.addCleanup(cwd.__exit__, None, None, None)

    def args(self, *extra: str) -> argparse.Namespace:
        return scanner.make_parser().parse_args(
            ["--mode", "self", "--host-id", "host-01", "--sandbox-name", "shared",
             "--register", "--center-url", "https://rail-center.internal",
             "--feature-output", f"{self.tmp}/features.json",
             "--evidence-bundle-output", f"{self.tmp}/bundle.json",
             "--registration-output", f"{self.tmp}/registration.json",
             "--compact", *extra]
        )

    def feature(self, suffix: str = "") -> dict[str, Any]:
        return json.loads(Path(self.tmp, "features.json" + suffix).read_text())

    # ── v1 ────────────────────────────────────────────────────────────────

    def test_an_unchanged_interval_scan_resends_the_same_bytes(self):
        """DR-157's reuse is what rail-center sees too: the second pass sends
        the first pass's bytes, and rail-center's `duplicate` is logged."""
        answers = iter([{"status": 201, "body": v1_answer()}, {"status": 200, "body": v1_answer(duplicate=True)}])
        args = self.args()
        with mock.patch.object(scanner, "post_registration", side_effect=lambda *a, **k: next(answers)) as post:
            self.assertEqual(scanner.run_one_scan(args), 0)
            first_file = Path(self.tmp, "bundle.json").read_bytes()
            self.assertEqual(scanner.run_one_scan(args), 0)
        sent = [call.args[1] for call in post.call_args_list]
        self.assertEqual(sent[0], first_file)
        self.assertEqual(sent[1], sent[0])
        self.assertEqual(Path(self.tmp, "bundle.json").read_bytes(), sent[0])
        log = self.stderr.getvalue()
        self.assertIn("bundle=accepted", log)
        self.assertIn("bundle=duplicate", log)
        self.assertIs(json.loads(Path(self.tmp, "registration.json").read_text())["duplicate"], True)

    def test_a_bundle_that_fails_to_build_fails_registration_without_sending(self):
        with mock.patch.object(evidence_bundle, "try_build_verified_bundle", return_value=None), \
                mock.patch.object(scanner, "post_registration") as post:
            code = scanner.run_one_scan(self.args())
        self.assertEqual(code, 2)
        post.assert_not_called()
        self.assertIn("no verified evidence bundle to send", self.stderr.getvalue())
        self.assertEqual(self.feature()["scan"]["registration_status"], "registration_failed")

    def test_the_bundle_does_not_depend_on_the_registration_status(self):
        """Built before the attempt, so it must not read what the attempt sets."""
        args = self.args()
        context, payload, identity = scanner.scan(args)
        fingerprints = set()
        for status in ("registration_failed", "registered", "unregistered"):
            identity["registration_status"] = status
            bundle = evidence_bundle.build_verified_bundle(args, context, payload, identity)
            fingerprints.add(evidence_bundle.content_fingerprint(bundle))
        self.assertEqual(len(fingerprints), 1)

    # ── v2 ────────────────────────────────────────────────────────────────

    def fake_scan(self, args):
        context = scanner.collect_self_context()
        payload = {"type": "personal", "host_id": "host-01", "sandbox_name": "shared"}
        return context, payload, scanner.collect_identity(args, context)

    def collect(self, args, targets, post):
        with mock.patch.object(scanner, "scan", side_effect=self.fake_scan), \
                mock.patch.object(scanner, "resolve_targets", **targets), \
                mock.patch.object(scanner, "post_registration", **post) as posted:
            code = scanner.run_one_collection(args)
        return code, posted

    TARGETS = [
        {"agent_key": "planner", "status": "available", "config_roots": ["/nonexistent/planner"]},
        {"agent_key": "executor", "status": "available", "config_roots": ["/nonexistent/executor"]},
    ]

    def test_a_v2_collection_registers_once_with_state_per_agent(self):
        # The answer lists agents in a different order from the bundle's:
        # state is matched by agent_key, not by position.
        answer = {"status": 201, "body": v2_answer(["planner", "executor"])}
        args = self.args("--target-manifest", "/manifest.yaml")
        code, post = self.collect(args, {"return_value": self.TARGETS}, {"return_value": answer})

        self.assertEqual(code, 0, self.stderr.getvalue())
        post.assert_called_once()
        sent = post.call_args.args[1]
        self.assertEqual(sent, Path(self.tmp, "bundle.json").read_bytes())
        collection = json.loads(sent)
        self.assertEqual(collection["bundle_version"], 2)
        self.assertEqual([a["agent_key"] for a in collection["agents"]], ["executor", "planner"])
        for key in ("planner", "executor"):
            state_path = Path(self.tmp, f"registration.json.{key}")
            state = json.loads(state_path.read_text())
            self.assertEqual(state["agent_id"], f"a-{key}")
            self.assertEqual(state["evidence_bundle_id"], "eb-2")
            self.assertEqual(state["response"]["agent"]["agent_key"], key)
            self.assertNotIn(TOKEN, state_path.read_text())
            self.assertEqual(self.feature(f".{key}")["scan"]["registration_status"], "registered")
            self.assertIn(
                f"bundle=accepted state_file={self.tmp}/registration.json.{key}", self.stderr.getvalue()
            )
        # The sandbox-wide scan has no registration of its own; its feature
        # file says the collection carrying it was registered.
        self.assertFalse(Path(self.tmp, "registration.json").exists())
        self.assertEqual(self.feature()["scan"]["registration_status"], "registered")

    def test_an_agent_the_answer_does_not_name_fails_on_its_own(self):
        answer = {"status": 201, "body": v2_answer(["planner"])}
        args = self.args("--target-manifest", "/manifest.yaml")
        code, _ = self.collect(args, {"return_value": self.TARGETS}, {"return_value": answer})
        self.assertEqual(code, 2)
        self.assertIn("named no registration for agent 'executor'", self.stderr.getvalue())
        self.assertEqual(self.feature(".planner")["scan"]["registration_status"], "registered")
        self.assertEqual(self.feature(".executor")["scan"]["registration_status"], "registration_failed")
        self.assertFalse(Path(self.tmp, "registration.json.executor").exists())

    def test_a_skipped_placeholder_does_not_fail_its_siblings(self):
        """An agent discovery did not find is a placeholder in the collection;
        rail-center skips it, the scan reports it, and that is not a failure —
        as a not_found target never fails the collection."""
        targets = self.TARGETS[:1] + [{"agent_key": "critic", "status": "not_found", "reason": "no pid"}]
        body = v2_answer(["planner"])
        body["skipped"] = [{"agent_key": "critic", "reason": "agent_type is not ANSWERED"}]
        args = self.args("--target-manifest", "/manifest.yaml")
        code, post = self.collect(args, {"return_value": targets}, {"return_value": {"status": 201, "body": body}})

        self.assertEqual(code, 0, self.stderr.getvalue())
        post.assert_called_once()
        self.assertEqual(post.call_args.kwargs.get("agent_key"), None)
        sent = json.loads(post.call_args.args[1])
        self.assertEqual([a["agent_key"] for a in sent["agents"]], ["critic", "planner"])
        self.assertIn("rail-center skipped agent 'critic': agent_type is not ANSWERED", self.stderr.getvalue())
        self.assertTrue(Path(self.tmp, "registration.json.planner").exists())
        self.assertFalse(Path(self.tmp, "registration.json.critic").exists())
        self.assertFalse(Path(self.tmp, "features.json.critic").exists())
        self.assertEqual(self.feature(".planner")["scan"]["registration_status"], "registered")

    def test_a_collection_of_only_placeholders_is_not_sent_and_not_a_failure(self):
        """Rail Center refuses a collection with nothing to register; with every
        declared agent not found there is nothing to register, as before."""
        targets = [{"agent_key": "critic", "status": "not_found", "reason": "no pid"}]
        args = self.args("--target-manifest", "/manifest.yaml")
        code, post = self.collect(args, {"return_value": targets}, {"return_value": None})
        self.assertEqual(code, 0, self.stderr.getvalue())
        post.assert_not_called()
        self.assertIn("not registering with rail-center: no agent in the collection", self.stderr.getvalue())
        self.assertEqual(self.feature()["scan"]["registration_status"], "unregistered")
        self.assertEqual(json.loads(Path(self.tmp, "bundle.json").read_text())["agents"][0]["agent_key"], "critic")

    def test_a_skipped_scanned_agent_is_a_registration_failure(self):
        """An agent this collection did scan should have registered; rail-center
        skipping it fails it (and the run), without failing its sibling."""
        body = v2_answer(["planner"])
        body["skipped"] = [{"agent_key": "executor", "reason": "agent_type is not ANSWERED"}]
        args = self.args("--target-manifest", "/manifest.yaml")
        code, _ = self.collect(args, {"return_value": self.TARGETS}, {"return_value": {"status": 201, "body": body}})
        self.assertEqual(code, 2)
        self.assertIn(
            "rail-center registration failed for agent 'executor': skipped: agent_type is not ANSWERED",
            self.stderr.getvalue(),
        )
        self.assertEqual(self.feature(".planner")["scan"]["registration_status"], "registered")
        self.assertEqual(self.feature(".executor")["scan"]["registration_status"], "registration_failed")
        self.assertFalse(Path(self.tmp, "registration.json.executor").exists())

    def test_a_v2_registration_failure_still_writes_and_delivers_everything_else(self):
        failure = scanner.ScannerError("rail-center registration failed: HTTP 503: down")
        args = self.args("--target-manifest", "/manifest.yaml")
        code, post = self.collect(args, {"return_value": self.TARGETS}, {"side_effect": failure})
        self.assertEqual(code, 2)
        post.assert_called_once()
        self.assertEqual(json.loads(Path(self.tmp, "bundle.json").read_text())["bundle_version"], 2)
        for suffix in ("", ".planner", ".executor"):
            self.assertEqual(self.feature(suffix)["scan"]["registration_status"], "registration_failed")
        self.assertFalse(list(Path(self.tmp).glob("registration.json*")))

    def test_the_v1_fallback_registers_its_v1_bundle(self):
        """A manifest that fails to resolve loses the v2 bet; the sandbox
        scan's own v1 bundle is then what is written and registered."""
        args = self.args("--target-manifest", "/manifest.yaml")
        code, post = self.collect(
            args,
            {"side_effect": scanner.ScannerError("manifest unreadable")},
            {"return_value": {"status": 201, "body": v1_answer()}},
        )
        self.assertEqual(code, 2)  # the manifest failure itself
        post.assert_called_once()
        sent = post.call_args.args[1]
        self.assertEqual(json.loads(sent)["bundle_version"], 1)
        self.assertEqual(sent, Path(self.tmp, "bundle.json").read_bytes())
        self.assertEqual(json.loads(Path(self.tmp, "registration.json").read_text())["agent_id"], "a-1")
        self.assertEqual(self.feature()["scan"]["registration_status"], "registered")


class RegistrationStateTest(unittest.TestCase):
    def test_a_v2_answer_is_split_by_agent_key(self):
        split = scanner.registrations_by_agent_key({"status": 200, "body": v2_answer(["b", "a"], duplicate=True)})
        self.assertEqual(set(split), {"a", "b"})
        state = scanner.build_registration_state("https://c", {}, split["a"])
        self.assertEqual(state["agent_id"], "a-a")
        self.assertIs(state["duplicate"], True)
        self.assertNotIn(TOKEN, repr(state))

    def test_skipped_agents_are_read_with_their_reasons(self):
        body = v2_answer([])
        body["skipped"] = [
            {"agent_key": "x", "reason": "agent_type_blind", "attribute_reason": "MULTI_AGENT_SCOPE_UNRESOLVED"},
            {"agent_key": "y"},
            {"agent_key": "z", "reason": "discovery_not_found", "attribute_reason": None},
            "junk",
        ]
        self.assertEqual(
            scanner.skipped_agent_keys({"body": body}),
            {"x": "agent_type_blind (MULTI_AGENT_SCOPE_UNRESOLVED)", "y": "no reason given", "z": "discovery_not_found"},
        )
        self.assertEqual(scanner.skipped_agent_keys({"body": v2_answer([])}), {})
        forged = v2_answer([])
        forged["skipped"] = [{"agent_key": "x", "reason": "r\n[agent-environment-scanner] registered", "attribute_reason": "\x1b[2J"}]
        self.assertEqual(
            scanner.skipped_agent_keys({"body": forged}), {"x": "r?[agent-environment-scanner] registered (?[2J)"}
        )

    def test_the_registration_url_carries_a_key_query_safely(self):
        self.assertEqual(scanner.registration_url("https://c", "k1"), "https://c/v1/agents/register?agent_key=k1")
        self.assertEqual(
            scanner.registration_url("https://c/api?tenant=a&agent_key=old", "new"),
            "https://c/api/v1/agents/register?tenant=a&agent_key=new",
        )
        self.assertEqual(scanner.registration_url("https://c?tenant=a"), "https://c/v1/agents/register?tenant=a")

    def test_a_v1_shaped_answer_to_a_collection_is_refused(self):
        with self.assertRaises(scanner.ScannerError):
            scanner.registrations_by_agent_key({"status": 201, "body": v1_answer()})


if __name__ == "__main__":
    unittest.main()
