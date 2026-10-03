"""DR-163: `railmon forward` posts the batch envelope Rail Center's
POST /v1/interactions takes, not one RuntimeInteraction object per request.

The request body is checked against a vendored copy of Rail Center's
published contract (tests/fixtures/rail-center/, source and commit in its
`$comment`), and against a fixture that was itself validated against both that
schema and Rail Center's Pydantic model. Stdlib only, like the forwarder.
"""

from __future__ import annotations

import importlib.util
import json
import re
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
SPEC = importlib.util.spec_from_file_location("forward", ROOT / "tools" / "forward" / "forward.py")
rail_collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rail_collector)

SCHEMA = json.loads((FIXTURES / "rail-center" / "interaction-batch-request.schema.json").read_text())
EXPECTED = json.loads((FIXTURES / "rail-center" / "interaction-batch.valid.json").read_text())
EVENTS = [json.loads(line) for line in (FIXTURES / "runtime-interactions.jsonl").read_text().splitlines() if line]

_DATE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$", re.IGNORECASE)
_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def problems(instance, schema, where="$"):
    """The slice of JSON Schema the vendored contract uses, and no more."""
    if "$ref" in schema:
        return problems(instance, SCHEMA["$defs"][schema["$ref"].rsplit("/", 1)[-1]], where)
    found = []
    if "oneOf" in schema:
        matches = sum(not problems(instance, branch, where) for branch in schema["oneOf"])
        if matches != 1:
            found.append(f"{where}: matches {matches} of oneOf's branches, not exactly one")
    kinds = schema.get("type")
    if kinds is not None:
        kinds = [kinds] if isinstance(kinds, str) else kinds
        if not any(_TYPES[kind](instance) for kind in kinds):
            return found + [f"{where}: {instance!r} is not {kinds}"]
    if "enum" in schema and instance not in schema["enum"]:
        found.append(f"{where}: {instance!r} is not one of {schema['enum']}")
    if isinstance(instance, dict):
        for key in schema.get("required", ()):
            if key not in instance:
                found.append(f"{where}.{key}: required")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, value in instance.items():
            if key in properties:
                found += problems(value, properties[key], f"{where}.{key}")
            elif additional is False:
                found.append(f"{where}.{key}: not allowed")
            elif isinstance(additional, dict):
                found += problems(value, additional, f"{where}.{key}")
    if isinstance(instance, list):
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            found.append(f"{where}: more than {schema['maxItems']} items")
        for index, item in enumerate(instance):
            found += problems(item, schema.get("items", {}), f"{where}[{index}]")
    if isinstance(instance, str):
        if len(instance) < schema.get("minLength", 0):
            found.append(f"{where}: too short")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            found.append(f"{where}: too long")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            found.append(f"{where}: does not match {schema['pattern']}")
        if schema.get("format") == "date-time" and not _DATE_TIME.match(instance):
            found.append(f"{where}: not a date-time")
    if _TYPES["integer"](instance) and "minimum" in schema and instance < schema["minimum"]:
        found.append(f"{where}: below {schema['minimum']}")
    return found


class Center(BaseHTTPRequestHandler):
    """Rail Center's POST /v1/interactions: records each body, answers with
    the per-item counts, and refuses (422) a batch carrying a poisoned item."""

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        self.server.bodies.append((self.path, body))
        items = (body.get("interactions") or []) if isinstance(body, dict) else []
        poisoned = any(item.get("idempotency_key") in self.server.poison for item in items)
        if poisoned or self.server.fail_status is not None:
            status, reply = (self.server.fail_status or 422), {"detail": "refused"}
            if self.server.fail_status is not None and not poisoned and len(items) == 1:
                status, reply = None, None
            if status is not None:
                payload = json.dumps(reply).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
        if not poisoned:
            self.server.accepted += [item.get("idempotency_key") for item in items]
        status, reply = (422, {"detail": "bad item"}) if poisoned else (
            202,
            {"received": len(items), "recorded": len(items), "duplicates": 0, "conflicts": 0,
             "session_id": body.get("session_id")},
        )
        payload = json.dumps(reply).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class ForwardEnvelopeTest(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Center)
        self.server.bodies = []
        self.server.poison = set()
        self.server.accepted = []
        # With fail_status set, every multi-item batch and every poisoned
        # item gets that status; a clean single item still lands.
        self.server.fail_status = None
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.spool = Path(tmp.name)

    def drain(self, events, **kwargs):
        for event in events:
            rail_collector.spool_event(rail_collector.validate_event(event), self.spool / "pending")
        return rail_collector.drain_pending(
            self.spool / "pending", self.spool / "sent", self.url, 5.0, False, None, **kwargs
        )

    def test_the_fixture_satisfies_the_vendored_schema(self):
        self.assertEqual(problems(EXPECTED, SCHEMA), [])

    def test_the_schema_check_refuses_the_old_per_item_body(self):
        self.assertTrue(problems(EVENTS[0], SCHEMA))

    def test_a_drain_posts_one_envelope_matching_the_fixture(self):
        self.assertEqual(self.drain(EVENTS), (3, 0))
        self.assertEqual(len(self.server.bodies), 1)
        path, body = self.server.bodies[0]
        self.assertEqual(path, "/v1/interactions")
        self.assertEqual(problems(body, SCHEMA), [])
        # Spool order is by file name, not capture order; compare as sets.
        key = lambda item: item["idempotency_key"]  # noqa: E731
        self.assertEqual({k: v for k, v in body.items() if k != "interactions"},
                         {k: v for k, v in EXPECTED.items() if k != "interactions"})
        self.assertEqual(sorted(body["interactions"], key=key), sorted(EXPECTED["interactions"], key=key))
        self.assertEqual(list((self.spool / "pending").glob("*.json")), [])

    def test_sessions_get_their_own_envelope_and_batches_are_bounded(self):
        events = []
        for session in ("s-1", "s-2"):
            for n in range(3):
                event = json.loads(json.dumps(EVENTS[0]))
                event["interaction_id"] = f"railmon-{session}-{n}"
                event["raw"]["railmon_session_id"] = session
                events.append(event)
        self.assertEqual(self.drain(events, batch_size=2), (6, 0))
        sizes = [(body["session_id"], len(body["interactions"])) for _, body in self.server.bodies]
        self.assertEqual(sorted(sizes), [("s-1", 1), ("s-1", 2), ("s-2", 1), ("s-2", 2)])
        for _, body in self.server.bodies:
            self.assertEqual(problems(body, SCHEMA), [])

    def test_a_refused_item_is_set_aside_and_the_rest_still_land(self):
        self.server.poison = {EVENTS[1]["interaction_id"]}
        self.assertEqual(self.drain(EVENTS), (2, 1))
        self.assertEqual(sorted(self.server.accepted), sorted([EVENTS[0]["interaction_id"], EVENTS[2]["interaction_id"]]))
        self.assertEqual(list((self.spool / "pending").glob("*.json")), [])
        self.assertEqual(len(list((self.spool / "rejected").glob("*.json"))), 1)

    def test_a_server_error_over_one_item_is_isolated_and_kept_for_retry(self):
        self.server.fail_status = 500
        self.server.poison = {EVENTS[1]["interaction_id"]}
        self.assertEqual(self.drain(EVENTS), (2, 1))
        self.assertEqual(sorted(self.server.accepted), sorted([EVENTS[0]["interaction_id"], EVENTS[2]["interaction_id"]]))
        # A 5xx may be transient: the item stays pending rather than rejected.
        self.assertEqual(len(list((self.spool / "pending").glob("*.json"))), 1)
        self.assertFalse((self.spool / "rejected").exists())

    def test_batches_are_bounded_by_bytes_too(self):
        events = []
        for n in range(3):
            event = json.loads(json.dumps(EVENTS[0]))
            event["interaction_id"] = f"railmon-big-{n}"
            event["raw"]["request"]["body"] = {"text": "x" * (7 * 1024 * 1024)}
            events.append(event)
        self.assertEqual(self.drain(events), (3, 0))
        self.assertEqual(sorted(len(body["interactions"]) for _, body in self.server.bodies), [1, 2])

    def test_values_longer_than_rail_centers_columns_are_trimmed(self):
        event = json.loads(json.dumps(EVENTS[0]))
        event["raw"]["request"]["path"] = "/" + "a" * 5000
        event["raw"]["railmon_session_id"] = "s" * 100
        item = rail_collector.to_interaction_item(event)
        self.assertEqual(len(item["request"]["path"]), 2048)
        self.assertEqual(len(rail_collector.event_session(event)[0]), 64)
        event["raw"]["request"]["method"] = "M" * 17
        self.assertNotIn("request", rail_collector.to_interaction_item(event))

    def test_an_unreachable_center_keeps_every_event_spooled(self):
        self.url = "http://127.0.0.1:9"
        self.assertEqual(self.drain(EVENTS), (0, 3))
        self.assertEqual(len(list((self.spool / "pending").glob("*.json"))), 3)

    def test_the_forward_command_end_to_end(self):
        import os
        import subprocess

        env = {k: v for k, v in os.environ.items() if not k.startswith(("RAIL_", "GCE_"))}
        env.update(RAILMON_ROOT=str(ROOT), RAIL_CENTER_URL=self.url)
        result = subprocess.run(
            [str(ROOT / "entrypoint.sh"), "forward", "--spool-dir", str(self.spool),
             "--input", str(FIXTURES / "runtime-interactions.jsonl"), "--flush-count", "3"],
            env=env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(self.server.accepted), sorted(event["interaction_id"] for event in EVENTS))
        for _, body in self.server.bodies:
            self.assertEqual(problems(body, SCHEMA), [])
        self.assertIn("forwarded 3 interaction(s)", result.stderr)

    def test_the_old_path_is_this_same_forwarder(self):
        legacy = ROOT / "rail-collector" / "rail_collector.py"
        self.assertEqual(legacy.resolve(), (ROOT / "tools" / "forward" / "forward.py").resolve())

    def test_an_event_without_raw_still_makes_a_valid_item(self):
        event = {k: v for k, v in EVENTS[0].items() if k != "raw"}
        item = rail_collector.to_interaction_item(event)
        self.assertEqual(item["request"], {"method": "POST", "path": "/v1/messages"})
        self.assertEqual(item["response"], {"status_code": 200})
        envelope = rail_collector.batch_envelope(rail_collector.event_session(event), [item])
        self.assertEqual(envelope["session_id"], "unknown")
        self.assertNotIn("capture_start", envelope)
        self.assertEqual(problems(envelope, SCHEMA), [])


if __name__ == "__main__":
    unittest.main()
