import base64
import json
import unittest

from collector.runtime_interaction import to_runtime_interaction


class RuntimeInteractionTest(unittest.TestCase):
    def test_decodes_alpha_agent_id_and_preserves_header(self) -> None:
        agent_id = "550e8400-e29b-41d4-a716-446655440000"
        token = base64.urlsafe_b64encode(
            json.dumps({"agent_id": agent_id}).encode()
        ).decode()
        interaction = {
            "timestamp": "2026-01-01T00:00:00+00:00",
            "request": {
                "method": "POST",
                "path": "/mcp",
                "headers": {"host": "example.test", "x-rail": token},
            },
            "response": {"status_code": 200},
        }

        result = to_runtime_interaction(interaction)

        self.assertEqual(result["agent_id"], agent_id)
        self.assertEqual(result["x_rail_header"], token)
        self.assertEqual(result["request"]["destination"], "example.test")

    def test_invalid_header_does_not_drop_interaction(self) -> None:
        interaction = {
            "request": {
                "method": "GET",
                "path": "/health",
                "headers": {"x-rail": "not-a-token"},
            },
            "response": {},
        }

        result = to_runtime_interaction(interaction)

        self.assertIsNone(result["agent_id"])
        self.assertEqual(result["x_rail_header"], "not-a-token")


if __name__ == "__main__":
    unittest.main()
