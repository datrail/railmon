import json
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize(
    "name",
    ["agent-ref-v1", "runtime-identity-v1", "target-manifest-v1"],
)
def test_published_multi_agent_fixture_matches_its_schema(name):
    schema = json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text())
    fixture = json.loads((ROOT / "tests" / "fixtures" / f"{name}.valid.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(fixture)


def test_duplicate_agent_keys_are_rejected_by_the_reference_semantic_rule():
    fixture = json.loads(
        (ROOT / "tests" / "fixtures" / "target-manifest-v1.valid.json").read_text()
    )
    fixture["agents"][1]["agent_key"] = fixture["agents"][0]["agent_key"]
    keys = [agent["agent_key"] for agent in fixture["agents"]]
    if len(keys) == len(set(keys)):
        raise AssertionError("duplicate-key fixture unexpectedly remained unique")
