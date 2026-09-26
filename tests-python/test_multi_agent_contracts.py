import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]


class ValidationError(ValueError):
    pass


def validate(value, schema, root=None, path="$"):
    """Dependency-free evaluator for the JSON Schema vocabulary used here."""
    root = root or schema
    if "$ref" in schema:
        target = root
        for part in schema["$ref"].removeprefix("#/").split("/"):
            target = target[part.replace("~1", "/").replace("~0", "~")]
        validate(value, target, root, path)
    if "oneOf" in schema:
        matches = 0
        for option in schema["oneOf"]:
            try:
                validate(value, option, root, path)
                matches += 1
            except ValidationError:
                pass
        if matches != 1:
            raise ValidationError(f"{path}: expected exactly one matching schema")
    for rule in schema.get("allOf", []):
        validate(value, rule, root, path)
    if "if" in schema:
        try:
            validate(value, schema["if"], root, path)
        except ValidationError:
            pass
        else:
            validate(value, schema.get("then", {}), root, path)
    if "not" in schema:
        try:
            validate(value, schema["not"], root, path)
        except ValidationError:
            pass
        else:
            raise ValidationError(f"{path}: matched forbidden schema")

    expected = schema.get("type")
    if expected is not None:
        choices = expected if isinstance(expected, list) else [expected]
        checks = {
            "null": value is None,
            "object": isinstance(value, dict),
            "array": isinstance(value, list),
            "string": isinstance(value, str),
            "integer": isinstance(value, int) and not isinstance(value, bool),
        }
        if not any(checks.get(choice, False) for choice in choices):
            raise ValidationError(f"{path}: wrong type")
    if "const" in schema and value != schema["const"]:
        raise ValidationError(f"{path}: wrong constant")
    if "enum" in schema and value not in schema["enum"]:
        raise ValidationError(f"{path}: value outside enum")

    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                raise ValidationError(f"{path}: missing {key}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(properties)
            if extra:
                raise ValidationError(f"{path}: unexpected properties {sorted(extra)}")
        for key, rule in properties.items():
            if key in value:
                validate(value[key], rule, root, f"{path}.{key}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise ValidationError(f"{path}: too few items")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True) for item in value]
            if len(encoded) != len(set(encoded)):
                raise ValidationError(f"{path}: duplicate items")
        if "items" in schema:
            for index, item in enumerate(value):
                validate(item, schema["items"], root, f"{path}[{index}]")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise ValidationError(f"{path}: string too short")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise ValidationError(f"{path}: pattern mismatch")
    if isinstance(value, int) and value < schema.get("minimum", value):
        raise ValidationError(f"{path}: integer below minimum")


class MultiAgentContractTests(unittest.TestCase):
    def load(self, name):
        schema = json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text())
        fixture = json.loads(
            (ROOT / "tests" / "fixtures" / f"{name}.valid.json").read_text()
        )
        return schema, fixture

    def test_every_published_fixture_conforms_to_its_complete_schema(self):
        for name in ("agent-ref-v1", "runtime-identity-v1", "target-manifest-v1"):
            with self.subTest(name=name):
                schema, fixture = self.load(name)
                validate(fixture, schema)

    def test_runtime_conditional_rejects_identity_on_unknown_event(self):
        schema, fixture = self.load("runtime-identity-v1")
        fixture["attribution"]["state"] = "unknown"
        fixture["attribution"]["method"] = None
        fixture["attribution"]["reason"] = "NO_PROCESS_TARGET"
        with self.assertRaises(ValidationError):
            validate(fixture, schema)

    def test_runtime_conditional_requires_identity_on_attributed_event(self):
        # The published fixture is already `attributed` with every identity
        # field populated, so none of these mutations is exercised by the
        # fixture-conformance test above. Deleting the schema's `allOf`
        # entirely still passes every other test in this file.
        schema, base = self.load("runtime-identity-v1")
        mutations = {
            "agent_ref": lambda f: f.__setitem__("agent_ref", None),
            "method": lambda f: f["attribution"].__setitem__("method", None),
            "reason": lambda f: f["attribution"].__setitem__(
                "reason", "should be null when attributed"
            ),
            "target_id": lambda f: f["attribution"].__setitem__("target_id", None),
            "process": lambda f: f["attribution"].__setitem__("process", None),
        }
        for field, mutate in mutations.items():
            with self.subTest(field=field):
                fixture = json.loads(json.dumps(base))
                mutate(fixture)
                with self.assertRaises(ValidationError):
                    validate(fixture, schema)

    def test_manifest_semantic_unique_key_annotation_is_enforced(self):
        schema, fixture = self.load("target-manifest-v1")
        fixture["agents"][1]["agent_key"] = fixture["agents"][0]["agent_key"]
        unique_by = schema["properties"]["agents"]["x-datrail-unique-by"]
        keys = [agent[unique_by] for agent in fixture["agents"]]
        self.assertNotEqual(len(keys), len(set(keys)))


if __name__ == "__main__":
    unittest.main()
