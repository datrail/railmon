"""`asp_normalize`: one attribute map per agent, the same for RailDash and Rail Center.

Rail Center's `profiling/asp.normalize` is the reference: these cases state its rules on
bundles as JSON. Its own fixture corpus, run through both, is the check that the two agree.
"""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]


def _load(name: str, **imports):
    """A private copy of `<name>.py` beside this directory, never left in sys.modules, so the suite
    reads the files here rather than any installed ones. `imports` are the modules it imports by
    name, present in sys.modules only while it loads, beside the copy itself, which a dataclass
    looks up there as it is defined."""
    spec = importlib.util.spec_from_file_location(f"{name}_under_test", HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    imports = {**imports, spec.name: module}
    saved = {key: sys.modules.get(key) for key in imports}
    sys.modules.update(imports)
    try:
        spec.loader.exec_module(module)
    finally:
        for key, value in saved.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value
    return module


asp_spelling = _load("asp_spelling")
N = _load("asp_normalize", asp_spelling=asp_spelling)

#: A caller's shapes, as Rail Center's `SHAPES` writes two of its own.
SHAPES = {
    "user": lambda value: isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool)),
    "tool_names": lambda value: isinstance(value, list) and all(isinstance(entry, str) for entry in value),
}


def answered(value, authored_by="subject", **more):
    return {"status": "ANSWERED", "tier": "observed", "value": value, "authored_by": authored_by, **more}


def v1(**attributes):
    return {"bundle_version": 1, "host_id": "h", "sandbox_name": "s", "attributes": attributes}


def v2(sandbox, **agents):
    return {
        "bundle_version": 2,
        "host_id": "h",
        "sandbox_name": "s",
        "sandbox": {"attributes": sandbox},
        "agents": [{"agent_key": key, "attributes": attributes} for key, attributes in agents.items()],
    }


class OneAttribute(unittest.TestCase):
    def test_a_read_value_is_respelled_and_sorted(self):
        out = N.normalized_attribute("mounts", answered([{"target": "/b/"}, {"target": "/a"}]))
        self.assertEqual(out["value"], [{"target": "/a"}, {"target": "/b"}])
        self.assertEqual(N.normalized_attribute("user", answered("0"))["value"], "root")

    def test_an_unread_value_is_sorted_but_not_respelled(self):
        for status in ("TEMPLATED", "ABSENT"):
            out = N.normalized_attribute("user", {"status": status, "tier": "declared", "value": ["0", "${U}"]})
            self.assertEqual(out["value"], ["${U}", "0"])

    def test_a_windows_keys_are_sorted_and_nothing_else_is_added(self):
        attribute = {**answered(["b"]), "window": {"added": ["z", "a"]}}
        out = N.normalized_attribute("skills", attribute)
        self.assertEqual(out["window"], {"added": ["a", "z"]})
        self.assertEqual(set(out), set(attribute))

    def test_the_attribute_given_is_not_changed(self):
        attribute = answered(["b", "a"], window={"added": ["z", "a"]})
        before = copy.deepcopy(attribute)
        N.normalized_attribute("tool_names", attribute)
        self.assertEqual(attribute, before)


class Readable(unittest.TestCase):
    def test_an_unusable_read_value_is_marked_failed_and_kept(self):
        out = N.readable({"user": answered(0.0), "tool_names": answered([{"x": 1}])}, SHAPES)
        for name, value in (("user", 0.0), ("tool_names", [{"x": 1}])):
            self.assertEqual(out[name]["status"], "FAILED")
            self.assertEqual(out[name]["reason"], "PARSE_FAILED")
            self.assertEqual(out[name]["value"], value)
            self.assertEqual(out[name]["authored_by"], "subject")
            self.assertTrue(N.unusable(out[name]))

    def test_a_partials_own_reason_gives_way(self):
        out = N.readable({"user": {**answered(True), "status": "PARTIAL", "reason": "TRUNCATED"}}, SHAPES)
        self.assertEqual(out["user"]["reason"], "PARSE_FAILED")

    def test_only_a_read_value_named_by_the_callers_shapes_is_checked(self):
        attributes = {
            "user": {"status": "TEMPLATED", "tier": "declared", "value": ["${U}"]},
            "mounts": answered(["/a"]),
            "tool_names": answered(["a"]),
        }
        self.assertEqual(N.readable(attributes, SHAPES), attributes)
        self.assertEqual(N.readable({"user": answered(0.0)}), {"user": answered(0.0)})

    def test_a_collectors_own_failure_is_not_unusable(self):
        self.assertFalse(N.unusable({"status": "FAILED", "tier": "observed", "value": None, "reason": "TIMEOUT"}))


class Bundles(unittest.TestCase):
    def test_a_v1_bundle_is_one_unkeyed_agent(self):
        [(key, attributes)] = N.normalized(v1(user=answered("0"), tool_names=answered([{}])), SHAPES)
        self.assertIsNone(key)
        self.assertEqual(attributes["user"]["value"], "root")
        self.assertEqual(attributes["tool_names"]["status"], "FAILED")

    def test_a_v2_bundle_is_each_agent_with_the_sandbox_merged_in(self):
        bundle = v2({"user": answered("root")}, a={"tool_names": answered(["y", "x"])}, b={})
        before = copy.deepcopy(bundle)
        out = N.normalized(bundle, SHAPES)
        self.assertEqual([key for key, _ in out], ["a", "b"])
        self.assertEqual(out[0][1], {"user": answered("root"), "tool_names": answered(["x", "y"])})
        self.assertEqual(out[1][1], {"user": answered("root")})
        self.assertEqual(bundle, before)

    def test_two_scopes_saying_the_same_thing_are_one_reading(self):
        out = N.normalized(v2({"user": answered("0")}, a={"user": answered("root")}))
        self.assertEqual(out[0][1]["user"]["value"], "root")

    def test_two_scopes_that_disagree_are_refused_with_every_conflict(self):
        bundle = v2(
            {"user": answered("root"), "privileged": answered(True), "workdir": answered("/w")},
            a={"privileged": answered(1), "workdir": answered("/w/")},
            b={"user": answered("app"), "privileged": answered(True)},
        )
        with self.assertRaises(N.ScopeConflict) as raised:
            N.normalized(bundle)
        # `1` and `true` are two readings; `/w` and `/w/` are one.
        self.assertEqual(raised.exception.conflicts, (("a", "privileged"), ("b", "user")))


class Vendored(unittest.TestCase):
    def test_both_files_vendored_into_a_package_import_each_other(self):
        """RailDash vendors the files into its own package, where `asp_spelling` is not top-level."""
        import shutil
        import tempfile

        with tempfile.TemporaryDirectory() as root:
            package = Path(root) / "vendoring_package_under_test"
            package.mkdir()
            (package / "__init__.py").write_text("")
            for name in ("asp_spelling.py", "asp_normalize.py"):
                shutil.copyfile(HERE / name, package / name)
            sys.path.insert(0, root)
            try:
                vendored = importlib.import_module("vendoring_package_under_test.asp_normalize")
                self.assertEqual(vendored.normalized(v1(user=answered("0")))[0][1]["user"]["value"], "root")
                self.assertTrue(vendored.respelled.__module__.startswith("vendoring_package_under_test."))
            finally:
                sys.path.remove(root)
                for key in [key for key in sys.modules if key.startswith("vendoring_package_under_test")]:
                    del sys.modules[key]


class Versions(unittest.TestCase):
    def test_each_step_changes_what_its_rules_name(self):
        steps = N.steps(SHAPES)
        self.assertEqual(sorted(steps), [2, N.RULES_VERSION])
        self.assertEqual(steps[2].changes, frozenset(SHAPES))
        self.assertEqual(asp_spelling.SPELLING_VERSION, 1, "a new spelling version is a new step, not step 3")
        self.assertEqual(steps[3].changes, frozenset(asp_spelling.SPELLINGS))

    def test_a_map_lifted_from_version_1_is_what_version_3_makes(self):
        bundle = v1(
            user=answered("0"),
            tool_names=answered([{"x": 1}]),
            mounts=answered([{"target": "/b/", "mode": "read-only"}, {"target": "/a"}]),
            skills=answered(["b", "a"]),
        )
        # Version 1 carried every value as sent, its lists sorted.
        made_by_1 = {name: {**a, "value": asp_spelling.sorted_lists(a["value"])} for name, a in bundle["attributes"].items()}
        [(_, made_by_3)] = N.normalized(bundle, SHAPES)
        lifted = N.lifted(made_by_1, 1, 3, N.steps(SHAPES))
        self.assertEqual(asp_spelling.canonical(lifted), asp_spelling.canonical(made_by_3))

    def test_a_marked_value_is_respelled_by_step_3(self):
        made_by_2 = N.readable({"user": answered(["0"])}, SHAPES)
        lifted = N.lifted(made_by_2, 2, 3, N.steps(SHAPES))
        self.assertEqual(lifted["user"]["status"], "FAILED")
        self.assertEqual(lifted["user"]["value"], ["0"])  # a list of users is not a user: kept as it came

    def test_no_chain_backwards_or_past_the_last_step(self):
        steps = N.steps()
        self.assertIsNone(N.chain(3, 2, steps))
        self.assertIsNone(N.chain(3, 4, steps))
        self.assertEqual(N.chain(3, 3, steps), [])
        with self.assertRaises(N.NoChainOfSteps):
            N.lifted({}, 2, 1, steps)

    def test_a_step_cannot_fail_to_lift_what_it_does_not_change(self):
        with self.assertRaises(ValueError):
            N.Step(changes=frozenset({"user"}), lift=lambda name, a: dict(a), cannot_lift=frozenset({"mounts"}))

    def test_what_a_step_cannot_lift_is_carried_as_made(self):
        steps = dict(N.steps(SHAPES))
        steps[3] = N.Step(changes=steps[3].changes, lift=steps[3].lift, cannot_lift=frozenset({"user"}))
        self.assertEqual(N.unliftable(1, 3, steps), frozenset({"user"}))
        self.assertEqual(N.lifted({"user": answered(0.0)}, 1, 3, steps), {"user": answered(0.0)})


if __name__ == "__main__":
    unittest.main()
