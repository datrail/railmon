"""`asp_spelling`: when two values of an ASP attribute are one value.

The cases are Rail Center's RC-386 cases, each as it was, read here through
`respelled` and `sorted_lists` directly rather than through Rail Center's
`normalize`: two spellings of one value read the same, and two values that are
only alike stay two.
"""

from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]


def _load():
    """A private copy, never put in sys.modules, so the suite reads the file
    beside it rather than any installed one."""
    spec = importlib.util.spec_from_file_location("asp_spelling_under_test", HERE / "asp_spelling.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


asp_spelling = _load()
SPELLINGS = asp_spelling.SPELLINGS
canonical = asp_spelling.canonical
respelled = asp_spelling.respelled
sorted_lists = asp_spelling.sorted_lists


def _read(name: str, value: object) -> str:
    """`value` as both consumers compare it: respelled, its lists sorted, as canonical JSON."""
    return canonical(sorted_lists(respelled(name, value)))


_MOUNT = {"source": "/data/support-exports", "target": "/data", "mode": "ro"}
_SERVER = {"name": "filesystem", "root": "/srv/ops", "mode": "rw"}

# Two spellings of one value, for every attribute `SPELLINGS` names, each beside the rule that makes
# them one: they normalise to one ASP.
_ONE_VALUE: list[tuple[str, object, object]] = [
    # A uid and a name denote one user, and a uid is a number however it is written.
    ("user", "root", "0"),
    ("user", "root", 0),
    ("user", "root", "00"),
    ("user", "root", "+0"),
    ("user", "root:root", "0:0"),
    ("user", "1000", 1000),
    ("user", "1000:1000", "01000:1000"),
    # A blank account is the runtime's default user, root, and a blank group is none.
    ("user", "root", ""),
    ("user", "root:1000", ":1000"),
    ("user", "root", "0:"),
    # Linux reads a run of slashes as one, and a trailing slash names the same directory.
    ("workdir", "/app", "/app/"),
    ("workdir", "/app", "//app"),
    ("mounts", [_MOUNT], [{**_MOUNT, "source": "/data/support-exports/", "target": "/data//"}]),
    ("mcp_servers_declared", [_SERVER], [{**_SERVER, "root": "/srv/ops/"}]),
    # `ro` and `read-only` are one mode.
    ("mounts", [_MOUNT], [{**_MOUNT, "mode": "read-only"}]),
    ("mcp_servers_declared", [_SERVER], [{**_SERVER, "mode": "read-write"}]),
    # DNS names are the same in any case.
    (
        "observed_destinations",
        [{"host": "files.vendor-x.com", "tls": True}],
        [{"host": "Files.Vendor-X.com", "tls": True}],
    ),
    ("declared_destinations", [{"host": "files.vendor-x.com"}], [{"host": "FILES.VENDOR-X.COM"}]),
    ("undeclared_destinations", ["files.vendor-x.com"], ["files.VENDOR-x.com"]),
    ("mcp_servers_observed", [{"endpoint": "mcp-gw.internal:7443"}], [{"endpoint": "MCP-GW.internal:7443"}]),
    # `:443` is https's default, and a URL's scheme and host are the same in any case.
    ("inference_endpoint", "https://api.example.com/v1", "https://api.example.com:443/v1"),
    ("inference_endpoint", "http://llm-gw.internal/v1", "http://llm-gw.internal:80/v1"),
    ("inference_endpoint", "http://llm-gw.internal:8080/v1", "HTTP://LLM-GW.Internal:8080/v1"),
    (
        "mcp_servers_declared",
        [{"name": "x", "url": "https://mcp.example.com/sse"}],
        [{"name": "x", "url": "https://mcp.example.com:443/sse"}],
    ),
    (
        "mcp_servers_observed",
        [{"endpoint": "https://mcp.example.com/sse"}],
        [{"endpoint": "https://MCP.example.com:443/sse"}],
    ),
    # `CAP_NET_ADMIN` and `NET_ADMIN` are one capability, in either case.
    (
        "permissions",
        {"privileged": False, "cap_add": ["CAP_NET_ADMIN"]},
        {"privileged": False, "cap_add": ["NET_ADMIN"]},
    ),
    ("permissions", {"privileged": False, "cap_drop": ["ALL"]}, {"privileged": False, "cap_drop": ["all"]}),
    ("permissions", {"caps": ["CAP_SYS_PTRACE"], "privileged": False}, {"caps": ["sys_ptrace"], "privileged": False}),
    # A `v` before a version is not part of it.
    ("harness_identity", "openclaw/1.8.2", "openclaw/v1.8.2"),
    ("framework_identity", "langgraph/0.2.61", "langgraph/v0.2.61"),
    ("framework_identity", {"node": "24.20.0", "openclaw": "1.8.2"}, {"node": "v24.20.0", "openclaw": "1.8.2"}),
]

# Two values that are alike and are not one, each beside why: they stay two ASPs. The first is the
# reason a spelling has to be exact, and several are what a looser rule would merge.
_TWO_VALUES: list[tuple[str, object, object]] = [
    ("observed_destinations", [{"host": "db.example.com"}], [{"host": "db.examp1e.com"}]),  # a lookalike
    ("image_digest", "sha256:4a7b91cc9e2f1d84", "sha256:4a7b91cc9e2f1d85"),  # one digit of a digest
    ("user", "root", "ROOT"),  # a user name is case-sensitive
    ("user", "root", " root"),
    ("user", "root", "0:0"),  # only one names its group
    ("user", "1000", "100"),
    ("user", "root", "0_0"),  # a name to the runtime, though Python's `int` reads it as 0
    ("workdir", "/app", "/App"),  # a path is case-sensitive
    ("workdir", "/b", "/a/../b"),  # `..` is not the parent through a symlink
    ("mounts", [_MOUNT], [{**_MOUNT, "mode": "rw"}]),
    ("mounts", [_MOUNT], [{**_MOUNT, "mode": "ro,Z"}]),  # an option beside the mode
    ("observed_destinations", [{"host": "bücher.example"}], [{"host": "BÜCHER.example"}]),  # IDNA's case, not ASCII's
    ("inference_endpoint", "https://api.example.com/v1", "https://api.example.com/V1"),  # a path is case-sensitive
    ("inference_endpoint", "https://api.example.com/v1", "https://api.example.com/v1/"),  # and its slash names another
    ("inference_endpoint", "https://api.example.com/v1", "http://api.example.com:443/v1"),
    ("inference_endpoint", "https://api.example.com/v1", "https://api.example.com:8443/v1"),
    ("inference_endpoint", "https://agent@api.example.com/v1", "https://AGENT@api.example.com/v1"),
    ("permissions", {"cap_add": ["CAP_NET_ADMIN"]}, {"cap_add": ["CAP_NET_RAW"]}),
    ("harness_identity", "openclaw/1.8.2", "openclaw/1.8.3"),
    ("harness_identity", "openclaw/1.8.2", "openclaw/version-1.8.2"),
    ("harness_identity", "https://example.com/1.8.2", "https://example.com/v1.8.2"),  # a path, not a version
    ("harness_identity", "acme/2", "acme/v2"),  # an org's repository as often as a version
    # A WHATWG parser reads the backslash as a slash: host `u`, and a path holding `Good.COM:80`.
    ("inference_endpoint", "http://u\\@Good.COM:80/A", "http://u\\@good.com/A"),
    # A URI's slashes are its own: the first is a local directory and the second a host.
    ("mcp_servers_declared", [{**_SERVER, "root": "file:///srv/ops"}], [{**_SERVER, "root": "file://srv/ops"}]),
    ("mcp_servers_declared", [{**_SERVER, "root": "s3://bucket/a/key"}], [{**_SERVER, "root": "s3://bucket/a//key"}]),
]



class OneValue(unittest.TestCase):
    def test_two_spellings_of_one_value_read_as_one(self) -> None:
        for name, one, other in _ONE_VALUE:
            with self.subTest(name=name, one=one, other=other):
                self.assertNotEqual(canonical(one), canonical(other), "the case is meant to spell one value two ways")
                self.assertEqual(_read(name, one), _read(name, other))

    def test_two_values_that_are_only_alike_stay_two(self) -> None:
        for name, one, other in _TWO_VALUES:
            with self.subTest(name=name, one=one, other=other):
                self.assertNotEqual(_read(name, one), _read(name, other))

    def test_every_spelling_is_tested(self) -> None:
        """A spelling added without a case fails here, and one named for an attribute nothing sends
        would sit in `SPELLINGS` doing nothing."""
        self.assertEqual({name for name, *_ in _ONE_VALUE}, set(SPELLINGS))

    def test_a_spelling_keeps_the_lookalike_the_rule_exists_to_catch(self) -> None:
        """RC-386's gate, in miniature: what a model passed is still two values here."""
        sent = [{"host": "DB.example.com"}, {"host": "db.examp1e.com"}]
        self.assertEqual(
            sorted_lists(respelled("observed_destinations", sent)),
            [{"host": "db.examp1e.com"}, {"host": "db.example.com"}],
        )

    def test_a_value_in_its_one_spelling_is_spelled_so_already(self) -> None:
        """So a value respelled again is the same value, whoever respelled it first."""
        for name, one, other in _ONE_VALUE + _TWO_VALUES:
            for value in (one, other):
                with self.subTest(name=name, value=value):
                    once = respelled(name, value)
                    self.assertEqual(canonical(respelled(name, once)), canonical(once))

    def test_a_number_past_what_int_reads_is_respelled_rather_than_refused(self) -> None:
        """`int` refuses a run of digits past 4300, so a number is respelled as text: one such value
        would otherwise refuse the whole bundle it came in."""
        cases = [
            ("user", "0" * 5000 + "1", "1"),
            ("user", "9" * 5000, "9" * 5000),
            ("inference_endpoint", "https://api.example.com:" + "0" * 5000 + "443/v1", "https://api.example.com/v1"),
            (
                "inference_endpoint",
                "https://api.example.com:" + "9" * 5000 + "/v1",
                "https://api.example.com:" + "9" * 5000 + "/v1",
            ),
        ]
        for name, sent, spelled in cases:
            with self.subTest(name=name, sent=sent[:40]):
                self.assertEqual(respelled(name, sent), spelled)

    def test_a_value_no_rule_can_use_is_respelled_as_any_other_is(self) -> None:
        """In the entries a spelling can read, so one unusable value sent in two spellings is one."""
        one = [{"source": "/data", "target": "/x", "mode": "ro"}, "bare"]
        other = [{"source": "//data/", "target": "/x", "mode": "read-only"}, "bare"]
        self.assertEqual(_read("mounts", one), _read("mounts", other))

    def test_a_name_spellings_does_not_know_is_kept_as_it_came(self) -> None:
        value = {"Anything": ["B", "a"]}
        self.assertIs(respelled("image_digest", value), value)

    def test_a_shape_a_spelling_does_not_know_is_kept_as_it_came(self) -> None:
        for name in SPELLINGS:
            for value in (None, True, 1.5, {"unexpected": 1} if name != "permissions" else ["x"]):
                with self.subTest(name=name, value=value):
                    self.assertEqual(canonical(respelled(name, value)), canonical(value))


class SortedLists(unittest.TestCase):
    def test_the_same_items_in_any_order_at_any_depth_are_one_value(self) -> None:
        one = {"a": [{"x": [3, 1, 2]}, {"y": 1}], "b": ["z", "a"]}
        other = {"b": ["a", "z"], "a": [{"y": 1}, {"x": [2, 3, 1]}]}
        self.assertEqual(canonical(sorted_lists(one)), canonical(sorted_lists(other)))

    def test_duplicates_are_kept(self) -> None:
        self.assertEqual(sorted_lists(["b", "a", "b"]), ["a", "b", "b"])

    def test_a_value_without_a_list_is_kept(self) -> None:
        self.assertEqual(sorted_lists({"k": "v", "n": 1}), {"k": "v", "n": 1})


class Canonical(unittest.TestCase):
    def test_values_python_reads_as_equal_are_two_readings(self) -> None:
        self.assertEqual(1, True)
        self.assertNotEqual(canonical(1), canonical(True))
        self.assertNotEqual(canonical(0), canonical(0.0))

    def test_key_order_is_not_state(self) -> None:
        self.assertEqual(canonical({"a": 1, "b": 2}), canonical({"b": 2, "a": 1}))
        self.assertEqual(canonical({"b": 2, "a": 1}), '{"a":1,"b":2}')


class Version(unittest.TestCase):
    def test_the_package_version_is_the_spelling_version(self) -> None:
        """A consumer pinning the package and one vendoring the file read the same number."""
        text = (HERE / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'^version = "([^"]+)"$', text, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), str(asp_spelling.SPELLING_VERSION))


if __name__ == "__main__":
    unittest.main()
