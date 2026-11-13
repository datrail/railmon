"""RC-509: pod mode reads the agent's own process, not the sidecar's.

With a shared process namespace the sidecar finds the agent's main process
(tools/scan/gke/agent_process.py) and reads its environment, user, command
line, runtimes and /etc/os-release through /proc/<pid>. These tests build a
fake /proc tree: per-process folders whose `root` links to a folder standing
in for that container's filesystem.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCANNER_DIR = ROOT / "tools" / "scan"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


scanner = _load("scan_agent_environment", SCANNER_DIR / "scan_agent_environment.py")
evidence_bundle = _load("evidence_bundle", SCANNER_DIR / "evidence_bundle.py")
agent_process = scanner._agent_process()   # tools/scan/gke/agent_process.py
pod_mode = scanner._pod_mode()             # tools/scan/gke/pod_mode.py

_PATCHED = {"scan_agent_environment": scanner, "evidence_bundle": evidence_bundle}
_saved: dict[str, Any] = {}


def setUpModule() -> None:
    for name, module in _PATCHED.items():
        _saved[name] = sys.modules.get(name)
        sys.modules[name] = module


def tearDownModule() -> None:
    for name, original in _saved.items():
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original


# The agent's config folder, as a path in its container. Nowhere real on the
# machine running the tests, so the scan's own look at it (it reads the config
# volume at the same path) finds nothing, as a non-root CI runner's /root would
# refuse it outright.
CONFIG = Path("/rc509-agent-config/.openclaw")
AGENT_SECRET = "sk-agent-placeholder-not-real-0001"
SIDECAR_SECRET = "sidecar-placeholder-not-real-0002"
AGENT_CONTAINER_ID = "a" * 64
SIDECAR_CONTAINER_ID = "5" * 64
AGENT_ENV = {
    "PATH": "/usr/local/bin:/usr/bin",
    "HOME": "/root",
    "NODE_VERSION": "24.18.1",
    "AGENT_LLM_API_KEY": AGENT_SECRET,
    "HTTPS_PROXY": "http://rail-proxy.gke-test:3128",
    # Settings the agent must not be able to set for itself.
    "RAIL_OWNER": "agent-chosen-owner",
    "RAIL_DEPLOYMENT": "agent-chosen-deployment",
    "RAIL_NAMESPACE": "agent-chosen-namespace",
    "RAIL_HOST_ID": "agent-chosen-host",
    "RAIL_SANDBOX_TYPE": "agent-chosen-sandbox",
}


class FakeProc:
    """A /proc tree. Each container's filesystem is a folder under roots/,
    and /proc/<pid>/root links to it, as the kernel's does."""

    def __init__(self, base: Path):
        self.base = base
        self.proc = base / "proc"
        self.roots = base / "roots"
        self.proc.mkdir()
        self.roots.mkdir()
        sidecar = self.container("sidecar")
        (self.proc / "self").mkdir()
        (self.proc / "self" / "root").symlink_to(sidecar)

    def container(self, name: str) -> Path:
        root = self.roots / name
        root.mkdir(exist_ok=True)
        return root

    def process(self, pid: int, container: str, cmdline: list[str],
                env: dict[str, str] | None = None, uid: int = 0, cgroup: str | None = None) -> Path:
        entry = self.proc / str(pid)
        entry.mkdir()
        (entry / "root").symlink_to(self.container(container))
        (entry / "cmdline").write_text("\x00".join(cmdline) + "\x00")
        if env is not None:
            (entry / "environ").write_text("".join(f"{k}={v}\x00" for k, v in env.items()))
        (entry / "status").write_text(f"Name:\t{cmdline[0]}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
                                      f"Gid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        if cgroup is not None:
            (entry / "cgroup").write_text(cgroup)
        return entry

    def agent_filesystem(self, container: str = "agent") -> Path:
        root = self.container(container)
        config = root / CONFIG.relative_to("/")
        config.mkdir(parents=True)
        (config / "openclaw.json").write_text("{}")
        (root / "root").mkdir()
        (root / "etc").mkdir()
        (root / "etc" / "os-release").write_text('ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12"\n')
        (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\nnode:x:1000:1000::/home/node:/bin/sh\n")
        package = root / "usr" / "local" / "lib" / "node_modules" / "openclaw"
        (package / "dist").mkdir(parents=True)
        (package / "package.json").write_text(json.dumps({"name": "openclaw", "version": "2026.9.2"}))
        (package / "dist" / "build-info.json").write_text(json.dumps({"version": "2026.9.2", "commit": "3928bad7"}))
        (root / "usr" / "local" / "bin").mkdir(parents=True)
        (root / "usr" / "local" / "bin" / "openclaw").symlink_to("/usr/local/lib/node_modules/openclaw/openclaw.mjs")
        (package / "openclaw.mjs").write_text("")
        return root

    def standard_pod(self) -> None:
        """The pause process, the agent, another container that doesn't hold
        the config (with a lower pid), and a second sidecar process."""
        self.agent_filesystem()
        self.process(1, "pause", ["/pause"], env={})
        self.process(5, "proxy", ["/usr/sbin/squid", "-N"], env={"PATH": "/usr/bin"})
        self.process(7, "agent", ["node", "/usr/local/bin/openclaw", "gateway"], env=AGENT_ENV)
        self.process(20, "sidecar", ["python3", "scan_agent_environment.py", "--mode", "pod"],
                     env={"RAIL_OWNER": "support-platform"})


class FindAgentProcessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fake = FakeProc(self.tmp)

    def find(self, config_paths=(CONFIG,)):
        return agent_process.find_agent_process(list(config_paths), self.fake.proc, own_pid=99999)

    def test_the_process_whose_root_holds_the_config_is_chosen(self):
        self.fake.standard_pod()
        agent, reason = self.find()
        self.assertEqual(reason, "found")
        self.assertEqual(agent["pid"], 7)
        self.assertEqual(agent["env"]["AGENT_LLM_API_KEY"], AGENT_SECRET)

    def test_the_pause_process_and_the_sidecars_own_processes_are_never_chosen(self):
        self.fake.standard_pod()
        # With no config anywhere, the lowest-numbered other container wins:
        # not the pause process (1), not the sidecar's own process (20).
        agent, _ = self.find(config_paths=[Path("/nowhere")])
        self.assertEqual(agent["pid"], 5)

    def test_a_restarted_agent_is_found_again_under_its_new_pid(self):
        self.fake.standard_pod()
        self.assertEqual(self.find()[0]["pid"], 7)
        shutil.rmtree(self.fake.proc / "7")
        self.fake.process(42, "agent", ["node", "/usr/local/bin/openclaw", "gateway"], env=AGENT_ENV)
        agent, reason = self.find()
        self.assertEqual((agent["pid"], reason), (42, "found"))

    def test_a_guessed_or_contested_choice_is_reported(self):
        self.fake.standard_pod()  # the agent holds the config; the proxy can be read too
        subject, _ = agent_process.read_subject([CONFIG], self.fake.proc, own_pid=99999)
        self.assertEqual((subject["holds_config"], subject["containers"]), (True, 2))
        self.assertIn("processes in 2 containers besides the sidecar's", pod_mode.choice_warning(subject))
        subject, _ = agent_process.read_subject([Path("/nowhere")], self.fake.proc, own_pid=99999)
        self.assertFalse(subject["holds_config"])
        self.assertIn("lowest pid was taken", pod_mode.choice_warning(subject))

    def test_one_readable_process_holding_the_config_gives_no_warning(self):
        self.fake.agent_filesystem()
        self.fake.process(1, "pause", ["/pause"], env={})
        self.fake.process(7, "agent", ["node", "/usr/local/bin/openclaw"], env=AGENT_ENV)
        subject, _ = agent_process.read_subject([CONFIG], self.fake.proc, own_pid=99999)
        self.assertEqual((subject["holds_config"], subject["containers"]), (True, 1))
        self.assertIsNone(pod_mode.choice_warning(subject))

    def test_the_agents_own_child_processes_do_not_trigger_the_warning(self):
        # A node gateway and its workers: many processes, one container.
        self.fake.agent_filesystem()
        self.fake.process(1, "pause", ["/pause"], env={})
        self.fake.process(7, "agent", ["node", "/usr/local/bin/openclaw", "gateway"], env=AGENT_ENV)
        self.fake.process(31, "agent", ["node", "worker.js"], env=AGENT_ENV)
        self.fake.process(32, "agent", ["sh", "-c", "git status"], env=AGENT_ENV)
        subject, _ = agent_process.read_subject([CONFIG], self.fake.proc, own_pid=99999)
        self.assertEqual((subject["pid"], subject["containers"]), (7, 1))
        self.assertIsNone(pod_mode.choice_warning(subject))

    def test_an_unreadable_agent_is_none_with_the_reason(self):
        self.fake.agent_filesystem()
        self.fake.process(1, "pause", ["/pause"], env={})
        self.fake.process(7, "agent", ["node", "/usr/local/bin/openclaw"], env=None)  # environ unreadable
        agent, reason = self.find()
        self.assertIsNone(agent)
        self.assertIn("can't be read", reason)

    def test_an_agent_running_as_another_user_says_so_not_no_shared_namespace(self):
        # /proc/<pid>/root of another user's process can't even be stat'ed.
        self.fake.agent_filesystem()
        self.fake.process(1, "pause", ["/pause"], env={})
        self.fake.process(7, "agent", ["node", "/usr/local/bin/openclaw"], env=None, uid=1000)
        self.fake.process(20, "sidecar", ["python3"], env={})
        real_stat = os.stat
        unreadable = {str(self.fake.proc / "1" / "root"), str(self.fake.proc / "7" / "root")}

        def stat(path, *args, **kwargs):
            if str(path) in unreadable:
                raise PermissionError(13, "Permission denied", str(path))
            return real_stat(path, *args, **kwargs)

        with mock.patch.object(agent_process.os, "stat", side_effect=stat):
            agent, reason = self.find()
        self.assertIsNone(agent)
        self.assertIn("a different user", reason)

    def test_only_an_unreadable_pause_process_still_means_no_agent_visible(self):
        self.fake.process(1, "pause", ["/pause"], env={})
        self.fake.process(20, "sidecar", ["python3"], env={})
        real_stat = os.stat
        pause_root = str(self.fake.proc / "1" / "root")

        def stat(path, *args, **kwargs):
            if str(path) == pause_root:
                raise PermissionError(13, "Permission denied", str(path))
            return real_stat(path, *args, **kwargs)

        with mock.patch.object(agent_process.os, "stat", side_effect=stat):
            agent, reason = self.find()
        self.assertIsNone(agent)
        self.assertIn("doesn't share its process namespace", reason)

    def test_no_shared_process_namespace_is_none_with_the_reason(self):
        self.fake.process(20, "sidecar", ["python3"], env={})
        agent, reason = self.find()
        self.assertIsNone(agent)
        self.assertIn("doesn't share its process namespace", reason)

    def test_no_proc_at_all_is_none(self):
        agent, reason = agent_process.find_agent_process([CONFIG], self.tmp / "missing", own_pid=1)
        self.assertEqual((agent, reason), (None, "no /proc to read"))


class ReadSubjectTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fake = FakeProc(self.tmp)
        self.fake.standard_pod()

    def test_the_agents_user_runtimes_and_os_release_are_read_through_its_root(self):
        subject, _ = agent_process.read_subject([CONFIG], self.fake.proc, own_pid=99999)
        self.assertEqual((subject["uid"], subject["gid"], subject["username"]), (0, 0, "root"))
        self.assertEqual(subject["home"], "/root")
        self.assertEqual(subject["runtimes"], {"openclaw": "OpenClaw 2026.9.2 (3928bad)", "node": "v24.18.1"})
        self.assertIn("ID=debian", subject["os_release"])
        self.assertEqual(subject["cmdline"], "node /usr/local/bin/openclaw gateway")

    def test_a_non_root_agent_is_named_from_its_own_passwd(self):
        shutil.rmtree(self.fake.proc / "7")
        self.fake.process(7, "agent", ["node", "/usr/local/bin/openclaw"], env=AGENT_ENV, uid=1000)
        subject, _ = agent_process.read_subject([CONFIG], self.fake.proc, own_pid=99999)
        self.assertEqual((subject["uid"], subject["username"]), (1000, "node"))


class AgentRootConfinementTest(unittest.TestCase):
    """Files in the agent's root are the agent's to arrange, so none of its
    links, FIFOs or documents may reach the sidecar or stop the scan."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fake = FakeProc(self.tmp)
        self.fake.standard_pod()
        self.agent_root = self.fake.roots / "agent"
        self.os_release = self.agent_root / "etc" / "os-release"
        # A file only the sidecar has, at a real absolute path on this machine.
        self.sidecar_file = self.fake.roots / "sidecar" / "environ"
        self.sidecar_file.write_text(f"SIDECAR_ONLY_TOKEN={SIDECAR_SECRET}\n")

    def subject(self):
        subject, _ = agent_process.read_subject([CONFIG], self.fake.proc, own_pid=99999)
        return subject

    def test_an_absolute_link_resolves_in_the_agents_root_not_the_sidecars(self):
        # The kernel would follow this to the sidecar's own file.
        self.os_release.unlink()
        self.os_release.symlink_to(self.sidecar_file)
        self.assertIsNone(self.subject()["os_release"])

    def test_dot_dot_never_climbs_out_of_the_agents_root(self):
        self.os_release.unlink()
        self.os_release.symlink_to("../../../../../../../../" + str(self.sidecar_file).lstrip("/"))
        self.assertIsNone(self.subject()["os_release"])
        # Clamped at the root, the same path still resolves inside it.
        self.assertEqual(agent_process.resolve_under_root(self.agent_root, "/../../etc/passwd"), "/etc/passwd")

    def test_a_link_into_another_filesystem_such_as_the_agents_proc_is_refused(self):
        # The agent's /proc is the pod's, so its /proc/self is the sidecar.
        procfs = self.agent_root / "proc" / "self"
        procfs.mkdir(parents=True)
        (procfs / "environ").write_text(f"SIDECAR_ONLY_TOKEN={SIDECAR_SECRET}\n")
        self.os_release.unlink()
        self.os_release.symlink_to("/proc/self/environ")
        # On one device the link resolves inside the agent's root, to its file...
        self.assertIn("SIDECAR_ONLY_TOKEN", agent_process.read_in_root(self.agent_root, "/etc/os-release"))
        real_stat = os.stat

        def other_device_for_proc(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            if path == "proc" and kwargs.get("dir_fd") is not None:
                fields = list(result[:10])
                fields[2] += 1  # st_dev: a mount, as /proc is
                return os.stat_result(fields)
            return result

        # ...but once /proc is a mount of its own, as it is, it is refused.
        with mock.patch.object(agent_process.os, "stat", side_effect=other_device_for_proc):
            self.assertIsNone(self.subject()["os_release"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs mkfifo")
    def test_a_fifo_is_skipped_without_blocking(self):
        self.os_release.unlink()
        os.mkfifo(self.os_release)
        self.assertIsNone(self.subject()["os_release"])

    def test_deeply_nested_json_does_not_stop_the_scan(self):
        build_info = self.agent_root / "usr/local/lib/node_modules/openclaw/dist/build-info.json"
        build_info.write_text("[" * 60_000)
        # package.json still gives the version; the build stamp is skipped.
        self.assertEqual(self.subject()["runtimes"]["openclaw"], "OpenClaw 2026.9.2")

    def test_a_secrets_file_path_is_checked_in_the_agents_root(self):
        context = {"mode": "pod", "subject": {"root": str(self.fake.proc / "7" / "root")}}
        exists = scanner.subject_path_checker(context)
        self.assertTrue(exists("/etc/passwd"))
        link = self.agent_root / "etc" / "sidecar-link"
        link.symlink_to(self.sidecar_file)
        self.assertFalse(exists("/etc/sidecar-link"))


class ScannerFileReadsTest(unittest.TestCase):
    """The scanner's own readers of config files, which in pod mode sit on a
    volume the agent writes."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs mkfifo")
    def test_a_fifo_at_a_config_path_reads_as_missing_without_blocking(self):
        fifo = self.tmp / ".mcp.json"
        os.mkfifo(fifo)
        self.assertIsNone(scanner.read_text(fifo))
        self.assertIsNone(scanner.load_json_file(fifo))
        self.assertEqual(evidence_bundle._read_json_capped(fifo), (None, "NO_SOURCE_ACCESS"))

    def test_deeply_nested_json_is_a_parse_failure_not_a_crash(self):
        # Both ranges: deep enough to overflow a walker of the parsed document
        # (about 1,000 levels), and deep enough to overflow the parser itself.
        nested = self.tmp / "openclaw.json"
        for depth in (101, 1_000, 2_000, 30_000):
            with self.subTest(depth=depth):
                nested.write_text('{"agents": ' + "[" * depth + "]" * depth + "}")
                with self.assertRaises(json.JSONDecodeError):
                    scanner.strict_json_loads(nested.read_text())
                self.assertIsNone(scanner.load_json_file(nested))
                self.assertEqual(evidence_bundle._read_json_capped(nested), (None, "PARSE_FAILED"))
                self.assertEqual(scanner.find_models_in_openclaw_config([self.tmp]), [])
        nested.write_text("[" * 60_000)
        self.assertIsNone(scanner.load_json_file(nested))

    def test_json_inside_strings_cannot_buy_fresh_depth(self):
        # The reviewer's case: ten string layers, each a JSON string inside 98
        # arrays. Every parse is within MAX_JSON_DEPTH, and together they
        # would overflow a recursive walk.
        text = json.dumps({"model": "gemini-flash-latest"})
        for _ in range(10):
            text = "[" * 98 + json.dumps(text) + "]" * 98
        config = self.tmp / "openclaw.json"
        config.write_text('{"agents": ' + text + "}")
        self.assertIsInstance(scanner.find_models_in_openclaw_config([self.tmp]), list)
        # JSON inside a string, shallowly, is still read.
        config.write_text(json.dumps({"agents": json.dumps({"model": "gemini-flash-latest"})}))
        self.assertEqual(scanner.find_models_in_openclaw_config([self.tmp]), ["gemini-flash-latest"])

    def test_json_within_the_depth_limit_still_parses(self):
        document = '{"a": ' + "[" * 98 + "1" + "]" * 98 + "}"
        self.assertEqual(scanner.json_depth_exceeds(scanner.strict_json_loads(document)), False)

    def test_a_regular_file_still_reads(self):
        good = self.tmp / ".mcp.json"
        good.write_text('{"mcpServers": {}}')
        self.assertEqual(scanner.load_json_file(good), {"mcpServers": {}})


class PodModeBundleTest(unittest.TestCase):
    """A real pod-mode scan, in process, against the fake /proc."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fake = FakeProc(self.tmp)
        podinfo = self.tmp / "podinfo"
        podinfo.mkdir()
        (podinfo / "labels").write_text('app="agent-finretail"\npod-template-hash="58cd78b55d"\n')
        self.sidecar_env = {
            "POD_NAME": "agent-finretail-58cd78b55d-48jcw", "POD_NAMESPACE": "gke-test",
            "POD_UID": "f3fe5e58-b328-40cb-9b03-1acf558d773d", "NODE_NAME": "node-1",
            "RAIL_POD_INFO_DIR": str(podinfo), "RAIL_OWNER": "support-platform",
            "SIDECAR_ONLY_TOKEN": SIDECAR_SECRET, "HOME": str(self.tmp / "sidecar-home"),
        }

    def scan(self, extra: list[str] | None = None):
        clean = {k: v for k, v in os.environ.items()
                 if not k.startswith(("RAIL_", "POD_", "GIT_")) and k not in ("NODE_NAME",)}
        args = scanner.make_parser().parse_args(
            ["--mode", "pod", "--config-path", str(CONFIG), "--no-feature-file"] + (["--host-id", "gke-test"] if extra is None else extra))
        with mock.patch.dict(os.environ, {**clean, **self.sidecar_env}, clear=True), \
                mock.patch.object(agent_process, "PROC_DIR", self.fake.proc), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            context, payload, identity = scanner.scan(args)
            bundle = evidence_bundle.build_verified_bundle(args, context, payload, identity)
        self.payload = payload
        return bundle, err.getvalue()

    def test_the_bundle_describes_the_agents_process(self):
        self.fake.standard_pod()
        bundle, _ = self.scan()
        attributes = bundle["attributes"]
        names = [entry["name"] for entry in attributes["credential_inventory"]["value"]]
        self.assertIn("AGENT_LLM_API_KEY", names)
        self.assertNotIn("SIDECAR_ONLY_TOKEN", names)
        user = attributes["user_info"]["value"]
        self.assertEqual((user["uid"], user["gid"], user["username"]), (0, 0, "root"))
        self.assertEqual(attributes["framework_identity"]["value"],
                         {"node": "v24.18.1", "openclaw": "OpenClaw 2026.9.2 (3928bad)"})
        self.assertEqual(attributes["egress_proxy_declared"]["status"], "ANSWERED")
        self.assertIn("rail-proxy.gke-test", json.dumps(attributes["egress_proxy_declared"]["value"]))
        self.assertEqual(attributes["system_info"]["value"]["os_release"]["id"], "debian")

    def test_a_scan_logs_when_another_container_could_be_the_agent(self):
        self.fake.standard_pod()
        _, err = self.scan()
        self.assertIn("may not be the agent's main process", err)

    def test_values_never_reach_the_bundle_only_names(self):
        self.fake.standard_pod()
        bundle, _ = self.scan()
        text = json.dumps(bundle)
        self.assertNotIn(AGENT_SECRET, text)
        self.assertNotIn(SIDECAR_SECRET, text)

    def test_the_rail_settings_come_from_the_sidecar_not_the_agent(self):
        self.fake.standard_pod()
        bundle, _ = self.scan()
        attributes = bundle["attributes"]
        self.assertEqual(attributes["owner"]["value"], {"owner": "support-platform", "source": "RAIL_OWNER"})
        self.assertEqual(attributes["deployment"]["value"],
                         {"RAIL_DEPLOYMENT": "agent-finretail", "RAIL_NAMESPACE": "gke-test"})
        self.assertEqual(attributes["sandbox_type"]["value"], "kubernetes")
        self.assertEqual(bundle["host_id"], "gke-test")
        self.assertNotIn("agent-chosen", json.dumps(bundle))

    def test_the_sidecars_own_rail_settings_win_over_the_agents(self):
        # As the webhook sets them: in the sidecar's environment, no flags.
        self.fake.standard_pod()
        self.sidecar_env.update({"RAIL_DEPLOYMENT": "finretail", "RAIL_NAMESPACE": "agents",
                                 "RAIL_HOST_ID": "gke-test-cluster"})
        bundle, _ = self.scan(extra=[])
        attributes = bundle["attributes"]
        self.assertEqual(attributes["deployment"]["value"],
                         {"RAIL_DEPLOYMENT": "finretail", "RAIL_NAMESPACE": "agents"})
        self.assertEqual(bundle["host_id"], "gke-test-cluster")
        self.assertEqual(attributes["owner"]["value"], {"owner": "support-platform", "source": "RAIL_OWNER"})
        self.assertNotIn("agent-chosen", json.dumps(bundle))

    def test_system_info_names_the_agents_process_and_says_versions_were_read(self):
        self.fake.standard_pod()
        bundle, _ = self.scan()
        attributes = bundle["attributes"]
        # The scan's payload names the agent's pid, not the sidecar's, and no cwd.
        info = scanner.collect_system_info(
            {"mode": "pod", "env": {}, "subject": {"pid": 7, "os_release": "", "runtimes": {}}}, "unset", [])
        self.assertEqual(info["process"]["pid"], 7)
        self.assertNotIn("cwd", info["process"])
        self.assertIn("build-info.json", attributes["harness_identity"]["method"])
        self.assertIn("not run", attributes["framework_identity"]["method"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs mkfifo")
    def test_config_and_mcp_paths_never_come_from_the_agents_home(self):
        # The agent points HOME at a folder the sidecar can also see and plants
        # a FIFO and a deeply nested document there. The scan never reads them.
        agent_home = self.tmp / "agent-chosen-home"
        (agent_home / ".openclaw").mkdir(parents=True)
        os.mkfifo(agent_home / ".mcp.json")
        (agent_home / ".openclaw" / "openclaw.json").write_text("[" * 60_000)
        self.fake.standard_pod()
        shutil.rmtree(self.fake.proc / "7")
        self.fake.process(7, "agent", ["node", "/usr/local/bin/openclaw", "gateway"],
                          env={**AGENT_ENV, "HOME": str(agent_home)})
        args = scanner.make_parser().parse_args(["--mode", "pod", "--no-feature-file", "--host-id", "gke-test",
                                                 "--config-path", str(CONFIG)])
        clean = {k: v for k, v in os.environ.items()
                 if not k.startswith(("RAIL_", "POD_", "GIT_")) and k not in ("NODE_NAME",)}
        with mock.patch.dict(os.environ, {**clean, **self.sidecar_env}, clear=True), \
                mock.patch.object(agent_process, "PROC_DIR", self.fake.proc), \
                contextlib.redirect_stderr(io.StringIO()):
            context, payload, identity = scanner.scan(args)
            bundle = evidence_bundle.build_verified_bundle(args, context, payload, identity)
        # The agent's HOME is reported as its user's home, and is nowhere else:
        # no config or MCP path the scan looked at was built from it.
        self.assertEqual(bundle["attributes"]["user_info"]["value"]["home"], str(agent_home))
        del bundle["attributes"]["user_info"], payload["environment"]["user_info"]
        self.assertNotIn(str(agent_home), json.dumps(bundle))
        self.assertNotIn(str(agent_home), json.dumps(payload))

    def scan_with_sidecar_container(self, agent_cgroup: str | None, extra: list[str] | None = None):
        self.fake.standard_pod()
        shutil.rmtree(self.fake.proc / "7")
        self.fake.process(7, "agent", ["node", "/usr/local/bin/openclaw", "gateway"], env=AGENT_ENV,
                          cgroup=agent_cgroup)
        with mock.patch.object(scanner, "detect_container_id", return_value=SIDECAR_CONTAINER_ID):
            return self.scan(extra)

    def test_the_container_id_is_the_agents_from_its_own_cgroup(self):
        bundle, _ = self.scan_with_sidecar_container(f"0::/kubepods.slice/cri-containerd-{AGENT_CONTAINER_ID}.scope\n")
        self.assertEqual(self.payload["environment"]["system_info"]["container"]["id"], AGENT_CONTAINER_ID)
        self.assertNotIn(SIDECAR_CONTAINER_ID, json.dumps(bundle) + json.dumps(self.payload))

    def test_a_cgroup_without_an_id_gives_no_container_id_not_the_sidecars(self):
        # A cgroup namespace shows the container only "/".
        bundle, _ = self.scan_with_sidecar_container("0::/\n")
        self.assertNotIn("id", self.payload["environment"]["system_info"]["container"])
        self.assertNotIn(SIDECAR_CONTAINER_ID, json.dumps(bundle) + json.dumps(self.payload))

    def test_the_mcp_config_is_read_from_the_agents_config_folder_not_the_sidecars_cwd(self):
        config = self.tmp / "config-volume" / ".openclaw"
        config.mkdir(parents=True)
        (config / ".mcp.json").write_text(json.dumps(
            {"mcpServers": {"finretail": {"url": "http://finretail-mcp-server:23004/mcp"}}}))
        sidecar_cwd = self.tmp / "sidecar-cwd"
        sidecar_cwd.mkdir()
        (sidecar_cwd / ".mcp.json").write_text(json.dumps(
            {"mcpServers": {"sidecar-only": {"url": "http://sidecar-only:1/mcp"}}}))
        self.fake.standard_pod()
        previous = os.getcwd()
        os.chdir(sidecar_cwd)
        self.addCleanup(os.chdir, previous)
        bundle, _ = self.scan(["--host-id", "gke-test", "--config-path", str(config)])
        mcp = bundle["attributes"]["mcp_servers_declared"]
        self.assertEqual(mcp["status"], "ANSWERED")
        text = json.dumps(bundle)
        self.assertIn("finretail", text)
        self.assertNotIn("sidecar-only", text)
        self.assertNotIn(str(sidecar_cwd), text)

    def test_pod_mode_without_config_path_scans_nothing_rather_than_the_sidecars_home(self):
        self.fake.standard_pod()
        args = scanner.make_parser().parse_args(["--mode", "pod", "--no-feature-file", "--host-id", "gke-test"])
        with mock.patch.dict(os.environ, self.sidecar_env), \
                mock.patch.object(agent_process, "PROC_DIR", self.fake.proc):
            with self.assertRaises(scanner.ScannerError) as raised:
                scanner.scan(args)
        self.assertIn("--mode pod needs --config-path", str(raised.exception))

    def test_an_agent_image_without_os_release_never_gets_the_sidecars(self):
        self.fake.standard_pod()
        (self.fake.roots / "agent" / "etc" / "os-release").unlink()
        with mock.patch.object(scanner, "read_text", side_effect=AssertionError("read the sidecar's own file")):
            info = scanner.collect_system_info(
                {"mode": "pod", "env": {}, "subject": {"os_release": None, "runtimes": {}}}, "unset", [])
        # Empty, not the sidecar's: no file of the scanner's own was read.
        self.assertEqual(info["os_release"], {})
        self.assertEqual(info["runtimes"], {})

    def test_the_agents_host_id_is_not_used_when_the_sidecar_has_none(self):
        self.fake.standard_pod()
        with self.assertRaises(scanner.ScannerError) as raised:
            self.scan(extra=[])
        self.assertIn("no host_id", str(raised.exception))

    def test_an_unreadable_agent_gives_blind_not_the_sidecars_values(self):
        self.fake.agent_filesystem()
        self.fake.process(1, "pause", ["/pause"], env={})
        self.fake.process(7, "agent", ["node", "/usr/local/bin/openclaw"], env=None)
        bundle, err = self.scan()
        attributes = bundle["attributes"]
        for name in ("credential_inventory", "user_info", "framework_identity",
                     "egress_proxy_declared", "system_info"):
            self.assertEqual(attributes[name]["status"], "BLIND", name)
            self.assertEqual(attributes[name]["reason"], "NO_SOURCE_ACCESS", name)
        text = json.dumps(bundle)
        self.assertNotIn(SIDECAR_SECRET, text)
        self.assertNotIn("SIDECAR_ONLY_TOKEN", text)
        self.assertIn("are reported BLIND", err)
        # The pod's own fields don't depend on the agent's process.
        self.assertEqual(attributes["owner"]["status"], "ANSWERED")
        self.assertEqual(attributes["agent_instance"]["status"], "ANSWERED")

    def test_an_unreadable_agent_leaves_the_model_and_endpoint_blind_not_absent(self):
        self.fake.agent_filesystem()
        self.fake.process(1, "pause", ["/pause"], env={})
        self.fake.process(7, "agent", ["node", "/usr/local/bin/openclaw"], env=None)
        bundle, _ = self.scan()
        attributes = bundle["attributes"]
        for name in ("model_name", "inference_endpoint"):
            self.assertEqual((attributes[name]["status"], attributes[name]["reason"]),
                             ("BLIND", "NO_SOURCE_ACCESS"), name)
        self.assertIn("agent process's uid", attributes["user"]["note"])

    def test_a_readable_agent_keeps_its_model_and_endpoint_answers(self):
        self.fake.standard_pod()
        shutil.rmtree(self.fake.proc / "7")
        self.fake.process(7, "agent", ["node", "/usr/local/bin/openclaw", "gateway"],
                          env={**AGENT_ENV, "OPENAI_BASE_URL": "https://llm-gateway.gke-test/v1",
                               "LLM_MODEL": "gemini-flash-latest"})
        bundle, _ = self.scan()
        attributes = bundle["attributes"]
        self.assertEqual(attributes["inference_endpoint"]["status"], "ANSWERED")
        self.assertEqual(attributes["model_name"]["status"], "ANSWERED")

    def test_an_unreadable_agent_is_never_called_a_host_process(self):
        # No agent environment (so no KUBERNETES_SERVICE_HOST) and a cgroup v2
        # namespace (so no container id): still a pod, never "a host process".
        self.fake.agent_filesystem()
        self.fake.process(1, "pause", ["/pause"], env={})
        self.fake.process(7, "agent", ["node", "/usr/local/bin/openclaw"], env=None)
        with mock.patch.object(scanner, "in_container", return_value=False):
            bundle, _ = self.scan()
        egress = bundle["attributes"]["egress_containment"]
        self.assertEqual((egress["status"], egress["reason"]), ("BLIND", "NO_SOURCE_ACCESS"))


if __name__ == "__main__":
    unittest.main()
