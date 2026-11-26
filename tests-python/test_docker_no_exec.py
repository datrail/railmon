"""DR-300: a docker-mode scan runs nothing in the agent's container.

What `docker exec` used to print (the environment, hostname, uname,
/etc/os-release, /etc/machine-id, `id`, the runtimes' `--version`, the
OpenClaw config files and `test -e` for a secret's path) comes from
`docker inspect` and the container's own files, read through
/proc/<pid>/root. These tests stand a folder in for that root and a fake
/proc beside it, and fail any Docker command other than inspect.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
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
agent_process = scanner._agent_process()

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


CONTAINER_ID = "c0ffee" * 10 + "abcd"
PID = 4242
USER_TABLE = "root:x:0:0:root:/root:/bin/bash\nnode:x:1000:1000::/home/node:/bin/bash\n"
GROUP = "root:x:0:\nnode:x:1000:\nagents:x:2000:\n"
OS_RELEASE = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n'


def inspect_output(env: list[str], user: str = "node", pid: int = PID) -> dict[str, Any]:
    return {
        "Id": CONTAINER_ID,
        "Name": "/my-agent",
        "Path": "docker-entrypoint.sh",
        "Config": {"Hostname": "a1b2c3d4e5f6", "User": user, "Image": "my-agent:1",
                   "Env": env, "Entrypoint": ["docker-entrypoint.sh"], "Cmd": ["openclaw", "gateway"]},
        "State": {"Pid": pid, "Running": True},
        "HostConfig": {"NetworkMode": "bridge"},
        "NetworkSettings": {"Networks": {}},
    }


class FakeContainer:
    """A container's root folder and a /proc whose <pid>/root links to it."""

    def __init__(self, tmp: Path) -> None:
        self.root = tmp / "rootfs"
        self.proc = tmp / "proc"
        for path, text in {"etc/passwd": USER_TABLE, "etc/group": GROUP,
                           "usr/lib/os-release": OS_RELEASE, "etc/machine-id": "0123456789abcdef\n"}.items():
            self.write(path, text)
        # As Debian ships it: an absolute link, which must resolve in the
        # container's root and not the scanner's.
        (self.root / "etc" / "os-release").symlink_to("/usr/lib/os-release")
        package = self.root / "usr/local/lib/node_modules/openclaw"
        self.write("usr/local/lib/node_modules/openclaw/package.json",
                   json.dumps({"name": "openclaw", "version": "2026.10.8"}))
        self.write("usr/local/lib/node_modules/openclaw/dist/build-info.json",
                   json.dumps({"version": "2026.10.8", "commit": "abcdef1234"}))
        (self.root / "usr/local/bin").mkdir(parents=True, exist_ok=True)
        (self.root / "usr/local/bin/openclaw").symlink_to("../lib/node_modules/openclaw/openclaw.mjs")
        (package / "openclaw.mjs").write_text("")
        self.write("home/node/.openclaw/openclaw.json",
                   json.dumps({"agents": {"defaults": {"model": "anthropic/claude-opus-4"}}}))
        self.write("run/secrets/llm_key", "never read")
        proc = self.proc / str(PID)
        proc.mkdir(parents=True)
        (proc / "cgroup").write_text(f"0::/system.slice/docker-{CONTAINER_ID}.scope\n")
        (proc / "root").symlink_to(self.root)

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def no_exec(cmd: list[str], timeout: float = 0.0) -> str | None:
    if cmd[:1] == ["docker"] and cmd[1:2] != ["inspect"] and cmd[1:3] not in (["container", "inspect"], ["network", "inspect"]):
        raise AssertionError(f"the scan ran a Docker command other than inspect: {cmd}")
    return None


class DockerScanRunsNothingInTheContainer(unittest.TestCase):
    ENV = ["PATH=/usr/local/bin:/usr/bin:/bin", "NODE_VERSION=24.11.1",
           "LLM_API_KEY_FILE=/run/secrets/llm_key", "MISSING_TOKEN_FILE=/run/secrets/gone"]

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.fake = FakeContainer(self.tmp)
        self.inspect = inspect_output(self.ENV)
        patches = [
            mock.patch.object(agent_process, "PROC_DIR", self.fake.proc),
            mock.patch.object(scanner, "docker_inspect", side_effect=lambda _c: self.inspect),
            mock.patch.object(scanner, "run_command", side_effect=no_exec),
            mock.patch.object(scanner, "collect_egress_containment", return_value={}),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def context(self) -> dict[str, Any]:
        return scanner.collect_docker_context("my-agent")

    def test_the_environment_is_what_docker_exec_env_printed(self):
        context = self.context()
        self.assertEqual(context["container_root"], str(self.fake.proc / str(PID) / "root"))
        self.assertIsNone(context["container_root_problem"])
        env = context["env"]
        # PATH from Env wins over Docker's default; HOSTNAME from inspect;
        # HOME from the exec user's passwd entry, as runc sets it.
        self.assertEqual(env["PATH"], "/usr/local/bin:/usr/bin:/bin")
        self.assertEqual(env["HOSTNAME"], "a1b2c3d4e5f6")
        self.assertEqual(env["HOME"], "/home/node")
        self.assertEqual(env["NODE_VERSION"], "24.11.1")
        self.assertEqual(context["hostname"], "a1b2c3d4e5f6")

    def test_docker_defaults_fill_what_env_leaves_out_and_env_wins_where_set(self):
        self.inspect = inspect_output(["HOME=/srv/agent", "HOSTNAME=chosen"])
        env = self.context()["env"]
        self.assertEqual(env["PATH"], scanner.DOCKER_DEFAULT_PATH)
        self.assertEqual((env["HOME"], env["HOSTNAME"]), ("/srv/agent", "chosen"))

    def test_the_exec_user_resolves_as_runc_resolves_it(self):
        root = str(self.fake.root)
        self.assertEqual(scanner.exec_user(root, ""), {"name": "root", "uid": 0, "gid": 0, "home": "/root"})
        self.assertEqual(scanner.exec_user(root, "1000"), {"name": "node", "uid": 1000, "gid": 1000, "home": "/home/node"})
        self.assertEqual(scanner.exec_user(root, "node:agents")["gid"], 2000)
        self.assertEqual(scanner.exec_user(root, "1234:5678"), {"name": None, "uid": 1234, "gid": 5678, "home": "/"})
        # Docker refuses to exec as a name or group the container doesn't know.
        self.assertIsNone(scanner.exec_user(root, "nobody-here"))
        self.assertIsNone(scanner.exec_user(root, "node:nogroup"))
        self.assertIsNone(scanner.exec_user(None, "node"))

    def test_system_and_user_info_come_from_the_containers_files(self):
        context = self.context()
        info = scanner.collect_system_info(context, "unset", [])
        self.assertEqual(info["os_release"]["id"], "debian")
        self.assertEqual(info["machine_id_sha256"], scanner.hash_identifier("0123456789abcdef\n"))
        own = os.uname()
        self.assertEqual(info["uname"], f"{own.sysname} {own.release} {own.machine}")
        self.assertEqual(info["runtimes"], {"node": "v24.11.1", "openclaw": "OpenClaw 2026.10.8 (abcdef1)"})
        user = scanner.collect_user_info(context, "me", "test")
        self.assertEqual((user["container_username"], user["container_uid"], user["container_gid"]),
                         ("node", "1000", "1000"))

    def test_the_machine_is_the_images_not_the_hosts(self):
        # An amd64 image emulated on an arm64 host: `uname -m` in it printed
        # x86_64, and the scanner's own uname says aarch64.
        def elf(machine: int, little: bool = True) -> bytes:
            order = "little" if little else "big"
            return (b"\x7fELF\x02" + (b"\x01" if little else b"\x02") + b"\x01" + bytes(9)
                    + (2).to_bytes(2, order) + machine.to_bytes(2, order))

        (self.fake.root / "bin").mkdir()
        (self.fake.root / "bin/busybox").write_bytes(elf(0x3E))
        (self.fake.root / "bin/sh").symlink_to("/bin/busybox")
        context = self.context()
        own = os.uname()
        info = scanner.collect_system_info(context, "unset", [])
        self.assertEqual(info["uname"], f"{own.sysname} {own.release} x86_64")
        # A script where /bin/sh should be is skipped for the next binary.
        (self.fake.root / "bin/sh").unlink()
        (self.fake.root / "bin/sh").write_text("#!/bin/false\n")
        self.fake.write("usr/bin/env", "")
        (self.fake.root / "usr/bin/env").write_bytes(elf(0xB7))
        self.assertEqual(scanner.container_machine(context["container_root"]), "aarch64")
        (self.fake.root / "usr/bin/env").write_bytes(elf(0x16, little=False))
        self.assertEqual(scanner.container_machine(context["container_root"]), "s390x")
        self.assertIsNone(scanner.container_machine(None))

    def test_a_secrets_path_is_checked_in_the_containers_root(self):
        exists = scanner.subject_path_checker(self.context())
        self.assertTrue(exists("/run/secrets/llm_key"))
        self.assertFalse(exists("/run/secrets/gone"))
        entries = {entry["key"]: entry["secret_class"]
                   for entry in scanner.collect_secret_hygiene(self.context()["env"], exists)}
        self.assertEqual(entries, {"LLM_API_KEY_FILE": "mount", "MISSING_TOKEN_FILE": "reference"})

    def test_the_model_is_found_in_the_containers_openclaw_config(self):
        root = self.context()["container_root"]
        self.assertEqual(scanner.find_container_config_files(root, ["/home/node/.openclaw", "/root/.openclaw"]),
                         ["/home/node/.openclaw/openclaw.json"])
        self.assertIn("anthropic/claude-opus-4",
                      scanner.find_models_in_container_openclaw_config(root, ["/home/node/.openclaw"]))

    def test_the_config_walk_follows_no_link_and_stays_bounded(self):
        config = self.fake.root / "home/node/.openclaw"
        # Links back to the folder itself: `find` never followed them, and
        # followed they would multiply the walk.
        for i in range(50):
            (config / f"loop{i}").symlink_to(".")
        (config / "linked.json").symlink_to("/etc/passwd")
        # find -maxdepth 4: deep/a/b/x.json is depth 4, deep/a/b/c/y.json is 5.
        (config / "deep/a/b/c").mkdir(parents=True)
        (config / "deep/a/b/four.json").write_text("{}")
        (config / "deep/a/b/c/five.json").write_text("{}")
        root = self.context()["container_root"]
        found = scanner.find_container_config_files(root, ["/home/node/.openclaw"])
        self.assertEqual(found, ["/home/node/.openclaw/openclaw.json",
                                 "/home/node/.openclaw/deep/a/b/four.json"])

    def test_a_config_file_comes_before_a_full_sessions_folder(self):
        sessions = self.fake.root / "home/node/.openclaw/agents/main/sessions"
        sessions.mkdir(parents=True)
        for i in range(scanner.CONTAINER_CONFIG_MAX_FILES + 5):
            (sessions / f"s{i:04}.jsonl").write_text("")
        found = scanner.find_container_config_files(self.context()["container_root"], ["/home/node/.openclaw"])
        self.assertEqual(found[0], "/home/node/.openclaw/openclaw.json")
        self.assertEqual(len(found), scanner.CONTAINER_CONFIG_MAX_FILES)

    def test_a_root_or_file_in_the_containers_proc_is_never_read(self):
        (self.fake.root / "proc/1").mkdir(parents=True)
        (self.fake.root / "proc/1/environ.json").write_text("{}")
        (self.fake.root / "home/node/.openclaw/sneaky").symlink_to("/proc/1")
        root = self.context()["container_root"]
        self.assertEqual(scanner.find_container_config_files(root, ["/proc/1", "/home/node/.openclaw/sneaky"]), [])
        self.assertIsNone(scanner.read_container_file(root, "/proc/1/environ.json"))
        self.assertIsNone(scanner.read_container_file(root, "/home/node/.openclaw/sneaky/environ.json"))
        # A file that is itself a link into /proc, as os-release could be made.
        (self.fake.root / "etc/os-release").unlink()
        (self.fake.root / "etc/os-release").symlink_to("../proc/1/environ.json")
        self.assertIsNone(scanner.read_container_file(root, "/etc/os-release"))

    def test_another_containers_process_under_that_pid_is_never_read(self):
        (self.fake.proc / str(PID) / "cgroup").write_text("0::/system.slice/docker-" + "f" * 64 + ".scope\n")
        context = self.context()
        self.assertIsNone(context["container_root"])
        self.assertIn("host's process namespace", context["container_root_problem"])
        info = scanner.collect_system_info(context, "unset", [])
        # Nothing of the scanner's own stands in for the container's.
        self.assertEqual(info["os_release"], {})
        self.assertNotIn("machine_id_sha256", info)
        self.assertEqual(info["runtimes"], {})
        self.assertNotIn("container_uid", scanner.collect_user_info(context, "me", "test"))

    def test_a_stopped_container_has_no_root(self):
        self.inspect = inspect_output(self.ENV, pid=0)
        self.assertEqual(self.context()["container_root_problem"], "the container is not running")

    def test_a_whole_scan_and_bundle_run_no_exec(self):
        args = scanner.make_parser().parse_args(
            ["--mode", "docker", "--container", "my-agent", "--host-id", "h1", "--no-feature-file"])
        clean = {k: v for k, v in os.environ.items() if not k.startswith(("RAIL_", "GIT_"))}
        with mock.patch.dict(os.environ, clean, clear=True), \
                mock.patch.object(scanner, "resolve_container", side_effect=lambda ref: ref), \
                contextlib.redirect_stderr(io.StringIO()):
            context, payload, identity = scanner.scan(args)
            bundle = evidence_bundle.build_verified_bundle(args, context, payload, identity)
        attributes = bundle["attributes"]
        self.assertEqual(bundle["rule_pack_version"], 19)
        self.assertEqual(attributes["harness_identity"]["value"], "openclaw/OpenClaw 2026.10.8 (abcdef1)")
        self.assertIn("build-info.json", attributes["harness_identity"]["method"])
        self.assertIn("not run", attributes["framework_identity"]["method"])
        self.assertIn("/etc/passwd", attributes["user_info"]["method"])
        self.assertNotIn("never read", json.dumps(bundle))

    def test_the_scan_says_why_the_containers_files_were_left_out(self):
        self.inspect = inspect_output(self.ENV, pid=PID + 1)
        args = scanner.make_parser().parse_args(
            ["--mode", "docker", "--container", "my-agent", "--host-id", "h1", "--no-feature-file"])
        with mock.patch.object(scanner, "resolve_container", side_effect=lambda ref: ref), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            scanner.scan(args)
        self.assertIn("host's process namespace", err.getvalue())


class ClaudeCodeVersionIsRead(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_the_npm_package_on_path(self):
        package = self.root / "usr/local/lib/node_modules/@anthropic-ai/claude-code"
        package.mkdir(parents=True)
        (package / "package.json").write_text(json.dumps({"name": "@anthropic-ai/claude-code", "version": "2.0.14"}))
        (package / "cli.js").write_text("")
        (self.root / "usr/local/bin").mkdir(parents=True)
        (self.root / "usr/local/bin/claude").symlink_to("../lib/node_modules/@anthropic-ai/claude-code/cli.js")
        versions = agent_process.runtime_versions(self.root, {"PATH": "/usr/local/bin"})
        self.assertEqual(versions["claude"], "2.0.14 (Claude Code)")

    def test_the_native_installers_versioned_file(self):
        versions_dir = self.root / "home/node/.local/share/claude/versions"
        versions_dir.mkdir(parents=True)
        (versions_dir / "2.0.20").write_text("")
        (self.root / "home/node/.local/bin").mkdir(parents=True)
        (self.root / "home/node/.local/bin/claude").symlink_to("/home/node/.local/share/claude/versions/2.0.20")
        versions = agent_process.runtime_versions(self.root, {"PATH": "/home/node/.local/bin:/usr/bin"})
        self.assertEqual(versions["claude"], "2.0.20 (Claude Code)")

    def test_another_package_of_that_name_is_not_claude_code(self):
        package = self.root / "usr/local/lib/node_modules/@anthropic-ai/claude-code"
        package.mkdir(parents=True)
        (package / "package.json").write_text(json.dumps({"name": "something-else", "version": "9"}))
        self.assertNotIn("claude", agent_process.runtime_versions(self.root, {}))


if __name__ == "__main__":
    unittest.main()
