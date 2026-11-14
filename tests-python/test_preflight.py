"""The sensors' start-up checks (DR-301): each names what is missing, a
capability, the kernel's tracing folder, Docker access or the host's PID
namespace, instead of the misleading message it used to give."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("railmon_preflight_test", ROOT / "tools/listen/preflight.py")
preflight = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(preflight)
_tls_spec = importlib.util.spec_from_file_location(
    "follow_container_tls_preflight_test", ROOT / "tools/collect/follow_container_tls.py")
tls = importlib.util.module_from_spec(_tls_spec)
_tls_spec.loader.exec_module(tls)

ALL = (1 << 21) | (1 << 38) | (1 << 39)


def caps(*numbers: int) -> int:
    return sum(1 << n for n in numbers)


class Tmp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def script(self, name: str, body: str) -> str:
        path = self.dir / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)
        return str(path)


class CapabilityTest(Tmp):
    def test_reads_the_effective_set_and_the_kernels_last_capability(self):
        proc = self.dir / "proc"
        (proc / "self").mkdir(parents=True)
        (proc / "sys/kernel").mkdir(parents=True)
        (proc / "self/status").write_text("Name:\tx\nCapPrm:\t0\nCapEff:\t000000c000200000\n")
        (proc / "sys/kernel/cap_last_cap").write_text("40\n")
        self.assertEqual(preflight.effective_caps(str(proc)), ALL)
        self.assertEqual(preflight.last_cap(str(proc)), 40)
        self.assertIsNone(preflight.effective_caps(str(self.dir / "none")))

    def test_names_each_missing_capability(self):
        self.assertIsNone(preflight.capability_problem(ALL, 40, "collect"))
        self.assertIsNone(preflight.capability_problem((1 << 41) - 1, 40, "collect"))  # privileged
        problem = preflight.capability_problem(0, 40)
        self.assertIn("missing capabilities BPF and PERFMON (or SYS_ADMIN)", problem)
        self.assertIn("add them with cap_add", problem)
        self.assertIn("missing capability PERFMON (or SYS_ADMIN)",
                      preflight.capability_problem(caps(39), 40))
        # Docker's default set: none of them.
        self.assertIn("BPF and PERFMON", preflight.capability_problem(0xa80425fb, 40))

    def test_sys_admin_stands_in_for_bpf_and_perfmon(self):
        # bpf_capable() and perfmon_capable() accept SYS_ADMIN.
        for command in ("collect", "listen", "files"):
            self.assertIsNone(preflight.capability_problem(caps(21), 40, command))

    def test_listen_and_files_need_no_sys_admin_once_tracefs_is_mounted(self):
        self.assertIsNone(preflight.capability_problem(caps(38, 39), 40, "listen"))
        self.assertIsNone(preflight.capability_problem(caps(38, 39), 40, "files"))

    def test_collect_needs_sys_admin_or_checkpoint_restore_for_the_maps(self):
        problem = preflight.capability_problem(caps(38, 39), 40, "collect")
        self.assertIn("collect reads the agent's memory maps", problem)
        self.assertIn("add it with cap_add", problem)
        self.assertIsNone(preflight.capability_problem(caps(38, 39, 40), 40, "collect"))
        # A kernel before CHECKPOINT_RESTORE: the bit means nothing there.
        self.assertIsNotNone(preflight.capability_problem(caps(38, 39, 40), 39, "collect"))

    def test_before_linux_5_8_sys_admin_is_the_one(self):
        self.assertIsNone(preflight.capability_problem(caps(21), 37, "collect"))
        self.assertIn("missing capability SYS_ADMIN:", preflight.capability_problem(0, 37))

    def test_an_unreadable_set_is_not_reported(self):
        self.assertIsNone(preflight.capability_problem(None, 40))


class TracefsTest(Tmp):
    def test_visible_or_mountable_tracefs_is_fine(self):
        mounted, missing = self.dir / "mounted", self.dir / "missing"
        (mounted / "events").mkdir(parents=True)
        missing.mkdir()
        self.assertIsNone(preflight.tracefs_problem([str(missing), str(mounted)], 0))
        self.assertIsNone(preflight.tracefs_problem([str(missing)], caps(21)))

    def test_missing_without_sys_admin_says_to_mount_it(self):
        missing = self.dir / "missing"
        problem = preflight.tracefs_problem([str(missing)], caps(38, 39))
        self.assertIn(f"mount {missing} into this container read-only", problem)
        self.assertIn(f"{missing}:{missing}:ro", problem)


class DockerTest(Tmp):
    def test_a_daemon_that_answers_is_fine(self):
        docker = self.script("docker", "echo 1.47\n")
        self.assertIsNone(preflight.docker_problem(docker, {}, str(self.dir / "sock")))

    def test_no_socket_and_no_docker_host(self):
        docker = self.script("docker", "echo 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock.' >&2\nexit 1\n")
        problem = preflight.docker_problem(docker, {}, str(self.dir / "docker.sock"))
        self.assertIn("no Docker access", problem)
        self.assertIn("isn't mounted and DOCKER_HOST isn't set", problem)

    def test_a_mounted_socket_whose_daemon_doesnt_answer(self):
        sock = self.dir / "docker.sock"
        sock.touch()
        docker = self.script("docker", "echo 'Cannot connect to the Docker daemon' >&2\nexit 1\n")
        self.assertIn("doesn't answer", preflight.docker_problem(docker, {}, str(sock)))

    def test_permission_denied(self):
        docker = self.script("docker", "echo 'permission denied while trying to connect' >&2\nexit 1\n")
        self.assertIn("no permission on the Docker socket",
                      preflight.docker_problem(docker, {}, str(self.dir / "s")))

    def test_docker_host_names_the_proxy(self):
        docker = self.script("docker", "echo 'error during connect' >&2\nexit 1\n")
        problem = preflight.docker_problem(docker, {"DOCKER_HOST": "tcp://docker-proxy:2375"}, "/nonexistent")
        self.assertIn("DOCKER_HOST=tcp://docker-proxy:2375 doesn't answer", problem)

    def test_no_client(self):
        self.assertIn("no Docker client", preflight.docker_problem(str(self.dir / "absent"), {}))

    def test_no_container_by_that_name(self):
        docker = self.script("docker", 'if [ "$1" = inspect ]; then echo "Error: No such object: agnet" >&2; exit 1; fi\necho 1.47\n')
        self.assertIn("no container named agnet", preflight.container_problem(docker, "agnet", {}))

    def test_a_stopped_container_or_a_sandbox_is_just_waiting(self):
        docker = self.script("docker", 'if [ "$1" = inspect ]; then echo exited; exit 0; fi\necho 1.47\n')
        self.assertIsNone(preflight.container_problem(docker, "agent", {}))
        self.assertIsNone(preflight.container_problem(str(self.dir / "absent"), "openshell:box", {}))


class ProcTest(Tmp):
    def test_an_invisible_host_pid_asks_for_pid_host(self):
        (self.dir / "proc/77").mkdir(parents=True)
        self.assertIsNone(preflight.pid_problem(77, str(self.dir / "proc")))
        self.assertIsNone(preflight.pid_problem(0, str(self.dir / "proc")))
        self.assertIn("pid: host", preflight.pid_problem(4242, str(self.dir / "proc")))

    def test_unreadable_memory_maps_name_sys_admin(self):
        maps = self.dir / "proc/77/map_files"
        maps.mkdir(parents=True)
        os.symlink("/bin/sh", maps / "7f00-7f01")
        proc = str(self.dir / "proc")
        self.assertIsNone(preflight.maps_problem(77, proc))
        with mock.patch.object(preflight.os, "stat", side_effect=PermissionError):
            self.assertIn("following them needs SYS_ADMIN", preflight.maps_problem(77, proc))
        with mock.patch.object(preflight.os, "listdir", side_effect=PermissionError):
            self.assertIn("SYS_PTRACE", preflight.maps_problem(77, proc))
        self.assertIsNone(preflight.maps_problem(78, proc))  # gone: nothing to say

    def test_collect_says_why_it_finds_no_tls_user(self):
        proc = self.dir / "proc"
        (proc / "77/map_files").mkdir(parents=True)
        self.assertIn("pid: host", tls.no_target_reason("agent", 4242, str(proc)))
        self.assertIn("loads libssl", tls.no_target_reason("agent", 77, str(proc)))
        with mock.patch.object(preflight.os, "listdir", side_effect=PermissionError):
            self.assertIn("ptrace access", tls.no_target_reason("agent", 77, str(proc)))


class WaitingTest(unittest.TestCase):
    def test_logs_each_reason_once_and_asks_again_only_after_the_interval(self):
        now = [0.0]
        logged: list[str] = []
        asked: list[str] = []
        waiting = preflight.Waiting(logged.append, every=30, clock=lambda: now[0])

        def explain(reason):
            def ask():
                asked.append(reason)
                return reason
            return ask

        waiting.wait("container", explain("no Docker access"))
        now[0] = 10
        waiting.wait("container", explain("no Docker access"))  # within 30 s: not asked
        now[0] = 31
        waiting.wait("container", explain("no Docker access"))  # asked, same reason: quiet
        waiting.wait("tls", explain("no process loads libssl"))  # a new kind: at once
        waiting.clear()
        waiting.wait("container", explain("no Docker access"))
        self.assertEqual(asked, ["no Docker access", "no Docker access", "no process loads libssl",
                                 "no Docker access"])
        self.assertEqual(logged, ["no Docker access", "no process loads libssl", "no Docker access"])


class StartupTest(Tmp):
    def proc(self, cap_eff: int) -> str:
        proc = self.dir / "proc"
        (proc / "self").mkdir(parents=True, exist_ok=True)
        (proc / "sys/kernel").mkdir(parents=True, exist_ok=True)
        (proc / "self/status").write_text(f"CapEff:\t{cap_eff:016x}\n")
        (proc / "sys/kernel/cap_last_cap").write_text("40\n")
        return str(proc)

    def test_a_privileged_sensor_has_nothing_to_say(self):
        tracefs = self.dir / "tracing"
        (tracefs / "events").mkdir(parents=True)
        for command in ("collect", "listen", "files"):
            self.assertEqual(preflight.startup_problems(command, proc=self.proc((1 << 41) - 1),
                                                        tracefs=[str(tracefs)]), [])

    def test_kyles_failure_modes_each_name_the_missing_piece(self):
        # DR-288's test log: capabilities dropped, tracefs not mounted, no socket.
        missing = self.dir / "tracing"
        docker = self.script("docker", "echo 'Cannot connect to the Docker daemon' >&2\nexit 1\n")
        problems = preflight.startup_problems("listen", "agent", proc=self.proc(0xa80425fb),
                                              tracefs=[str(missing)], docker=docker, env={},
                                              socket=str(self.dir / "docker.sock"))
        self.assertEqual(len(problems), 3, problems)
        self.assertIn("BPF and PERFMON (or SYS_ADMIN)", problems[0])
        self.assertIn("tracing folder", problems[1])
        self.assertIn("no Docker access", problems[2])
        # collect needs no tracefs.
        self.assertEqual(len(preflight.startup_problems(
            "collect", proc=self.proc(0xa80425fb), tracefs=[str(missing)])), 1)

    def test_a_running_agent_outside_this_pid_namespace(self):
        docker = self.script("docker", 'case "$*" in *State.Pid*) echo 4242;; *) echo running;; esac\n')
        problems = preflight.startup_problems("files", "agent", proc=self.proc(ALL),
                                              tracefs=[str(self.dir)], docker=docker, env={})
        # tracefs has no events/ but SYS_ADMIN mounts it: only the pid is reported.
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("pid: host", problems[0])

    def test_main_prints_one_line_per_problem_and_exits_zero(self):
        with mock.patch.object(preflight, "startup_problems", return_value=["a", "b"]), \
                mock.patch.object(sys, "stderr") as err:
            self.assertEqual(preflight.main(["collect"]), 0)
        written = "".join(call.args[0] for call in err.write.call_args_list)
        self.assertIn("[railmon collect] start-up check: a\n", written)
        self.assertIn("[railmon collect] start-up check: b\n", written)


if __name__ == "__main__":
    unittest.main()
