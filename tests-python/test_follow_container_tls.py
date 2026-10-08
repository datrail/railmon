"""`railmon collect` following a container (DR-187): which process and TLS
library it attaches to, and that it re-attaches when the container restarts."""

from __future__ import annotations

import importlib.util
import os
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/collect/follow_container_tls.py"
_spec = importlib.util.spec_from_file_location("follow_container_tls", SCRIPT)
tls = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tls)


class FakeProc:
    """A /proc with just the files the resolver reads."""

    def __init__(self, base: Path):
        self.base = base
        self.rootfs = base / "rootfs"
        self.rootfs.mkdir()

    def process(self, pid: int, exe: str, *, children=(), maps=(), comm="x", session=1):
        """`maps` paths are inside the root; each becomes a `map_files` link
        to the file in it, as the kernel's links name the mapped inode."""
        d = self.base / "proc" / str(pid)
        (d / "task" / str(pid)).mkdir(parents=True)
        (d / "task" / str(pid) / "children").write_text(" ".join(map(str, children)))
        (d / "map_files").mkdir()
        lines = []
        for i, path in enumerate(maps):
            rng = f"7f{i:02d}00-7f{i:02d}01"
            lines.append(f"{rng} r-xp 00000000 08:01 1 {path}\n")
            real = self.rootfs / path.removesuffix(" (deleted)").lstrip("/")
            os.symlink(real, d / "map_files" / rng)
        (d / "maps").write_text("".join(lines))
        (d / "comm").write_text(comm + "\n")
        (d / "stat").write_text(f"{pid} ({comm}) S 1 {pid} {session} 0 -1\n")
        os.symlink(self.rootfs / exe.lstrip("/"), d / "exe")

    def file(self, path: str, content: bytes = b"\x7fELF") -> None:
        target = self.rootfs / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)

    @property
    def proc(self) -> str:
        return str(self.base / "proc")


class ResolverTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fake = FakeProc(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_node_child_with_bundled_tls_is_found_below_an_init_without_it(self):
        # OpenClaw's shape: tini as init, node below it with OpenSSL linked in.
        self.fake.file("/sbin/tini")
        self.fake.file("/usr/local/bin/node", b"\x7fELF" + b"\0" * (3 << 20) + b"SSL_write" + b"\0")
        self.fake.process(10, "/sbin/tini", children=[11], comm="tini")
        self.fake.process(11, "/usr/local/bin/node", comm="node")
        pid, path, how = tls.find_tls_target(10, {}, proc=self.fake.proc)
        self.assertEqual(pid, 11)
        self.assertEqual(path, f"{self.fake.proc}/11/exe")
        self.assertIn("built into", how)

    def test_a_needle_across_a_read_boundary_is_found(self):
        self.fake.file("/bin/agent", b"\0" * (tls.CHUNK - 4) + b"SSL_write")
        self.assertTrue(tls.embeds_tls(str(self.fake.rootfs / "bin/agent"), {}))

    def test_a_mapped_libssl_wins_over_an_executable_that_only_names_ssl_write(self):
        # Linked against libssl, so SSL_write is in its symbol table but the
        # code is in the library: attaching to the executable would hook nothing.
        self.fake.file("/usr/bin/agent", b"\x7fELF SSL_write")
        self.fake.file("/usr/lib/libssl.so.3")
        self.fake.process(10, "/usr/bin/agent", maps=["/usr/lib/libssl.so.3"])
        pid, path, how = tls.find_tls_target(10, {}, proc=self.fake.proc)
        self.assertEqual(path, f"{self.fake.proc}/10/map_files/7f0000-7f0001")
        self.assertIn("loads /usr/lib/libssl.so.3", how)

    def test_a_deleted_mapping_is_attached_through_its_link_not_its_old_name(self):
        # The agent can plant a file under the name a deleted mapping shows;
        # the map_files link still names the inode that is mapped.
        self.fake.file("/usr/bin/agent")
        self.fake.file("/usr/lib/libssl.so.3")
        self.fake.process(10, "/usr/bin/agent", maps=["/usr/lib/libssl.so.3 (deleted)"])
        pid, path, how = tls.find_tls_target(10, {}, proc=self.fake.proc)
        self.assertEqual(path, f"{self.fake.proc}/10/map_files/7f0000-7f0001")

    def test_an_executable_that_is_a_fifo_is_not_read(self):
        # Opening a FIFO for reading blocks until a writer comes; it must not.
        fifo = self.fake.rootfs / "bin/agent"
        fifo.parent.mkdir(parents=True)
        os.mkfifo(fifo)
        self.fake.process(10, "/bin/agent")
        started = time.monotonic()
        self.assertIsNone(tls.find_tls_target(10, {}, proc=self.fake.proc))
        self.assertLess(time.monotonic() - started, 5)

    def test_a_container_with_no_tls_yet_resolves_to_nothing(self):
        self.fake.file("/bin/sh")
        self.fake.process(10, "/bin/sh", children=[11])
        self.fake.process(11, "/bin/sh")
        self.assertIsNone(tls.find_tls_target(10, {}, proc=self.fake.proc))

    def test_the_session_is_read_after_a_comm_with_spaces_and_parens(self):
        self.fake.file("/bin/x")
        self.fake.process(10, "/bin/x", comm="a) (b", session=4242)
        self.assertEqual(tls.session_of(10, proc=self.fake.proc), 4242)

    def test_a_flag_that_picks_processes_itself_is_refused(self):
        out = subprocess.run([sys.executable, str(SCRIPT), "agent", "--mode", "http", "--comm", "node"],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 2)
        self.assertIn("--comm", out.stderr)


@unittest.skipUnless(Path("/proc/self/maps").exists() and os.geteuid() == 0,
                     "needs Linux /proc, and root to read /proc/<pid>/map_files")
class FollowTest(unittest.TestCase):
    """The supervisor against real processes: a session leader standing in for
    the container's init, a fake `docker` naming it, and a fake collector that
    records the arguments it was started with."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.pid_file = self.tmp / "init.pid"
        self.calls = self.tmp / "calls"
        docker = self.tmp / "docker"
        docker.write_text(f"#!/bin/sh\ncat {self.pid_file} 2>/dev/null || exit 1\n")
        collector = self.tmp / "collector"
        collector.write_text(textwrap.dedent(f"""\
            #!/bin/sh
            echo "$*" >> {self.calls}
            trap 'exit 0' TERM
            while :; do sleep 0.1; done
            """))
        for f in (docker, collector):
            f.chmod(f.stat().st_mode | stat.S_IEXEC)
        self.docker, self.collector = docker, collector
        self.agents: list[subprocess.Popen] = []

    def tearDown(self):
        for agent in self.agents:
            agent.kill()
            agent.wait()

    def start_agent(self) -> int:
        # Imports ssl, so its python maps libssl, and leads its own session
        # the way a container's init does.
        agent = subprocess.Popen([sys.executable, "-c", "import ssl, time; time.sleep(120)"],
                                 start_new_session=True)
        self.agents.append(agent)
        for _ in range(100):
            if tls.mapped_libssl(agent.pid):
                break
            time.sleep(0.05)
        self.pid_file.write_text(f"{agent.pid}\n")
        return agent.pid

    def wait_for_calls(self, n: int) -> list[str]:
        for _ in range(200):
            if self.calls.exists():
                lines = self.calls.read_text().splitlines()
                if len(lines) >= n:
                    return lines
            time.sleep(0.05)
        self.fail(f"collector started fewer than {n} times")

    def test_attaches_to_the_containers_libssl_and_session_and_follows_a_restart(self):
        first = self.start_agent()
        if tls.mapped_libssl(first) is None:
            self.skipTest("this python's ssl module does not map a libssl.so")
        env = dict(os.environ, RAIL_DOCKER=str(self.docker))
        sup = subprocess.Popen([sys.executable, str(SCRIPT), "--collector", str(self.collector),
                                "agent", "--mode", "http", "--webhook", "http://x/hook"],
                               env=env, stderr=subprocess.PIPE, text=True)
        try:
            call = self.wait_for_calls(1)[0].split()
            self.assertEqual(call[:4], ["--mode", "http", "--webhook", "http://x/hook"])
            path = call[call.index("--binary-path") + 1]
            self.assertTrue(path.startswith(f"/proc/{first}/map_files/"), path)
            self.assertIn("libssl.so", os.readlink(path))
            self.assertEqual(call[call.index("--session") + 1], str(first))

            gone = self.agents.pop(0)
            gone.kill()
            gone.wait()
            second = self.start_agent()
            call = self.wait_for_calls(2)[1].split()
            self.assertEqual(call[call.index("--session") + 1], str(second))
        finally:
            sup.send_signal(signal.SIGTERM)
            _, err = sup.communicate(timeout=30)
        self.assertEqual(sup.returncode, 0, err)
        self.assertIn("restarted; re-attaching", err)

    def test_a_collector_that_keeps_failing_ends_the_supervisor_with_its_status(self):
        self.start_agent()
        failing = self.tmp / "failing"
        failing.write_text("#!/bin/sh\nexit 3\n")
        failing.chmod(0o755)
        env = dict(os.environ, RAIL_DOCKER=str(self.docker))
        out = subprocess.run([sys.executable, str(SCRIPT), "--collector", str(failing), "agent"],
                             env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(out.returncode, 3, out.stderr)
        self.assertIn("giving up", out.stderr)


if __name__ == "__main__":
    unittest.main()
