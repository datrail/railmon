"""AgentSight's process probe as `railmon listen`/`files`' source (DR-170).

The default source since AgentSight v1.0.35, the first release with
eunomia-bpf/agentsight#237 and the fix for #238. tests/fixtures/agentsight-v1.0.35
is a real capture by that release beside listensnoop and filesnoop. The synthetic
fixtures under tests/fixtures/agentsight-adapter model the 2026-10-08 parity run on
#237's head: `*.agentsight.jsonl` is the probe's output (the event shapes on
agentsight master: bpf/process.c, bpf/process_ext/map_flush.h), `*.expected.jsonl`
the adapter's golden output, and `*.listensnoop.jsonl` / `*.filesnoop.jsonl` what our
probes wrote for the same workload. Parity is checked where it matters: the scanner's
summary of either file is the same.
"""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "agentsight-adapter"
RELEASE = ROOT / "tests" / "fixtures" / "agentsight-v1.0.35"
ADAPTER = ROOT / "tools" / "listen" / "agentsight_adapter.py"
SUPERVISOR = ROOT / "tools" / "listen" / "follow_container.py"


def _load(name: str, path: Path):
    """A private copy, never put in sys.modules (see test_egress_containment)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


adapter = _load("agentsight_adapter", ADAPTER)
scanner = _load("scan_agent_environment", ROOT / "tools" / "scan" / "scan_agent_environment.py")
evidence_bundle = _load("evidence_bundle", ROOT / "tools" / "scan" / "evidence_bundle.py")

# Just after the fixtures' last heartbeat (10:00:04Z, every 2s): fresh.
NOW = datetime(2026, 10, 8, 10, 0, 5, tzinfo=timezone.utc)
WALL = 1791453600000000000  # 2026-10-08T10:00:00Z


def fixture(name: str) -> list[bytes]:
    return (FIXTURES / name).read_bytes().splitlines(keepends=True)


def adapt(lines, mode: str, instance=None) -> list[bytes]:
    return list(adapter.adapt_lines(lines, mode, instance))


def records(lines) -> list[dict]:
    return [json.loads(line) for line in lines]


def raw(**event) -> bytes:
    return json.dumps(event).encode() + b"\n"


def liveness(kind: str, k: int = 0, **extra) -> bytes:
    return raw(event="PROBE_LIVENESS", kind=kind, pid=0, comm="process", timestamp=k,
               wall_time_ns=WALL + k * 2_000_000_000, every=2, **extra)


def summary(kind: str, port: int, pid: int = 100, comm: str = "srv", **extra) -> bytes:
    return raw(timestamp=1, event="SUMMARY", comm=comm, pid=pid, process_start_ns=7,
               type=kind, detail="", count=1, port=port, **extra)


START = liveness("start", trace_net=True)
EXEC = raw(timestamp=2, event="EXEC", comm="srv", pid=100)
SNAPSHOT_FIELDS = ("listeners", "peers", "peers_reported", "lost", "unlisted", "peers_unlisted",
                   "malformed", "outside_namespace", "starts", "restarted", "last_alive", "stale")


class ReleaseParityTest(unittest.TestCase):
    """The real v1.0.35 capture (tests/fixtures/agentsight-v1.0.35/README.md):
    the scanner reads the same listeners, peers and files from it, adapted,
    as from listensnoop's and filesnoop's files for the same run, including
    a nested PID namespace's (agentsight#238), a child forked from a worker
    thread (#240), a process entered later, and nothing from outside."""

    @staticmethod
    def read(name: str) -> list[str]:
        return (RELEASE / name).read_bytes().decode("utf-8", "surrogateescape").splitlines()

    @staticmethod
    def adapted(mode: str) -> list[str]:
        lines = (RELEASE / "process.agentsight.jsonl").read_bytes().splitlines(keepends=True)
        return [line.decode("utf-8", "surrogateescape") for line in adapt(lines, mode)]

    @staticmethod
    def at_last_beat(summarize, lines):
        # Each probe's file read as of its own last heartbeat: the references
        # stopped when the workload's namespace ended, AgentSight later.
        result = summarize(lines, now=datetime(2026, 10, 23, tzinfo=timezone.utc))
        now = datetime.fromisoformat(result["last_alive"].replace("Z", "+00:00"))
        return summarize(lines, now=now)

    def test_listeners_and_peers(self):
        ours = self.at_last_beat(scanner.summarize_listeners, self.read("listen.listensnoop.jsonl"))
        theirs = self.at_last_beat(scanner.summarize_listeners, self.adapted("listen"))
        same = [k for k in SNAPSHOT_FIELDS if k != "last_alive"]
        self.assertEqual({k: theirs[k] for k in same}, {k: ours[k] for k in same})
        self.assertEqual((theirs["source"], ours["source"]), ("agentsight", "listensnoop"))
        ports = {entry["port"] for entry in theirs["listeners"]}
        # 7000 the nested namespace's, 7001 the thread-forked child's, 7002 the
        # entered process's; 7003 (outside) in neither.
        self.assertTrue({18170, 18171, 18172, 7000, 7001, 7002} <= ports, ports)
        self.assertNotIn(7003, ports)
        self.assertEqual(sum(entry["port"] == "ephemeral" for entry in theirs["listeners"]), 2)
        self.assertEqual(sorted(p["peer"] for p in theirs["peers"]), ["127.0.0.1", "::1"])
        self.assertEqual((theirs["stale"], theirs["lost"], theirs["outside_namespace"]), (False, 0, 0))

    def test_files(self):
        ours = self.at_last_beat(scanner.summarize_file_access, self.read("files.filesnoop.jsonl"))
        theirs = self.at_last_beat(scanner.summarize_file_access, self.adapted("files"))
        for result in (ours, theirs):
            result.pop("last_alive")
        self.assertEqual((theirs.pop("source"), ours.pop("source")), ("agentsight", "filesnoop"))
        self.assertEqual(theirs, ours)
        paths = {entry["path"] for entry in theirs["files"]}
        for name in ("nested.txt", "thread-child.txt", "exec.txt", "out.txt"):
            self.assertIn(f"/tmp/dr170w/{name}", paths)
        self.assertNotIn("/tmp/dr170w/control.txt", paths)
        self.assertEqual(sum(len(path) > 600 for path in paths), 1)  # the long path, whole
        # The two non-UTF-8 names print as one U+FFFD path, as filesnoop's do.
        self.assertEqual(sum(path.startswith("/tmp/dr170w/n\ufffd") for path in paths), 1)

class GoldenTest(unittest.TestCase):
    """The adapter's exact lines for the parity workload."""

    def test_listen(self):
        self.assertEqual(adapt(fixture("listen.agentsight.jsonl"), "listen"),
                         fixture("listen.expected.jsonl"))

    def test_files(self):
        self.assertEqual(adapt(fixture("files.agentsight.jsonl"), "files"),
                         fixture("files.expected.jsonl"))

    def test_the_debug_runners_wrapped_lines_adapt_the_same(self):
        # `agentsight debug process` prints a banner, then each event as
        # {"timestamp", "source": "process", "pid", "comm", "data": <raw>}.
        for mode in ("listen", "files"):
            wrapped = [b"Raw Process Events\n", b"=" * 40 + b"\n",
                       b"Starting process event stream with raw JSON output (press Ctrl+C to stop):\n"]
            for line in fixture(f"{mode}.agentsight.jsonl"):
                event = json.loads(line)
                wrapped.append(json.dumps({"timestamp": 1, "source": "process",
                                           "pid": event.get("pid", 0), "comm": event.get("comm", ""),
                                           "data": event}).encode() + b"\n")
            with self.subTest(mode=mode):
                self.assertEqual(adapt(wrapped, mode), fixture(f"{mode}.expected.jsonl"))

    def test_the_start_record_keeps_the_prefix_the_supervisor_looks_for(self):
        for mode in ("listen", "files"):
            first = adapt(fixture(f"{mode}.agentsight.jsonl"), mode)[0]
            self.assertTrue(first.startswith(b'{"kind":"start"'), first)


class ParityTest(unittest.TestCase):
    """What the scanner makes of each source's file for one workload: the
    2026-10-08 run's listeners (fixed, port 0, autobind, [::]:0, [::1], UDP),
    accepted peers (v4, v6, a v4 client of a dual-stack listener), and file
    opens (read, write, exec, creat/trunc/append, two non-UTF-8 names, a
    744-byte path, an unreadable path, a layer open, a loss)."""

    def test_listeners_and_peers(self):
        ours = scanner.summarize_listeners(
            [line.decode() for line in fixture("listen.listensnoop.jsonl")], now=NOW)
        theirs = scanner.summarize_listeners(
            [line.decode() for line in adapt(fixture("listen.agentsight.jsonl"), "listen")], now=NOW)
        self.assertEqual({k: theirs[k] for k in SNAPSHOT_FIELDS}, {k: ours[k] for k in SNAPSHOT_FIELDS})
        # Six listeners; the two kernel-chosen 0.0.0.0 ports are one "ephemeral" entry.
        self.assertEqual(len(theirs["listeners"]), 5)
        self.assertEqual([p["peer"] for p in theirs["peers"]], ["127.0.0.1", "127.0.0.1", "::1"])
        self.assertIs(theirs["peers_reported"], True)
        self.assertEqual((theirs["starts"], theirs["stale"]), (1, False))

    def test_resolved_file_opens(self):
        ours = scanner.summarize_file_access(
            [line.decode() for line in fixture("files.filesnoop.jsonl")], now=NOW)
        theirs = scanner.summarize_file_access(
            [line.decode() for line in adapt(fixture("files.agentsight.jsonl"), "files")], now=NOW)
        self.assertEqual((theirs.pop("source"), ours.pop("source")), ("agentsight", "filesnoop"))
        self.assertEqual(theirs, ours)
        self.assertEqual((theirs["unnamed"], theirs["lost"], theirs["starts"]), (1, 2, 1))

    def test_the_supervisor_dedupes_both_sources_alike(self):
        # `railmon files` keeps one record per distinct access (DR-185).
        def keys(lines):
            return {k for k in map(SUPERVISOR_MODULE.open_key, lines) if k is not None}
        ours = [line for line in fixture("files.filesnoop.jsonl")]
        theirs = adapt(fixture("files.agentsight.jsonl"), "files")
        self.assertEqual(len(keys(theirs)), len(keys(ours)))
        self.assertEqual(len(keys(theirs)), 9)  # the two non-UTF-8 names stay two

    def test_udp_send_without_bind_is_an_accepted_gap(self):
        # listensnoop's `autobind` (a UDP socket's first sendto() without a
        # bind); AgentSight does not report it, by design since #229.
        out = adapt([START, summary("NET_CONNECT", 0), EXEC], "listen")
        self.assertEqual([r["kind"] for r in records(out)], ["start"])


class ListenerMappingTest(unittest.TestCase):

    def test_ephemeral_is_a_port_the_process_did_not_ask_bind_for(self):
        out = records(adapt([
            START,
            summary("NET_BIND", 8080),  # bind() asked for 8080, in an earlier batch
            EXEC,
            summary("NET_LISTEN", 8080, protocol="tcp", address="0.0.0.0"),
            summary("NET_LISTEN", 8080, pid=101, protocol="tcp", address="0.0.0.0"),  # not its bind
            summary("NET_LISTEN", 9000, protocol="tcp", address="0.0.0.0"),
        ], "listen"))
        self.assertEqual([(r["pid"], r["port"], r["ephemeral"]) for r in out[1:]],
                         [(100, 8080, False), (101, 8080, True), (100, 9000, True)])

    def test_the_bare_fd_records_are_not_listeners(self):
        bare = raw(timestamp=1, event="SUMMARY", comm="srv", pid=100, process_start_ns=7,
                   type="NET_LISTEN", detail="fd=3", count=1, local_endpoint="fd=3")
        family = raw(timestamp=1, event="SUMMARY", comm="srv", pid=100, process_start_ns=7,
                     type="NET_BIND", detail="family=1", count=1, port=0)
        self.assertEqual(records(adapt([START, bare, family], "listen")),
                         [{"kind": "start", "time": "2026-10-08T10:00:00Z", "every": 2, "peers": True,
                           "probe": "agentsight"}])

    def test_datagram_protocols_listensnoop_names_are_binds(self):
        out = records(adapt([summary("NET_BIND", 5353, protocol=p, address="0.0.0.0")
                             for p in ("udp", "udplite", "icmp", "icmpv6")], "listen"))
        self.assertEqual([(r["kind"], r["protocol"]) for r in out],
                         [("bind", "udp"), ("bind", "udplite"), ("bind", "icmp"), ("bind", "icmpv6")])

    def test_addresses_are_written_as_inet_ntop_writes_them(self):
        cases = {
            "0000:0000:0000:0000:0000:0000:0000:0001": ("ipv6", "::1"),
            "fe80:0000:0000:0000:0000:0000:0000:00ab": ("ipv6", "fe80::ab"),
            "0000:0000:0000:0000:0000:ffff:7f00:0001": ("ipv6", "::ffff:127.0.0.1"),
            "10.1.2.3": ("ipv4", "10.1.2.3"),
        }
        for given, want in cases.items():
            with self.subTest(given=given):
                out = records(adapt([summary("NET_LISTEN", 80, protocol="tcp", address=given)], "listen"))
                self.assertEqual((out[0]["family"], out[0]["addr"]), want)

    def test_a_listener_it_cannot_write_is_a_gap(self):
        out = records(adapt([summary("NET_LISTEN", 80, protocol="tcp", address="fd=4")], "listen"))
        self.assertEqual(out, [{"kind": "lost", "count": 1}])

    def test_a_peer_on_a_snapshot_listener_takes_the_listeners_address(self):
        instance = adapter.Adapter("listen")
        instance.note_listeners([{"kind": "listen", "pid": 1, "comm": "srv", "protocol": "tcp",
                                  "family": "ipv4", "addr": "0.0.0.0", "port": 8443,
                                  "ephemeral": False, "snapshot": True}])
        accepted = summary("NET_ACCEPT", 8443, protocol="tcp", local_endpoint="172.17.0.2:8443",
                           address="172.17.0.2", peer="8.8.8.8")
        out = records(adapt([accepted], "listen", instance))
        self.assertEqual((out[0]["addr"], out[0]["peer"], out[0]["ephemeral"]),
                         ("0.0.0.0", "8.8.8.8", False))

    def test_a_peer_on_an_unseen_listener_falls_back_to_the_local_address(self):
        accepted = summary("NET_ACCEPT", 8443, protocol="tcp", local_endpoint="172.17.0.2:8443",
                           address="172.17.0.2", peer="8.8.8.8")
        out = records(adapt([accepted], "listen"))
        self.assertEqual((out[0]["kind"], out[0]["addr"], out[0]["family"]), ("peer", "172.17.0.2", "ipv4"))
        self.assertEqual(scanner.peer_scope(scanner._peer_address(out[0]["peer"])), "public")

    def test_process_names_are_one_character_per_byte_as_listensnoop_writes_them(self):
        out = records(adapt([summary("NET_LISTEN", 80, protocol="tcp", address="0.0.0.0",
                                     comm="naïve")], "listen"))
        # listensnoop escapes each byte >= 0x7f as \\u00XX.
        self.assertEqual(out[0]["comm"], "naÃ¯ve")

    def test_files_mode_ignores_network_and_listen_mode_ignores_files(self):
        opened = raw(timestamp=1, event="FILE_OPEN", comm="srv", pid=100, count=1, filepath="/a",
                     flags=0, read=True, write=False, exec=False, layer=False, dev=1, ino=1)
        overflow = raw(timestamp=0, event="WARNING", pid=0, type="AGG_MAP_OVERFLOW", overflow_count=4)
        self.assertEqual(adapt([summary("NET_LISTEN", 80, protocol="tcp", address="0.0.0.0"),
                                overflow], "files"), [])
        self.assertEqual(adapt([opened, raw(event="FILE_OPEN_LOST", pid=0, count=4)], "listen"), [])


class FileMappingTest(unittest.TestCase):

    def test_the_syscall_fallback_is_counted_never_listed(self):
        # On a kernel without the resolved hook AgentSight reports the path
        # as passed, with no access: not evidence of which file was opened.
        fallback = raw(timestamp=1, event="FILE_OPEN", comm="srv", pid=100, count=1,
                       filepath="relative.txt", flags=0o1101)
        out = records(adapt([liveness("start"), fallback], "files"))
        self.assertEqual(out[1]["path"], "")
        self.assertEqual((out[1]["write"], out[1]["creat"], out[1]["trunc"]), (True, True, True))
        result = scanner.summarize_file_access([json.dumps(r) for r in out], now=NOW)
        self.assertEqual((result["files"], result["unnamed"], result["unnamed_write_exec"]), ([], 1, 1))

    def test_dev_is_computed_from_the_raw_dev_not_dev_maj_min(self):
        # agentsight#235: dev_maj_min decodes the kernel dev_t as a userspace one.
        opened = raw(timestamp=1, event="FILE_OPEN", comm="srv", pid=100, count=1,
                     filepath="/etc/hostname", flags=0, read=True, write=False, exec=False,
                     layer=False, dev=271581185, dev_maj_min="0:66305", ino=5)
        self.assertEqual(records(adapt([opened], "files"))[0]["dev"], "259:1")


class LivenessTest(unittest.TestCase):
    """A dead or absent probe never reads as "nothing happened"."""

    def gaps(self, lines, mode, now=NOW):
        text = [line.decode() for line in adapt(lines, mode)]
        if mode == "listen":
            result = scanner.summarize_listeners(text, now=now)
            return evidence_bundle._probe_gaps(result, "listensnoop")
        result = scanner.summarize_file_access(text, now=now)
        return evidence_bundle._probe_gaps(result, "filesnoop")

    def test_a_probe_that_never_reported_liveness_is_unreachable(self):
        # No --heartbeat, or a probe that never started: no start record.
        gaps, unreachable = self.gaps([EXEC], "listen")
        self.assertTrue(unreachable)
        self.assertIn("no listensnoop start record (it may never have attached)", gaps)

    def test_liveness_without_wall_time_is_not_trusted(self):
        # v1.0.34's records had only a boot-time timestamp.
        old = raw(event="PROBE_LIVENESS", kind="start", timestamp=5, every=2)
        self.assertEqual(adapt([old], "files"), [])
        self.assertTrue(self.gaps([old], "files")[1])

    def test_a_start_without_trace_net_is_not_a_listener_probe(self):
        lines = [liveness("start", trace_net=False), liveness("alive", 1)]
        self.assertEqual(adapt(lines, "listen"), [])
        self.assertTrue(self.gaps(lines, "listen")[1])
        # The same probe still counts for files.
        self.assertEqual(len(adapt(lines, "files")), 2)

    def test_a_stopped_heartbeat_is_stale(self):
        lines = [START, liveness("alive", 1)]
        gaps, unreachable = self.gaps(lines, "listen", now=datetime(2026, 10, 8, 10, 1, tzinfo=timezone.utc))
        self.assertTrue(unreachable)
        self.assertIn("listensnoop stopped reporting (its heartbeat is stale)", gaps)
        self.assertEqual(self.gaps(lines, "listen"), ([], False))

    def test_a_restart_is_a_second_start(self):
        gaps, unreachable = self.gaps([START, liveness("alive", 1), liveness("start", 2, trace_net=True)],
                                      "listen")
        self.assertTrue(unreachable)
        self.assertIn("listensnoop restarted 1 time (what opened while it was down is missing)", gaps)

    def test_losses_are_lost_records(self):
        diagnostic = json.dumps({"timestamp": 1, "source": "diagnostic", "pid": 0, "comm": "",
                                 "data": {"reason": "missing pid", "parse_error_count": 1}}).encode()
        out = records(adapt([b"banner text\n", b'{"event": "FILE_OPEN", \n', diagnostic,
                             raw(event="FILE_OPEN_LOST", pid=0, comm="process", count=2)], "files"))
        self.assertEqual(out, [{"kind": "lost", "count": 1}, {"kind": "lost", "count": 1},
                               {"kind": "lost", "count": 2}])


class StreamTest(unittest.TestCase):

    def test_a_held_batch_is_written_when_the_stream_goes_quiet(self):
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "rb", buffering=0) as stream, os.fdopen(write_fd, "wb", buffering=0) as sink:
            sink.write(START + summary("NET_LISTEN", 80, protocol="tcp", address="0.0.0.0"))
            out = adapter.adapt_stream(stream, adapter.Adapter("listen"), idle=0.05)
            self.assertTrue(next(out).startswith(b'{"kind":"start"'))
            # The pipe is still open: only the idle pause ends the batch.
            self.assertIn(b'"kind":"listen"', next(out))
            sink.write(b'{"event":"PROBE_LIVENESS","kind":"alive","wall_time_ns":')
            threading.Timer(0.1, lambda: sink.write(b'%d,"every":2}\n' % WALL)).start()
            self.assertTrue(next(out).startswith(b'{"kind":"alive"'))

    def test_the_probe_command(self):
        with mock.patch.dict(os.environ, {"AGENTSIGHT_PATH": "/usr/local/bin/agentsight"}):
            os.environ.pop("RAIL_AGENTSIGHT_PROCESS", None)
            self.assertEqual(adapter.probe_command(4242, 60, "listen"),
                             ["/usr/local/bin/agentsight", "debug", "process", "--", "-m", "0",
                              "--pidns-of", "4242", "--trace-net", "--heartbeat", "60"])
            self.assertNotIn("--trace-net", adapter.probe_command(4242, 60, "files"))
        with mock.patch.dict(os.environ, {"RAIL_AGENTSIGHT_PROCESS": "/opt/process -v"}):
            self.assertEqual(adapter.probe_command(7, 5, "files", ["-x"]),
                             ["/opt/process", "-v", "-m", "0", "--pidns-of", "7", "--heartbeat", "5", "-x"])


SUPERVISOR_MODULE = _load("follow_container", SUPERVISOR)

# A stand-in for AgentSight: records its arguments, says it started, waits.
FAKE_AGENTSIGHT = """#!/bin/sh
echo "$*" >> "$FAKE_ARGS"
printf '%s\\n' '{"event":"PROBE_LIVENESS","kind":"start","pid":0,"comm":"process","timestamp":1,"wall_time_ns":1791453600000000000,"every":5,"trace_net":true}'
printf '%s\\n' '{"timestamp":1,"event":"FILE_OPEN","comm":"a","pid":5,"count":1,"filepath":"/a","flags":0,"read":true,"write":false,"exec":false,"layer":false,"dev":1,"ino":1}'
[ -n "$FAKE_EXIT" ] && exit 0
exec sleep 30
"""


class WiringTest(unittest.TestCase):
    """The selectors, the supervisor, and AgentSight as the default."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.args = self.dir / "args"
        fake = self.dir / "agentsight"
        fake.write_text(FAKE_AGENTSIGHT)
        fake.chmod(0o755)
        self.env = {**os.environ, "RAIL_AGENTSIGHT_PROCESS": str(fake), "FAKE_ARGS": str(self.args),
                    "RAILMON_ROOT": str(ROOT)}

    def tearDown(self):
        self.tmp.cleanup()

    def wait_for(self, predicate, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not predicate():
            time.sleep(0.05)
        return predicate()

    def test_the_supervisor_follows_the_container_and_restarts_on_a_new_pid(self):
        pid_file = self.dir / "pid"
        pid_file.write_text("4242\n")
        docker = self.dir / "docker"
        docker.write_text(f'#!/bin/sh\ncat "{pid_file}"\n')
        docker.chmod(0o755)
        output = self.dir / "files.jsonl"
        supervisor = subprocess.Popen(
            [sys.executable, str(SUPERVISOR), "--source", "agentsight", "--command", "files",
             "--output", str(output), "--distinct-opens", "--heartbeat", "5", "agent"],
            env={**self.env, "RAIL_DOCKER": str(docker)}, stderr=subprocess.PIPE, text=True)
        try:
            self.assertTrue(self.wait_for(lambda: output.exists() and output.read_text().count("\n") >= 2))
            pid_file.write_text("4343\n")  # the agent restarted
            self.assertTrue(self.wait_for(lambda: output.read_text().count('"kind":"start"') >= 2))
        finally:
            supervisor.send_signal(signal.SIGTERM)
            _, stderr = supervisor.communicate(timeout=20)
        lines = records(output.read_bytes().splitlines())
        self.assertEqual([r["kind"] for r in lines], ["start", "open", "start"])  # the open once (DR-185)
        self.assertEqual(self.args.read_text().splitlines(),
                         ["-m 0 --pidns-of 4242 --heartbeat 5", "-m 0 --pidns-of 4343 --heartbeat 5"])
        self.assertIn("[railmon files] attaching to agent (pid 4343)", stderr)
        self.assertEqual(supervisor.returncode, 0)

    def test_the_entrypoint_runs_agentsight_by_default(self):
        listen = self.dir / "listen.jsonl"
        env = {k: v for k, v in self.env.items() if k not in ("RAIL_LISTEN_SOURCE", "RAIL_LISTEN_CONTAINER")}
        run = subprocess.run([str(ROOT / "entrypoint.sh"), "listen"],
                             env={**env, "FAKE_EXIT": "1",
                                  "RAIL_LISTEN_FILE": str(listen), "RAIL_LISTEN_HEARTBEAT": "5"},
                             capture_output=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(records(listen.read_bytes().splitlines()),
                         [{"kind": "start", "time": "2026-10-08T10:00:00Z", "every": 5, "peers": True,
                           "probe": "agentsight"}])
        args = self.args.read_text().split()
        # Its own PID namespace, as listensnoop -n: the agent's under --pid container:.
        self.assertEqual(args[:3] + args[4:], ["-m", "0", "--pidns-of", "--trace-net", "--heartbeat", "5"])
        self.assertTrue(args[3].isdigit())

    def test_an_operators_own_listensnoop_or_filesnoop_runs_when_asked(self):
        for command, var, source, probe_var in (
                ("listen", "RAIL_LISTEN_SOURCE", "listensnoop", "LISTENSNOOP_PATH"),
                ("files", "RAIL_FILES_SOURCE", "filesnoop", "FILESNOOP_PATH")):
            probe = self.dir / command
            probe.write_text('#!/bin/sh\necho "probe $*"\n')
            probe.chmod(0o755)
            env = {k: v for k, v in self.env.items()
                   if k not in ("RAIL_LISTEN_CONTAINER", "RAIL_FILES_CONTAINER", "RAIL_LISTEN_FILE",
                                "RAIL_FILES_FILE", "LISTENSNOOP_PATH", "FILESNOOP_PATH")}
            run = subprocess.run([str(ROOT / "entrypoint.sh"), command],
                                 env={**env, var: source, probe_var: str(probe)},
                                 capture_output=True, text=True, timeout=30)
            # The image ships neither, so without a path it is refused.
            missing = subprocess.run([str(ROOT / "entrypoint.sh"), command], env={**env, var: source},
                                     capture_output=True, text=True, timeout=30)
            with self.subTest(command=command):
                self.assertEqual(run.stdout, "probe -n -H 60\n")
                self.assertFalse(self.args.exists())
                self.assertEqual(missing.returncode, 64)
                self.assertIn(f"needs {probe_var}", missing.stderr)

    def test_an_unknown_source_is_refused(self):
        for command, var in (("listen", "RAIL_LISTEN_SOURCE"), ("files", "RAIL_FILES_SOURCE")):
            run = subprocess.run([str(ROOT / "entrypoint.sh"), command], env={**self.env, var: "ebpf"},
                                 capture_output=True, text=True, timeout=30)
            with self.subTest(command=command):
                self.assertEqual(run.returncode, 64)
                self.assertIn(f"{var} must be", run.stderr)


if __name__ == "__main__":
    unittest.main()
