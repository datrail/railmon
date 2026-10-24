#!/usr/bin/env python3
"""Keep a listener or file-open probe attached to one agent container's PID namespace (DR-143).

`railmon listen` with RAIL_LISTEN_CONTAINER set runs this. The supervisor
itself sits in the host PID namespace, so the agent cannot see or signal it.
Each round it asks Docker for the container's PID (for `openshell:<sandbox>`,
first which container is that sandbox's now, DR-247) and runs AgentSight's
process probe with `--pidns-of` that PID (DR-170), its events written in
listensnoop's lines by `agentsight_adapter.py`, appending to the output.
--pidns-of pins the namespace when the probe starts and does not die with
the agent, so the supervisor watches the container's PID and restarts the
probe when that changes. When the probe exits, because the agent restarted
or the probe was killed, the supervisor waits for the container and
attaches again.

Each attach starts with the probe's own `start` record. The probe does
not report sockets already listening when it attaches, and an agent that
listens as soon as it starts usually beats the attach. So right after the
start record the supervisor reads the agent's socket table and appends one
record per socket already open to accept traffic, in listensnoop's shape with
`"snapshot": true` (DR-182). A second start is how the scanner knows the
probe was down: a socket opened and closed in the gap is missing, and the
bundle says so instead of reading as "no new listeners".

The same supervisor runs the probe for `railmon files` (DR-154), written in
filesnoop's lines: `--command files` picks the mode and `--output` the file
it appends to (default RAIL_LISTEN_FILE). Its start records are the same, so
a restart shows the same way.

The probe reports a file once per process, so an agent that starts a new
process for each task re-reports the same files every time, and an always-on
output file grows without end while the scanner re-reads all of it. With
`--distinct-opens` the supervisor appends an open record only the first time
it sees that access to that file (DR-185), counting the records already in
the output file, so a restarted supervisor does not append them again. The
scanner keeps the union of each file's access with no counts, so the ASP is
the same; only the feature file's raw event counts (`outside_namespace`,
`unnamed`, `unlisted` and their `_write_exec` parts) count distinct records
instead of every one. Past 16,384 paths of a class, where the attribute is
already PARTIAL, which entries are listed may differ.

With `--source probe` the probe is an operator's own listensnoop or
filesnoop binary instead (`--probe`, else LISTENSNOOP_PATH): entered with
nsenter into the agent's PID namespace, it dies with the agent, and
everything after (the snapshot, distinct opens, the scanner) is the same.

Needs: `--pid host`, eBPF privilege, and the Docker socket.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time

POLL_SECONDS = 1.0
# The host's /proc: the supervisor runs in the host PID namespace.
PROC = "/proc"
# /proc/net socket states (include/net/tcp_states.h): a TCP socket in
# LISTEN, and a UDP one in CLOSE, which for UDP means bound but unconnected.
TCP_LISTEN, UDP_UNCONNECTED = "0A", "07"
SOCKET_TABLES = (
    ("tcp", socket.AF_INET, "tcp", TCP_LISTEN, "listen"),
    ("tcp6", socket.AF_INET6, "tcp", TCP_LISTEN, "listen"),
    ("udp", socket.AF_INET, "udp", UDP_UNCONNECTED, "bind"),
    ("udp6", socket.AF_INET6, "udp", UDP_UNCONNECTED, "bind"),
)


def _proc_address(text: str, family: int) -> tuple[str, int]:
    """`0100007F:1F90` -> ("127.0.0.1", 8080). The kernel prints the address
    as 32-bit words in host byte order; inet_ntop formats it the way
    listensnoop does, so both sources give one listener the same key."""
    address, port = text.split(":")
    raw = bytes.fromhex(address)
    if sys.byteorder == "little":
        raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    return socket.inet_ntop(family, raw), int(port, 16)


def _namespace_sockets(proc: str, pid: int) -> dict[int, tuple[int, str, int]]:
    """Socket inode -> (namespace PID, comm, host PID) for every process in
    `pid`'s PID namespace. A socket shared by several (a pre-forked server)
    goes to the lowest namespace PID, usually the one that opened it.

    The comm is the agent's to set, any bytes but NUL, so it is read as
    bytes and decoded one character per byte, as listensnoop escapes it:
    the same name gives the same key, and no name can make the read fail
    and drop the process's sockets. It is the main thread's name, where
    listensnoop has the binding thread's; they differ only for a socket
    bound in a thread named apart."""
    owners: dict[int, tuple[int, str, int]] = {}
    namespace = os.readlink(f"{proc}/{pid}/ns/pid")
    for entry in os.listdir(proc):
        if not entry.isdigit():
            continue
        base = f"{proc}/{entry}"
        try:
            if os.readlink(f"{base}/ns/pid") != namespace:
                continue
            with open(f"{base}/status", "rb") as f:
                nspid = next(int(line.split()[-1]) for line in f if line.startswith(b"NSpid:"))
            with open(f"{base}/comm", "rb") as f:
                comm = f.read().decode("latin-1").removesuffix("\n")
            links = [os.readlink(f"{base}/fd/{fd}") for fd in os.listdir(f"{base}/fd")]
        except (OSError, StopIteration, ValueError):
            continue  # gone meanwhile, or not ours to read
        for link in links:
            if link.startswith("socket:[") and link.endswith("]"):
                inode = int(link[8:-1])
                if inode not in owners or nspid < owners[inode][0]:
                    owners[inode] = (nspid, comm, int(entry))
    return owners


def listening_sockets(pid: int, proc: str = PROC, host_pids: bool = False) -> list[dict]:
    """The sockets `pid`'s container already has open to accept traffic, as
    listensnoop records with `"snapshot": true`. Each record's pid is as the
    container's namespace numbers it, as listensnoop writes it, or with
    `host_pids` the host's, as the AgentSight adapter writes it, so one file
    never mixes the two.

    Read from the network namespace of `pid` and kept only when a process in
    its PID namespace holds the socket, so another container sharing the
    network namespace stays out, as listensnoop's -n keeps it out. The
    kernel no longer says whether the port was chosen for the socket, so
    `ephemeral` is false: an unasked-for port shows as its number, which
    is churn at worst, never a hidden listener."""
    owners = _namespace_sockets(proc, pid)
    records = []
    for table, family, protocol, state, kind in SOCKET_TABLES:
        try:
            with open(f"{proc}/{pid}/net/{table}") as f:
                rows = f.read().splitlines()[1:]
        except OSError:
            continue  # no IPv6 in this kernel
        for row in rows:
            fields = row.split()
            if len(fields) < 10 or fields[3] != state:
                continue
            addr, port = _proc_address(fields[1], family)
            owner = owners.get(int(fields[9]))
            if port == 0 or owner is None:
                continue
            nspid, comm, host_pid = owner
            records.append({"kind": kind, "pid": host_pid if host_pids else nspid,
                            "uid": int(fields[7]), "comm": comm, "protocol": protocol,
                            "family": "ipv6" if family == socket.AF_INET6 else "ipv4",
                            "addr": addr, "port": port, "ephemeral": False, "snapshot": True})
    return records


def load_container_ref():
    """tools/scan/container_ref.py, loaded by path as load_adapter is: the
    scanner and the supervisors share one sandbox lookup (DR-247)."""
    spec = importlib.util.spec_from_file_location(
        "container_ref", os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir,
                                      "scan", "container_ref.py"))
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


container_ref = load_container_ref()
# The last problem logged for each reference, so a sandbox with two running
# containers is logged once, not on every poll.
_reported: dict[str, str | None] = {}


def container_pid(docker: str, container: str, log=None) -> int:
    """The container's init PID on the host, or 0 while it is not running.
    `container` may be `openshell:<sandbox>`, looked up again on every call,
    so a recreated sandbox's new container is the one found (DR-247). With
    `log`, a lookup problem is logged once until it changes."""
    resolved, problem = container_ref.resolve(container, docker)
    if log is not None and _reported.get(container) != problem:
        _reported[container] = problem
        if problem:
            log(f"{problem}; not attaching until exactly one runs")
    if resolved is None:
        return 0
    try:
        out = subprocess.run(
            [docker, "inspect", "-f", "{{.State.Pid}}", resolved],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 0
    try:
        return int(out.stdout.strip()) if out.returncode == 0 else 0
    except ValueError:
        return 0


def load_adapter():
    """agentsight_adapter.py beside this file, loaded by path: tests load
    this file the same way, without tools/listen on sys.path."""
    spec = importlib.util.spec_from_file_location(
        "agentsight_adapter", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "agentsight_adapter.py"))
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def stop_agentsight(child: subprocess.Popen) -> None:
    """AgentSight runs here, not under nsenter: signal it, and it stops the
    probe it started."""
    try:
        child.send_signal(signal.SIGTERM)
    except ProcessLookupError:
        pass


# Consecutive polls without an answer (container stopped, or docker
# inspect failing) before the probe is stopped anyway. One failed inspect
# must not restart it: the restart makes every attribute PARTIAL, which
# RailDash shows as drift for an agent that did not change.
WATCH_MISSES = 10


def watch_container(docker: str, container: str, pid: int, child: subprocess.Popen,
                    stop, misses: int = WATCH_MISSES) -> None:
    """Stop `child` once `container` is running as another PID, or has not
    answered for `misses` polls in a row. AgentSight's --pidns-of pins the
    namespace it started in, and outlives an agent restart that
    listensnoop, inside the namespace, dies with."""
    missed = 0
    while child.poll() is None:
        time.sleep(POLL_SECONDS)
        if child.poll() is not None:
            return
        current = container_pid(docker, container)
        missed = missed + 1 if not current else 0
        if (current and current != pid) or missed >= misses:
            stop(child)
            return


def stop_listensnoop(child: subprocess.Popen) -> None:
    """Signal listensnoop, not nsenter: nsenter forks for -p, and a signalled
    nsenter dies leaving its child running as an orphan. Right after Popen
    the fork may not have happened yet, so give it a moment to appear."""
    inner: list[int] = []
    for _ in range(20):
        try:
            with open(f"/proc/{child.pid}/task/{child.pid}/children") as f:
                inner = [int(pid) for pid in f.read().split()]
        except OSError:
            break  # nsenter already gone
        if inner or child.poll() is not None:
            break
        time.sleep(0.05)
    for pid in inner or [child.pid]:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass


# The railmon command this supervisor runs for, in its log prefix. `listen`
# by default, so existing log filters on "[railmon listen]" keep matching.
COMMAND = "listen"

# What makes two filesnoop open records the same access: everything the
# scanner reads, and the open flags, without the per-process and per-inode
# fields (pid, tid, comm, uid, timestamp, inode) that differ every time.
# Whether pid is 0 is kept, since the scanner counts those apart.
OPEN_KEY_FIELDS = ("path", "path_hex", "path_error", "layer", "read", "write", "exec",
                   "creat", "trunc", "append")
# Distinct records remembered, each as a 16-byte digest, so an agent naming
# its files with long paths can't grow the supervisor's memory with them
# (~100 bytes a key; a few MB at the cap). Past it, a new one is appended
# without being remembered: never dropped, only no longer de-duplicated.
DISTINCT_TRACKED = 65536
# A record longer than this is passed through, not parsed.
DISTINCT_LINE_MAX = 64 * 1024


def open_key(line: bytes) -> bytes | None:
    """The de-duplication key of a filesnoop open record, or None for any
    other line (start, alive, lost, malformed), which is always kept."""
    if len(line) > DISTINCT_LINE_MAX or not line.startswith(b"{"):
        return None
    try:
        record = json.loads(line)
    except ValueError:
        return None
    if not isinstance(record, dict) or record.get("kind") != "open":
        return None
    key = json.dumps([record.get("pid") == 0, *(record.get(name) for name in OPEN_KEY_FIELDS)],
                     sort_keys=True, separators=(",", ":"))
    return hashlib.blake2b(key.encode(), digest_size=16).digest()


def seen_opens(path: str | None) -> set[bytes]:
    """The keys of the open records already in the output file."""
    seen: set[bytes] = set()
    if not path:
        return seen
    try:
        with open(path, "rb") as existing:
            while len(seen) < DISTINCT_TRACKED:
                line = existing.readline(DISTINCT_LINE_MAX + 1)
                if not line:
                    break
                key = open_key(line)
                if key is not None:
                    seen.add(key)
    except OSError:
        pass
    return seen


def copy_distinct(stream, sink, seen: set[bytes]) -> None:
    """Copy the probe's lines to `sink`, leaving out an open record whose
    key is already in `seen` (DR-185)."""
    for line in stream:
        key = open_key(line)
        if key is not None:
            if key in seen:
                continue
            if len(seen) < DISTINCT_TRACKED:
                seen.add(key)
        sink.write(line)
        sink.flush()


def log(message: str) -> None:
    print(f"[railmon {COMMAND}] {message}", file=sys.stderr, flush=True)


def announce_attach(stream, probe_name: str):
    """Pass the probe's lines on, logging each start record as an attach:
    AgentSight's own log does not say so in words, as filesnoop's did."""
    for line in stream:
        if line.startswith(b'{"kind":"start"'):
            log(f"{probe_name} attached")
        yield line


def copy_with_snapshot(stream, sink, pid: int, probe_name: str, on_snapshot=None,
                       host_pids: bool = False) -> None:
    """Copy the probe's lines to `sink`, and after its start record append
    the sockets that were already listening. Taken after the probe attached,
    so nothing opened in between is missed, and a socket both report is
    usually one listener to the scanner. Not when the probe reported the
    port as kernel-chosen ("ephemeral"), which a snapshot lists by number:
    one opened in that instant, or one still open at a later reattach. A
    reattach already makes the bundle PARTIAL."""
    snapshotted = False
    for line in stream:
        sink.write(line)
        # Each line reaches stdout (`docker logs`) as soon as the probe
        # flushed it, as when the probe wrote there itself.
        sink.flush()
        if snapshotted or not line.startswith(b'{"kind":"start"'):
            continue
        snapshotted = True
        try:
            records = listening_sockets(pid, host_pids=host_pids)
        except OSError as exc:  # the agent exited meanwhile
            log(f"cannot read the sockets already listening: {exc}")
            continue
        if on_snapshot is not None:
            on_snapshot(records)
        sink.write(b"".join(json.dumps(r, separators=(",", ":")).encode() + b"\n" for r in records))
        sink.flush()
        log(f"{probe_name} attached; {len(records)} socket(s) were already listening")


def main() -> int:
    global COMMAND
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--command", default=COMMAND, help="railmon command, for the log prefix")
    parser.add_argument("--probe", help="probe binary for --source probe (default: LISTENSNOOP_PATH)")
    parser.add_argument("--output", help="file to append to; empty for stdout "
                        "(default: RAIL_LISTEN_FILE)")
    parser.add_argument("--snapshot-listeners", action="store_true",
                        help="after each attach, also record the sockets the agent already "
                        "has open to accept traffic (listensnoop only)")
    parser.add_argument("--distinct-opens", action="store_true",
                        help="append each distinct file open record once (files only)")
    parser.add_argument("--source", choices=("agentsight", "probe"), default="agentsight",
                        help="agentsight: AgentSight's process probe with --pidns-of, adapted "
                        "to listensnoop's or filesnoop's lines (DR-170, default); probe: an "
                        "operator's own --probe under nsenter")
    parser.add_argument("--heartbeat", type=int, default=60,
                        help="AgentSight's --heartbeat (--source agentsight only)")
    parser.add_argument("container", help="agent container name or id, or openshell:<sandbox>")
    parser.add_argument("listensnoop_args", nargs=argparse.REMAINDER,
                        help="arguments passed to the probe")
    args = parser.parse_args()

    docker = os.environ.get("RAIL_DOCKER", "docker")
    nsenter = os.environ.get("RAIL_NSENTER", "nsenter")
    listensnoop = args.probe or os.environ.get("LISTENSNOOP_PATH", "")
    COMMAND = args.command
    agentsight = args.source == "agentsight"
    if not agentsight and not listensnoop:
        parser.error("--source probe needs --probe or LISTENSNOOP_PATH")
    adapter_module = load_adapter() if agentsight else None
    if agentsight:
        adapter_module.ensure_tracefs(log)
    mode = "files" if args.command == "files" else "listen"
    probe_name = "agentsight" if agentsight else os.path.basename(listensnoop)
    stop_probe = stop_agentsight if agentsight else stop_listensnoop
    output = args.output if args.output is not None else os.environ.get("RAIL_LISTEN_FILE")
    sink = open(output, "ab", buffering=0) if output else sys.stdout.buffer
    seen = seen_opens(output) if args.distinct_opens else set()

    child: subprocess.Popen | None = None
    stopping = False

    def stop(signo, _frame):
        nonlocal stopping
        stopping = True
        if child and child.poll() is None:
            stop_probe(child)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    waiting_logged = False
    while not stopping:
        pid = container_pid(docker, args.container, log)
        if not pid:
            if not waiting_logged:
                log(f"waiting for container {args.container} to run")
                waiting_logged = True
            time.sleep(POLL_SECONDS)
            continue
        waiting_logged = False
        if stopping:  # a signal that landed during docker inspect
            break
        log(f"attaching to {args.container} (pid {pid})")
        if agentsight:
            # From here, in the host PID namespace: --pidns-of scopes it to
            # the agent's, which nsenter would otherwise do.
            command = adapter_module.probe_command(pid, args.heartbeat, mode, args.listensnoop_args)
        else:
            # -p only: listensnoop then lives in the agent's PID namespace (its
            # PIDs are the agent's) but keeps this container's mounts and BPF
            # privilege. nsenter forks for -p, so its child is the one inside.
            command = [nsenter, "-t", str(pid), "-p", "--", listensnoop, *args.listensnoop_args]
        child = subprocess.Popen(command,
                                 stdout=subprocess.PIPE
                                 if agentsight or args.snapshot_listeners or args.distinct_opens
                                 else sink)
        # A signal that landed before `child` was set found nothing to stop.
        # (Not a blocked mask around Popen: the child would inherit it, and
        # listensnoop would never see the SIGTERM meant for it.)
        if stopping:
            stop_probe(child)
        stream = child.stdout
        on_snapshot = None
        if agentsight:
            threading.Thread(target=watch_container, daemon=True,
                             args=(docker, args.container, pid, child, stop_probe)).start()
            adapter = adapter_module.Adapter(mode)
            on_snapshot = adapter.note_listeners
            stream = adapter_module.adapt_stream(child.stdout, adapter)
        if agentsight and not args.snapshot_listeners:
            stream = announce_attach(stream, probe_name)
        if args.snapshot_listeners:
            copy_with_snapshot(stream, sink, pid, probe_name, on_snapshot, host_pids=agentsight)
        elif args.distinct_opens:
            copy_distinct(stream, sink, seen)
        elif agentsight:
            for line in stream:
                sink.write(line)
                sink.flush()
        code = child.wait()
        child = None
        if not stopping:
            log(f"{probe_name} exited ({code}); reattaching")
            time.sleep(POLL_SECONDS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
