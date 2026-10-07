#!/usr/bin/env python3
"""Keep listensnoop attached to one agent container's PID namespace (DR-143).

`railmon listen` with RAIL_LISTEN_CONTAINER set runs this. The supervisor
itself sits in the host PID namespace, so the agent cannot see or signal it.
Each round it asks Docker for the container's PID, enters that namespace with
nsenter, and runs listensnoop there, appending to the output. When listensnoop
exits, because the agent restarted (its namespace died with it) or the agent
killed it, the supervisor waits for the container and attaches again.

Each attach starts with listensnoop's own `start` record. listensnoop does
not report sockets already listening when it attaches, and an agent that
listens as soon as it starts usually beats the attach. So right after the
start record the supervisor reads the agent's socket table and appends one
record per socket already open to accept traffic, in listensnoop's shape with
`"snapshot": true` (DR-182). A second start is how the scanner knows the
probe was down: a socket opened and closed in the gap is missing, and the
bundle says so instead of reading as "no new listeners".

The same supervisor runs filesnoop for `railmon files` (DR-154): `--probe`
names the binary and `--output` the file it appends to. Without them it is
listensnoop (LISTENSNOOP_PATH) appending to RAIL_LISTEN_FILE, as before.
filesnoop prints the same start records, so a restart shows the same way.

filesnoop reports a file once per process, so an agent that starts a new
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

Needs: `--pid host`, eBPF privilege, and the Docker socket.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
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


def _namespace_sockets(proc: str, pid: int) -> dict[int, tuple[int, str]]:
    """Socket inode -> (namespace PID, comm) for every process in
    `pid`'s PID namespace. A socket shared by several (a pre-forked server)
    goes to the lowest namespace PID, usually the one that opened it.

    The comm is the agent's to set, any bytes but NUL, so it is read as
    bytes and decoded one character per byte, as listensnoop escapes it:
    the same name gives the same key, and no name can make the read fail
    and drop the process's sockets. It is the main thread's name, where
    listensnoop has the binding thread's; they differ only for a socket
    bound in a thread named apart."""
    owners: dict[int, tuple[int, str]] = {}
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
                    owners[inode] = (nspid, comm)
    return owners


def listening_sockets(pid: int, proc: str = PROC) -> list[dict]:
    """The sockets `pid`'s container already has open to accept traffic, as
    listensnoop records with `"snapshot": true`.

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
            nspid, comm = owner
            records.append({"kind": kind, "pid": nspid,
                            "uid": int(fields[7]), "comm": comm, "protocol": protocol,
                            "family": "ipv6" if family == socket.AF_INET6 else "ipv4",
                            "addr": addr, "port": port, "ephemeral": False, "snapshot": True})
    return records


def container_pid(docker: str, container: str) -> int:
    """The container's init PID on the host, or 0 while it is not running."""
    try:
        out = subprocess.run(
            [docker, "inspect", "-f", "{{.State.Pid}}", container],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 0
    try:
        return int(out.stdout.strip()) if out.returncode == 0 else 0
    except ValueError:
        return 0


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


def copy_with_snapshot(stream, sink, pid: int, probe_name: str) -> None:
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
            records = listening_sockets(pid)
        except OSError as exc:  # the agent exited meanwhile
            log(f"cannot read the sockets already listening: {exc}")
            continue
        sink.write(b"".join(json.dumps(r, separators=(",", ":")).encode() + b"\n" for r in records))
        sink.flush()
        log(f"{probe_name} attached; {len(records)} socket(s) were already listening")


def main() -> int:
    global COMMAND
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--command", default=COMMAND, help="railmon command, for the log prefix")
    parser.add_argument("--probe", help="probe binary (default: LISTENSNOOP_PATH, else listensnoop)")
    parser.add_argument("--output", help="file to append to; empty for stdout "
                        "(default: RAIL_LISTEN_FILE)")
    parser.add_argument("--snapshot-listeners", action="store_true",
                        help="after each attach, also record the sockets the agent already "
                        "has open to accept traffic (listensnoop only)")
    parser.add_argument("--distinct-opens", action="store_true",
                        help="append each distinct file open record once (filesnoop only)")
    parser.add_argument("container", help="agent container name or id")
    parser.add_argument("listensnoop_args", nargs=argparse.REMAINDER,
                        help="arguments passed to the probe")
    args = parser.parse_args()

    docker = os.environ.get("RAIL_DOCKER", "docker")
    nsenter = os.environ.get("RAIL_NSENTER", "nsenter")
    listensnoop = args.probe or os.environ.get("LISTENSNOOP_PATH", "/usr/local/bin/listensnoop")
    COMMAND = args.command
    probe_name = os.path.basename(listensnoop)
    output = args.output if args.output is not None else os.environ.get("RAIL_LISTEN_FILE")
    sink = open(output, "ab", buffering=0) if output else sys.stdout.buffer
    seen = seen_opens(output) if args.distinct_opens else set()

    child: subprocess.Popen | None = None
    stopping = False

    def stop(signo, _frame):
        nonlocal stopping
        stopping = True
        if child and child.poll() is None:
            stop_listensnoop(child)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    waiting_logged = False
    while not stopping:
        pid = container_pid(docker, args.container)
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
        # -p only: listensnoop then lives in the agent's PID namespace (its
        # PIDs are the agent's) but keeps this container's mounts and BPF
        # privilege. nsenter forks for -p, so its child is the one inside.
        child = subprocess.Popen([nsenter, "-t", str(pid), "-p", "--", listensnoop,
                                  *args.listensnoop_args],
                                 stdout=subprocess.PIPE if args.snapshot_listeners or args.distinct_opens
                                 else sink)
        # A signal that landed before `child` was set found nothing to stop.
        # (Not a blocked mask around Popen: the child would inherit it, and
        # listensnoop would never see the SIGTERM meant for it.)
        if stopping:
            stop_listensnoop(child)
        if args.snapshot_listeners:
            copy_with_snapshot(child.stdout, sink, pid, probe_name)
        elif args.distinct_opens:
            copy_distinct(child.stdout, sink, seen)
        code = child.wait()
        child = None
        if not stopping:
            log(f"{probe_name} exited ({code}); reattaching")
            time.sleep(POLL_SECONDS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
