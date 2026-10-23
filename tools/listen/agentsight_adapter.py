#!/usr/bin/env python3
"""Turn AgentSight's process-probe events into listensnoop/filesnoop lines (DR-170).

`railmon listen` and `railmon files` run AgentSight this way by default
since AgentSight v1.0.35, the first release with the `--pidns-of` scope and
streamed liveness (eunomia-bpf/agentsight#237) and nested PID namespaces
kept (#238); see the README.

`agentsight debug process -- -m 0 --pidns-of PID --trace-net --heartbeat N`
prints one JSON line per probe event, either raw (`{"event": ...}`) or
wrapped by AgentSight's runner (`{"source": "process", "data": {...}}`).
This writes the lines the scanner already reads from listensnoop (`--mode
listen`) and filesnoop (`--mode files`), so `scan --listen-file` and `scan
--files-file` read either source unchanged:

- liveness: PROBE_LIVENESS start/alive, by `wall_time_ns`, become the
  probes' `{"kind":"start"|"alive","time":...,"every":N}`, and a start
  names its probe, `"probe":"agentsight"`, which the bundle repeats. A start whose
  `--trace-net` is off is not a listener probe, so in listen mode its
  liveness is withheld: the file then has no start record and the scanner
  says the probe may never have attached, never "no listeners". A probe
  without `--heartbeat`, or one too old for `wall_time_ns`, likewise
  writes no start;
- listeners: a NET_LISTEN that names its protocol (not the bare `fd=N` one)
  is a `listen`, and a NET_BIND that names one (a datagram socket's bound
  port) is a `bind`, the protocols listensnoop reports. A port is
  `ephemeral` unless the same process asked bind() for it, as AgentSight's
  protocol-less NET_BIND records say;
- peers: a NET_ACCEPT is a `peer` on its listener, joined on (process,
  protocol, port): its `local_endpoint` is the accepted socket's address,
  not the listener's. A listener this run never saw opening (one already
  listening at attach, as `railmon listen`'s snapshot records it) is found
  by (protocol, port); failing that the accepted socket's local address
  stands in for it;
- addresses are written the way listensnoop's inet_ntop writes them, so an
  IPv6 address AgentSight writes fully expanded keys the same listener;
- file opens: a resolved FILE_OPEN is an `open` with its path, path_hex,
  path_error, layer, read/write/exec, creat/trunc/append from its open
  flags, and dev as major:minor computed from the raw dev (agentsight#235:
  its dev_maj_min is wrong). An unresolved one (AgentSight's syscall
  fallback, on a kernel without the resolved hook) has no trustworthy path
  or access, so it is an open with no path, which the scanner counts as
  unnamed: a gap, never a file it invents;
- losses: FILE_OPEN_LOST (files) and AGG_MAP_OVERFLOW (listen; the network
  summaries live in that map) become `{"kind":"lost"}`, as does a runner
  parse error or an unreadable event line in either mode.

AgentSight prints its network summaries in batches, one map flush at a
time, in hash order, so a listener can come before the bind that asked for
its port. Network records are held until the batch ends: the next line that
is not a SUMMARY, an idle pause in the stream, or its end.

Kept apart, as before: everything here is `observed`; nothing is declared,
attested or inferred. What AgentSight does not report stays missing rather
than filled in, so pid is the host PID (the scanner only reads whether it
is 0, and --pidns-of already leaves other namespaces out), and tid and uid
are not written.

Known gap against listensnoop/filesnoop, recorded on DR-170: a UDP socket
that sends without binding (listensnoop's `autobind`) is not reported, by
AgentSight's design since #229. Accepted. A process in a PID namespace
nested inside the agent's (a sandboxed tool call) is kept since v1.0.35
(#238), as listensnoop -n keeps it.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import select
import shlex
import signal
import socket
import subprocess
import sys
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

# Open flags (asm-generic, which x86-64 and arm64 both use).
O_ACCMODE, O_WRONLY, O_RDWR = 0o3, 0o1, 0o2
O_CREAT, O_TRUNC, O_APPEND = 0o100, 0o1000, 0o2000
# Kernel-internal dev_t: 12-bit major above a 20-bit minor (MINORBITS).
MINORBITS = 20
# What an unresolved open's path_error says: the probe could not resolve it.
EOPNOTSUPP = 95
# Protocols listensnoop names; AgentSight writes the same names.
PROTOCOLS = {"tcp", "udp", "udplite", "icmp", "icmpv6", "mptcp"}
DATAGRAM_PROTOCOLS = {"udp", "udplite", "icmp", "icmpv6"}
# Remembered binds and listeners, each; past it the oldest go first.
TRACKED = 65536
# A line longer than this is a gap, not parsed.
LINE_MAX = 256 * 1024
# How long the stream may sit quiet before a held batch is written.
IDLE_SECONDS = 0.5


def _bounded_set(store: OrderedDict, key: Any, value: Any = True) -> None:
    store[key] = value
    store.move_to_end(key)
    while len(store) > TRACKED:
        store.popitem(last=False)


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _address(value: Any) -> tuple[str, str] | None:
    """("ipv4"|"ipv6", inet_ntop's text) for an address AgentSight wrote,
    IPv6 fully expanded or not, or None."""
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        address = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        if address.scope_id is not None:
            return None
        return "ipv6", socket.inet_ntop(socket.AF_INET6, address.packed)
    return "ipv4", socket.inet_ntop(socket.AF_INET, address.packed)


def _peer(value: Any) -> str | None:
    """A peer as listensnoop writes it: an IPv4 client of a dual-stack
    listener is the IPv4 address it is."""
    parsed = _address(value)
    if parsed is None:
        return None
    family, text = parsed
    if family == "ipv6":
        mapped = ipaddress.IPv6Address(text).ipv4_mapped
        if mapped is not None:
            return str(mapped)
    return text


def _comm(value: Any) -> str:
    """The process name one character per byte, as listensnoop escapes it,
    so one name keys the same whichever probe wrote it."""
    if not isinstance(value, str):
        return ""
    return value.encode("utf-8", "surrogateescape").decode("latin-1")


def _time(wall_time_ns: Any) -> str | None:
    ns = _int(wall_time_ns)
    if ns is None or ns <= 0:
        return None
    try:
        return datetime.fromtimestamp(ns / 1e9, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


class Adapter:
    """One AgentSight process stream, as listensnoop's (`listen`) or
    filesnoop's (`files`) records. `feed` takes a line and returns the
    records it completes; `flush` ends the current network batch."""

    def __init__(self, mode: str) -> None:
        if mode not in ("listen", "files"):
            raise ValueError(f"mode must be listen or files, not {mode!r}")
        self.mode = mode
        # (pid, process start, port) a process asked bind() for.
        self.asked: OrderedDict = OrderedDict()
        # (pid, process start, protocol, port) -> (family, addr, ephemeral).
        self.listeners: OrderedDict = OrderedDict()
        # (protocol, port) -> the same, for a peer whose process is not known.
        self.by_port: OrderedDict = OrderedDict()
        self.pending: list[dict[str, Any]] = []
        # Whether the newest start record traced the network (listen only).
        self.net_traced: bool | None = None

    # ── input ────────────────────────────────────────────────────────────

    def feed(self, line: bytes | str) -> list[dict[str, Any]]:
        if isinstance(line, str):
            line = line.encode("utf-8", "surrogateescape")
        line = line.strip()
        if not line.startswith(b"{"):
            return []  # blank, or the runner's banner text
        if len(line) > LINE_MAX:
            return [*self.flush(), self._lost(1)]
        try:
            record = json.loads(line.decode("utf-8", "surrogateescape"), strict=False)
        except ValueError:
            return [*self.flush(), self._lost(1)]
        if not isinstance(record, dict):
            return [*self.flush(), self._lost(1)]
        if "event" not in record and isinstance(record.get("data"), dict):
            data = record["data"]
            if record.get("source") != "process":
                # A runner diagnostic: a parse error is an event it dropped.
                failed = "parse_error_count" in data or data.get("reason")
                return [*self.flush(), self._lost(1)] if failed else []
            record = data
        event = record.get("event")
        if event == "SUMMARY":
            self._summary(record)
            return []
        out = self.flush()
        if event == "PROBE_LIVENESS":
            out.extend(self._liveness(record))
        elif event == "FILE_OPEN" and self.mode == "files":
            out.append(self._open(record))
        elif event == "FILE_OPEN_LOST" and self.mode == "files":
            count = _int(record.get("count"))
            if count:
                out.append(self._lost(count))
        elif (event == "WARNING" and record.get("type") == "AGG_MAP_OVERFLOW"
              and self.mode == "listen"):
            count = _int(record.get("overflow_count"))
            if count:
                out.append(self._lost(count))
        return out

    def flush(self) -> list[dict[str, Any]]:
        """End the network batch: listeners first, so a peer in the same
        batch finds its listener."""
        pending, self.pending = self.pending, []
        out = []
        for record in pending:
            if record.get("type") != "NET_ACCEPT":
                out.append(self._listener(record))
        for record in pending:
            if record.get("type") == "NET_ACCEPT":
                out.append(self._accept(record))
        return [record for record in out if record is not None]

    def note_listeners(self, records: Iterable[dict[str, Any]]) -> None:
        """Listeners found already open at attach (`railmon listen`'s
        snapshot), so a peer on one finds its bound address."""
        for record in records:
            parsed = _address(record.get("addr"))
            port, protocol = _int(record.get("port")), record.get("protocol")
            if parsed is not None and port is not None and protocol in PROTOCOLS:
                _bounded_set(self.by_port, (protocol, port),
                             (parsed[0], parsed[1], record.get("ephemeral") is True))

    # ── mapping ──────────────────────────────────────────────────────────

    @staticmethod
    def _lost(count: int) -> dict[str, Any]:
        return {"kind": "lost", "count": count}

    def _liveness(self, record: dict[str, Any]) -> list[dict[str, Any]]:
        kind, every, stamp = record.get("kind"), _int(record.get("every")), _time(record.get("wall_time_ns"))
        if kind not in ("start", "alive") or every is None or stamp is None:
            return []
        if kind == "start":
            self.net_traced = record.get("trace_net") is True
        # A start names its probe, so the bundle says which one observed
        # (the scanner's PROBE_NAMES); an alive needs no name.
        named = {"probe": "agentsight"} if kind == "start" else {}
        if self.mode == "files":
            return [{"kind": kind, "time": stamp, "every": every, **named}]
        if self.net_traced is False:
            return []  # not a listener probe: no start, so never "no listeners"
        return [{"kind": kind, "time": stamp, "every": every, "peers": True, **named}]

    def _summary(self, record: dict[str, Any]) -> None:
        if self.mode != "listen":
            return
        kind = record.get("type")
        pid, start, port = _int(record.get("pid")), _int(record.get("process_start_ns")), _int(record.get("port"))
        if kind == "NET_BIND" and "protocol" not in record:
            # bind()'s own request: a port asked for is not ephemeral.
            if pid is not None and port:
                _bounded_set(self.asked, (pid, start, port))
            return
        if kind in ("NET_LISTEN", "NET_BIND", "NET_ACCEPT") and "protocol" in record:
            self.pending.append(record)

    def _base(self, record: dict[str, Any], kind: str) -> dict[str, Any]:
        pid = _int(record.get("pid")) or 0
        out = {"kind": kind, "pid": pid, "host_pid": pid, "comm": _comm(record.get("comm"))}
        timestamp = _int(record.get("timestamp"))
        return {"timestamp_ns": timestamp, **out} if timestamp is not None else out

    def _listener(self, record: dict[str, Any]) -> dict[str, Any] | None:
        protocol, port, pid = record.get("protocol"), _int(record.get("port")), _int(record.get("pid"))
        kind = "listen" if record.get("type") == "NET_LISTEN" else "bind"
        parsed = _address(record.get("address"))
        if (kind == "bind" and protocol not in DATAGRAM_PROTOCOLS) or protocol not in PROTOCOLS:
            return None
        if parsed is None or port is None or not 0 < port <= 65535 or pid is None:
            return self._lost(1)  # a listener opened that cannot be written
        start = _int(record.get("process_start_ns"))
        ephemeral = (pid, start, port) not in self.asked
        family, addr = parsed
        _bounded_set(self.listeners, (pid, start, protocol, port), (family, addr, ephemeral))
        _bounded_set(self.by_port, (protocol, port), (family, addr, ephemeral))
        return {**self._base(record, kind), "protocol": protocol, "family": family,
                "addr": addr, "port": port, "ephemeral": ephemeral}

    def _accept(self, record: dict[str, Any]) -> dict[str, Any] | None:
        protocol, port, pid = record.get("protocol"), _int(record.get("port")), _int(record.get("pid"))
        peer = _peer(record.get("peer"))
        if protocol not in PROTOCOLS or port is None or pid is None or peer is None:
            return self._lost(1)
        listener = (self.listeners.get((pid, _int(record.get("process_start_ns")), protocol, port))
                    or self.by_port.get((protocol, port)))
        if listener is None:
            local = _address(record.get("address"))
            if local is None:
                return self._lost(1)
            listener = (local[0], local[1], False)
        family, addr, ephemeral = listener
        return {**self._base(record, "peer"), "protocol": protocol, "family": family,
                "addr": addr, "port": port, "ephemeral": ephemeral, "peer": peer}

    def _open(self, record: dict[str, Any]) -> dict[str, Any]:
        flags = _int(record.get("flags")) or 0
        out = self._base(record, "open")
        access = [record.get(name) for name in ("read", "write", "exec")]
        if not all(isinstance(flag, bool) for flag in access):
            # The syscall fallback: the path as passed, not resolved, and no
            # access the kernel granted. Counted, not listed.
            mode = flags & O_ACCMODE
            return {**out, "path": "", "path_error": -EOPNOTSUPP,
                    "read": mode != O_WRONLY, "write": mode in (O_WRONLY, O_RDWR), "exec": False,
                    "creat": bool(flags & O_CREAT), "trunc": bool(flags & O_TRUNC),
                    "append": bool(flags & O_APPEND)}
        path = record.get("filepath")
        out["path"] = path if isinstance(path, str) else ""
        if isinstance(record.get("filepath_hex"), str):
            out["path_hex"] = record["filepath_hex"]
        path_error = _int(record.get("path_error"))
        if path_error:
            out["path_error"] = path_error
        if record.get("layer") is True:
            out["layer"] = True
        read, write, run = access
        out.update(read=read, write=write, exec=run,
                   creat=bool(flags & O_CREAT), trunc=bool(flags & O_TRUNC),
                   append=bool(flags & O_APPEND))
        dev = _int(record.get("dev"))
        if dev is not None:
            out["dev"] = f"{dev >> MINORBITS}:{dev & ((1 << MINORBITS) - 1)}"
        ino = _int(record.get("ino"))
        if ino is not None:
            out["ino"] = ino
        return out


def render(record: dict[str, Any]) -> bytes:
    """One line, `kind` first where the probes put it first, so `railmon
    listen`'s supervisor still finds the start record by its prefix."""
    return json.dumps(record, separators=(",", ":")).encode() + b"\n"


def adapt_lines(lines: Iterable[bytes | str], mode: str, adapter: Adapter | None = None) -> Iterator[bytes]:
    """Every line of a finished capture, adapted (the parity run, tests)."""
    adapter = adapter or Adapter(mode)
    for line in lines:
        for record in adapter.feed(line):
            yield render(record)
    for record in adapter.flush():
        yield render(record)


def adapt_stream(stream, adapter: Adapter, idle: float = IDLE_SECONDS) -> Iterator[bytes]:
    """A live probe's stdout, adapted as it arrives. A held network batch
    is written once the stream has been quiet for `idle` seconds, so a
    listener never waits for the next heartbeat."""
    fd = stream.fileno()
    buffered = b""
    while True:
        ready, _, _ = select.select([fd], [], [], idle)
        if not ready:
            for record in adapter.flush():
                yield render(record)
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        buffered += chunk
        *lines, buffered = buffered.split(b"\n")
        if len(buffered) > LINE_MAX:
            lines.append(buffered)  # too long; feed() counts it as lost
            buffered = b""
        for line in lines:
            for record in adapter.feed(line):
                yield render(record)
    for record in adapter.feed(buffered) if buffered else ():
        yield render(record)
    for record in adapter.flush():
        yield render(record)


# ── running the probe ─────────────────────────────────────────────────────


# The two places libbpf reads a tracepoint's ID from. The process probe
# attaches sched/sched_process_exec and the syscall tracepoints, so without
# a mounted tracefs it fails to attach (-ENOENT). A privileged container
# gets sysfs but not tracefs; `collect`'s TLS uprobes never needed it.
TRACEFS = ("/sys/kernel/tracing", "/sys/kernel/debug/tracing")


def ensure_tracefs(log=lambda message: print(message, file=sys.stderr, flush=True),
                   roots: Iterable[str] = TRACEFS, mount: str = "mount") -> bool:
    """Mount tracefs at the first of `roots` when none has tracepoints yet.
    True when one has them. A refused mount (no CAP_SYS_ADMIN) is logged,
    not raised: AgentSight then fails to attach, writes no start record, and
    the scan says the probe never attached."""
    roots = list(roots)
    if any(os.path.isdir(os.path.join(root, "events")) for root in roots):
        return True
    try:
        done = subprocess.run([mount, "-t", "tracefs", "tracefs", roots[0]],
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log(f"cannot mount tracefs at {roots[0]}: {exc}")
        return False
    if done.returncode != 0:
        log(f"cannot mount tracefs at {roots[0]}: {done.stderr.strip() or done.returncode}")
        return False
    return os.path.isdir(os.path.join(roots[0], "events"))


def probe_command(pid: int, heartbeat: int, mode: str, extra: Iterable[str] = ()) -> list[str]:
    """AgentSight's process probe scoped to `pid`'s PID namespace.
    RAIL_AGENTSIGHT_PROCESS overrides how it is run (default `$AGENTSIGHT_PATH
    debug process --`), for the release's own invocation or a local build."""
    prefix = os.environ.get("RAIL_AGENTSIGHT_PROCESS")
    if prefix:
        command = shlex.split(prefix)
    else:
        command = [os.environ.get("AGENTSIGHT_PATH", "agentsight"), "debug", "process", "--"]
    command += ["-m", "0", "--pidns-of", str(pid)]
    if mode == "listen":
        command.append("--trace-net")
    return [*command, "--heartbeat", str(heartbeat), *extra]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", choices=("listen", "files"), required=True)
    parser.add_argument("--input", help="adapt this finished capture ('-' for stdin) "
                        "instead of running AgentSight")
    parser.add_argument("--pidns-of", type=int, default=0,
                        help="trace this PID's namespace (default: this process's own, "
                        "as listensnoop -n does)")
    parser.add_argument("--heartbeat", type=int, default=60)
    parser.add_argument("extra", nargs=argparse.REMAINDER, help="more arguments for the probe")
    args = parser.parse_args()
    sink = sys.stdout.buffer

    if args.input:
        source = sys.stdin.buffer if args.input == "-" else open(args.input, "rb")
        with source:
            for line in adapt_lines(source, args.mode):
                sink.write(line)
        sink.flush()
        return 0

    extra = args.extra[1:] if args.extra[:1] == ["--"] else args.extra
    command = probe_command(args.pidns_of or os.getpid(), args.heartbeat, args.mode, extra)
    ensure_tracefs()
    child = subprocess.Popen(command, stdout=subprocess.PIPE)

    def stop(signo, _frame):
        if child.poll() is None:
            child.send_signal(signal.SIGTERM)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    for line in adapt_stream(child.stdout, Adapter(args.mode)):
        sink.write(line)
        sink.flush()
    return child.wait()


if __name__ == "__main__":
    sys.exit(main())
