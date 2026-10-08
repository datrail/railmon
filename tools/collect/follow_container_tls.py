#!/usr/bin/env python3
"""Keep the TLS collector attached to one agent container (DR-187).

`railmon collect` with RAIL_COLLECT_CONTAINER set runs this instead of the
collector directly. It sits in the host PID namespace and, each round:

1. asks Docker for the container's init PID;
2. finds the TLS library the agent uses, the way AgentSight's `docker://`
   reference does: the first process in the container's tree that maps a
   `libssl.so`, or whose executable has TLS built in (Node, Bun, and other
   runtimes that bundle OpenSSL or BoringSSL, so no libssl is loaded for a
   `--comm` filter to hook). A mapped libssl is checked first, because a
   program linked against libssl names `SSL_write` without containing it;
3. runs the collector with `--binary-path` naming that file through the
   kernel's own link to it (`/proc/<pid>/map_files/<range>` or
   `/proc/<pid>/exe`) and `--session` set to that process's session. Every
   process in that session that uses that file is captured; others, the
   host's and `docker exec` sessions included (the scanner's), are not;
4. stops the collector (which flushes what it holds) and starts again when
   the container is recreated or restarted, or when the agent's process is
   replaced by one using a different TLS library file.

The paths are never re-walked from text the agent controls. A path read out
of `maps` or `readlink(exe)` is resolved again by whoever opens it, and a
symlink planted in the agent's filesystem then resolves in ours: a host file,
a FIFO that blocks the open, `/dev/zero` that never ends. The `map_files` and
`exe` links name the inode the process actually has mapped.

If the collector keeps failing straight after it starts, the supervisor exits
with its status instead of retrying for ever, so Docker sees the failure.

Needs: `--pid host`, eBPF privilege (`map_files` needs CAP_SYS_ADMIN), and
the Docker socket.
"""

from __future__ import annotations

import argparse
import os
import signal
import stat
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "listen"))
from follow_container import container_pid  # noqa: E402

POLL_SECONDS = 2.0
PROC = "/proc"
# What AgentSight's `binary_embeds_ssl` looks for in an executable.
TLS_NEEDLES = (b"SSL_write", b"BoringSSLError", b"OPENSSL_internal", b"grok-cli")
CHUNK = 1 << 20
# No real executable is near this; it bounds a read the agent can lengthen.
SCAN_LIMIT = 1 << 30
# Under Docker's 10 s stop grace, so the collector's flush is not SIGKILLed.
STOP_WAIT = 8.0
# A collector that exits this soon after starting, this many times running,
# is failing, not being restarted with the agent.
FAST_EXIT_SECONDS = 15.0
FAST_EXITS = 3


def log(message: str) -> None:
    print(f"[railmon collect] {message}", file=sys.stderr, flush=True)


def embeds_tls(path: str, cache: dict) -> bool:
    """Whether the file contains one of TLS_NEEDLES. Only a regular file is
    read, without blocking and at most SCAN_LIMIT bytes. Cached by inode,
    since a Node binary is ~100 MB and the tree is walked again and again."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return False
        key = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
        if key in cache:
            return cache[key]
        keep = max(len(n) for n in TLS_NEEDLES) - 1
        found, tail, read = False, b"", 0
        while read < SCAN_LIMIT and (chunk := os.read(fd, CHUNK)):
            read += len(chunk)
            window = tail + chunk
            if any(n in window for n in TLS_NEEDLES):
                found = True
                break
            tail = window[-keep:]
    except OSError:
        return False
    finally:
        os.close(fd)
    cache[key] = found
    return found


def mapped_libssl(pid: int, proc: str = PROC) -> tuple[str, str] | None:
    """(the kernel's link to it, its path inside the process's root) for the
    libssl this process has mapped. The link names the mapped inode even when
    the file was since deleted or replaced, so the name is only for the log."""
    try:
        with open(f"{proc}/{pid}/maps") as f:
            for line in f:
                parts = line.split(None, 5)
                if len(parts) < 6:
                    continue
                path = parts[5].rstrip("\n")
                if not path.startswith("/") or "libssl.so" not in os.path.basename(path):
                    continue
                # `maps` pads addresses to 8 digits; `map_files` names do not.
                start, _, end = parts[0].partition("-")
                link = f"{proc}/{pid}/map_files/{int(start, 16):x}-{int(end, 16):x}"
                try:
                    if stat.S_ISREG(os.stat(link).st_mode):
                        return link, path
                except OSError:
                    continue
    except OSError:
        pass
    return None


def children(pid: int, proc: str = PROC) -> list[int]:
    try:
        with open(f"{proc}/{pid}/task/{pid}/children") as f:
            return [int(p) for p in f.read().split()]
    except (OSError, ValueError):
        return []


def session_of(pid: int, proc: str = PROC) -> int | None:
    """Field 6 of /proc/<pid>/stat, after the parenthesised comm."""
    try:
        with open(f"{proc}/{pid}/stat") as f:
            stat = f.read()
        return int(stat[stat.rindex(")") + 2:].split()[3])
    except (OSError, ValueError, IndexError):
        return None


def comm_of(pid: int, proc: str = PROC) -> str:
    try:
        with open(f"{proc}/{pid}/comm") as f:
            return f.read().strip()
    except OSError:
        return "?"


def find_tls_target(init_pid: int, cache: dict, proc: str = PROC) -> tuple[int, str, str] | None:
    """(pid, attach path, how it was found) for the first process in the
    container's tree, breadth first, that uses TLS."""
    queue, seen = [init_pid], set()
    while queue:
        pid = queue.pop(0)
        if pid in seen:
            continue
        seen.add(pid)
        lib = mapped_libssl(pid, proc)
        if lib:
            return pid, lib[0], f"loads {lib[1]}"
        exe = f"{proc}/{pid}/exe"
        if embeds_tls(exe, cache):
            try:
                name = os.readlink(exe)
            except OSError:
                name = "its executable"
            return pid, exe, f"has TLS built into {name}"
        queue.extend(children(pid, proc))
    return None


def file_identity(path: str) -> tuple[int, int] | None:
    try:
        st = os.stat(path)
        return st.st_dev, st.st_ino
    except OSError:
        return None


def alive(pid: int, proc: str = PROC) -> bool:
    return os.path.exists(f"{proc}/{pid}")


def stop(child: subprocess.Popen) -> int:
    """SIGTERM is the collector's stop-and-flush (DR-130)."""
    if child.poll() is None:
        child.send_signal(signal.SIGTERM)
    try:
        return child.wait(timeout=STOP_WAIT)
    except subprocess.TimeoutExpired:
        child.kill()
        return child.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--collector", default=os.environ.get("RAIL_COLLECTOR", "/usr/local/bin/railmon"),
                        help="collector binary")
    parser.add_argument("container", help="agent container name or id")
    parser.add_argument("collector_args", nargs=argparse.REMAINDER,
                        help="arguments passed to the collector, e.g. --mode http --webhook URL")
    args = parser.parse_args()
    passthrough = [a for a in args.collector_args if a != "--"]
    for flag in ("--pid", "--uid", "--comm", "--binary-path", "--session", "--target-manifest"):
        if any(a == flag or a.startswith(flag + "=") for a in passthrough):
            log(f"{flag} chooses the processes itself; unset RAIL_COLLECT_CONTAINER to use it")
            return 2

    docker = os.environ.get("RAIL_DOCKER", "docker")
    cache: dict = {}
    child: subprocess.Popen | None = None
    stopping = False

    def on_signal(_signo, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    waiting_for = None
    fast_exits = 0
    while not stopping:
        init = container_pid(docker, args.container)
        if not init:
            if waiting_for != "container":
                log(f"waiting for container {args.container} to run")
                waiting_for = "container"
            time.sleep(POLL_SECONDS)
            continue
        target = find_tls_target(init, cache)
        session = session_of(target[0]) if target else None
        if not target or session is None:
            if waiting_for != "tls":
                log(f"no process in container {args.container} loads libssl or has TLS built in yet; "
                    f"nothing to capture until one does (checking every {POLL_SECONDS:.0f}s)")
                waiting_for = "tls"
            time.sleep(POLL_SECONDS)
            continue
        waiting_for = None
        if stopping:  # a signal that landed during docker inspect
            break
        pid, path, how = target
        identity = file_identity(path)
        log(f"attaching to {args.container}: pid {pid} ({comm_of(pid)}) {how}; "
            f"--binary-path {path} --session {session}")
        started = time.monotonic()
        agent_gone = False
        child = subprocess.Popen([args.collector, *passthrough, "--binary-path", path,
                                  "--session", str(session)])
        reason = None
        while not stopping and reason is None:
            time.sleep(POLL_SECONDS)
            if stopping:
                break
            if child.poll() is not None:
                reason = f"collector exited ({child.returncode})"
                # An attach that failed because the agent exited while the
                # collector started is the agent's restart, not a failure.
                agent_gone = not alive(init) or not alive(pid)
                break
            now = container_pid(docker, args.container)
            # 0 is Docker not answering, which is not a restart; a dead init is.
            if (now and now != init) or not alive(init):
                reason = f"container {args.container} restarted"
            elif not alive(pid):
                replaced = find_tls_target(init, cache)
                if replaced is None:
                    pass  # keep the attach; the agent may start again in this session
                elif file_identity(replaced[1]) != identity or session_of(replaced[0]) != session:
                    reason = f"pid {pid} was replaced by one using another TLS library or session"
                else:
                    pid = replaced[0]
        code = stop(child)
        child = None
        if stopping:
            return code
        if (reason.startswith("collector exited") and not agent_gone
                and time.monotonic() - started < FAST_EXIT_SECONDS):
            fast_exits += 1
            if fast_exits >= FAST_EXITS:
                log(f"the collector exited {fast_exits} times within {FAST_EXIT_SECONDS:.0f}s "
                    f"of starting; giving up (exit {code})")
                return code or 1
        else:
            fast_exits = 0
        log(f"{reason}; re-attaching (collector exit {code})")
        time.sleep(POLL_SECONDS * (1 + fast_exits))
    return 0


if __name__ == "__main__":
    sys.exit(main())
