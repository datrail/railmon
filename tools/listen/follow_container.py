#!/usr/bin/env python3
"""Keep listensnoop attached to one agent container's PID namespace (DR-143).

`railmon listen` with RAIL_LISTEN_CONTAINER set runs this. The supervisor
itself sits in the host PID namespace, so the agent cannot see or signal it.
Each round it asks Docker for the container's PID, enters that namespace with
nsenter, and runs listensnoop there, appending to the output. When listensnoop
exits, because the agent restarted (its namespace died with it) or the agent
killed it, the supervisor waits for the container and attaches again.

Each attach starts with listensnoop's own `start` record. A second start is
how the scanner knows the probe was down: listensnoop does not report sockets
already listening when it attaches, so anything opened in the gap is missing,
and the bundle says so instead of reading as "no new listeners".

Needs: `--pid host`, eBPF privilege, and the Docker socket.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time

POLL_SECONDS = 1.0


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


def log(message: str) -> None:
    print(f"[railmon listen] {message}", file=sys.stderr, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("container", help="agent container name or id")
    parser.add_argument("listensnoop_args", nargs=argparse.REMAINDER,
                        help="arguments passed to listensnoop")
    args = parser.parse_args()

    docker = os.environ.get("RAIL_DOCKER", "docker")
    nsenter = os.environ.get("RAIL_NSENTER", "nsenter")
    listensnoop = os.environ.get("LISTENSNOOP_PATH", "/usr/local/bin/listensnoop")
    output = os.environ.get("RAIL_LISTEN_FILE")
    sink = open(output, "ab", buffering=0) if output else sys.stdout.buffer

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
                                  *args.listensnoop_args], stdout=sink)
        # A signal that landed before `child` was set found nothing to stop.
        # (Not a blocked mask around Popen: the child would inherit it, and
        # listensnoop would never see the SIGTERM meant for it.)
        if stopping:
            stop_listensnoop(child)
        code = child.wait()
        child = None
        if not stopping:
            log(f"listensnoop exited ({code}); reattaching")
            time.sleep(POLL_SECONDS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
