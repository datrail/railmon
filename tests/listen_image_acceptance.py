#!/usr/bin/env python3
"""The built image reports a port an agent opens, through `listen` and `scan` (DR-143).

Containers from one image, deployed the way the README says:

- an "agent" that waits for a go-ahead, then listens on a port it asks for
  (and again after every restart);
- `railmon listen` with RAIL_LISTEN_CONTAINER: a privileged supervisor in the
  host PID namespace that runs listensnoop inside the agent's, appending to a
  volume the agent does not mount;
- `railmon scan`, reading that volume read-only into a bundle.

Checked, in order:

1. the event carries the agent's own PID (as its namespace numbers it) and an
   asked-for port, and the bundle's observed_listeners names port and process;
2. the agent kills listensnoop: the supervisor attaches again, and the
   bundle goes PARTIAL, because the probe missed whatever opened meanwhile;
3. the agent container restarts: the probe follows it into the new namespace
   and records the agent's listener again.

Needs Docker and a privileged-capable host (eBPF), as CI's runner is.

  python3 tests/listen_image_acceptance.py --image railmon:ci
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PORT = 47001
AGENT = r"""
import os, socket, time
while not os.path.exists("/sig/go"):
    time.sleep(0.1)
s = socket.socket()
s.bind(("0.0.0.0", %d))
s.listen()
with open("/sig/pid.tmp", "w") as f:
    f.write(str(os.getpid()))
os.rename("/sig/pid.tmp", "/sig/pid")
time.sleep(600)
""" % PORT
# Run inside the agent: kill the probe the way a misaligned agent could.
KILL_PROBE = r"""
import os, signal
for pid in os.listdir("/proc"):
    if pid.isdigit():
        try:
            if open(f"/proc/{pid}/comm").read().strip() == "listensnoop":
                os.kill(int(pid), signal.SIGKILL)
                print(pid)
        except OSError:
            pass
"""


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check, timeout=300)


def wait_for(what: str, ready, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ready():
            return
        time.sleep(0.5)
    raise TimeoutError(what)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--image", required=True)
    args = parser.parse_args()

    work = Path(tempfile.mkdtemp())
    sig, data, out = work / "sig", work / "data", work / "out"
    for path in (sig, data, out):
        path.mkdir()
        path.chmod(0o777)
    agent, probe = "ci-listen-agent", "ci-listen-probe"
    listen_file = data / "listen.jsonl"
    checks: dict[str, bool] = {}
    finished = False

    def attaches() -> int:
        return docker("logs", probe, check=False).stderr.count("listensnoop: attached")

    def records() -> list[dict]:
        if not listen_file.exists():
            return []
        return [json.loads(line) for line in listen_file.read_text().splitlines() if line.strip()]

    def ours() -> list[dict]:
        return [e for e in records() if e.get("port") == PORT and e.get("kind") == "listen"]

    def scan() -> dict | None:
        result = docker("run", "--rm", "-v", f"{data}:/data:ro", "-v", f"{out}:/out",
                        args.image, "scan", "--mode", "self", "--host-id", "ci-listen-host",
                        "--listen-file", "/data/listen.jsonl",
                        "--feature-output", "/out/features.json",
                        "--evidence-bundle-output", "/out/bundle.json", check=False)
        if result.returncode != 0:
            print(result.stdout, result.stderr, file=sys.stderr)
            return None
        return json.loads((out / "bundle.json").read_text())["attributes"]["observed_listeners"]

    try:
        # --init, so the agent is not PID 1 and "its own PID" means something.
        docker("run", "-d", "--init", "--name", agent, "-v", f"{sig}:/sig",
               "--entrypoint", "python3", args.image, "-c", AGENT)
        docker("run", "-d", "--name", probe, "--privileged", "--pid", "host",
               "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", f"{data}:/data",
               "-e", f"RAIL_LISTEN_CONTAINER={agent}", "-e", "RAIL_LISTEN_FILE=/data/listen.jsonl",
               "-e", "RAIL_LISTEN_HEARTBEAT=2", args.image, "listen")
        wait_for("listensnoop to attach", lambda: attaches() >= 1)
        (sig / "go").touch()
        wait_for("the agent to listen", (sig / "pid").exists)
        agent_pid = int((sig / "pid").read_text())
        wait_for("the event", lambda: len(ours()) >= 1, timeout=30)

        # 1. the event and the bundle
        mine = ours()
        checks["listen wrote one event for the agent's port"] = len(mine) == 1
        checks["with the agent's own PID and an asked-for port"] = (
            mine[0]["pid"] == agent_pid and agent_pid > 1 and mine[0]["ephemeral"] is False
            and mine[0]["comm"] == "python3"
        )
        checks["only the agent's namespace, one start, heartbeats"] = (
            not any(e.get("pid") == 0 for e in records())
            and sum(e.get("kind") == "start" for e in records()) == 1
        )
        wait_for("a heartbeat", lambda: any(e.get("kind") == "alive" for e in records()), timeout=15)
        listeners = scan()
        checks["the bundle names the port and process"] = bool(listeners) and (
            listeners["status"] == "ANSWERED"
            and {"protocol": "tcp", "addr": "0.0.0.0", "port": PORT, "process": "python3"}
            in listeners["value"]
        )

        # 2. the agent kills the probe
        killed = docker("exec", agent, "python3", "-c", KILL_PROBE).stdout.split()
        checks["the agent could kill the probe"] = len(killed) == 1
        wait_for("the probe to come back", lambda: attaches() >= 2, timeout=30)
        listeners = scan()
        checks["a killed probe makes the bundle PARTIAL, not quiet"] = bool(listeners) and (
            listeners["status"] == "PARTIAL" and listeners["reason"] == "NO_SOURCE_ACCESS"
            and "restarted" in listeners["note"]
        )

        # 3. the agent container restarts
        # The probe cannot see sockets already listening when it attaches, so
        # the restarted agent waits for it before listening again.
        (sig / "pid").unlink()
        (sig / "go").unlink()
        docker("restart", agent)
        wait_for("the probe to follow the agent", lambda: attaches() >= 3, timeout=60)
        (sig / "go").touch()
        wait_for("the agent to listen again", (sig / "pid").exists)
        wait_for("the second event", lambda: len(ours()) >= 2, timeout=30)
        checks["after the agent restarts, the probe records its listener again"] = (
            ours()[-1]["pid"] == int((sig / "pid").read_text())
        )
        finished = True
    finally:
        for name in (agent, probe):
            if not finished or not all(checks.values()):
                logs = docker("logs", name, check=False)
                print(f"--- {name}\n{logs.stdout}{logs.stderr}", file=sys.stderr)
            docker("rm", "-f", name, check=False)
        shutil.rmtree(work, ignore_errors=True)

    for name, passed in checks.items():
        print(("ok:   " if passed else "FAIL: ") + name)
    if len(checks) < 7 or not all(checks.values()):
        return 1
    print(json.dumps({"result": "PASS", "port": PORT, "agent_pid": agent_pid}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
