#!/usr/bin/env python3
"""The built image reports a port an agent opens, through `listen` and `scan` (DR-143).

Containers from one image, deployed the way the README says:

- an "agent" that listens on one port as soon as it starts, then waits for
  a go-ahead and listens on a second port it asks for (both again after
  every restart);
- `railmon listen` with RAIL_LISTEN_CONTAINER: a privileged supervisor in the
  host PID namespace that runs listensnoop inside the agent's, appending to a
  volume the agent does not mount;
- `railmon scan`, reading that volume read-only into a bundle.

Checked, in order:

1. the event carries the agent's own PID (as its namespace numbers it) and an
   asked-for port, and the bundle's observed_listeners names port and process;
2. listensnoop is killed (by the agent where the host lets it, else from
   outside, as a crash): the supervisor attaches again, and the bundle goes
   PARTIAL, because the probe missed whatever opened meanwhile;
3. the agent container restarts: the probe follows it into the new namespace
   and records the agent's listener again.

And (DR-182) with 1 and 3: the port the agent opened before the probe
attached is recorded from the agent's socket table, as a snapshot record,
and named in the bundle.

And (DR-145) between 1 and 2: a client container connects to the agent over
the Docker network; the probe reports the client's address as a peer of the
agent's listener, and the bundle's observed_ingress_peers names it, scoped
private.

Needs Docker and a privileged-capable host (eBPF), as CI's runner is.

  python3 tests/listen_image_acceptance.py --image railmon:ci
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PORT, EARLY_PORT = 47001, 47002
AGENT = r"""
import os, socket, time
early = socket.socket()
early.bind(("0.0.0.0", %d))
early.listen()
while not os.path.exists("/sig/go"):
    time.sleep(0.1)
s = socket.socket()
s.bind(("0.0.0.0", %d))
s.listen()
def serve():
    while True:
        s.accept()[0].close()
import threading
threading.Thread(target=serve, daemon=True).start()
with open("/sig/pid.tmp", "w") as f:
    f.write(str(os.getpid()))
os.rename("/sig/pid.tmp", "/sig/pid")
time.sleep(600)
""" % (EARLY_PORT, PORT)
# Kill the probe: from inside the agent, the way a misaligned agent would
# try, or from the probe's own container (host PID namespace) to stand in
# for a crash where the agent cannot (a host security profile can stop it,
# e.g. Docker's AppArmor profile against an unconfined, privileged probe).
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
        # Logged once the sockets already listening are written, so a port
        # the agent opens after this is the probe's to report.
        return docker("logs", probe, check=False).stderr.count("socket(s) were already listening")

    def records() -> list[dict]:
        if not listen_file.exists():
            return []
        return [json.loads(line) for line in listen_file.read_text().splitlines() if line.strip()]

    def ours() -> list[dict]:
        return [e for e in records() if e.get("port") == PORT and e.get("kind") == "listen"
                and not e.get("snapshot")]

    def early() -> list[dict]:
        return [e for e in records() if e.get("port") == EARLY_PORT and e.get("snapshot")]

    def scan(attribute: str = "observed_listeners") -> dict | None:
        # As this user: the scanner writes its outputs 0600, for its owner.
        result = docker("run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
                        "-v", f"{data}:/data:ro", "-v", f"{out}:/out",
                        args.image, "scan", "--mode", "self", "--host-id", "ci-listen-host",
                        "--listen-file", "/data/listen.jsonl",
                        "--feature-output", "/out/features.json",
                        "--evidence-bundle-output", "/out/bundle.json", check=False)
        if result.returncode != 0:
            print(result.stdout, result.stderr, file=sys.stderr)
            return None
        return json.loads((out / "bundle.json").read_text())["attributes"][attribute]

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
        checks["the port opened before the probe attached is a snapshot record"] = [
            (e["kind"], e["pid"], e["comm"], e["addr"], e["ephemeral"]) for e in early()
        ] == [("listen", agent_pid, "python3", "0.0.0.0", False)]
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
            and {"protocol": "tcp", "addr": "0.0.0.0", "port": EARLY_PORT, "process": "python3"}
            in listeners["value"]
        )

        # 1b. a client on the Docker network connects in (DR-145)
        # Per network: Docker 28 dropped the top-level NetworkSettings.IPAddress.
        agent_ip = docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                          agent).stdout.strip()
        connected = docker("run", "--rm", "--entrypoint", "python3", args.image, "-c",
                           "import socket; c = socket.create_connection((%r, %d), timeout=10);"
                           " print(c.getsockname()[0]); c.recv(1)" % (agent_ip, PORT), check=False)
        client_ip = connected.stdout.strip()
        checks["a client connected to the agent"] = connected.returncode == 0 and bool(client_ip)
        peer_events = lambda: [e for e in records() if e.get("kind") == "peer" and e.get("port") == PORT]
        wait_for("the peer event", lambda: peer_events(), timeout=30)
        checks["listen reported the client as the agent's peer"] = [
            (e["pid"], e["peer"]) for e in peer_events()] == [(agent_pid, client_ip)] and all(
            e.get("peers") is True for e in records() if e.get("kind") == "start")
        peers = scan("observed_ingress_peers")
        checks["the bundle names the peer, scoped private"] = bool(peers) and (
            peers["status"] == "ANSWERED"
            and {"protocol": "tcp", "addr": "0.0.0.0", "port": PORT, "process": "python3",
                 "peer": client_ip, "scope": "private"} in peers["value"]
        )

        # 2. the probe is killed
        killed = docker("exec", agent, "python3", "-c", KILL_PROBE, check=False).stdout.split()
        if killed:
            print("note: the agent could kill the probe; the restart record is what shows it")
        else:
            print("note: the agent cannot signal the probe here; killing it from outside instead")
            killed = docker("exec", probe, "python3", "-c", KILL_PROBE, check=False).stdout.split()
        checks["the probe was killed"] = len(killed) == 1
        wait_for("the probe to come back", lambda: attaches() >= 2, timeout=30)
        listeners = scan()
        checks["a killed probe makes the bundle PARTIAL, not quiet"] = bool(listeners) and (
            listeners["status"] == "PARTIAL" and listeners["reason"] == "NO_SOURCE_ACCESS"
            and "restarted" in listeners["note"]
        )

        # 3. the agent container restarts
        # It listens on EARLY_PORT at once, before the probe can follow it,
        # and waits for the probe before listening on PORT, which the probe
        # itself must then report.
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
        # One per attach: the first, after the kill, after the restart.
        checks["and the snapshot records the port it opened at once"] = len(early()) == 3
        finished = True
    finally:
        # Every log first: removing the agent tears its namespace down and
        # kills the probe, which would then show up in the probe's log.
        if not finished or not all(checks.values()):
            for name in (agent, probe):
                logs = docker("logs", name, check=False)
                print(f"--- {name}\n{logs.stdout}{logs.stderr}", file=sys.stderr)
        for name in (probe, agent):
            docker("rm", "-f", name, check=False)
        shutil.rmtree(work, ignore_errors=True)

    for name, passed in checks.items():
        print(("ok:   " if passed else "FAIL: ") + name)
    if len(checks) < 12 or not all(checks.values()):  # twelve checks, all passed
        return 1
    print(json.dumps({"result": "PASS", "port": PORT, "agent_pid": agent_pid}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
