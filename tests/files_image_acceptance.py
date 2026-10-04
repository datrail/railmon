#!/usr/bin/env python3
"""The built image reports a file an agent writes, through `files` and `scan` (DR-154).

Containers from one image, deployed the way the README says:

- an "agent" that waits for a go-ahead, then writes a file inside its own
  container;
- `railmon files` with RAIL_FILES_CONTAINER: the same privileged supervisor
  as `railmon listen`, in the host PID namespace, running filesnoop inside
  the agent's and appending to a volume the agent does not mount;
- `railmon scan`, reading that volume read-only into a bundle. The scan
  exits non-zero on a bundle that fails its contract, so a bundle here is
  one that passed it.

Checked, in order:

1. the write event carries the agent's own PID (as its namespace numbers
   it), the path as the agent sees it, and no layer events: the container's
   root is an overlay the runtime mounted, whose layer opens filesnoop skips;
2. the bundle's observed_file_access names the path as written, ANSWERED;
3. filesnoop is killed (by the agent where the host lets it, else from
   outside, as a crash): the supervisor attaches again, and the bundle goes
   PARTIAL, because the probe missed whatever was opened meanwhile.

Needs Docker and a privileged-capable host (eBPF), as CI's runner is.

  python3 tests/files_image_acceptance.py --image railmon:ci
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

WRITTEN = "/tmp/rail-files-acceptance.txt"
AGENT = r"""
import os, time
while not os.path.exists("/sig/go"):
    time.sleep(0.1)
with open(%r, "w") as f:
    f.write("drift")
with open("/sig/pid.tmp", "w") as f:
    f.write(str(os.getpid()))
os.rename("/sig/pid.tmp", "/sig/pid")
time.sleep(600)
""" % WRITTEN
KILL_PROBE = r"""
import os, signal
for pid in os.listdir("/proc"):
    if pid.isdigit():
        try:
            if open(f"/proc/{pid}/comm").read().strip() == "filesnoop":
                os.kill(int(pid), signal.SIGKILL)
                print(pid)
        except OSError:
            pass
"""
EXPECTED = {"path": WRITTEN, "read": False, "write": True, "exec": False, "layer": False}


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
    agent, probe = "ci-files-agent", "ci-files-probe"
    files_file = data / "files.jsonl"
    checks: dict[str, bool] = {}
    finished = False
    agent_pid = 0

    def attaches() -> int:
        return docker("logs", probe, check=False).stderr.count("filesnoop: attached")

    def records() -> list[dict]:
        if not files_file.exists():
            return []
        # The last line may still be being written.
        lines = files_file.read_text().splitlines()
        events = []
        for line in lines:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return events

    def ours() -> list[dict]:
        return [e for e in records() if e.get("kind") == "open" and e.get("path") == WRITTEN]

    def scan() -> dict | None:
        # As this user: the scanner writes its outputs 0600, for its owner.
        result = docker("run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
                        "-v", f"{data}:/data:ro", "-v", f"{out}:/out",
                        args.image, "scan", "--mode", "self", "--host-id", "ci-files-host",
                        "--files-file", "/data/files.jsonl",
                        "--feature-output", "/out/features.json",
                        "--evidence-bundle-output", "/out/bundle.json", check=False)
        if result.returncode != 0:
            print(result.stdout, result.stderr, file=sys.stderr)
            return None
        return json.loads((out / "bundle.json").read_text())["attributes"]["observed_file_access"]

    try:
        # --init, so the agent is not PID 1 and "its own PID" means something.
        docker("run", "-d", "--init", "--name", agent, "-v", f"{sig}:/sig",
               "--entrypoint", "python3", args.image, "-c", AGENT)
        docker("run", "-d", "--name", probe, "--privileged", "--pid", "host",
               "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", f"{data}:/data",
               "-e", f"RAIL_FILES_CONTAINER={agent}", "-e", "RAIL_FILES_FILE=/data/files.jsonl",
               "-e", "RAIL_FILES_HEARTBEAT=2", args.image, "files")
        wait_for("filesnoop to attach", lambda: attaches() >= 1)
        (sig / "go").touch()
        wait_for("the agent to write", (sig / "pid").exists)
        agent_pid = int((sig / "pid").read_text())
        wait_for("the event", lambda: len(ours()) >= 1, timeout=30)

        # 1. the event
        mine = ours()
        checks["files wrote one event for the agent's write"] = len(mine) == 1
        checks["with the agent's own PID, the path it saw, write access"] = bool(mine) and (
            mine[0]["pid"] == agent_pid and agent_pid > 1 and mine[0]["comm"] == "python3"
            and (mine[0]["read"], mine[0]["write"], mine[0]["exec"]) == (False, True, False)
        )
        checks["only the agent's namespace, one start, no layer opens"] = (
            not any(e.get("pid") == 0 for e in records())
            and sum(e.get("kind") == "start" for e in records()) == 1
            and not any(e.get("layer") for e in records())
        )
        wait_for("a heartbeat", lambda: any(e.get("kind") == "alive" for e in records()), timeout=15)

        # 2. the bundle
        field = scan()
        checks["the bundle names the written path, observed"] = bool(field) and (
            field["status"] == "ANSWERED" and field["tier"] == "observed"
            and EXPECTED in field["value"]
        )

        # 3. the probe is killed
        killed = docker("exec", agent, "python3", "-c", KILL_PROBE, check=False).stdout.split()
        if killed:
            print("note: the agent could kill the probe; the restart record is what shows it")
        else:
            print("note: the agent cannot signal the probe here; killing it from outside instead")
            killed = docker("exec", probe, "python3", "-c", KILL_PROBE, check=False).stdout.split()
        checks["the probe was killed"] = len(killed) == 1
        wait_for("the probe to come back", lambda: attaches() >= 2, timeout=30)
        field = scan()
        checks["a killed probe makes the bundle PARTIAL, not quiet"] = bool(field) and (
            field["status"] == "PARTIAL" and field["reason"] == "NO_SOURCE_ACCESS"
            and "restarted" in field["note"] and EXPECTED in field["value"]
        )
        finished = True
    finally:
        if not finished or not all(checks.values()):
            for name in (agent, probe):
                logs = docker("logs", name, check=False)
                print(f"--- {name}\n{logs.stdout}{logs.stderr}", file=sys.stderr)
        for name in (probe, agent):
            docker("rm", "-f", name, check=False)
        shutil.rmtree(work, ignore_errors=True)

    for name, passed in checks.items():
        print(("ok:   " if passed else "FAIL: ") + name)
    if len(checks) < 6 or not all(checks.values()):  # six checks, all passed
        return 1
    print(json.dumps({"result": "PASS", "path": WRITTEN, "agent_pid": agent_pid}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
