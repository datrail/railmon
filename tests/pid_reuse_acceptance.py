#!/usr/bin/env python3
"""Built-binary DR-109 M4 acceptance for stale PID reuse: once a pinned target
exits and an unrelated process takes over its PID, nothing the old tap still
emits may be attributed to the old agent, and the newcomer is not captured
until something declares it.

The newcomer is made as hard to tell apart as the kernel allows: the same PID,
the same UID, and — because it calls setsid() too — the same session ID the
old tap filters on. Only the process start time differs, which is exactly
what RailMon's pinned incarnation carries. A real AgentSight bound to that
session would keep delivering the newcomer's traffic; the stub here stands in
for that by emitting one more interaction after the reuse.

Then the PID file names the newcomer, which makes it a declared restart: it
is captured under the same `agent_key` with a fresh incarnation, on the same
PID but a different start time.

Forcing a specific PID writes `/proc/sys/kernel/ns_last_pid`, which needs
root with CAP_SYS_ADMIN or CAP_CHECKPOINT_RESTORE over the PID namespace and
a writable `/proc/sys` that no AppArmor profile guards — in Docker,
`--cap-add CHECKPOINT_RESTORE --security-opt systempaths=unconfined
--security-opt apparmor=unconfined`. CI runs it inside the built image that
way.
"""

import json
import os
import pathlib
import shutil
import signal
import subprocess
import tempfile
import time

NS_LAST_PID = pathlib.Path("/proc/sys/kernel/ns_last_pid")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def spawn_agent(seconds: int = 60) -> subprocess.Popen[bytes]:
    # Popen's child is not a process-group leader, so setsid(1) calls
    # setsid() in place rather than forking: the session ID is the PID.
    return subprocess.Popen(
        ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--ptracer=any", "setsid", "sleep", str(seconds)]
    )


def spawn_agent_at(pid: int) -> subprocess.Popen[bytes]:
    # Another process can take the PID between the write and the fork, so
    # retry a few times rather than fail on the first miss.
    for _ in range(20):
        NS_LAST_PID.write_text(f"{pid - 1}\n")
        agent = spawn_agent()
        if agent.pid == pid:
            return agent
        agent.kill()
        agent.wait()
    raise RuntimeError(f"could not start a process at PID {pid}")


def start_time_ticks(pid: int) -> int:
    stat = pathlib.Path(f"/proc/{pid}/stat").read_text()
    # Field 22; the command name (field 2) may contain spaces, so split after it.
    return int(stat.rsplit(")", 1)[1].split()[19])


def main() -> None:
    require(os.geteuid() == 0, "run as root so supervisor and agent UIDs differ")
    try:
        NS_LAST_PID.write_text(NS_LAST_PID.read_text())
    except OSError as error:
        raise RuntimeError(
            f"cannot write {NS_LAST_PID} ({error}); see this script's docstring for the privilege it needs"
        ) from error
    root = pathlib.Path(tempfile.mkdtemp(prefix="dr109-pid-reuse-", dir="/run"))
    root.chmod(0o700)
    agents: list[subprocess.Popen[bytes]] = []
    railmon = None
    try:
        agents.append(spawn_agent())
        old = agents[-1]
        time.sleep(0.1)
        require(old.poll() is None, "planner process did not remain live")
        pid_file = root / "planner.pid"
        pid_file.write_text(f"{old.pid}\n")
        pid_file.chmod(0o600)
        old_start = start_time_ticks(old.pid)

        # Attempt 0 emits one interaction, then waits for `fire` and emits a
        # second one — the traffic its session filter would still deliver
        # after the reuse — noting first that it was still up to do so. Later attempts emit one
        # interaction and stay up. Each attempt is its own process, hence the
        # counter file.
        probe = root / "agentsight"
        probe.write_text(
            f"""#!/usr/bin/env python3
import json, os, pathlib, sys, time
args = sys.argv
require = lambda c, m: c or (_ for _ in ()).throw(RuntimeError(m))
require("--session" in args, "RailMon did not use AgentSight session filtering")
sid = int(args[args.index("--session") + 1])
counter = pathlib.Path("{root}/attempts")
attempt = int(counter.read_text()) if counter.exists() else 0
counter.write_text(str(attempt + 1))
def interaction(path):
    base = {{"source":"ssl","pid":sid,"comm":"python","data":{{"pid":sid,"tid":sid,"timestamp_ns":time.monotonic_ns(),"function":"SSL_write"}}}}
    request = json.loads(json.dumps(base))
    request["data"].update({{"message_type":"request","method":"POST","path":path,"headers":{{"host":"example.test"}},"body":"{{}}"}})
    print(json.dumps(request), flush=True)
    response = json.loads(json.dumps(base))
    response["data"].update({{"message_type":"response","status":200,"headers":{{}},"body":"{{}}"}})
    print(json.dumps(response), flush=True)
interaction(f"/attempt/{{attempt}}")
if attempt == 0:
    fire = pathlib.Path("{root}/fire")
    while not fire.exists():
        time.sleep(0.01)
    # Marked first: RailMon may kill this tap as soon as it reads the request.
    pathlib.Path("{root}/fired").touch()
    interaction("/after-reuse")
time.sleep(60)
"""
        )
        probe.chmod(0o700)
        manifest = root / "targets.yaml"
        manifest.write_text(
            f"""manifest_version: 1
sandbox:
  host_id: acceptance-host
  sandbox_name: shared-container
  access:
    kind: docker
    container: shared-container
agents:
  - agent_key: planner
    discovery:
      pid_file: {pid_file}
    capture:
      binary_path: /usr/bin/python3
"""
        )
        manifest.chmod(0o600)
        output = root / "interactions.jsonl"
        log = root / "railmon.log"
        binary = pathlib.Path(os.environ.get("RAILMON_BIN", "target/debug/railmon")).resolve()
        with log.open("w") as log_file:
            railmon = subprocess.Popen(
                [
                    str(binary),
                    "--target-manifest", str(manifest),
                    "--agentsight", str(probe),
                    "--output", str(output),
                    "--output-format", "runtime-interaction",
                ],
                stderr=log_file,
            )

        def rows() -> list[dict]:
            if not output.exists():
                return []
            return [json.loads(line) for line in output.read_text().splitlines()]

        def wait_for_rows(count: int, seconds: float, what: str) -> list[dict]:
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline and len(rows()) < count:
                require(railmon.poll() is None, f"RailMon exited while waiting for {what}")
                time.sleep(0.05)
            return rows()

        first = wait_for_rows(1, 10, "the first interaction")
        require(len(first) == 1, f"expected one row before the reuse, got {len(first)}")
        require(first[0]["agent_ref"]["agent_key"] == "planner", "first row is not the planner's")
        require(
            first[0]["attribution"]["process"] == {"pid": old.pid, "start_time_ticks": old_start},
            f"first row is not pinned to the original incarnation: {first[0]['attribution']}",
        )

        # The locator no longer names anything, so whatever takes the PID is
        # unrelated to the planner. Then the reuse, then the old tap speaks.
        pid_file.unlink()
        old.terminate()
        old.wait(timeout=2)
        agents.append(spawn_agent_at(old.pid))
        new = agents[-1]
        time.sleep(0.05)
        require(new.poll() is None, "the process reusing the PID did not remain live")
        require(os.getsid(new.pid) == old.pid, "the newcomer does not share the old session ID")
        new_start = start_time_ticks(new.pid)
        require(new_start != old_start, "the newcomer has the old start time; the check cannot tell them apart")
        (root / "fire").touch()

        # Longer than one 5s retry tick, so the sweep and the rediscovery pass
        # have both had their chance to relabel or re-pin.
        deadline = time.monotonic() + 7
        while time.monotonic() < deadline:
            require(railmon.poll() is None, "RailMon exited after its target's PID was reused")
            time.sleep(0.1)
        after_reuse = rows()
        require(
            not any("/after-reuse" in json.dumps(row) for row in after_reuse),
            "the old tap's post-reuse traffic was recorded",
        )
        require(
            not any((row.get("attribution") or {}).get("process", {}).get("start_time_ticks") == new_start for row in after_reuse),
            "a row was attributed to the unrelated newcomer's incarnation",
        )
        require(len(after_reuse) == 1, f"expected no rows after the reuse, got {len(after_reuse) - 1}")
        require((root / "attempts").read_text() == "1", "the unrelated newcomer was tapped")
        require(
            "exited or its PID was reused" in log.read_text(),
            "RailMon did not notice the pinned incarnation was gone",
        )
        # Whether the old tap was still up to emit after the reuse, or the
        # retry tick's sweep had already stopped it; either way nothing may be
        # recorded, but say which.
        path = "event" if (root / "fired").exists() else "sweep"

        # Now the locator names the newcomer: a declared restart, captured
        # under the same key with a fresh incarnation on the same PID.
        pid_file.write_text(f"{new.pid}\n")
        final = wait_for_rows(2, 10, "the declared replacement's interaction")
        require(len(final) == 2, f"expected a row from the declared replacement, got {len(final)} rows")
        second = final[1]
        require(second["agent_ref"]["agent_key"] == "planner", "the replacement's row lost its agent_ref")
        require(
            second["attribution"]["process"] == {"pid": old.pid, "start_time_ticks": new_start},
            f"the replacement is not pinned to its own incarnation: {second['attribution']}",
        )
        require("/attempt/1" in json.dumps(second), "the replacement's row is not from a fresh tap")

        railmon.send_signal(signal.SIGINT)
        require(railmon.wait(timeout=5) == 0, "RailMon did not stop cleanly on SIGINT after a PID reuse")
        print(json.dumps({"result": "PASS", "pid": old.pid, "stale_event_stopped_by": path}))
    finally:
        if railmon is not None and railmon.poll() is None:
            railmon.kill()
            try:
                railmon.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        for agent in agents:
            if agent.poll() is None:
                agent.terminate()
                try:
                    agent.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    agent.kill()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
