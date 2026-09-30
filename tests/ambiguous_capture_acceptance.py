#!/usr/bin/env python3
"""Built-binary DR-109 acceptance: a collision that appears and clears while
the collector runs (design doc §5, "One process matches multiple keys").

Two agent processes, A and B, under one UID but each leading its own
session, and a stub AgentSight that reports one exchange each time a tap
opens on a session:

1. Only `planner`'s locator names A, so its row is `attributed`.
2. `executor`'s PID file then names A too. Within a retry interval,
   `planner`'s own tap stops and A's session is tapped once more, now as a
   shared tap: its row is `ambiguous`, names no agent, and its audit lists
   both keys.
3. `reviewer`'s PID file names B, which shares their UID. B's session gets a
   shared tap whose audit lists all three keys; A's shared tap is not
   restarted although its claiming set grew.
4. `reviewer`'s PID file is removed. B's tap stops; A's keeps running.
5. `executor`'s PID file is removed. A's shared tap stops, `planner`'s tap
   restarts, and its row is `attributed` again.
6. `planner`'s PID file is removed: A still runs, so its tap stays. Then
   `executor`'s names A: `planner`'s tap stops and `executor` gets its own.
7. `executor`'s PID file is removed and `planner`'s and `reviewer`'s both
   name A. `executor`'s tap stops and A gets a shared tap listing the two
   (if the writes land in separate retry passes, `planner` briefly gets its
   own tap on A first).

Taps open on A, A, B, A, A, then only on A. After every
phase no session has two live taps, and a shared tap is not restarted when
only the set of targets claiming it changes.
"""

import json
import os
import pathlib
import shutil
import signal
import subprocess
import tempfile
import time

HOST_ID = "acceptance-host"
SANDBOX_NAME = "shared-container"
# Longer than the collector's 5s discovery retry interval, with margin.
PHASE_TIMEOUT = 20
# Two retry intervals: time for a change that should open no tap to show one.
SETTLE = 11

STUB = """#!/usr/bin/env python3
import json, os, sys, time
args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as log:
    log.write(json.dumps({"args": args, "pid": os.getpid()}) + "\\n")
pid = int(args[args.index("--session") + 1])
base = {"source": "ssl", "pid": pid, "comm": "python",
        "data": {"pid": pid, "tid": pid, "timestamp_ns": time.monotonic_ns(), "function": "SSL_write"}}
request = json.loads(json.dumps(base))
request["data"].update({"message_type": "request", "method": "POST", "path": f"/{pid}",
                        "headers": {"host": "example.test"}, "body": "{}"})
print(json.dumps(request), flush=True)
response = json.loads(json.dumps(base))
response["data"].update({"message_type": "response", "status": 200, "headers": {}, "body": "{}"})
print(json.dumps(response), flush=True)
time.sleep(600)
"""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def write_private(path: pathlib.Path, text: str) -> None:
    # Written aside and renamed, so discovery never reads a partial or
    # not-yet-private PID file.
    staged = path.with_name(path.name + ".tmp")
    staged.write_text(text)
    staged.chmod(0o600)
    staged.rename(path)


def read_rows(output: pathlib.Path) -> list[dict]:
    if not output.exists():
        return []
    return [json.loads(line) for line in output.read_text().splitlines()]


def running(pid: int) -> bool:
    try:
        stat = pathlib.Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return False
    return stat.rsplit(")", 1)[1].split()[0] != "Z"


def taps(taps_log: pathlib.Path) -> list[dict]:
    return [json.loads(line) for line in taps_log.read_text().splitlines()]


def require_one_tap_per_session(taps_log: pathlib.Path, phase: int) -> None:
    # A stopped tap's probe is killed; give it a moment to be reaped.
    deadline = time.monotonic() + 3
    while True:
        live = [
            int(tap["args"][tap["args"].index("--session") + 1])
            for tap in taps(taps_log)
            if running(tap["pid"])
        ]
        if len(live) == len(set(live)):
            return
        require(time.monotonic() < deadline, f"phase {phase}: two live taps on one session: {live}")
        time.sleep(0.1)


def wait_for_rows(railmon: subprocess.Popen[bytes], output: pathlib.Path, count: int) -> list[dict]:
    deadline = time.monotonic() + PHASE_TIMEOUT
    while time.monotonic() < deadline:
        rows = read_rows(output)
        if len(rows) >= count:
            return rows
        require(railmon.poll() is None, "RailMon exited during capture")
        time.sleep(0.1)
    raise RuntimeError(f"RailMon wrote {len(read_rows(output))} row(s), expected {count}")


def main() -> None:
    require(os.geteuid() == 0, "run as root so supervisor and agent UIDs differ")
    binary = pathlib.Path(os.environ.get("RAILMON_BIN", "target/debug/railmon")).resolve()
    root = pathlib.Path(tempfile.mkdtemp(prefix="dr109-amb-", dir="/run"))
    root.chmod(0o700)
    agents = [
        subprocess.Popen(
            ["setpriv", "--reuid=65532", "--regid=65532", "--clear-groups", "--ptracer=any", "setsid", "sleep", "600"]
        )
        for _ in range(2)
    ]
    agent, other = agents
    railmon = None
    try:
        time.sleep(0.1)
        require(all(proc.poll() is None for proc in agents), "agent processes did not stay live")
        write_private(root / "planner.pid", f"{agent.pid}\n")
        stub = root / "agentsight"
        stub.write_text(STUB)
        stub.chmod(0o700)
        manifest = root / "targets.yaml"
        manifest.write_text(
            f"""manifest_version: 1
sandbox:
  host_id: {HOST_ID}
  sandbox_name: {SANDBOX_NAME}
  access:
    kind: docker
    container: {SANDBOX_NAME}
agents:
  - agent_key: planner
    discovery:
      pid_file: {root}/planner.pid
  - agent_key: executor
    discovery:
      pid_file: {root}/executor.pid
  - agent_key: reviewer
    discovery:
      pid_file: {root}/reviewer.pid
"""
        )
        manifest.chmod(0o600)
        output = root / "rows.jsonl"
        taps_log = root / "taps.jsonl"
        railmon = subprocess.Popen(
            [
                str(binary),
                "--target-manifest", str(manifest),
                "--agentsight", str(stub),
                "--output-format", "runtime-interaction",
                "--output", str(output),
            ],
            env={**os.environ, "STUB_LOG": str(taps_log)},
        )

        first = wait_for_rows(railmon, output, 1)[0]
        require(first["attribution"]["state"] == "attributed", f"phase 1 row was {first['attribution']}")
        require(first["agent_ref"]["agent_key"] == "planner", f"phase 1 row names {first['agent_ref']}")

        write_private(root / "executor.pid", f"{agent.pid}\n")
        second = wait_for_rows(railmon, output, 2)[1]
        require(second["attribution"]["state"] == "ambiguous", f"phase 2 row was {second['attribution']}")
        require(second["agent_ref"] is None and second["agent_id"] is None, "ambiguous row names an agent")
        require(second["attribution"]["reason"] == "MULTIPLE_TARGETS", f"reason {second['attribution']['reason']}")
        require(second["attribution"]["process"]["pid"] == agent.pid, "ambiguous row carries another process")
        audit = second["raw"]["railmon_attribution_audit"]
        require(audit["candidate_targets"] == ["executor", "planner"], f"audit {audit}")
        require_one_tap_per_session(taps_log, 2)

        write_private(root / "reviewer.pid", f"{other.pid}\n")
        third = wait_for_rows(railmon, output, 3)[2]
        require(third["attribution"]["state"] == "ambiguous", f"phase 3 row was {third['attribution']}")
        require(third["attribution"]["process"]["pid"] == other.pid, "phase 3 row carries another process")
        audit = third["raw"]["railmon_attribution_audit"]
        require(audit["candidate_targets"] == ["executor", "planner", "reviewer"], f"audit {audit}")
        time.sleep(SETTLE)
        require(len(read_rows(output)) == 3, "A's shared tap restarted when its candidate set grew")
        require_one_tap_per_session(taps_log, 3)

        (root / "reviewer.pid").unlink()
        time.sleep(SETTLE)
        require(len(read_rows(output)) == 3, "a tap opened when reviewer's locator went away")
        require(not running(taps(taps_log)[2]["pid"]), "B's shared tap still runs with no collision on B")
        require_one_tap_per_session(taps_log, 4)

        (root / "executor.pid").unlink()
        fourth = wait_for_rows(railmon, output, 4)[3]
        require(fourth["attribution"]["state"] == "attributed", f"phase 5 row was {fourth['attribution']}")
        require(fourth["agent_ref"]["agent_key"] == "planner", f"phase 5 row names {fourth['agent_ref']}")

        require_one_tap_per_session(taps_log, 5)

        (root / "planner.pid").unlink()
        time.sleep(SETTLE)
        require(len(read_rows(output)) == 4, "a tap opened when planner's locator went away")
        require(running(taps(taps_log)[-1]["pid"]), "planner's tap stopped although A still runs")
        write_private(root / "executor.pid", f"{agent.pid}\n")
        fifth = wait_for_rows(railmon, output, 5)[4]
        require(fifth["attribution"]["state"] == "attributed", f"phase 6 row was {fifth['attribution']}")
        require(fifth["agent_ref"]["agent_key"] == "executor", f"phase 6 row names {fifth['agent_ref']}")
        require_one_tap_per_session(taps_log, 6)

        (root / "executor.pid").unlink()
        write_private(root / "planner.pid", f"{agent.pid}\n")
        write_private(root / "reviewer.pid", f"{agent.pid}\n")
        rows = wait_for_rows(railmon, output, 6)
        # The two writes may land in different retry passes, so `planner` may
        # briefly get its own tap on A first; the last row is the shared one.
        time.sleep(SETTLE)
        rows = read_rows(output)
        last = rows[-1]
        require(last["attribution"]["state"] == "ambiguous", f"phase 7 row was {last['attribution']}")
        audit = last["raw"]["railmon_attribution_audit"]
        require(audit["candidate_targets"] == ["planner", "reviewer"], f"audit {audit}")
        require_one_tap_per_session(taps_log, 7)

        # Another retry interval with nothing changing: no further tap or row.
        count = len(rows)
        time.sleep(7)
        require(len(read_rows(output)) == count, "a tap opened with nothing changing")
        require(railmon.poll() is None, "RailMon exited after the collisions")
        railmon.send_signal(signal.SIGINT)
        require(railmon.wait(timeout=5) == 0, "RailMon did not stop cleanly")
        rows = read_rows(output)
        sessions = [int(tap["args"][tap["args"].index("--session") + 1]) for tap in taps(taps_log)]
        require(set(sessions[5:]) == {agent.pid}, f"phase 7 tapped {sessions[5:]}")
        expected = [agent.pid, agent.pid, other.pid, agent.pid, agent.pid]
        require(sessions[:5] == expected, f"taps opened on {sessions}, expected {expected} first")

        print(
            json.dumps(
                {
                    "result": "PASS",
                    "states": [row["attribution"]["state"] for row in rows],
                    "taps": len(sessions),
                }
            )
        )
    finally:
        if railmon is not None and railmon.poll() is None:
            railmon.kill()
        for proc in agents:
            proc.terminate()
        for proc in agents:
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
