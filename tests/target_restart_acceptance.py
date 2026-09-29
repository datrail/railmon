#!/usr/bin/env python3
"""Built-binary DR-109 M3 acceptance: a target's tap stops mid-flight and
RailMon survives it — flushing the pending request as incomplete, retrying
discovery, and restarting capture under the same `agent_key` — instead of the
whole collector exiting (the pre-M3-restart-work behavior this replaces). Then
the target exits quietly, with its tap still up and silent, and RailMon must
still notice and restart capture against the replacement process.

Companion to `two_agent_acceptance.py`, which only covers the steady-state
two-agent happy path. Root-only (needs `setpriv` to run the target under a
distinct UID), like that script; CI runs it inside the built image.
"""

import json
import os
import pathlib
import shutil
import signal
import subprocess
import tempfile
import time


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> None:
    require(os.geteuid() == 0, "run as root so supervisor and agent UIDs differ")
    root = pathlib.Path(tempfile.mkdtemp(prefix="dr109-restart-", dir="/run"))
    root.chmod(0o700)
    target = None
    railmon = None
    try:
        target = subprocess.Popen(
            [
                "setpriv",
                "--reuid=65534",
                "--regid=65534",
                "--clear-groups",
                "--ptracer=any",
                "setsid",
                "sleep",
                "60",
            ]
        )
        time.sleep(0.1)
        require(target.poll() is None, "planner process did not remain live")
        (root / "planner.pid").write_text(f"{target.pid}\n")
        (root / "planner.pid").chmod(0o600)

        # Attempt 0 sends only a request, then exits immediately — simulating
        # a tap that stops mid-flight, leaving one request pending with no
        # response. Attempt 1+ behaves like the steady-state probe: request,
        # response, then stay up. The attempts counter is a file because each
        # attempt is a separate process.
        probe = root / "agentsight"
        probe.write_text(
            f"""#!/usr/bin/env python3
import json, os, pathlib, sys, time
args = sys.argv
require = lambda c, m: c or (_ for _ in ()).throw(RuntimeError(m))
require("--session" in args, "RailMon did not use AgentSight session filtering")
sid = int(args[args.index("--session") + 1])
require(os.getsid(sid) == sid, "target is not its own process session")
counter = pathlib.Path("{root}/attempts")
attempt = int(counter.read_text()) if counter.exists() else 0
counter.write_text(str(attempt + 1))
base = {{"source":"ssl","pid":sid,"comm":"python","data":{{"pid":sid,"tid":sid,"timestamp_ns":time.monotonic_ns(),"function":"SSL_write"}}}}
request = json.loads(json.dumps(base))
request["data"].update({{"message_type":"request","method":"POST","path":f"/{{sid}}/{{attempt}}","headers":{{"host":"example.test"}},"body":"{{}}"}})
print(json.dumps(request), flush=True)
if attempt == 0:
    sys.exit(0)
response = json.loads(json.dumps(base))
response["data"].update({{"message_type":"response","status":200,"headers":{{}},"body":"{{}}"}})
print(json.dumps(response), flush=True)
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
      pid_file: {root}/planner.pid
    capture:
      binary_path: /usr/bin/python3
"""
        )
        manifest.chmod(0o600)
        output = root / "interactions.jsonl"
        binary = pathlib.Path(os.environ.get("RAILMON_BIN", "target/debug/railmon")).resolve()
        railmon = subprocess.Popen(
            [
                str(binary),
                "--target-manifest",
                str(manifest),
                "--agentsight",
                str(probe),
                "--output",
                str(output),
                "--output-format",
                "runtime-interaction",
            ],
        )

        def rows() -> list[dict]:
            if not output.exists():
                return []
            return [json.loads(line) for line in output.read_text().splitlines()]

        # First: the incomplete row from the attempt-0 tap exit. Poll for "at
        # least one row" rather than "exactly one" — TARGET_RETRY_INTERVAL is
        # only 5s, so a slow machine could already have the restart's second
        # row land before this loop notices the first one.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and len(rows()) < 1:
            require(railmon.poll() is None, "RailMon exited after its only tap stopped")
            time.sleep(0.05)
        first = rows()
        require(len(first) >= 1, "expected the flushed incomplete row, got none")
        require(first[0]["raw"].get("incomplete") is True, "pending request was not flushed as incomplete")
        require(first[0]["response"]["status"] is None, "a flushed request must carry no response")
        require(first[0]["agent_ref"]["agent_key"] == "planner", "incomplete row lost its agent_ref")

        # RailMon must still be running: the old behavior was to bail out the
        # entire process the moment one target's tap ended.
        require(railmon.poll() is None, "RailMon exited instead of retrying discovery")

        # Then: discovery retries (TARGET_RETRY_INTERVAL, currently 5s),
        # restarts the tap, and attempt 1 completes normally.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and len(rows()) < 2:
            require(railmon.poll() is None, "RailMon exited before the tap could restart")
            time.sleep(0.1)
        both = rows()
        require(len(both) == 2, f"expected a second, completed row after restart, got {len(both)}")
        second = both[1]
        require(not second["raw"].get("incomplete"), "the post-restart interaction should be complete")
        require(second["raw"]["response"] is not None, "the post-restart interaction has no response")
        require(second["agent_ref"]["agent_key"] == "planner", "restarted tap lost its agent_ref")
        require(
            second["attribution"]["process"]["pid"] == target.pid,
            "restarted tap attributed traffic to the wrong process",
        )

        # Then: the target exits *quietly*. Attempt 1's tap is still up and
        # emits nothing more, so no event ever reaches the per-event liveness
        # check — the retry tick's sweep has to notice the dead incarnation,
        # stop that tap, and pick up the replacement process from the same
        # locator under the same `agent_key`.
        old_pid = target.pid
        target.terminate()
        target.wait(timeout=2)
        target = subprocess.Popen(
            ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--ptracer=any", "setsid", "sleep", "60"]
        )
        time.sleep(0.1)
        require(target.poll() is None, "replacement planner process did not remain live")
        require(target.pid != old_pid, "replacement planner reused the old PID; rerun")
        (root / "planner.pid").write_text(f"{target.pid}\n")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and len(rows()) < 3:
            require(railmon.poll() is None, "RailMon exited after its target exited quietly")
            time.sleep(0.1)
        after = rows()
        require(len(after) == 3, f"expected a row from the replacement process, got {len(after)} rows")
        third = after[2]
        require(not third["raw"].get("incomplete"), "the replacement's interaction should be complete")
        require(third["agent_ref"]["agent_key"] == "planner", "replacement tap lost its agent_ref")
        require(
            third["attribution"]["process"]["pid"] == target.pid,
            "replacement tap attributed traffic to the wrong process",
        )
        require((root / "attempts").read_text() == "3", "quiet exit did not restart the tap exactly once")

        railmon.send_signal(signal.SIGINT)
        require(railmon.wait(timeout=5) == 0, "RailMon did not stop cleanly on SIGINT after a restart")
        print(json.dumps({"result": "PASS", "rows": len(after)}))
    finally:
        if railmon is not None and railmon.poll() is None:
            railmon.kill()
            try:
                railmon.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        if target is not None:
            target.terminate()
            try:
                target.wait(timeout=2)
            except subprocess.TimeoutExpired:
                target.kill()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
