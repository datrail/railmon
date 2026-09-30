#!/usr/bin/env python3
"""Built-binary DR-109 acceptance with two real isolated agent processes.

`--stop-signal TERM` stops RailMon the way `docker stop` does instead of with
SIGINT; both must take the same clean shutdown path (DR-130).

`--raildash BASE_URL` also delivers over RailMon's webhook to that RailDash,
then checks RailDash stored both rows with their keys, attribution, PIDs and
response status (DR-109 M4: CI runs it between the two built images).
"""

import argparse
import json
import os
import pathlib
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.request


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stop-signal", choices=("INT", "TERM"), default="INT")
    parser.add_argument("--raildash", metavar="BASE_URL", help="also deliver to this RailDash and check what it stored")
    options = parser.parse_args()
    stop_signal = signal.Signals[f"SIG{options.stop_signal}"]
    raildash = options.raildash.rstrip("/") if options.raildash else None
    require(os.geteuid() == 0, "run as root so supervisor and agent UIDs differ")
    root = pathlib.Path(tempfile.mkdtemp(prefix="dr109-", dir="/run"))
    root.chmod(0o700)
    agents: list[subprocess.Popen[bytes]] = []
    try:
        for uid in (65532, 65533):
            proc = subprocess.Popen(
                [
                    "setpriv",
                    f"--reuid={uid}",
                    f"--regid={uid}",
                    "--clear-groups",
                    "--ptracer=any",
                    "setsid",
                    "sleep",
                    "60",
                ]
            )
            agents.append(proc)
        time.sleep(0.1)
        for name, proc in zip(("planner", "executor"), agents):
            require(proc.poll() is None, f"{name} process did not remain live")
            (root / f"{name}.pid").write_text(f"{proc.pid}\n")
            (root / f"{name}.pid").chmod(0o600)

        probe = root / "agentsight"
        probe.write_text(
            """#!/usr/bin/env python3
import json, os, sys, time
args = sys.argv
require = lambda c, m: c or (_ for _ in ()).throw(RuntimeError(m))
require("--session" in args, "RailMon did not use AgentSight session filtering")
sid = int(args[args.index("--session") + 1])
require(os.getsid(sid) == sid, "target is not its own process session")
base = {"source":"ssl","pid":sid,"comm":"python","data":{"pid":sid,"tid":sid,"timestamp_ns":time.monotonic_ns(),"function":"SSL_write"}}
request = json.loads(json.dumps(base))
request["data"].update({"message_type":"request","method":"POST","path":f"/{sid}","headers":{"host":"example.test"},"body":"{}"})
print(json.dumps(request), flush=True)
response = json.loads(json.dumps(base))
response["data"].update({"message_type":"response","status_code":200,"headers":{},"body":"{}"})
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
  - agent_key: executor
    discovery:
      pid_file: {root}/executor.pid
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
            ]
            + (["--webhook", f"{raildash}/webhook/http-interactions"] if raildash else []),
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if output.exists() and len(output.read_text().splitlines()) == 2:
                break
            require(railmon.poll() is None, "RailMon exited before capturing both agents")
            time.sleep(0.05)
        else:
            raise RuntimeError("RailMon did not capture both agents before timeout")
        railmon.send_signal(stop_signal)
        require(railmon.wait(timeout=5) == 0, f"RailMon did not stop cleanly on {stop_signal.name}")
        rows = [json.loads(line) for line in output.read_text().splitlines()]
        require(len(rows) == 2, f"expected two interactions, got {len(rows)}")
        by_key = {row["agent_ref"]["agent_key"]: row for row in rows}
        require(set(by_key) == {"planner", "executor"}, "agent references collapsed")
        for name, proc in zip(("planner", "executor"), agents):
            row = by_key[name]
            require(row["attribution"]["state"] == "attributed", f"{name} not attributed")
            require(row["attribution"]["process"]["pid"] == proc.pid, f"{name} PID crossed")
            require(row["attribution"]["process"]["start_time_ticks"] > 0, f"{name} start time absent")
        require(
            by_key["planner"]["attribution"]["process"] != by_key["executor"]["attribution"]["process"],
            "process incarnations collapsed",
        )
        if raildash:
            # Stopping flushed the webhook batch, so RailDash has everything
            # it will get: the same two rows, indexed under the same keys.
            stored = get_json(f"{raildash}/api/interactions")
            require(stored.get("total") == len(rows), f"RailDash stored {stored.get('total')} rows, not {len(rows)}")
            for item in stored["items"]:
                name = item.get("agent_key")
                require(name in by_key, f"RailDash row names agent {name!r}")
                require(item.get("attribution_state") == "attributed", f"RailDash lost {name}'s attribution")
                require(item.get("pid") == by_key[name]["attribution"]["process"]["pid"], f"RailDash crossed {name}'s PID")
                require(item.get("status_code") == 200, f"RailDash lost {name}'s response status")
            filters = get_json(f"{raildash}/api/filters")
            require(
                filters.get("agent_keys") == sorted(by_key),
                f"RailDash indexed {filters.get('agent_keys')}, not {sorted(by_key)}",
            )
        print(
            json.dumps(
                {
                    "result": "PASS",
                    "agents": sorted(by_key),
                    "rows": len(rows),
                    "stop_signal": stop_signal.name,
                    **({"raildash_rows": len(rows)} if raildash else {}),
                }
            )
        )
    finally:
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
