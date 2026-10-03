#!/usr/bin/env python3
"""A listening socket, or a peer connecting in, that appears after the baseline
is locked is drift (DR-125, DR-145).

Drives the real scanner and a real RailDash end to end. RailDash compares a
new ASP against the active alignment when it arrives, so:

1. scan with a listensnoop file holding one listener; lock that ASP as the
   baseline and make it active;
2. scan the same file again: ALIGNED. The listener value has no counts or
   PIDs, so an unchanged window must not churn;
3. append a new listener (an agent opening a covert port) and scan: DRIFT
   DETECTED, with observed_listeners the only attribute that changed. Both
   ports were asked for and sit inside the kernel's ephemeral range, where
   a guess from the number alone once called them both "ephemeral" and
   the new one vanished.
4. lock that ASP as the new baseline; a known peer connecting again (another
   PID, a later time) stays ALIGNED, and a new peer connecting in is DRIFT
   DETECTED, with observed_ingress_peers the only attribute that changed.

The scan command is a prefix the scanner's own arguments are appended to, so
CI runs it in the RailMon image and a developer runs the source directly:

  python3 tests/listen_drift_acceptance.py --raildash http://127.0.0.1:8000 \\
      --token "$(cat raildash.db.token)" \\
      --scan "python3 tools/scan/scan_agent_environment.py"

With --listen-dir/--scan-listen-dir the event file is written on this side
and named by the path the scanner sees (a container mount).
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import Request, urlopen

AGENT_KEY = "listen-acceptance-agent"


def event(port: int, comm: str, peer: str | None = None, pid: int = 7) -> str:
    return json.dumps({
        "timestamp_ns": time.monotonic_ns(), "kind": "peer" if peer else "listen", "pid": pid,
        "tid": pid, "host_pid": 7000 + pid, "uid": 1000, "comm": comm, "protocol": "tcp",
        "family": "ipv4", "addr": "0.0.0.0", "port": port, "ephemeral": False,
        **({"peer": peer} if peer else {}),
    })


def api(base: str, path: str, token: str | None = None, body: dict | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-RailDash-Token"] = token
    data = json.dumps(body).encode() if body is not None else None
    with urlopen(Request(base + path, data=data, headers=headers,
                         method="POST" if body is not None else "GET"), timeout=30) as response:
        return json.load(response)


def asp_ids(base: str) -> list[str]:
    items = api(base, "/api/asps?limit=500")["items"]
    return [item["asp_id"] for item in items
            if (item.get("agent_identity") or {}).get("value") == AGENT_KEY]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--raildash", required=True, help="RailDash URL as this script reaches it")
    parser.add_argument("--scan-raildash", help="RailDash URL as the scanner reaches it (default: --raildash)")
    parser.add_argument("--token", required=True, help="RailDash's local token")
    parser.add_argument("--scan", required=True, help="command prefix that runs the scanner")
    parser.add_argument("--listen-dir", help="directory to write the event file in (default: a temp dir)")
    parser.add_argument("--scan-listen-dir", help="that directory as the scanner sees it (default: same)")
    args = parser.parse_args()

    listen_dir = Path(args.listen_dir or tempfile.mkdtemp())
    listen_dir.mkdir(parents=True, exist_ok=True)
    listen_file = listen_dir / "listen.jsonl"
    scan_listen_file = Path(args.scan_listen_dir or listen_dir) / "listen.jsonl"
    env = {**os.environ, "RAIL_RAILDASH_TOKEN": args.token, "RAIL_HOST_ID": "ci-listen-host"}
    workdir = tempfile.mkdtemp()

    def scan() -> str:
        before = set(asp_ids(args.raildash))
        argv = shlex.split(args.scan) + [
            "--mode", "self", "--agent-key", AGENT_KEY,
            "--listen-file", str(scan_listen_file),
            "--raildash-url", args.scan_raildash or args.raildash,
        ]
        proc = subprocess.run(argv, cwd=workdir, env=env, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            sys.exit(f"scan failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}")
        new = [asp for asp in asp_ids(args.raildash) if asp not in before]
        if len(new) != 1:
            sys.exit(f"expected one new ASP from the scan, got {new}:\n{proc.stderr}")
        return new[0]

    checks: dict[str, bool] = {}
    # A real probe's file opens with its start record (DR-143); without one
    # the scanner reports that the probe may never have attached. No -H here
    # ("every": 0), so no heartbeat is expected. "peers": this probe reports
    # who connects in (DR-144).
    start = json.dumps({"kind": "start", "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "every": 0, "peers": True})
    listen_file.write_text(start + "\n" + event(40000, "agent") + "\n"
                           + event(40000, "agent", peer="127.0.0.1") + "\n", encoding="utf-8")

    baseline = scan()
    bundle = api(args.raildash, f"/api/asps/{baseline}/bundle", args.token)
    listeners = bundle["attributes"]["observed_listeners"]
    checks["the bundle carries the listener"] = (
        listeners["status"] == "ANSWERED"
        and listeners["value"] == [{"protocol": "tcp", "addr": "0.0.0.0", "port": 40000, "process": "agent"}]
    )
    version = api(args.raildash, f"/api/asps/{baseline}/lock", args.token, {"version": f"listen-{time.time_ns()}"})
    api(args.raildash, f"/api/alignments/{version['alignment_version_id']}/switch", args.token, {})

    unchanged = scan()
    state = api(args.raildash, f"/api/asps/{unchanged}/state")
    checks["an unchanged window stays aligned"] = state["state"] == "ALIGNED"

    with listen_file.open("a", encoding="utf-8") as f:
        f.write(event(45000, "agent") + "\n")
    opened = scan()
    state = api(args.raildash, f"/api/asps/{opened}/state")
    changes = (state.get("drift") or {}).get("changes") or []
    checks["a new listening port is drift"] = state["state"] == "DRIFT_DETECTED"
    checks["and observed_listeners is the only change"] = [c["name"] for c in changes] == ["observed_listeners"]
    peers = api(args.raildash, f"/api/asps/{opened}/bundle", args.token)["attributes"]["observed_ingress_peers"]
    checks["the bundle carries the peer and its scope"] = (
        peers["status"] == "ANSWERED"
        and peers["value"] == [{"protocol": "tcp", "addr": "0.0.0.0", "port": 40000, "process": "agent",
                                "peer": "127.0.0.1", "scope": "loopback"}]
    )

    version = api(args.raildash, f"/api/asps/{opened}/lock", args.token, {"version": f"peers-{time.time_ns()}"})
    api(args.raildash, f"/api/alignments/{version['alignment_version_id']}/switch", args.token, {})
    with listen_file.open("a", encoding="utf-8") as f:
        f.write(event(40000, "agent", peer="127.0.0.1", pid=8) + "\n")
    again = scan()
    checks["a known peer connecting again stays aligned"] = (
        api(args.raildash, f"/api/asps/{again}/state")["state"] == "ALIGNED")
    with listen_file.open("a", encoding="utf-8") as f:
        f.write(event(40000, "agent", peer="8.8.4.4") + "\n")
    connected = scan()
    state = api(args.raildash, f"/api/asps/{connected}/state")
    changes = (state.get("drift") or {}).get("changes") or []
    checks["a new peer connecting in is drift"] = state["state"] == "DRIFT_DETECTED"
    checks["and observed_ingress_peers is the only change"] = (
        [c["name"] for c in changes] == ["observed_ingress_peers"])

    for name, passed in checks.items():
        print(("ok:   " if passed else "FAIL: ") + name)
    if not all(checks.values()):
        print(json.dumps({"unchanged_state": api(args.raildash, f"/api/asps/{unchanged}/state"),
                          "opened_state": state}, indent=1))
        return 1
    print(json.dumps({"result": "PASS", "baseline": baseline, "drifted": opened}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
