#!/usr/bin/env python3
"""A file the agent opens in a new way after the baseline is locked is drift (DR-154, DR-166).

Drives the real scanner and a real RailDash end to end, the way
listen_drift_acceptance.py does for listeners:

1. scan with a filesnoop file holding one read; lock that ASP as the
   baseline and make it active;
2. scan again after another process read the same file (another PID, thread
   name and time): ALIGNED. The value has no counts, PIDs or process names,
   so an unchanged set of files must not churn;
3. append a write to a new path and scan: DRIFT DETECTED, with
   observed_file_access the only attribute that changed;
4. lock that ASP; a write to the file that was only read before is DRIFT
   DETECTED again: the entry's `write` turned true;
5. (DR-166) the agent writes and reads back randomly named temp files, named
   by the real generators (Python's tempfile.mkstemp, NamedTemporaryFile
   and the name it checks /tmp with, coreutils mktemp): they arrive folded into templated
   paths (/tmp/tmp*, ...) and the note says so. Lock that ASP;
6. a second run writes temp files under new random names: ALIGNED;
7. a write to a new fixed name in /tmp (/tmp/exfil.tar) is DRIFT DETECTED,
   on observed_file_access alone, with the path kept as it is.

  python3 tests/files_drift_acceptance.py --raildash http://127.0.0.1:8000 \\
      --token "$(cat raildash.db.token)" \\
      --scan "python3 tools/scan/scan_agent_environment.py"

With --files-dir/--scan-files-dir the event file is written on this side
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

AGENT_KEY = "files-acceptance-agent"


def event(path: str, *, read: bool = True, write: bool = False, pid: int = 7, comm: str = "agent") -> str:
    # A line as filesnoop (ebpf-tls-tap 7b6da87) prints it.
    return json.dumps({
        "timestamp_ns": time.monotonic_ns(), "kind": "open", "pid": pid, "tid": pid,
        "host_pid": 7000 + pid, "uid": 1000, "comm": comm, "path": path, "read": read,
        "write": write, "exec": False, "creat": write, "trunc": False, "append": False,
        "dev": "0:52", "ino": 77,
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
    parser.add_argument("--files-dir", help="directory to write the event file in (default: a temp dir)")
    parser.add_argument("--scan-files-dir", help="that directory as the scanner sees it (default: same)")
    args = parser.parse_args()

    files_dir = Path(args.files_dir or tempfile.mkdtemp())
    files_dir.mkdir(parents=True, exist_ok=True)
    files_file = files_dir / "files.jsonl"
    scan_files_file = Path(args.scan_files_dir or files_dir) / "files.jsonl"
    env = {**os.environ, "RAIL_RAILDASH_TOKEN": args.token, "RAIL_HOST_ID": "ci-files-host"}
    workdir = tempfile.mkdtemp()

    def scan() -> str:
        before = set(asp_ids(args.raildash))
        argv = shlex.split(args.scan) + [
            "--mode", "self", "--agent-key", AGENT_KEY,
            "--files-file", str(scan_files_file),
            "--raildash-url", args.scan_raildash or args.raildash,
        ]
        proc = subprocess.run(argv, cwd=workdir, env=env, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            sys.exit(f"scan failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}")
        new = [asp for asp in asp_ids(args.raildash) if asp not in before]
        if len(new) != 1:
            sys.exit(f"expected one new ASP from the scan, got {new}:\n{proc.stderr}")
        return new[0]

    def append(*lines: str) -> None:
        with files_file.open("a", encoding="utf-8") as f:
            f.write("".join(line + "\n" for line in lines))

    def lock(asp: str, name: str) -> None:
        version = api(args.raildash, f"/api/asps/{asp}/lock", args.token, {"version": f"{name}-{time.time_ns()}"})
        api(args.raildash, f"/api/alignments/{version['alignment_version_id']}/switch", args.token, {})

    def drift(asp: str) -> tuple[str, list[str]]:
        state = api(args.raildash, f"/api/asps/{asp}/state")
        return state["state"], [c["name"] for c in (state.get("drift") or {}).get("changes") or []]

    checks: dict[str, bool] = {}
    # A real probe's file opens with its start record; no -H ("every": 0).
    start = json.dumps({"kind": "start", "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "every": 0})
    files_file.write_text("", encoding="utf-8")
    append(start, event("/workspace/config.json"))

    baseline = scan()
    field = api(args.raildash, f"/api/asps/{baseline}/bundle", args.token)["attributes"]["observed_file_access"]
    checks["the bundle carries the read, observed"] = (
        field["status"] == "ANSWERED" and field["tier"] == "observed"
        and field["value"] == [{"path": "/workspace/config.json", "read": True, "write": False,
                                "exec": False, "layer": False}]
    )
    lock(baseline, "files")

    append(event("/workspace/config.json", pid=8, comm="Thread-3 (work)"))
    checks["the same file read again stays aligned"] = drift(scan())[0] == "ALIGNED"

    append(event("/workspace/exfil.txt", read=False, write=True))
    wrote = scan()
    state, changed = drift(wrote)
    checks["a newly written path is drift"] = state == "DRIFT_DETECTED"
    checks["and observed_file_access is the only change"] = changed == ["observed_file_access"]

    lock(wrote, "files-written")
    append(event("/workspace/config.json", read=False, write=True, pid=9))
    state, changed = drift(scan())
    checks["writing a file that was only read is drift"] = (
        state == "DRIFT_DETECTED" and changed == ["observed_file_access"])

    # DR-166: randomly named temp files. Each run creates real ones the way
    # an agent would, and removes them; the events carry the names they got.
    def temp_run(pid: int) -> list[str]:
        # The file Python's tempfile writes to check /tmp is writable, once
        # per process, is named the way this private generator names it.
        made = ["/tmp/" + next(tempfile._get_candidate_names())]
        fd, path = tempfile.mkstemp(dir="/tmp")
        os.close(fd)
        made.append(path)
        with tempfile.NamedTemporaryFile(dir="/tmp", suffix=".json") as named:
            made.append(named.name)
        made.append(subprocess.run(["mktemp", "-p", "/tmp"], capture_output=True, text=True,
                                   check=True).stdout.strip())
        for path in made:
            if os.path.exists(path):
                os.unlink(path)
        append(*(event(path, read=False, write=True, pid=pid) for path in made),
               event(made[1], pid=pid))  # the mkstemp file, read back
        return made

    first_names = temp_run(20)
    temp = scan()
    field = api(args.raildash, f"/api/asps/{temp}/bundle", args.token)["attributes"]["observed_file_access"]
    paths = {entry["path"]: entry for entry in field["value"]}
    checks["random temp names arrive as templated paths"] = (
        field["status"] == "ANSWERED"
        and paths.get("/tmp/tmp*", {}).get("write") is True and paths["/tmp/tmp*"]["read"] is True
        and paths.get("/tmp/tmp*.json", {}).get("write") is True
        and paths.get("/tmp/tmp.*", {}).get("write") is True
        and paths.get("/tmp/*", {}).get("write") is True
        and not any(name in paths for name in first_names)
    )
    checks["and the note says they were folded"] = "randomly named temp files are folded" in field["note"]
    lock(temp, "files-temp")

    second_names = temp_run(21)
    checks["the second run's names differ from the first's"] = not set(first_names) & set(second_names)
    checks["a second run under new random names stays aligned"] = drift(scan())[0] == "ALIGNED"

    append(event("/tmp/exfil.tar", read=False, write=True, pid=22))
    exfil = scan()
    state, changed = drift(exfil)
    value = api(args.raildash, f"/api/asps/{exfil}/bundle", args.token)["attributes"]["observed_file_access"]["value"]
    checks["a new fixed name in /tmp is still drift"] = (
        state == "DRIFT_DETECTED" and changed == ["observed_file_access"]
        and any(entry["path"] == "/tmp/exfil.tar" and entry["write"] for entry in value)
    )

    for name, passed in checks.items():
        print(("ok:   " if passed else "FAIL: ") + name)
    if not all(checks.values()):
        return 1
    print(json.dumps({"result": "PASS", "baseline": baseline, "drifted": wrote}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
