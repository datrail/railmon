#!/usr/bin/env python3
"""A declared agent whose process is gone is drift on that agent (DR-109).

Drives the real scanner with a target manifest and a real RailDash end to end:

1. start two agents under their own UIDs and declare both in a manifest;
   scan, so the scanner delivers one evidence-bundle v2 collection; lock it
   as the baseline and make it active;
2. scan again with nothing changed: ALIGNED, with no changes at all;
3. stop one agent and scan: DRIFT DETECTED. The first change is
   AGENT_CHANGED on that agent (`available` -> `not_found`), and every
   change is scoped to it -- its sibling and the shared sandbox scope did
   not move.

Run as root, so the supervisor and agent UIDs differ, with RAILMON_BIN
naming the collector the scanner resolves the manifest through. CI runs it
inside the RailMon image:

  docker run --rm --user 0 --entrypoint python3 \\
      -e RAILMON_BIN=/usr/local/bin/railmon-collector \\
      -v "$PWD/tests:/tests:ro" railmon:ci /tests/multi_agent_drift_acceptance.py \\
      --raildash http://raildash:8000 --token "$token"
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.request import Request, urlopen

KEYS = ("drift-executor", "drift-planner")
GONE = "drift-executor"
DEFAULT_SCANNER = "/opt/railmon/tools/scan/scan_agent_environment.py"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def api(base: str, path: str, token: str | None = None, body: dict | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-RailDash-Token"] = token
    data = json.dumps(body).encode() if body is not None else None
    request = Request(base + path, data=data, headers=headers, method="POST" if body is not None else "GET")
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def asp_ids(base: str) -> list[str]:
    items = api(base, "/api/asps?limit=500")["items"]
    return [item["asp_id"] for item in items
            if (item.get("agent_identity") or {}).get("value") == list(KEYS)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--raildash", required=True, help="RailDash base URL")
    parser.add_argument("--token", required=True, help="RailDash's local token")
    parser.add_argument("--scanner", default=DEFAULT_SCANNER, help="path to scan_agent_environment.py")
    options = parser.parse_args()
    require(os.geteuid() == 0, "run as root so supervisor and agent UIDs differ")
    base = options.raildash.rstrip("/")

    # Control paths must not sit under a group/other-writable directory,
    # which rules out /tmp.
    root = pathlib.Path(tempfile.mkdtemp(prefix="dr109-drift-", dir="/run"))
    root.chmod(0o700)
    agents: dict[str, subprocess.Popen[bytes]] = {}
    try:
        for uid, key in zip((65532, 65533), KEYS):
            agents[key] = subprocess.Popen(
                ["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups",
                 "setsid", "sleep", "300"]
            )
        time.sleep(0.1)
        for key, proc in agents.items():
            require(proc.poll() is None, f"{key} did not stay live")
            (root / f"{key}.pid").write_text(f"{proc.pid}\n")
            (root / f"{key}.pid").chmod(0o600)
        manifest = root / "targets.yaml"
        manifest.write_text(
            "manifest_version: 1\n"
            "sandbox:\n"
            "  host_id: drift-host\n"
            "  sandbox_name: drift-sandbox\n"
            "  access:\n"
            "    kind: docker\n"
            "    container: drift-sandbox\n"
            "agents:\n"
            + "".join(
                f"  - agent_key: {key}\n"
                f"    discovery:\n"
                f"      pid_file: {root}/{key}.pid\n"
                f"    capture:\n"
                f"      binary_path: {shutil.which('sleep')}\n"
                for key in KEYS
            )
        )
        manifest.chmod(0o600)
        env = {**os.environ, "RAIL_RAILDASH_TOKEN": options.token, "RAIL_HOST_ID": "drift-host"}

        def scan() -> str:
            before = set(asp_ids(base))
            proc = subprocess.run(
                [sys.executable, options.scanner, "--mode", "self",
                 "--target-manifest", str(manifest), "--no-feature-file",
                 "--no-evidence-bundle", "--raildash-url", base, "-o", str(root / "payload.json")],
                cwd=root, env=env, capture_output=True, text=True, timeout=300,
            )
            require(proc.returncode == 0, f"scan failed ({proc.returncode}):\n{proc.stderr}")
            require("evidence bundle v2" in proc.stderr, f"scan did not deliver a v2 collection:\n{proc.stderr}")
            new = [asp for asp in asp_ids(base) if asp not in before]
            require(len(new) == 1, f"expected one new ASP from the scan, got {new}:\n{proc.stderr}")
            return new[0]

        checks: dict[str, bool] = {}
        baseline = scan()
        locked = api(base, f"/api/asps/{baseline}/lock", options.token, {"version": "v1.0"})
        require(locked["contract"]["bundle_version"] == 2, f"locked a non-v2 contract: {locked}")
        api(base, f"/api/alignments/{locked['alignment_version_id']}/switch", options.token, {})
        checks["v2 collection locks as the baseline"] = True

        again = scan()
        state = api(base, f"/api/asps/{again}/state")
        require(state["state"] == "ALIGNED", f"unchanged rescan is {state['state']}: {state['drift']}")
        require(state["drift"]["change_count"] == 0, f"unchanged rescan churned: {state['drift']}")
        checks["unchanged rescan is ALIGNED with no changes"] = True

        agents[GONE].terminate()
        agents[GONE].wait(timeout=5)
        gone = scan()
        state = api(base, f"/api/asps/{gone}/state")
        require(state["state"] == "DRIFT_DETECTED", f"stopped agent is {state['state']}")
        drift = api(base, f"/api/asps/{gone}/drift/explained", options.token)
        first = drift["changes"][0]
        require(
            (first["agent_key"], first["type"], first["baseline"], first["current"])
            == (GONE, "AGENT_CHANGED", {"discovery_status": "available"}, {"discovery_status": "not_found"}),
            f"first change is not {GONE} going not_found: {first}",
        )
        scopes = {change["agent_key"] for change in drift["changes"]}
        require(scopes == {GONE}, f"drift leaked outside {GONE}: {sorted(map(str, scopes))}")
        checks[f"stopped agent is AGENT_CHANGED on {GONE} only"] = True

        print(json.dumps({"result": "PASS", "checks": checks, "changes": drift["change_count"]}))
        return 0
    finally:
        for proc in agents.values():
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
