#!/usr/bin/env python3
"""Built-binary DR-109 M4 acceptance for the cases that must fail closed, plus
the single-agent path that must not change.

Four cases, each against the shipped collector (and, for evidence, the shipped
scanner), with real processes under distinct UIDs and a stub AgentSight:

- ambiguity: two agent keys whose locators resolve to one process incarnation
  are both `ambiguous` — discovery gives neither a PID, and neither key gets a
  tap or a row. The shared process is tapped once, and its traffic is one
  `ambiguous` row naming no agent (design doc §5), whatever its ticket claims;
- unknown: a key whose PID file names a process that has exited is
  `not_found`, and gets no tap and no row;
- partial evidence: the scanner still writes one v2 collection holding every
  declared key, in canonical order, where only the available agent carries
  evidence and the others record their discovery status, every input
  unattempted, and no attributes;
- single agent: without `--target-manifest`, `--pid` capture keeps the legacy
  shape — the x-rail ticket names the agent and no keyed field appears.

Throughout, the one available agent in the same manifest is still captured
and attributed: a sibling failing closed never drops it.
"""

import base64
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

HOST_ID = "acceptance-host"
SANDBOX_NAME = "shared-container"
KEYS = ("executor", "planner", "reviewer", "retired")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def spawn_agent(uid: int, seconds: int = 60) -> subprocess.Popen[bytes]:
    # Its own session, so a manifest target has a session of its own to tap.
    return subprocess.Popen(
        [
            "setpriv",
            f"--reuid={uid}",
            f"--regid={uid}",
            "--clear-groups",
            "--ptracer=any",
            "setsid",
            "sleep",
            str(seconds),
        ]
    )


def write_private(path: pathlib.Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o600)


def railmon_root() -> pathlib.Path:
    # CI mounts this file at /tests with no source tree beside it, so the scanner
    # is the one the image ships (its RAILMON_ROOT); from a checkout it is the
    # checkout's.
    configured = os.environ.get("RAILMON_ROOT")
    if configured:
        return pathlib.Path(configured)
    checkout = pathlib.Path(__file__).resolve().parent.parent
    if (checkout / "tools/agent-environment-scanner").is_dir():
        return checkout
    return pathlib.Path("/opt/railmon")


STUB = """#!/usr/bin/env python3
import json, os, sys, time
args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as log:
    log.write(json.dumps(args) + "\\n")
flag = next(f for f in ("--session", "--pid", "-p") if f in args)
pid = int(args[args.index(flag) + 1])
headers = {"host": "example.test"}
if os.environ.get("STUB_X_RAIL"):
    headers["x-rail"] = os.environ["STUB_X_RAIL"]
base = {"source": "ssl", "pid": pid, "comm": "python",
        "data": {"pid": pid, "tid": pid, "timestamp_ns": time.monotonic_ns(), "function": "SSL_write"}}
request = json.loads(json.dumps(base))
request["data"].update({"message_type": "request", "method": "POST", "path": f"/{pid}",
                        "headers": headers, "body": "{}"})
print(json.dumps(request), flush=True)
response = json.loads(json.dumps(base))
response["data"].update({"message_type": "response", "status": 200, "headers": {}, "body": "{}"})
print(json.dumps(response), flush=True)
time.sleep(60)
"""


def run_collector(
    binary: pathlib.Path, args: list[str], output: pathlib.Path, rows: int, env: dict[str, str]
) -> list[dict]:
    """Run the collector until it has written `rows` rows, then linger long
    enough that a row it should not write would have arrived too."""
    railmon = subprocess.Popen([str(binary), *args, "--output", str(output)], env=env)
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if output.exists() and len(output.read_text().splitlines()) >= rows:
                break
            require(railmon.poll() is None, "RailMon exited before capturing")
            time.sleep(0.05)
        else:
            raise RuntimeError(f"RailMon did not write {rows} row(s) before timeout")
        time.sleep(2)
        require(railmon.poll() is None, "RailMon exited while a sibling target was failing closed")
        railmon.send_signal(signal.SIGINT)
        require(railmon.wait(timeout=5) == 0, "RailMon did not stop cleanly")
    finally:
        if railmon.poll() is None:
            railmon.kill()
    return [json.loads(line) for line in output.read_text().splitlines()]


def main() -> None:
    require(os.geteuid() == 0, "run as root so supervisor and agent UIDs differ")
    binary = pathlib.Path(os.environ.get("RAILMON_BIN", "target/debug/railmon")).resolve()
    root = pathlib.Path(tempfile.mkdtemp(prefix="dr109-fc-", dir="/run"))
    root.chmod(0o700)
    agents: list[subprocess.Popen[bytes]] = []
    try:
        shared = spawn_agent(65532)
        reviewer = spawn_agent(65533)
        agents += [shared, reviewer]
        # A process that has already exited: its PID file is what a crashed
        # agent leaves behind.
        gone = spawn_agent(65534, 0)
        gone.wait(timeout=5)
        time.sleep(0.1)
        require(shared.poll() is None and reviewer.poll() is None, "agent processes did not stay live")

        write_private(root / "shared.pid", f"{shared.pid}\n")
        write_private(root / "reviewer.pid", f"{reviewer.pid}\n")
        write_private(root / "retired.pid", f"{gone.pid}\n")
        config = root / "reviewer-config"
        config.mkdir(mode=0o700)
        write_private(config / "settings.json", json.dumps({"model": "acceptance"}))

        stub = root / "agentsight"
        stub.write_text(STUB)
        stub.chmod(0o700)
        manifest = root / "targets.yaml"
        write_private(
            manifest,
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
      pid_file: {root}/shared.pid
    capture:
      binary_path: /usr/bin/python3
  - agent_key: executor
    discovery:
      pid_file: {root}/shared.pid
    capture:
      binary_path: /usr/bin/python3
  - agent_key: reviewer
    discovery:
      pid_file: {root}/reviewer.pid
    scan:
      config_roots: [{config}]
    capture:
      binary_path: /usr/bin/python3
  - agent_key: retired
    discovery:
      pid_file: {root}/retired.pid
    capture:
      binary_path: /usr/bin/python3
""",
        )

        # Discovery, through the same contract the scanner reads.
        resolved = json.loads(
            subprocess.run(
                [str(binary), "--target-manifest", str(manifest), "--print-resolved-targets"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )
        status = {row["agent_key"]: row for row in resolved}
        require(set(status) == set(KEYS), f"resolved keys differ: {sorted(status)}")
        for key in ("planner", "executor"):
            require(status[key]["status"] == "ambiguous", f"{key} sharing one process was {status[key]['status']}")
            require(status[key]["pid"] is None, f"ambiguous {key} still carries a PID")
            require("multiple agent keys" in (status[key]["reason"] or ""), f"{key} reason: {status[key]['reason']}")
        require(status["retired"]["status"] == "not_found", f"exited target was {status['retired']['status']}")
        require(status["retired"]["pid"] is None, "not_found target still carries a PID")
        require(
            status["reviewer"]["status"] == "available" and status["reviewer"]["pid"] == reviewer.pid,
            f"available sibling was not resolved: {status['reviewer']}",
        )

        # Capture: the available agent gets an attributed row; the shared
        # process is tapped once and its row names no agent, even though its
        # ticket claims one.
        claimed = str(uuid.uuid4())
        ticket = base64.urlsafe_b64encode(json.dumps({"agent_id": claimed}).encode()).decode().rstrip("=")
        env = {**os.environ, "STUB_LOG": str(root / "keyed-taps.jsonl"), "STUB_X_RAIL": ticket}
        rows = run_collector(
            binary,
            ["--target-manifest", str(manifest), "--agentsight", str(stub), "--output-format", "runtime-interaction"],
            root / "keyed.jsonl",
            2,
            env,
        )
        require(len(rows) == 2, f"expected two interactions, got {len(rows)}")
        by_state = {row["attribution"]["state"]: row for row in rows}
        require(set(by_state) == {"attributed", "ambiguous"}, f"row states {sorted(by_state)}")
        row = by_state["attributed"]
        require(row["agent_ref"]["agent_key"] == "reviewer", f"row attributed to {row['agent_ref']}")
        require(row["attribution"]["process"]["pid"] == reviewer.pid, "row carries another process")
        row = by_state["ambiguous"]
        require(row["agent_ref"] is None and row["agent_id"] is None, "ambiguous row names an agent")
        require(
            row["attribution"]["reason"] == "MULTIPLE_TARGETS" and row["attribution"]["target_id"] is None,
            f"ambiguous attribution {row['attribution']}",
        )
        require(row["attribution"]["process"]["pid"] == shared.pid, "ambiguous row carries another process")
        require(
            row["raw"]["railmon_attribution_audit"]["candidate_targets"] == ["executor", "planner"],
            f"ambiguous audit {row['raw'].get('railmon_attribution_audit')}",
        )
        taps = [json.loads(line) for line in (root / "keyed-taps.jsonl").read_text().splitlines()]
        tapped = sorted(int(args[args.index("--session") + 1]) for args in taps)
        require(tapped == sorted([reviewer.pid, shared.pid]), f"taps opened on {tapped}, not once per process")

        # Evidence: one v2 collection keeps every key; only the reviewer has any.
        bundle_path = root / "evidence-bundle.json"
        scanner = railmon_root() / "tools/agent-environment-scanner/scan_agent_environment.py"
        scan = subprocess.run(
            [
                sys.executable,
                str(scanner),
                "--mode", "self",
                "--host-id", HOST_ID,
                "--sandbox-name", SANDBOX_NAME,
                "--target-manifest", str(manifest),
                "--evidence-bundle-output", str(bundle_path),
                "--output", str(root / "registration.json"),
            ],
            cwd=root,
            env={**os.environ, "RAILMON_BIN": str(binary)},
            capture_output=True,
            text=True,
        )
        require(scan.returncode == 0, f"scanner exited {scan.returncode}: {scan.stderr}")
        require(bundle_path.exists(), f"no evidence bundle written: {scan.stderr}")
        bundle = json.loads(bundle_path.read_text())
        require(bundle["bundle_version"] == 2, f"bundle_version {bundle['bundle_version']}")
        require(
            (bundle["host_id"], bundle["sandbox_name"]) == (HOST_ID, SANDBOX_NAME),
            "bundle names another sandbox",
        )
        require(bundle["sandbox"]["attributes"], "shared sandbox scope carries no evidence")
        entries = {agent["agent_key"]: agent for agent in bundle["agents"]}
        require([agent["agent_key"] for agent in bundle["agents"]] == sorted(KEYS), "agents missing or not in key order")
        expected = {"planner": "ambiguous", "executor": "ambiguous", "retired": "not_found", "reviewer": "available"}
        for key, discovery in expected.items():
            require(entries[key]["discovery_status"] == discovery, f"{key} discovery_status {entries[key]['discovery_status']}")
        for key in ("planner", "executor", "retired"):
            require(entries[key]["attributes"] == {}, f"{key} gained evidence without a process")
            attempted = entries[key]["inputs_attempted"]
            require(
                attempted and all(item["attempted"] is False for item in attempted.values()),
                f"{key} claims inputs were attempted: {attempted}",
            )
        # A failed agent scan still fills attributes, every one FAILED, so
        # require an answer rather than merely a non-empty map.
        require(
            any(attr.get("status") == "ANSWERED" for attr in entries["reviewer"]["attributes"].values()),
            f"the available agent's scoped evidence has no answer: {entries['reviewer']['attributes']}",
        )
        require(
            all("image_digest" not in entry["attributes"] for entry in bundle["agents"]),
            "sandbox evidence leaked into an agent scope",
        )

        # Single agent: no manifest, the legacy `--pid` path, unchanged.
        claimed = str(uuid.uuid4())
        ticket = base64.urlsafe_b64encode(json.dumps({"agent_id": claimed}).encode()).decode().rstrip("=")
        env = {**os.environ, "STUB_LOG": str(root / "legacy-taps.jsonl"), "STUB_X_RAIL": ticket}
        rows = run_collector(
            binary,
            ["--pid", str(reviewer.pid), "--agentsight", str(stub), "--output-format", "runtime-interaction"],
            root / "legacy.jsonl",
            1,
            env,
        )
        require(len(rows) == 1, f"expected one legacy interaction, got {len(rows)}")
        legacy = rows[0]
        require(legacy["agent_id"] == claimed, "legacy row did not take its agent from the x-rail ticket")
        for field in ("runtime_identity_version", "agent_ref", "attribution"):
            require(field not in legacy, f"legacy row gained keyed field {field}")
        taps = [json.loads(line) for line in (root / "legacy-taps.jsonl").read_text().splitlines()]
        require(
            len(taps) == 1 and taps[0][taps[0].index("-p") + 1] == str(reviewer.pid) and "--session" not in taps[0],
            f"legacy tap arguments changed: {taps}",
        )

        print(
            json.dumps(
                {
                    "result": "PASS",
                    "discovery": {key: status[key]["status"] for key in sorted(status)},
                    "keyed_rows": {state: 1 for state in sorted(by_state)},
                    "bundle_agents": {key: entries[key]["discovery_status"] for key in sorted(entries)},
                    "legacy_rows": 1,
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
