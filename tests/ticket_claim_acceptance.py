#!/usr/bin/env python3
"""Built-binary DR-109 M3 acceptance: an unsigned `x-rail` ticket only ever
corroborates or contradicts the process target (design doc §4.5).

Three real agent processes under distinct UIDs, each with its own tap:
`planner` sends a ticket claiming its own registered agent_id (agreement),
`executor` sends a ticket claiming planner's agent_id (conflict), and `critic`
sends no ticket and has not registered (process target alone). Registration
state is written where the scanner would put it and handed to RailMon with
`--registration-state`. Root-only and not wired into CI, matching
`two_agent_acceptance.py`. Pass `--dump <path>` to keep the captured rows,
e.g. to validate them against the consumers' schemas.
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

PLANNER_ID = "550e8400-e29b-41d4-a716-446655440000"
EXECUTOR_ID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def ticket(agent_id: str) -> str:
    return base64.urlsafe_b64encode(json.dumps({"agent_id": agent_id}).encode()).decode().rstrip("=")


def main() -> None:
    require(os.geteuid() == 0, "run as root so supervisor and agent UIDs differ")
    dump = pathlib.Path(sys.argv[sys.argv.index("--dump") + 1]) if "--dump" in sys.argv else None
    root = pathlib.Path(tempfile.mkdtemp(prefix="dr109-ticket-", dir="/run"))
    root.chmod(0o700)
    names = ("planner", "executor", "critic")
    agents: list[subprocess.Popen[bytes]] = []
    railmon = None
    try:
        for uid in (65531, 65532, 65533):
            agents.append(
                subprocess.Popen(
                    ["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups", "--ptracer=any", "setsid", "sleep", "60"]
                )
            )
        time.sleep(0.1)
        for name, proc in zip(names, agents):
            require(proc.poll() is None, f"{name} process did not remain live")
            (root / f"{name}.pid").write_text(f"{proc.pid}\n")
            (root / f"{name}.pid").chmod(0o600)

        # What each agent's traffic carries, keyed by its session id.
        tickets = {
            str(agents[0].pid): ticket(PLANNER_ID),
            str(agents[1].pid): ticket(PLANNER_ID),
        }
        (root / "tickets.json").write_text(json.dumps(tickets))
        for key, agent_id in (("planner", PLANNER_ID), ("executor", EXECUTOR_ID)):
            state = root / f"registration.json.{key}"
            state.write_text(
                json.dumps({"agent_id": agent_id, "host_id": "acceptance-host", "sandbox_name": "shared-container"})
            )
            state.chmod(0o600)

        probe = root / "agentsight"
        probe.write_text(
            f"""#!/usr/bin/env python3
import json, os, sys, time
args = sys.argv
require = lambda c, m: c or (_ for _ in ()).throw(RuntimeError(m))
require("--session" in args, "RailMon did not use AgentSight session filtering")
sid = int(args[args.index("--session") + 1])
require(os.getsid(sid) == sid, "target is not its own process session")
headers = {{"host": "example.test"}}
token = json.load(open("{root}/tickets.json")).get(str(sid))
if token:
    headers["x-rail"] = token
base = {{"source":"ssl","pid":sid,"comm":"python","data":{{"pid":sid,"tid":sid,"timestamp_ns":time.monotonic_ns(),"function":"SSL_write"}}}}
request = json.loads(json.dumps(base))
request["data"].update({{"message_type":"request","method":"POST","path":f"/{{sid}}","headers":headers,"body":"{{}}"}})
print(json.dumps(request), flush=True)
response = json.loads(json.dumps(base))
response["data"].update({{"message_type":"response","status":200,"headers":{{}},"body":"{{}}"}})
print(json.dumps(response), flush=True)
time.sleep(60)
"""
        )
        probe.chmod(0o700)
        manifest = root / "targets.yaml"
        manifest.write_text(
            "manifest_version: 1\n"
            "sandbox:\n  host_id: acceptance-host\n  sandbox_name: shared-container\n"
            "  access:\n    kind: docker\n    container: shared-container\nagents:\n"
            + "".join(
                f"  - agent_key: {name}\n    discovery:\n      pid_file: {root}/{name}.pid\n"
                "    capture:\n      binary_path: /usr/bin/python3\n"
                for name in names
            )
        )
        manifest.chmod(0o600)
        output = root / "interactions.jsonl"
        binary = pathlib.Path("target/debug/railmon").resolve()
        railmon = subprocess.Popen(
            [
                str(binary),
                "--target-manifest", str(manifest),
                "--registration-state", str(root / "registration.json"),
                "--agentsight", str(probe),
                "--output", str(output),
                "--output-format", "runtime-interaction",
            ],
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if output.exists() and len(output.read_text().splitlines()) == 3:
                break
            require(railmon.poll() is None, "RailMon exited before capturing every agent")
            time.sleep(0.05)
        else:
            raise RuntimeError("RailMon did not capture every agent before timeout")
        railmon.send_signal(signal.SIGINT)
        require(railmon.wait(timeout=5) == 0, "RailMon did not stop cleanly on SIGINT")
        rows = [json.loads(line) for line in output.read_text().splitlines()]
        require(len(rows) == 3, f"expected three interactions, one per agent, got {len(rows)}")
        by_pid = {row["attribution"]["process"]["pid"]: row for row in rows}
        planner, executor, critic = (by_pid[proc.pid] for proc in agents)

        require(planner["attribution"]["state"] == "attributed", "agreeing ticket was not attributed")
        require(
            planner["attribution"]["method"] == "process_target_with_ticket_claim",
            "agreeing ticket was not recorded as corroboration",
        )
        require(planner["agent_ref"]["agent_key"] == "planner", "planner lost its agent_ref")
        require(planner["agent_id"] == PLANNER_ID, "planner's agent_id is not its registered id")

        require(executor["attribution"]["state"] == "conflict", "a ticket naming a sibling was not a conflict")
        require(executor["agent_ref"] is None, "a conflict kept an authoritative agent_ref")
        require(executor["agent_id"] is None, "a conflict kept the forged ticket's agent_id")
        audit = executor["raw"]["railmon_attribution_audit"]
        require(
            audit == {"process_target": "executor", "ticket_claim": {"agent_key": "planner", "agent_id": PLANNER_ID}},
            f"conflict audit record is wrong: {audit}",
        )

        require(critic["attribution"]["state"] == "attributed", "ticketless critic was not attributed")
        require(critic["attribution"]["method"] == "process_target", "ticketless critic has the wrong method")
        require(critic["agent_id"] is None, "unregistered critic invented an agent_id")

        require(
            sum(1 for row in rows if (row.get("agent_ref") or {}).get("agent_key") == "planner") == 1,
            "the executor's claim copied its traffic into planner",
        )
        if dump is not None:
            dump.write_text("".join(json.dumps(row) + "\n" for row in rows))
        print(json.dumps({"result": "PASS", "states": sorted(row["attribution"]["state"] for row in rows)}))
    finally:
        if railmon is not None and railmon.poll() is None:
            railmon.kill()
            railmon.wait(timeout=2)
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
