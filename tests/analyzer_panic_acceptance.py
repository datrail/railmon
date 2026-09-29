#!/usr/bin/env python3
"""Built-binary DR-129 acceptance: a malformed HPACK block in one target's
captured HTTP/2 traffic panics hpack 0.3.0 inside AgentSight's HTTPParser.
RailMon must contain it to that target's tap — still running, still capturing
the other target, and restarting the one whose tap stopped — instead of the
whole collector aborting.

Root-only (distinct target UIDs via `setpriv`), like `two_agent_acceptance.py`;
CI runs it inside the built image (see `ci.yml`), `RAILMON_BIN` picks the binary.
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
    root = pathlib.Path(tempfile.mkdtemp(prefix="dr129-", dir="/run"))
    root.chmod(0o700)
    agents: list[subprocess.Popen[bytes]] = []
    railmon = None
    try:
        for uid in (65532, 65533):
            agents.append(
                subprocess.Popen(
                    ["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups", "--ptracer=any", "setsid", "sleep", "60"]
                )
            )
        time.sleep(0.1)
        for name, proc in zip(("planner", "executor"), agents):
            require(proc.poll() is None, f"{name} process did not remain live")
            (root / f"{name}.pid").write_text(f"{proc.pid}\n")
            (root / f"{name}.pid").chmod(0o600)

        # executor's traffic is one HTTP/2 HEADERS frame whose HPACK block is
        # an oversized dynamic-table-size update; planner's is ordinary.
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        block = bytes([0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F])
        malformed = preface + bytes([0, 0, len(block), 0x1, 0x4, 0, 0, 0, 1]) + block
        probe = root / "agentsight"
        probe.write_text(
            f"""#!/usr/bin/env python3
import json, os, pathlib, sys, time
args = sys.argv
sid = int(args[args.index("--session") + 1])
counter = pathlib.Path("{root}/attempts-%d" % sid)
counter.write_text(str(int(counter.read_text()) + 1 if counter.exists() else 1))
base = {{"source":"ssl","pid":sid,"comm":"python","data":{{"pid":sid,"tid":sid,"timestamp_ns":time.monotonic_ns(),"function":"SSL_write"}}}}
if sid == {agents[1].pid}:
    event = json.loads(json.dumps(base))
    event["data"].update({{"function":"WRITE/SEND","data":"HEX:{malformed.hex()}"}})
    print(json.dumps(event), flush=True)
else:
    request = json.loads(json.dumps(base))
    request["data"].update({{"message_type":"request","method":"POST","path":"/ok","headers":{{"host":"example.test"}},"body":"{{}}"}})
    print(json.dumps(request), flush=True)
    response = json.loads(json.dumps(base))
    response["data"].update({{"message_type":"response","status_code":200,"headers":{{}},"body":"{{}}"}})
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
                for name in ("planner", "executor")
            )
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
            # Long enough for at least one 5s retry tick to restart executor.
            deadline = time.monotonic() + 12
            executor_attempts = root / f"attempts-{agents[1].pid}"
            while time.monotonic() < deadline:
                require(railmon.poll() is None, "RailMon died on a malformed HPACK block")
                if executor_attempts.exists() and int(executor_attempts.read_text()) >= 2:
                    break
                time.sleep(0.1)
            require(railmon.poll() is None, "RailMon died on a malformed HPACK block")
            text = log.read_text()
            require("capture analyzer panicked" in text, "the contained panic was not logged")
            require(
                executor_attempts.exists() and int(executor_attempts.read_text()) >= 2,
                "the panicked target's tap was not restarted",
            )
            railmon.send_signal(signal.SIGINT)
            require(railmon.wait(timeout=5) == 0, "RailMon did not stop cleanly after a contained panic")
        rows = [json.loads(line) for line in output.read_text().splitlines()]
        keys = [(row.get("agent_ref") or {}).get("agent_key") for row in rows]
        require("planner" in keys, "the healthy target stopped being captured")
        require("executor" not in keys, "a panicked parser's output was trusted")

        # Single-target mode has nothing to restart into, so the contained
        # panic must surface as a failing exit a supervisor acts on — not a
        # clean 0 that reads as healthy.
        single = root / "single-probe"
        single.write_text(
            "#!/usr/bin/env python3\nimport json, time\n"
            f"print(json.dumps({{'source': 'ssl', 'pid': 1, 'comm': 'x', 'data': {{'pid': 1, 'tid': 1, "
            f"'timestamp_ns': 1, 'function': 'WRITE/SEND', 'data': 'HEX:{malformed.hex()}'}}}}), flush=True)\n"
            "time.sleep(30)\n"
        )
        single.chmod(0o700)
        finished = subprocess.run(
            [str(binary), "--agentsight", str(single), "--output", str(root / "single.jsonl")],
            capture_output=True,
            text=True,
            timeout=15,
        )
        require(finished.returncode != 0, "single-target RailMon exited 0 after its only tap stopped")
        require("analyzer failed on captured traffic" in finished.stderr, "single-target exit gave no reason")
        print(json.dumps({"result": "PASS", "executor_tap_starts": int(executor_attempts.read_text()), "rows": len(rows)}))
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
