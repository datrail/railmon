#!/usr/bin/env python3
"""Built-binary DR-184 acceptance: with RailDash's local write token set, the
collector's webhook batches carry it in `X-RailDash-Token`, beside whatever
`RAIL_AUTH_MODE` sends, and a heartbeat goes to `/webhook/heartbeat` while
the tap is attached. Without the token, nothing changes and no heartbeat goes.

A stub AgentSight emits one interaction, then a second a few seconds later; a
local server stands in for RailDash's webhook and heartbeat routes.
`RAIL_HEARTBEAT_INTERVAL` shortens the 60 s heartbeat. Needs no root, eBPF or
network; CI runs it inside the built image with the other acceptance scripts.
"""

import json
import os
import pathlib
import signal
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BINARY = pathlib.Path(os.environ.get("RAILMON_BIN", "target/debug/railmon")).resolve()
TOKEN_VARS = (
    "RAIL_AUTH_MODE",
    "RAIL_AUTH_TOKEN",
    "RAIL_AUTH_TOKEN_FILE",
    "RAIL_AUTH_AUDIENCE",
    "RAIL_RAILDASH_TOKEN",
    "RAIL_RAILDASH_TOKEN_FILE",
    "RAIL_HEARTBEAT_INTERVAL",
    "RAIL_HOST_ID",
)

PROBE = r"""#!/usr/bin/env python3
import json, os, sys, time
pid = os.getpid()
def ssl(function, text):
    print(json.dumps({"source":"ssl","pid":pid,"comm":"python","data":{"pid":pid,"tid":pid,"timestamp_ns":time.monotonic_ns(),"function":function,"data":text}}), flush=True)
def emit(path):
    ssl("WRITE/SEND", f"POST {path} HTTP/1.1\r\nHost: example.test\r\nContent-Length: 2\r\n\r\n{{}}")
    ssl("READ/RECV", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
emit("/first")
time.sleep(3)
emit("/second")
time.sleep(60)
"""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


class Recorder(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        token = self.headers.get("X-RailDash-Token")
        if self.path == "/webhook/heartbeat":
            self.server.heartbeats.append((token, body))
            self.send_response(self.server.heartbeat_status)
        else:
            paths = [i.get("request", {}).get("path") for i in body.get("interactions", [])]
            self.server.posts.append((self.path, token, self.headers.get("Authorization"), paths))
            self.send_response(202)
        self.end_headers()


class Run:
    def __init__(self, root: pathlib.Path):
        self.root = root
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
        self.server.posts, self.server.heartbeats = [], []
        self.server.heartbeat_status = 200
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.host = f"127.0.0.1:{self.server.server_address[1]}"
        self.probe = root / "agentsight"
        self.probe.write_text(PROBE)
        self.probe.chmod(0o700)

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def start(self, **env_vars) -> subprocess.Popen:
        env = {k: v for k, v in os.environ.items() if k not in TOKEN_VARS}
        env.update({"RAIL_HEARTBEAT_INTERVAL": "0.5", **env_vars})
        return subprocess.Popen(
            [
                str(BINARY),
                "--agentsight", str(self.probe),
                "--pid", str(os.getpid()),
                "--webhook", f"http://{self.host}/webhook/http-interactions",
                "--batch-size", "1",
                "--flush-interval", "0.2",
            ],
            env=env,
            stderr=subprocess.PIPE,
            text=True,
        )

    def wait_for(self, proc: subprocess.Popen, done, timeout: float = 15) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not done():
            if proc.poll() is not None:
                raise RuntimeError(f"collector exited early: {proc.stderr.read()}")
            time.sleep(0.05)
        require(done(), "timed out waiting for the collector")

    def stop(self, proc: subprocess.Popen) -> str:
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
        _, stderr = proc.communicate(timeout=15)
        return stderr


def case_unset_sends_no_token_and_no_heartbeat(root: pathlib.Path) -> None:
    run = Run(root)
    try:
        proc = run.start()
        run.wait_for(proc, lambda: len(run.server.posts) >= 2)
        run.stop(proc)
        require(
            run.server.posts[:2]
            == [
                ("/webhook/http-interactions", None, None, ["/first"]),
                ("/webhook/http-interactions", None, None, ["/second"]),
            ],
            f"unset: {run.server.posts}",
        )
        require(run.server.heartbeats == [], f"heartbeat without a token: {run.server.heartbeats}")
    finally:
        run.close()


def case_token_beside_bearer_and_heartbeat(root: pathlib.Path) -> None:
    run = Run(root)
    try:
        proc = run.start(
            RAIL_RAILDASH_TOKEN="dash-s3cret",
            RAIL_AUTH_MODE="bearer",
            RAIL_AUTH_TOKEN="rc-s3cret",
            RAIL_HOST_ID="hb-host",
        )
        run.wait_for(proc, lambda: len(run.server.posts) >= 1 and len(run.server.heartbeats) >= 2)
        stderr = run.stop(proc)
        require(
            run.server.posts[0]
            == ("/webhook/http-interactions", "dash-s3cret", "Bearer rc-s3cret", ["/first"]),
            f"batch: {run.server.posts}",
        )
        for token, body in run.server.heartbeats:
            require(token == "dash-s3cret", f"heartbeat token: {token!r}")
            require(sorted(body) == ["collector_id", "sent_at", "taps_attached"], f"body: {body}")
            require(body["taps_attached"] == 1, f"body: {body}")
            require(body["collector_id"] == f"hb-host:{proc.pid}", f"body: {body}")
            require(body["sent_at"].endswith("Z"), f"body: {body}")
        require("s3cret" not in stderr, "a token reached the log")
    finally:
        run.close()


def case_refused_heartbeat_never_stops_capture(root: pathlib.Path) -> None:
    token = root / "token"
    token.write_text("dash-file\n")
    run = Run(root)
    run.server.heartbeat_status = 403
    try:
        proc = run.start(RAIL_RAILDASH_TOKEN_FILE=str(token))
        run.wait_for(proc, lambda: len(run.server.heartbeats) >= 3)
        token.write_text("dash-rotated\n")  # rotated while running
        run.wait_for(proc, lambda: len(run.server.posts) >= 2)
        stderr = run.stop(proc)
        require(
            [(t, p) for _, t, _, p in run.server.posts[:2]]
            == [("dash-file", ["/first"]), ("dash-rotated", ["/second"])],
            f"capture after refused heartbeats: {run.server.posts}",
        )
        require(run.server.heartbeats[-1][0] == "dash-rotated", f"{run.server.heartbeats}")
        require(stderr.count("RailDash refused the token") == 1, f"logged per heartbeat:\n{stderr}")
        require("dash-file" not in stderr and "dash-rotated" not in stderr, "a token reached the log")
    finally:
        run.close()


def case_both_forms_refused(root: pathlib.Path) -> None:
    run = Run(root)
    try:
        proc = run.start(RAIL_RAILDASH_TOKEN="dash-s3cret", RAIL_RAILDASH_TOKEN_FILE=str(root / "t"))
        try:
            _, stderr = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise RuntimeError("collector kept running instead of refusing")
        require(proc.returncode != 0, f"collector exited 0 on a refusal: {stderr}")
        require("both set" in stderr and "s3cret" not in stderr, stderr)
        require(run.server.posts == [] and run.server.heartbeats == [], "posted despite refusal")
    finally:
        run.close()


def main() -> None:
    require(BINARY.exists(), f"no collector at {BINARY}; build it or set RAILMON_BIN")
    cases = [
        case_unset_sends_no_token_and_no_heartbeat,
        case_token_beside_bearer_and_heartbeat,
        case_refused_heartbeat_never_stops_capture,
        case_both_forms_refused,
    ]
    for case in cases:
        with tempfile.TemporaryDirectory(prefix="dr184-") as tmp:
            case(pathlib.Path(tmp))
        print(f"ok  {case.__name__}")
    print("DR-184 RailDash token and heartbeat acceptance: all cases passed")


if __name__ == "__main__":
    main()
