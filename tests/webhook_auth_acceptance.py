#!/usr/bin/env python3
"""Built-binary DR-78 acceptance: the collector's webhook presents the
credential `RAIL_AUTH_MODE` names (RM-F2…F5), and never sends anonymously
when it was asked for one.

A stub AgentSight emits one interaction, then a second a few seconds later; a
local server stands in for Rail Center's POST /v1/interactions and for the GCP
metadata server. What is asserted is the `Authorization` header that actually
arrives. Needs no root, eBPF or network; CI runs it inside the built image
with the other acceptance scripts.
"""

import base64
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
AUTH_VARS = ("RAIL_AUTH_MODE", "RAIL_AUTH_TOKEN", "RAIL_AUTH_TOKEN_FILE", "RAIL_AUTH_AUDIENCE", "GCE_METADATA_HOST")

# Two interactions: the second after a pause long enough for the first batch
# to be flushed on its own, so a credential change in between is observable.
PROBE = r"""#!/usr/bin/env python3
import json, os, sys, time
pid = os.getpid()
def ssl(function, text):
    print(json.dumps({"source":"ssl","pid":pid,"comm":"python","data":{"pid":pid,"tid":pid,"timestamp_ns":time.monotonic_ns(),"function":function,"data":text}}), flush=True)
def emit(path):
    ssl("WRITE/SEND", f"POST {path} HTTP/1.1\r\nHost: example.test\r\nContent-Length: 2\r\n\r\n{{}}")
    ssl("READ/RECV", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
emit("/first")
time.sleep(float(os.environ.get("PROBE_PAUSE", "3")))
emit("/second")
time.sleep(60)
"""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def jwt(exp: int) -> str:
    enc = lambda v: base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")  # noqa: E731
    return ".".join([enc('{"alg":"RS256"}'), enc(json.dumps({"exp": exp})), "sig"])


class Recorder(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        paths = [i.get("request", {}).get("path") for i in body.get("interactions", [])]
        self.server.posts.append((self.headers.get("Authorization"), paths))
        self.send_response(202)
        self.end_headers()

    def do_GET(self):
        self.server.mints.append((self.path, self.headers.get("Metadata-Flavor")))
        body = self.server.identity.encode()
        self.send_response(self.server.identity_status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Run:
    def __init__(self, root: pathlib.Path):
        self.root = root
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
        self.server.posts, self.server.mints = [], []
        self.server.identity = jwt(int(time.time()) + 3600)
        self.server.identity_status = 200
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.host = f"127.0.0.1:{self.server.server_address[1]}"
        self.probe = root / "agentsight"
        self.probe.write_text(PROBE)
        self.probe.chmod(0o700)

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def start(self, **auth) -> subprocess.Popen:
        env = {k: v for k, v in os.environ.items() if k not in AUTH_VARS}
        env.update(auth)
        return subprocess.Popen(
            [
                str(BINARY),
                "--agentsight", str(self.probe),
                "--pid", str(os.getpid()),
                "--webhook", f"http://{self.host}/v1/interactions",
                "--batch-size", "1",
                "--flush-interval", "0.2",
            ],
            env=env,
            stderr=subprocess.PIPE,
            text=True,
        )

    def wait_for_posts(self, proc: subprocess.Popen, count: int, timeout: float = 15) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and len(self.server.posts) < count:
            if proc.poll() is not None:
                raise RuntimeError(f"collector exited early: {proc.stderr.read()}")
            time.sleep(0.05)

    def refused(self, proc: subprocess.Popen) -> str:
        """The collector's own exit on a refusal, not one we caused."""
        try:
            _, stderr = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise RuntimeError("collector kept running instead of refusing")
        require(proc.returncode != 0, f"collector exited 0 on a refusal: {stderr}")
        return stderr

    def stop(self, proc: subprocess.Popen) -> str:
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
        _, stderr = proc.communicate(timeout=15)
        return stderr


def case_none(root: pathlib.Path) -> None:
    run = Run(root)
    try:
        proc = run.start()
        run.wait_for_posts(proc, 1)
        run.stop(proc)
        require(run.server.posts[0] == (None, ["/first"]), f"none: {run.server.posts}")
    finally:
        run.close()


def case_token_beside_none(root: pathlib.Path) -> None:
    run = Run(root)
    try:
        proc = run.start(RAIL_AUTH_TOKEN="s3cret")
        stderr = run.refused(proc)
        require("unset, which is none" in stderr and "s3cret" not in stderr, stderr)
        require(run.server.posts == [], f"posted despite refusal: {run.server.posts}")
    finally:
        run.close()


def case_bearer_env(root: pathlib.Path) -> None:
    run = Run(root)
    try:
        proc = run.start(RAIL_AUTH_MODE="bearer", RAIL_AUTH_TOKEN="t-env")
        run.wait_for_posts(proc, 1)
        stderr = run.stop(proc)
        require(run.server.posts[0] == ("Bearer t-env", ["/first"]), f"bearer env: {run.server.posts}")
        require("t-env" not in stderr, "the token reached the log")
    finally:
        run.close()


def case_bearer_file_rotation_and_loss(root: pathlib.Path) -> None:
    token = root / "token"
    token.write_text("t-before\n")
    run = Run(root)
    try:
        proc = run.start(RAIL_AUTH_MODE="bearer", RAIL_AUTH_TOKEN_FILE=str(token))
        run.wait_for_posts(proc, 1)
        token.write_text("t-after\n")  # rotated while running
        run.wait_for_posts(proc, 2)
        run.stop(proc)
        require(
            run.server.posts[:2] == [("Bearer t-before", ["/first"]), ("Bearer t-after", ["/second"])],
            f"rotation: {run.server.posts}",
        )
    finally:
        run.close()

    token.write_text("t-only\n")
    run = Run(root)
    try:
        proc = run.start(RAIL_AUTH_MODE="bearer", RAIL_AUTH_TOKEN_FILE=str(token))
        run.wait_for_posts(proc, 1)
        token.unlink()  # the secret disappears mid-run
        time.sleep(4)
        stderr = run.stop(proc)
        require(run.server.posts == [("Bearer t-only", ["/first"])], f"loss: {run.server.posts}")
        require("rather than sending them anonymously" in stderr, stderr)
    finally:
        run.close()


def case_gcp(root: pathlib.Path) -> None:
    run = Run(root)
    try:
        proc = run.start(RAIL_AUTH_MODE="gcp", RAIL_AUTH_AUDIENCE="https://rc.example/api", GCE_METADATA_HOST=run.host)
        run.wait_for_posts(proc, 2)
        run.stop(proc)
        expected = f"Bearer {run.server.identity}"
        require([auth for auth, _ in run.server.posts[:2]] == [expected, expected], f"gcp: {run.server.posts}")
        require(
            run.server.mints
            == [
                (
                    "/computeMetadata/v1/instance/service-accounts/default/identity"
                    "?audience=https%3A%2F%2Frc.example%2Fapi",
                    "Google",
                )
            ],
            f"gcp should mint once and reuse a fresh token: {run.server.mints}",
        )
    finally:
        run.close()


def case_gcp_without_identity(root: pathlib.Path) -> None:
    run = Run(root)
    run.server.identity_status = 404
    try:
        proc = run.start(RAIL_AUTH_MODE="gcp", RAIL_AUTH_AUDIENCE="aud", GCE_METADATA_HOST=run.host)
        stderr = run.refused(proc)
        require("404" in stderr, stderr)
        require(run.server.posts == [], f"posted anonymously: {run.server.posts}")
    finally:
        run.close()


def main() -> None:
    require(BINARY.exists(), f"no collector at {BINARY}; build it or set RAILMON_BIN")
    cases = [
        case_none,
        case_token_beside_none,
        case_bearer_env,
        case_bearer_file_rotation_and_loss,
        case_gcp,
        case_gcp_without_identity,
    ]
    for case in cases:
        with tempfile.TemporaryDirectory(prefix="dr78-") as tmp:
            case(pathlib.Path(tmp))
        print(f"ok  {case.__name__}")
    print("DR-78 webhook auth acceptance: all cases passed")


if __name__ == "__main__":
    main()
