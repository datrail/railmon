#!/usr/bin/env python3
"""The built image scans a container through a read-only Docker API (DR-300).

`railmon scan --mode docker` runs nothing in the agent's container: it asks
Docker only to inspect, and reads the container's files through
/proc/<pid>/root. Containers from one image:

- an "agent" running as `nobody`, so reading its root takes SYS_PTRACE;
- `railmon scan --mode docker`, in the host PID namespace with SYS_PTRACE,
  once on the Docker socket and once through a proxy this script runs. The
  proxy forwards GET and HEAD to the socket, refuses every other method with
  403 (as a read-only Docker API proxy does), and logs each call.

Checked:

1. the scan through the proxy made only GET/HEAD calls, the proxy refused
   nothing, and each call is one of the reads the scan is known to make
   (`_ping`, a container inspect, a network inspect), so a new
   Docker call fails here before a stricter read-only proxy refuses it;
2. the two bundles' attributes are equal (instance fields aside);
3. the fields `docker exec` used to give are there: the image's Python, its
   os-release, the exec user `nobody` and its HOME.

Needs Docker, as CI's runner has.

  python3 tests/docker_readonly_acceptance.py --image railmon:ci
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

DOCKER_SOCKET = "/var/run/docker.sock"
# Where this copy runs, not what it is: they differ between any two scans.
INSTANCE = {"agent_instance", "scan_window"}


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str) -> None:
        super().__init__("localhost", timeout=60)
        self._path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._path)


class ReadOnlyProxy(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str) -> None:
        self.calls: list[tuple[str, str, int]] = []
        self.lock = threading.Lock()
        super().__init__(path, _Handler)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: ReadOnlyProxy

    def address_string(self) -> str:  # a Unix socket has no client address
        return "proxy-client"

    def log_message(self, *_args) -> None:
        pass

    def _forward(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        if self.command not in ("GET", "HEAD"):
            status, payload, headers = 403, b'{"message":"read-only proxy"}', {"Content-Type": "application/json"}
        else:
            upstream = _UnixConnection(DOCKER_SOCKET)
            forwarded = {k: v for k, v in self.headers.items() if k.lower() not in ("connection", "content-length")}
            upstream.request(self.command, self.path, body=body, headers=forwarded)
            response = upstream.getresponse()
            payload = response.read()
            status = response.status
            headers = {k: v for k, v in response.getheaders()
                       if k.lower() not in ("transfer-encoding", "connection", "content-length")}
            upstream.close()
        with self.server.lock:
            self.server.calls.append((self.command, self.path, status))
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = _forward


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check, timeout=300)


def scan(image: str, agent: str, out: Path, name: str, docker_args: list[str]) -> dict | None:
    """One docker-mode scan as root (SYS_PTRACE is root's only), its bundle
    read back through the image itself, since the scanner writes it 0600."""
    result = docker("run", "--rm", "--pid", "host", "--cap-add", "SYS_PTRACE", *docker_args,
                    "-v", f"{out}:/out", image, "scan", "--mode", "docker", "--container", agent,
                    "--host-id", "ci-readonly-host", "--agent-key", "ci-readonly-agent",
                    "--feature-output", f"/out/{name}-features.json",
                    "--evidence-bundle-output", f"/out/{name}.json", check=False)
    print(result.stderr, file=sys.stderr)
    if result.returncode != 0:
        print(result.stdout, file=sys.stderr)
        return None
    text = docker("run", "--rm", "-v", f"{out}:/out", "--entrypoint", "cat", image, f"/out/{name}.json").stdout
    return json.loads(text)


# Every kind of Docker API call the scan may make, after an optional
# version prefix and before any query string: _ping, a container inspect
# (the agent's, and for egress containment the owner of its network
# namespace or another container on an internal network) and a network
# inspect. A new kind fails the check until it is added here and to the
# read-only proxy the install runs.
EXPECTED_CALLS = (
    ("HEAD", r"/_ping"),
    ("GET", r"/_ping"),
    ("GET", r"/containers/[^/?]+/json"),
    ("GET", r"/networks/[^/?]+"),
)


def unexpected_calls(calls: list[tuple[str, str, int]]) -> list[tuple[str, str, int]]:
    """The calls that are not one of EXPECTED_CALLS."""
    patterns = [(method, re.compile(r"^(?:/v[0-9.]+)?" + path + r"(?:\?.*)?$"))
                for method, path in EXPECTED_CALLS]
    return [call for call in calls
            if not any(call[0] == method and pattern.match(call[1]) for method, pattern in patterns)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--image", required=True)
    args = parser.parse_args()

    work = Path(tempfile.mkdtemp())
    out, proxy_dir = work / "out", work / "proxy"
    for path in (out, proxy_dir):
        path.mkdir()
        path.chmod(0o777)
    proxy_path = str(proxy_dir / "docker.sock")
    proxy = ReadOnlyProxy(proxy_path)
    os.chmod(proxy_path, 0o666)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    agent = "ci-readonly-agent"
    checks: dict[str, bool] = {}
    try:
        docker("run", "-d", "--name", agent, "--user", "nobody", "--entrypoint", "sleep", args.image, "600")
        on_socket = scan(args.image, agent, out, "socket", ["-v", f"{DOCKER_SOCKET}:{DOCKER_SOCKET}"])
        with proxy.lock:
            proxy.calls.clear()
        through_proxy = scan(args.image, agent, out, "proxy",
                             ["-v", f"{proxy_dir}:/proxy", "-e", "DOCKER_HOST=unix:///proxy/docker.sock"])
        calls = list(proxy.calls)
        print("Docker API calls through the proxy:", *(f"  {m} {p} -> {s}" for m, p, s in calls),
              sep="\n", file=sys.stderr)

        checks["both scans produced a bundle"] = on_socket is not None and through_proxy is not None
        checks["the proxied scan made calls, only GET/HEAD, none refused, no exec"] = bool(calls) and all(
            method in ("GET", "HEAD") and status != 403 and "/exec" not in path for method, path, status in calls)
        unexpected = unexpected_calls(calls)
        if unexpected:
            print("Docker API calls not in EXPECTED_CALLS:", *(f"  {m} {p}" for m, p, _ in unexpected),
                  sep="\n", file=sys.stderr)
        checks["every call is a known read: _ping, a container inspect, a network inspect"] = not unexpected
        checks["the scan inspected the agent's container"] = any(
            re.search(rf"/containers/{re.escape(agent)}/json", path) for _, path, _ in calls)
        if on_socket is not None and through_proxy is not None:
            a, b = on_socket["attributes"], through_proxy["attributes"]
            differing = sorted(k for k in set(a) | set(b) if k not in INSTANCE and a.get(k) != b.get(k))
            if differing:
                print("attributes that differ:", differing, file=sys.stderr)
                for key in differing:
                    print(f"  {key}: socket={json.dumps(a.get(key))[:400]}", file=sys.stderr)
                    print(f"  {key}: proxy ={json.dumps(b.get(key))[:400]}", file=sys.stderr)
            checks["the socket's and the proxy's bundles are the same"] = not differing
            framework = b.get("framework_identity", {})
            checks["the image's Python, read not run"] = (
                framework.get("status") == "ANSWERED"
                and str(framework.get("value", {}).get("python", "")).startswith("Python 3.")
                and "not run" in framework.get("method", ""))
            system = b.get("system_info", {}).get("value", {})
            checks["the container's os-release"] = system.get("os_release", {}).get("id") == "debian"
            user = b.get("user_info", {}).get("value", {})
            checks["the exec user, from the container's passwd"] = (
                user.get("container_username"), user.get("container_uid")) == ("nobody", "65534")
            checks["HOME and HOSTNAME are in the environment, as docker exec gave them"] = (
                {"HOME", "HOSTNAME"} <= set(system.get("environment_keys") or []))
    finally:
        docker("rm", "-f", agent, check=False)
        proxy.shutdown()
        proxy.server_close()
        shutil.rmtree(work, ignore_errors=True)

    for name, ok in checks.items():
        print(("PASS " if ok else "FAIL ") + name)
    return 0 if checks and all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
