"""`railmon gke-scan`: the central GKE service, one per cluster in rail-system.

This is its first part (RC-515): the sidecar intake, which takes each scan
sidecar's evidence bundle, checks who sent it, and relays the same bytes to
Rail Center (intake.py). gke-scan's own view of the cluster (its watches,
field collectors and its own bundle per workload) comes in later tasks of the
gke-scan design and runs in this same process.

Configuration, each flag also read from its environment variable:

* `--cluster-name` / RAIL_CLUSTER_NAME: this cluster's name, the `host_id`
  every sidecar in it reports under (the webhook gives sidecars the same
  value as RAIL_HOST_ID). Required.
* `--center-url` / RAIL_CENTER_URL: Rail Center, where bundles are relayed.
  Required. The credential is RAIL_AUTH_MODE's, as for the scanner: `gcp`
  in the cluster, gke-scan's Google identity through Workload Identity, for
  RAIL_AUTH_AUDIENCE.
* `--tls-cert-file`, `--tls-key-file` / RAIL_INTAKE_TLS_CERT_FILE,
  RAIL_INTAKE_TLS_KEY_FILE: the intake's certificate from the chart's CA.
  Required.
* `--listen` / RAIL_INTAKE_LISTEN: host:port, default 0.0.0.0:8443.
* `--audience` / RAIL_INTAKE_AUDIENCE: the audience sidecar tokens must
  carry, default gke-scan.
* `--kube-api-url`, `--kube-token-file`, `--kube-ca-file`: the Kubernetes API
  and gke-scan's credential for it; in a pod, found where Kubernetes mounts
  them.

SIGTERM stops taking posts, gives relays in flight up to 10 seconds, and exits.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import signal
import sys
import threading
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request

HERE = Path(__file__).resolve().parent
SCAN_DIR = HERE.parent.parent
DEFAULT_LISTEN = "0.0.0.0:8443"
DEFAULT_AUDIENCE = "gke-scan"
# gke-scan's post to Rail Center (the gke-scan design's timeouts); the
# sidecar's own post allows 30 seconds, which covers it.
RELAY_TIMEOUT_SECONDS = 15.0


def _load(name: str, path: Path) -> ModuleType:
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


def scanner() -> ModuleType:
    """The scanner (tools/scan/scan_agent_environment.py), for the parts
    gke-scan shares with it: auth_headers, registration_url and the register
    opener, which refuses redirects."""
    return _load("scan_agent_environment", SCAN_DIR / "scan_agent_environment.py")


def intake_module() -> ModuleType:
    return _load("gke_scan_intake", HERE / "intake.py")


def kube_module() -> ModuleType:
    return _load("gke_scan_kube", HERE / "kube.py")


def make_relay(center_url: str, auth_mode: str | None = None, timeout: float = RELAY_TIMEOUT_SECONDS) -> Any:
    """The relay: the sidecar's bytes, unchanged, to Rail Center's register
    route, with X-Rail-Source and X-Rail-Pod-UID and gke-scan's credential.
    Rail Center's answer is returned raw, whatever it is; the intake decides
    what the sidecar gets."""
    scan = scanner()
    intake = intake_module()
    opener = scan.registration_opener(None)

    def relay(data: bytes, pod_uid: str) -> Any:
        # No agent_key, ever: Rail Center files the bundle under its own
        # host_id and sandbox_name, which the intake has checked against the
        # sender's token (RC-515 rail review).
        request = Request(
            scan.registration_url(center_url),
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                intake.SOURCE_HEADER: intake.SOURCE_SIDECAR,
                intake.POD_UID_HEADER: pod_uid,
                **scan.auth_headers(auth_mode, timeout),
            },
        )
        try:
            with opener.open(request, timeout=timeout) as resp:
                return intake.RelayAnswer(resp.status, resp.read(), resp.headers.get("Content-Type"),
                                          resp.headers.get("Retry-After"))
        except HTTPError as exc:
            headers = exc.headers
            return intake.RelayAnswer(exc.code, exc.read(),
                                      headers.get("Content-Type") if headers is not None else None,
                                      headers.get("Retry-After") if headers is not None else None)
        except (URLError, TimeoutError, OSError) as exc:
            return intake.RelayAnswer(None, detail=f"{exc.__class__.__name__}: {exc}")

    return relay


def first(*values: str | None) -> str | None:
    for value in values:
        if value is not None and value.strip():
            return value.strip()
    return None


def parse_listen(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not port.isdigit() or not 0 <= int(port) < 65536:
        raise ValueError(f"--listen must be host:port, got {value!r}")
    return host.strip("[]") or "0.0.0.0", int(port)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="railmon gke-scan",
        description="gke-scan, the central GKE service: relays each scan sidecar's evidence bundle "
                    "to Rail Center after checking the pod that sent it (tools/scan/gke/central_service/README.md).")
    parser.add_argument("--cluster-name", help="This cluster's name, the host_id sidecars report under. "
                        "Also RAIL_CLUSTER_NAME.")
    parser.add_argument("--center-url", help="Rail Center's URL. Also RAIL_CENTER_URL; the credential is "
                        "RAIL_AUTH_MODE's (gcp in the cluster).")
    parser.add_argument("--listen", help=f"host:port for the intake. Also RAIL_INTAKE_LISTEN; default {DEFAULT_LISTEN}.")
    parser.add_argument("--tls-cert-file", help="The intake's certificate. Also RAIL_INTAKE_TLS_CERT_FILE.")
    parser.add_argument("--tls-key-file", help="The intake's private key. Also RAIL_INTAKE_TLS_KEY_FILE.")
    parser.add_argument("--audience", help="The audience sidecar tokens must carry. Also RAIL_INTAKE_AUDIENCE; "
                        f"default {DEFAULT_AUDIENCE}.")
    parser.add_argument("--kube-api-url", help="The Kubernetes API; default the in-cluster one.")
    parser.add_argument("--kube-token-file", help="gke-scan's token for the Kubernetes API; default its "
                        "service account's.")
    parser.add_argument("--kube-ca-file", help="The Kubernetes API's CA; default its service account's.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    env = os.environ
    cluster_name = first(args.cluster_name, env.get("RAIL_CLUSTER_NAME"))
    center_url = first(args.center_url, env.get("RAIL_CENTER_URL"))
    cert = first(args.tls_cert_file, env.get("RAIL_INTAKE_TLS_CERT_FILE"))
    key = first(args.tls_key_file, env.get("RAIL_INTAKE_TLS_KEY_FILE"))
    missing = [name for name, value in (("--cluster-name/RAIL_CLUSTER_NAME", cluster_name),
                                        ("--center-url/RAIL_CENTER_URL", center_url),
                                        ("--tls-cert-file/RAIL_INTAKE_TLS_CERT_FILE", cert),
                                        ("--tls-key-file/RAIL_INTAKE_TLS_KEY_FILE", key)) if not value]
    if missing:
        print(f"gke-scan: {', '.join(missing)} required", file=sys.stderr)
        return 2
    assert cluster_name and center_url and cert and key
    intake = intake_module()
    kube = kube_module()
    try:
        address = parse_listen(first(args.listen, env.get("RAIL_INTAKE_LISTEN")) or DEFAULT_LISTEN)
        client = kube.KubeClient(args.kube_api_url, args.kube_token_file, args.kube_ca_file)
        context = intake.server_tls_context(cert, key)
    except (ValueError, OSError, kube.KubeError) as exc:
        print(f"gke-scan: {exc}", file=sys.stderr)
        return 2
    audience = first(args.audience, env.get("RAIL_INTAKE_AUDIENCE")) or DEFAULT_AUDIENCE
    server = intake.IntakeServer(address, intake.Intake(client, make_relay(center_url), cluster_name, audience),
                                 context)

    def stop(signum: int, frame: Any) -> None:
        threading.Thread(target=server.shutdown, name="gke-scan-shutdown", daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(f"gke-scan: intake listening on {address[0]}:{address[1]} for cluster {cluster_name}, "
          f"audience {audience}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    finally:
        left = server.drain()
        server.server_close()
        print(f"gke-scan: stopped" + (f"; {left} relay(s) still in flight were abandoned" if left else ""),
              file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
