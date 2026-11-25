"""`railmon gke-scan`: the central GKE service, one per cluster in rail-system.

It runs the sidecar intake (RC-515), which takes each scan sidecar's evidence
bundle, checks who sent it, and relays the same bytes to Rail Center
(intake.py), and the cluster reader (RC-550), which lists and watches the
enrolled namespaces and keeps a copy that the intake's pod check answers from
(cluster_reader.py). gke-scan's field collectors and its own bundle per
workload come in later tasks of the gke-scan design, in this same process,
and read the configuration below that they need.

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
* `--namespaces` / RAIL_NAMESPACES: the enrolled namespaces, comma-separated,
  or `*` for every namespace. Required.
* `--label-selector` / RAIL_LABEL_SELECTOR: the agent pods, default
  rail.datrail.io/scan=true.
* `--interval` / RAIL_INTERVAL_SECONDS: how often everything is listed again
  and every workload's bundle sent again, default 3600.
* `--registry-access`, `--no-registry-access` / RAIL_REGISTRY_ACCESS: whether
  images are read from their registry, default yes (RC-553).
* `--layer-budget` / RAIL_LAYER_BUDGET: the bytes of image layers read per
  image, default 2Gi; a number of bytes, or with Ki, Mi or Gi (RC-553).
* `--probe-external`, `--no-probe-external` / RAIL_PROBE_EXTERNAL: whether
  API specs are fetched from hosts outside the cluster, default no (RC-554).
* `--data-guardrail-url` / RAIL_DATA_GUARDRAIL_URL: Rail Center's
  /data-guardrail route; none by default, and nothing is sent there.
* `--sidecar-interval` / RAIL_SIDECAR_INTERVAL_SECONDS: the sidecars' scan
  interval, default 3600; a sidecar's report is current for two of them
  (RC-555).
* `--register-without-sidecar`, `--no-register-without-sidecar` /
  RAIL_REGISTER_WITHOUT_SIDECAR: whether a labeled workload with no sidecar
  gets a cluster-only bundle, default no (RC-555).

A flag wins over its variable, and the variable over the default. A missing
required value, or one that doesn't parse, exits 2 naming it.

SIGTERM stops taking posts, gives relays in flight up to 10 seconds, and exits.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import signal
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request

HERE = Path(__file__).resolve().parent
SCAN_DIR = HERE.parent.parent
DEFAULT_LISTEN = "0.0.0.0:8443"
DEFAULT_AUDIENCE = "gke-scan"
# gke-scan's post to Rail Center (the gke-scan design's timeouts); the
# sidecar's own post allows 30 seconds, which covers it.
RELAY_TIMEOUT_SECONDS = 15.0
DEFAULT_LABEL_SELECTOR = "rail.datrail.io/scan=true"
DEFAULT_INTERVAL_SECONDS = 3600
DEFAULT_SIDECAR_INTERVAL_SECONDS = 3600
DEFAULT_LAYER_BUDGET = 2 * 1024 ** 3
SIZE_UNITS = {"": 1, "K": 1000, "M": 1000 ** 2, "G": 1000 ** 3,
              "Ki": 1024, "Mi": 1024 ** 2, "Gi": 1024 ** 3}
NAMESPACE_NAME = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
TRUE_WORDS = {"1", "true", "yes", "on"}
FALSE_WORDS = {"0", "false", "no", "off"}


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


def reader_module() -> ModuleType:
    return _load("gke_scan_cluster_reader", HERE / "cluster_reader.py")


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


class ConfigError(ValueError):
    """A value gke-scan can't start with; the message names the flag."""


@dataclass(frozen=True)
class Config:
    cluster_name: str
    center_url: str
    tls_cert_file: str
    tls_key_file: str
    listen: tuple[str, int]
    audience: str
    kube_api_url: str | None
    kube_token_file: str | None
    kube_ca_file: str | None
    namespaces: tuple[str, ...]
    label_selector: str
    interval: int
    registry_access: bool
    layer_budget: int
    probe_external: bool
    data_guardrail_url: str | None
    sidecar_interval: int
    register_without_sidecar: bool


def parse_namespaces(value: str) -> tuple[str, ...]:
    names = [name.strip() for name in value.split(",") if name.strip()]
    if names == ["*"]:
        return ("*",)
    if not names or "*" in names:
        raise ValueError("a comma-separated list of namespaces, or * alone")
    for name in names:
        if not NAMESPACE_NAME.match(name):
            raise ValueError(f"{name!r} isn't a namespace name")
    return tuple(dict.fromkeys(names))


def parse_seconds(value: str) -> int:
    if not value.strip().isdigit() or int(value) < 1:
        raise ValueError(f"a whole number of seconds, at least 1, got {value!r}")
    return int(value)


def parse_size(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([KMG]i?)?\s*", value)
    if not match or int(match[1]) < 1:
        raise ValueError(f"a number of bytes, or with K, M, G, Ki, Mi or Gi, got {value!r}")
    return int(match[1]) * SIZE_UNITS[match[2] or ""]


def parse_bool(value: str) -> bool:
    word = value.strip().lower()
    if word in TRUE_WORDS:
        return True
    if word in FALSE_WORDS:
        return False
    raise ValueError(f"true or false, got {value!r}")


def parse_http_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"an http or https URL, got {value!r}")
    return value


def parse_config(argv: list[str] | None, env: Any) -> Config:
    """The flags, then their variables, then the defaults. ConfigError names
    every required value that's missing, or the first one that won't parse."""
    args = build_parser().parse_args(argv)

    def value(flag: str, variable: str | None) -> str | None:
        return first(getattr(args, flag.lstrip("-").replace("-", "_")), env.get(variable) if variable else None)

    def parsed(flag: str, variable: str | None, parse: Any, default: Any) -> Any:
        raw = getattr(args, flag.lstrip("-").replace("-", "_"))
        if isinstance(raw, bool):  # --x / --no-x
            return raw
        text = first(raw, env.get(variable) if variable else None)
        if text is None:
            return default
        try:
            return parse(text)
        except ValueError as exc:
            raise ConfigError(f"{flag}/{variable}: {exc}") from None

    required = {"--cluster-name": "RAIL_CLUSTER_NAME", "--center-url": "RAIL_CENTER_URL",
                "--tls-cert-file": "RAIL_INTAKE_TLS_CERT_FILE", "--tls-key-file": "RAIL_INTAKE_TLS_KEY_FILE",
                "--namespaces": "RAIL_NAMESPACES"}
    missing = [f"{flag}/{variable}" for flag, variable in required.items() if not value(flag, variable)]
    if missing:
        raise ConfigError(f"{', '.join(missing)} required")
    selector = parsed("--label-selector", "RAIL_LABEL_SELECTOR", lambda text: text, DEFAULT_LABEL_SELECTOR)
    try:
        reader_module().parse_selector(selector)
    except ValueError as exc:
        raise ConfigError(f"--label-selector/RAIL_LABEL_SELECTOR: {exc}") from None
    return Config(
        cluster_name=str(value("--cluster-name", "RAIL_CLUSTER_NAME")),
        center_url=str(value("--center-url", "RAIL_CENTER_URL")),
        tls_cert_file=str(value("--tls-cert-file", "RAIL_INTAKE_TLS_CERT_FILE")),
        tls_key_file=str(value("--tls-key-file", "RAIL_INTAKE_TLS_KEY_FILE")),
        listen=parsed("--listen", "RAIL_INTAKE_LISTEN", parse_listen, parse_listen(DEFAULT_LISTEN)),
        audience=value("--audience", "RAIL_INTAKE_AUDIENCE") or DEFAULT_AUDIENCE,
        kube_api_url=value("--kube-api-url", None),
        kube_token_file=value("--kube-token-file", None),
        kube_ca_file=value("--kube-ca-file", None),
        namespaces=parsed("--namespaces", "RAIL_NAMESPACES", parse_namespaces, ()),
        label_selector=selector,
        interval=parsed("--interval", "RAIL_INTERVAL_SECONDS", parse_seconds, DEFAULT_INTERVAL_SECONDS),
        registry_access=parsed("--registry-access", "RAIL_REGISTRY_ACCESS", parse_bool, True),
        layer_budget=parsed("--layer-budget", "RAIL_LAYER_BUDGET", parse_size, DEFAULT_LAYER_BUDGET),
        probe_external=parsed("--probe-external", "RAIL_PROBE_EXTERNAL", parse_bool, False),
        data_guardrail_url=parsed("--data-guardrail-url", "RAIL_DATA_GUARDRAIL_URL", parse_http_url, None),
        sidecar_interval=parsed("--sidecar-interval", "RAIL_SIDECAR_INTERVAL_SECONDS", parse_seconds,
                                DEFAULT_SIDECAR_INTERVAL_SECONDS),
        register_without_sidecar=parsed("--register-without-sidecar", "RAIL_REGISTER_WITHOUT_SIDECAR",
                                        parse_bool, False),
    )


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
    parser.add_argument("--namespaces", help="The enrolled namespaces, comma-separated, or * for all. "
                        "Also RAIL_NAMESPACES. Required.")
    parser.add_argument("--label-selector", help="The agent pods. Also RAIL_LABEL_SELECTOR; default "
                        f"{DEFAULT_LABEL_SELECTOR}.")
    parser.add_argument("--interval", help="Seconds between full relists and resends. Also "
                        f"RAIL_INTERVAL_SECONDS; default {DEFAULT_INTERVAL_SECONDS}.")
    parser.add_argument("--registry-access", action=argparse.BooleanOptionalAction, default=None,
                        help="Read images from their registry. Also RAIL_REGISTRY_ACCESS; default yes.")
    parser.add_argument("--layer-budget", help="Bytes of image layers read per image (Ki, Mi, Gi allowed). "
                        "Also RAIL_LAYER_BUDGET; default 2Gi.")
    parser.add_argument("--probe-external", action=argparse.BooleanOptionalAction, default=None,
                        help="Fetch API specs from hosts outside the cluster. Also RAIL_PROBE_EXTERNAL; default no.")
    parser.add_argument("--data-guardrail-url", help="Rail Center's /data-guardrail route. Also "
                        "RAIL_DATA_GUARDRAIL_URL; default none.")
    parser.add_argument("--sidecar-interval", help="The sidecars' scan interval in seconds. Also "
                        f"RAIL_SIDECAR_INTERVAL_SECONDS; default {DEFAULT_SIDECAR_INTERVAL_SECONDS}.")
    parser.add_argument("--register-without-sidecar", action=argparse.BooleanOptionalAction, default=None,
                        help="Send a cluster-only bundle for a labeled workload with no sidecar. Also "
                        "RAIL_REGISTER_WITHOUT_SIDECAR; default no.")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        config = parse_config(argv, os.environ)
    except ConfigError as exc:
        print(f"gke-scan: {exc}", file=sys.stderr)
        return 2
    intake = intake_module()
    kube = kube_module()
    try:
        client = kube.KubeClient(config.kube_api_url, config.kube_token_file, config.kube_ca_file)
        context = intake.server_tls_context(config.tls_cert_file, config.tls_key_file)
    except (ValueError, OSError, kube.KubeError) as exc:
        print(f"gke-scan: {exc}", file=sys.stderr)
        return 2
    address, cluster_name, audience = config.listen, config.cluster_name, config.audience
    reader = reader_module().ClusterReader(client, config.namespaces, config.label_selector, config.interval)
    server = intake.IntakeServer(address, intake.Intake(client, make_relay(config.center_url), cluster_name,
                                                        audience, pods=reader), context)

    def stop(signum: int, frame: Any) -> None:
        threading.Thread(target=server.shutdown, name="gke-scan-shutdown", daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(f"gke-scan: intake listening on {address[0]}:{address[1]} for cluster {cluster_name}, "
          f"audience {audience}", file=sys.stderr, flush=True)
    print(f"gke-scan: reading {', '.join(config.namespaces)} for pods matching {config.label_selector}, "
          f"listing again every {config.interval}s", file=sys.stderr, flush=True)
    reader.start()
    try:
        server.serve_forever()
    finally:
        reader.stop()
        left = server.drain()
        server.server_close()
        print(f"gke-scan: stopped" + (f"; {left} relay(s) still in flight were abandoned" if left else ""),
              file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
