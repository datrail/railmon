"""Egress containment: can the agent open a connection to any outside host itself (DR-207).

The design is railxia/docs `design/2026-10-11-egress-containment`. One closed level, read
from what the Docker API says about the container and its networks, never from what the
container declares. The observations it rests on travel with it, so a consumer can
re-derive it (RailMon provides data; Daniel, 2026-10-08).

`classify` is a pure function of inspect output. `collect_inputs` is the only part that
calls Docker, and it runs in the scan that already inspected the target.
"""

from __future__ import annotations

import re
from typing import Any, Callable

# Ordered as the design's §4.2 walks them; the first three are contained.
CONTAINED_LEVELS = ("allow_list_enforced", "no_network", "internal_network")
LEVELS = (*CONTAINED_LEVELS, "open", "host_network", "host_process")

# OpenShell 0.1.3's Docker driver writes these last, over any template label
# (openshell-driver-docker/src/lib.rs), and refuses a sandbox that isn't
# NetworkMode=none with no attached network.
OPENSHELL_LABELS = {
    "openshell.ai/managed-by": "openshell",
    "openshell.ai/isolation-backend": "openshell-sandbox",
    "openshell.ai/isolation-role": "sandbox",
}

SOCKET_NAMES = ("docker.sock", "podman.sock", "containerd.sock", "crio.sock")
KNOWN_SOCKET_PATHS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/containerd/containerd.sock",
    "/run/k3s/containerd/containerd.sock",
    "/run/podman/podman.sock",
    "/var/run/podman/podman.sock",
    "/run/crio/crio.sock",
    "/var/run/crio/crio.sock",
)
# Rootless Docker and Podman: /run/user/<uid>/docker.sock and
# /run/user/<uid>/podman/podman.sock, for a uid we don't know. A source that
# is one of them, or a directory on the way to one, reaches a socket.
_ROOTLESS = re.compile(r"^/run/user(/[0-9]+(/docker\.sock|/podman(/podman\.sock)?)?)?$")


def _norm(path: Any) -> str:
    text = str(path or "").strip()
    if not text.startswith("/"):
        return ""
    collapsed = re.sub(r"/+", "/", text)
    return collapsed.rstrip("/") or "/"


def _is_above(directory: str, path: str) -> bool:
    return directory == "/" or path.startswith(directory + "/")


def _reaches_socket(source: str, extra_sockets: tuple[str, ...]) -> bool:
    """A bind source that is a known runtime socket or any directory above one."""
    if not source:
        return False
    if _ROOTLESS.match(source) or _is_above(source, "/run/user"):
        return True
    return any(source == sock or _is_above(source, sock) for sock in (*KNOWN_SOCKET_PATHS, *extra_sockets))


def runtime_socket_mounts(inspect: dict[str, Any], extra_sockets: tuple[str, ...] = ()) -> list[str]:
    """The targets of the mounts that put a container-runtime socket in reach."""
    found: list[str] = []
    for mount in inspect.get("Mounts") or []:
        if not isinstance(mount, dict) or mount.get("Type") not in (None, "bind"):
            continue
        source = _norm(mount.get("Source"))
        target = _norm(mount.get("Destination") or mount.get("Target"))
        named = any(p.endswith("/" + name) for p in (source, target) if p for name in SOCKET_NAMES)
        if named or _reaches_socket(source, extra_sockets):
            found.append(target or source)
    return sorted(set(found))


def _attached_networks(inspect: dict[str, Any]) -> list[str]:
    """Attached network names, without the entry Docker names `none` for
    `--network none` (OpenShell's driver filters it the same way)."""
    networks = ((inspect.get("NetworkSettings") or {}).get("Networks")) or {}
    if not isinstance(networks, dict):
        return []
    return sorted(name for name in networks if name != "none")


def _container_name(inspect: dict[str, Any]) -> str:
    return str(inspect.get("Name") or "").lstrip("/") or str(inspect.get("Id") or "")[:12]


def _downgrades(inspect: dict[str, Any], extra_sockets: tuple[str, ...]) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    sockets = runtime_socket_mounts(inspect, extra_sockets)
    if sockets:
        reasons.append("container-runtime socket in reach: " + ", ".join(sockets))
    if (inspect.get("HostConfig") or {}).get("Privileged"):
        reasons.append("privileged container")
    return reasons, sockets


def collect_inputs(
    inspect: dict[str, Any],
    inspect_container: Callable[[str], dict[str, Any] | None],
    inspect_network: Callable[[str], dict[str, Any] | None],
) -> dict[str, Any]:
    """Everything `classify` reads beyond the target's own inspect: the
    namespace owner in `container:` mode, each attached network, and, for an
    internal network, which other containers on it can also reach outside.

    The two callables return None when Docker can't answer; nothing here
    raises."""
    owner = None
    mode = str((inspect.get("HostConfig") or {}).get("NetworkMode") or "")
    if mode.startswith("container:"):
        owner = inspect_container(mode.partition(":")[2])
    subject = owner if owner is not None else inspect
    network_cache: dict[str, dict[str, Any] | None] = {}

    def network(name: str) -> dict[str, Any] | None:
        if name not in network_cache:
            network_cache[name] = inspect_network(name)
        return network_cache[name]

    networks: dict[str, dict[str, Any] | None] = {}
    for name in _attached_networks(subject):
        info = network(name)
        if info is None:
            networks[name] = None
            continue
        entry: dict[str, Any] = {"internal": bool(info.get("Internal")), "gateway_peers": []}
        if entry["internal"]:
            own_id = str(subject.get("Id") or "")
            for peer_id, peer in (info.get("Containers") or {}).items():
                if peer_id == own_id or not isinstance(peer, dict):
                    continue
                peer_inspect = inspect_container(peer_id)
                if peer_inspect is None:
                    continue
                peer_mode = str((peer_inspect.get("HostConfig") or {}).get("NetworkMode") or "")
                outside = peer_mode == "host" or any(
                    (network(other) or {"Internal": False}).get("Internal") is not True
                    for other in _attached_networks(peer_inspect)
                )
                if outside:
                    entry["gateway_peers"].append(str(peer.get("Name") or _container_name(peer_inspect)))
            entry["gateway_peers"].sort()
        networks[name] = entry
    return {"owner": owner, "owner_wanted": mode.startswith("container:"), "networks": networks}


def classify(
    inspect: dict[str, Any],
    inputs: dict[str, Any],
    extra_sockets: tuple[str, ...] = (),
) -> tuple[str, dict[str, Any] | None]:
    """(status, value) for the `egress_containment` attribute of a Docker
    target: `ANSWERED`, `PARTIAL` (an uninspected network decided it, at
    level `open`) or `FAILED` (no value: the namespace owner or the network
    mode couldn't be read)."""
    host_config = inspect.get("HostConfig") or {}
    mode = str(host_config.get("NetworkMode") or "")
    if not mode:
        return "FAILED", None
    owner = inputs.get("owner")
    if inputs.get("owner_wanted") and owner is None:
        return "FAILED", None
    subject = owner if owner is not None else inspect
    subject_mode = str((subject.get("HostConfig") or {}).get("NetworkMode") or "")
    labels = ((subject.get("Config") or {}).get("Labels")) or {}
    openshell = all(labels.get(k) == v for k, v in OPENSHELL_LABELS.items())

    reasons, sockets = _downgrades(inspect, extra_sockets)
    if owner is not None:
        owner_reasons, owner_sockets = _downgrades(owner, extra_sockets)
        reasons += [f"namespace owner {_container_name(owner)}: {r}" for r in owner_reasons]
        sockets = sorted(set(sockets) | set(owner_sockets))

    networks_in = inputs.get("networks") or {}
    networks = [
        {"name": name, "internal": (info or {}).get("internal") if info is not None else None,
         "gateway_peers": list((info or {}).get("gateway_peers") or [])}
        for name, info in sorted(networks_in.items())
    ]
    attached = [n["name"] for n in networks]
    status = "ANSWERED"
    enforcer = None

    if reasons:
        level = "open"
    elif subject_mode == "host":
        level, reasons = "host_network", ["NetworkMode host"]
    elif subject_mode == "none" and not attached:
        if openshell:
            level, enforcer = "allow_list_enforced", "openshell"
            reasons = ["openshell sandbox labels", "NetworkMode none, no attached network"]
        else:
            level, reasons = "no_network", ["NetworkMode none, no attached network"]
    elif not attached:
        level, reasons = "open", [f"NetworkMode {subject_mode} with no attached network"]
    else:
        open_nets = [n["name"] for n in networks if n["internal"] is False]
        unknown = [n["name"] for n in networks if n["internal"] is None]
        if open_nets:
            level, reasons = "open", ["not internal: " + ", ".join(open_nets)]
        elif unknown:
            level, status = "open", "PARTIAL"
            reasons = ["could not inspect: " + ", ".join(unknown)]
        else:
            level = "internal_network"
            reasons = ["every attached network is internal: " + ", ".join(attached)]
            peers = sorted({p for n in networks for p in n["gateway_peers"]})
            if peers:
                reasons.append("reaches outside only through: " + ", ".join(peers))

    value = {
        "level": level,
        "contained": level in CONTAINED_LEVELS,
        "enforcer": enforcer,
        "observations": {
            "network_mode": subject_mode,
            "networks": networks,
            "openshell_labels": openshell,
            "privileged": bool(host_config.get("Privileged"))
            or bool(owner is not None and (owner.get("HostConfig") or {}).get("Privileged")),
            "runtime_socket_mounts": sockets,
        },
        "via": f"container:{_container_name(owner)}" if owner is not None else None,
        "allow_list": None,
        "reasons": reasons,
    }
    return status, value


def host_process_value() -> dict[str, Any]:
    """A process scanned on the host, outside any container."""
    return {
        "level": "host_process",
        "contained": False,
        "enforcer": None,
        "observations": {
            "network_mode": None,
            "networks": [],
            "openshell_labels": False,
            "privileged": False,
            "runtime_socket_mounts": [],
        },
        "via": None,
        "allow_list": None,
        "reasons": ["a host process, not in a container"],
    }


PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")


def declared_proxy(env: dict[str, str], redact_url: Callable[[str | None], str | None]) -> dict[str, str] | None:
    """The proxy variables the container's environment sets, either case, with
    credentials removed; None when it sets none. NO_PROXY is a host list, not a
    URL, and is kept as written."""
    found: dict[str, str] = {}
    for name in PROXY_VARS:
        value = env.get(name) or env.get(name.lower())
        if not value:
            continue
        if name == "NO_PROXY":
            found[name] = value
        else:
            found[name] = redact_url(value) or "[unparseable]"
    return found or None

