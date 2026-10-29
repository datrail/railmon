"""Egress containment: can the agent open a connection to any outside host itself (DR-207).

The design is railxia/docs `design/2026-10-11-egress-containment`. One closed level, read
from what the Docker API says about the container and its networks, never from what the
container declares. The observations it rests on travel with it, so a consumer can
re-derive it (RailMon provides data; Daniel, 2026-10-08).

`classify` is a pure function of inspect output. `collect_inputs` is the only part that
calls Docker, and it runs in the scan that already inspected the target.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Callable

# The schema's bounds (`$defs.egress_containment_value`). A bundle past one
# fails its contract and is not delivered at all, so the value is cut here:
# the level is always decided on everything inspected, and the lists say how
# much they left out.
MAX_LIST = 64
MAX_REASON = 1024
# Other containers inspected per scan, over every internal network, to find
# gateway peers: each is a `docker container inspect`, and a scan runs every
# minute. Peers past the budget aren't checked; the level doesn't depend on them.
PEER_INSPECT_BUDGET = 64
# A NetworkMode that is never an internal network.
_DEFAULT_BRIDGE_MODES = ("bridge", "default")

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

# The sandbox a container is the workload of (OpenShell's Docker driver).
OPENSHELL_SANDBOX_LABEL = "openshell.ai/sandbox-name"

# The allow-list (DR-266): what `railmon openshell` read from `openshell
# policy get` and wrote to RAIL_OPENSHELL_POLICY_FILE. Bounds as the schema's
# `$defs.egress_containment_value.allow_list`.
MAX_ALLOW_ENTRIES = 256
MAX_ALLOW_RULES = 32
MAX_ALLOW_BINARIES = 32
MAX_ALLOW_TEXT = 256
MAX_ALLOW_PATH = 1024
ALLOW_RULE_FIELDS = ("method", "path", "command", "operation_type", "tool")
# The policy file's own bound; a larger one isn't read.
MAX_POLICY_FILE = 1024 * 1024
# A copy older than this many of the collector's intervals (plus a minute)
# is a stopped collector's, not the sandbox's policy now.
POLICY_STALE_INTERVALS = 3

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
        reasons.append(_joined("container-runtime socket in reach: ", sockets))
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
    budget = PEER_INSPECT_BUDGET
    for name in _attached_networks(subject):
        info = network(name)
        if info is None:
            networks[name] = None
            continue
        entry: dict[str, Any] = {"internal": bool(info.get("Internal")), "gateway_peers": [], "unchecked": 0}
        if entry["internal"]:
            own_id = str(subject.get("Id") or "")
            members = info.get("Containers") or {}
            for peer_id in sorted(members if isinstance(members, dict) else {}):
                peer = members[peer_id]
                if peer_id == own_id or not isinstance(peer, dict):
                    continue
                if budget <= 0:
                    entry["unchecked"] += 1
                    continue
                budget -= 1
                peer_inspect = inspect_container(peer_id)
                if peer_inspect is None:
                    entry["unchecked"] += 1
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


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: Any, limit: int = MAX_ALLOW_TEXT) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= limit and value.isprintable() else None


def allow_list_entries(view: Any) -> tuple[list[dict[str, Any]], int]:
    """The allow-list of one `openshell policy get` view, as the collector
    stripped it, and how many entries the bound left out: one entry per
    endpoint and port, `{host, port, protocol, enforcement, access, rules,
    binaries}`, sorted, a port the endpoint names none of being null.
    Anything not in the shape OpenShell writes is skipped, not guessed."""
    policy = view.get("policy") if isinstance(view, dict) else None
    network = policy.get("network_policies") if isinstance(policy, dict) else None
    entries: dict[str, dict[str, Any]] = {}
    for rule in (network.values() if isinstance(network, dict) else ()):
        if not isinstance(rule, dict):
            continue
        binaries = sorted({
            path for path in (
                _text(binary.get("path") if isinstance(binary, dict) else binary, MAX_ALLOW_PATH)
                for binary in _list(rule.get("binaries"))
            ) if path
        })[:MAX_ALLOW_BINARIES]
        for endpoint in _list(rule.get("endpoints")):
            if not isinstance(endpoint, dict) or (host := _text(endpoint.get("host"), 253)) is None:
                continue
            ports: list[int | None] = []
            for port in [endpoint.get("port"), *_list(endpoint.get("ports"))]:
                if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
                    ports.append(port)
            rules: list[dict[str, str]] = []
            for allow_rule in _list(endpoint.get("rules")):
                allow = allow_rule.get("allow") if isinstance(allow_rule, dict) else None
                if isinstance(allow, dict):
                    kept = {field: text for field in ALLOW_RULE_FIELDS
                            if (text := _text(allow.get(field), MAX_ALLOW_PATH)) is not None}
                    if kept:
                        rules.append(kept)
            rules = sorted(rules, key=lambda item: sorted(item.items()))[:MAX_ALLOW_RULES]
            for port in sorted(set(ports)) or [None]:
                entry = {"host": host, "port": port, "protocol": _text(endpoint.get("protocol")),
                         "enforcement": _text(endpoint.get("enforcement")), "access": _text(endpoint.get("access")),
                         "rules": rules, "binaries": binaries}
                entries[json.dumps(entry, sort_keys=True)] = entry
    ordered = sorted(entries.values(), key=lambda entry: (entry["host"], entry["port"] or 0,
                                                         json.dumps(entry, sort_keys=True)))
    return ordered[:MAX_ALLOW_ENTRIES], max(0, len(ordered) - MAX_ALLOW_ENTRIES)


def read_policy_file(path: str | None) -> dict[str, Any] | None:
    """RAIL_OPENSHELL_POLICY_FILE as `railmon openshell` wrote it, or None
    when there is no file, it is too large or isn't one of those. Never
    raises: without a copy the allow-list just stays unread."""
    if not path:
        return None
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_POLICY_FILE + 1)
        if len(raw) > MAX_POLICY_FILE:
            return None
        body = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(body, dict) or body.get("kind") != "openshell_policy":
        return None
    return body


def _policy_age(body: dict[str, Any], now: float) -> float | None:
    try:
        read_at = datetime.fromisoformat(str(body.get("read_at")).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None
    return now - read_at


def allow_list_for(sandbox: str | None, body: dict[str, Any] | None, now: float) -> tuple[list[dict[str, Any]] | None, list[str]]:
    """(allow_list, reasons) for an OpenShell sandbox's container: the list
    from the collector's copy when it is for this sandbox and fresh, else
    None and a reason why. No copy at all adds no reason, so a stack
    without the collector says what it said before DR-266. A reason carries
    no time, so it doesn't change from one scan to the next."""
    if body is None:
        return None, []
    if not sandbox or body.get("sandbox") != sandbox:
        return None, ["allow-list not read: railmon openshell follows another sandbox"]
    every = body.get("every")
    every = float(every) if isinstance(every, (int, float)) and not isinstance(every, bool) and 5 <= every <= 3600 else 60.0
    age = _policy_age(body, now)
    if age is None or age > POLICY_STALE_INTERVALS * every + 60 or age < -60:
        return None, ["allow-list not read: railmon openshell's copy of the policy is not current"]
    entries, left_out = allow_list_entries(body.get("view"))
    view = body.get("view") if isinstance(body.get("view"), dict) else {}
    revision = view.get("active_version", view.get("current_policy_version"))
    reasons = [f"allow-list: OpenShell's loaded policy"
               + (f" revision {revision}" if isinstance(revision, int) and not isinstance(revision, bool) else "")
               + ", read by railmon openshell"]
    if left_out:
        reasons.append(f"{left_out} more allow-list entries not listed")
    return entries, reasons


def _joined(prefix: str, names: list[str]) -> str:
    text = prefix + ", ".join(names)
    return text if len(text) <= MAX_REASON else text[: MAX_REASON - 1] + "…"


def _capped(items: list[Any]) -> list[Any]:
    return items[:MAX_LIST]


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
    unchecked = sum(int((info or {}).get("unchecked") or 0) for info in networks_in.values())
    attached = [n["name"] for n in networks]
    status = "ANSWERED"
    enforcer = None
    allow_list: list[dict[str, Any]] | None = None

    if reasons:
        level = "open"
    elif subject_mode == "host":
        level, reasons = "host_network", ["NetworkMode host"]
    elif subject_mode == "none" and not attached:
        if openshell:
            level, enforcer = "allow_list_enforced", "openshell"
            reasons = ["openshell sandbox labels", "NetworkMode none, no attached network"]
            allow_list, allow_reasons = allow_list_for(
                labels.get(OPENSHELL_SANDBOX_LABEL), inputs.get("openshell_policy"), float(inputs.get("now") or 0))
            reasons += allow_reasons
        else:
            level, reasons = "no_network", ["NetworkMode none, no attached network"]
    elif not attached:
        level, reasons = "open", [f"NetworkMode {subject_mode} with no attached network"]
    elif subject_mode in _DEFAULT_BRIDGE_MODES:
        level, reasons = "open", [f"NetworkMode {subject_mode}: the default bridge is never internal"]
    else:
        open_nets = [n["name"] for n in networks if n["internal"] is False]
        unknown = [n["name"] for n in networks if n["internal"] is None]
        if open_nets:
            level, reasons = "open", [_joined("not internal: ", open_nets)]
        elif unknown:
            level, status = "open", "PARTIAL"
            reasons = [_joined("could not inspect: ", unknown)]
        else:
            level = "internal_network"
            reasons = [_joined("every attached network is internal: ", attached)]
            peers = sorted({p for n in networks for p in n["gateway_peers"]})
            if peers:
                reasons.append(_joined("reaches outside only through: ", peers))
            if unchecked:
                reasons.append(f"{unchecked} other container(s) on these networks not checked for outside reach")
    for n in networks:
        n["gateway_peers"] = _capped(n["gateway_peers"])
    if len(networks) > MAX_LIST:
        reasons.append(f"{len(networks) - MAX_LIST} more attached network(s) not listed")

    value = {
        "level": level,
        "contained": level in CONTAINED_LEVELS,
        "enforcer": enforcer,
        "observations": {
            "network_mode": subject_mode,
            "networks": _capped(networks),
            "openshell_labels": openshell,
            "privileged": bool(host_config.get("Privileged"))
            or bool(owner is not None and (owner.get("HostConfig") or {}).get("Privileged")),
            "runtime_socket_mounts": _capped(sockets),
        },
        "via": f"container:{_container_name(owner)}" if owner is not None else None,
        "allow_list": allow_list,
        "reasons": [reason[:MAX_REASON] for reason in reasons][:16],
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

