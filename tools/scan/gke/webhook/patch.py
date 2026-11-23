"""The JSON patch that adds the scan sidecar to a pod (RC-518).

`sidecar_patch(pod, spec)` is the webhook's whole decision, with no I/O, so
it is what the unit tests exercise. `spec` is the sidecar spec the chart
renders into its ConfigMap (deploy/helm/railmon-gke/templates/
sidecar-spec.yaml): the container, its volumes, and the defaults. It is the
one sidecar spec: the webhook fills in only what differs from pod to pod,
listed here, and a manifest that adds the sidecar by hand copies the same
spec and fills in the same parts (the chart's README says how).

Per pod:

* **The agent's container**: the `rail.datrail.io/scan-agent-container`
  annotation, else the pod's first container.
* **The config path**: `rail.datrail.io/scan-config-path`, else the spec's
  `configPath` (the chart's `sidecar.configPath`). It goes to the sidecar as
  `--config-path`, and the agent's volume mounts that hold it (at it, above it
  or under it) are mounted read-only in the sidecar at the same paths, so the
  same path names the same files in both containers.
  One at a path the sidecar mounts its own volume at (`/tmp`, say) is left
  out, with a warning: two mounts at one path would make the API server
  refuse the pod.
* **The UID and GID**: the agent container's `securityContext`, else the
  pod's, else the `rail.datrail.io/scan-run-as-user` and `-run-as-group`
  annotations, else the spec's defaults. A GID that none of these give is
  taken to be the UID, and a warning says so. Without any UID the sidecar runs
  as the image's (65532), which can't read the agent's process, and a warning
  says that too. `runAsNonRoot` is set when the UID isn't 0, and when there
  is no UID (the image's 65532 isn't root), so Pod Security `restricted`
  admits the pod.
* **Capabilities**: none (the spec drops ALL), unless the agent runs as root.
  Linux lets a process read another's environment and root only when its
  permitted capabilities include all of the other's (or it has SYS_PTRACE),
  even at the same UID, and a root agent keeps the runtime's default set. So
  a root agent's sidecar gets exactly the agent container's `capabilities`
  (the runtime default when the agent sets none): what it needs to read the
  agent, and never a capability the agent doesn't have. A non-root agent has
  no permitted capabilities, so its sidecar keeps none.
* **`RAIL_SANDBOX_TYPE`**: `gvisor` when the pod's `runtimeClassName` is
  `gvisor` (GKE Sandbox), else `kubernetes`.
* **`shareProcessNamespace: true`**, so the sidecar reads the agent's process.

A pod that already has a container or init container named as the sidecar
gets no patch: it was added by hand, or by an earlier pass of this webhook
(reinvocation). A pod with a volume of one of the sidecar's volume names
gets no patch either, and a warning: two volumes of one name would make the
API server refuse the pod, and this webhook must never stop a pod starting.
For the same reason a pod with `hostPID: true` gets no patch and a warning:
the API server refuses `shareProcessNamespace` beside it.

The sidecar goes in as a native sidecar (an init container with
`restartPolicy: Always`) unless the spec says otherwise, so a Job's pod
still completes when its agent does, and the sidecar is stopped after the
agent at shutdown.
"""

from __future__ import annotations

import copy
import posixpath
from dataclasses import dataclass, field
from typing import Any

SCAN_LABEL = "rail.datrail.io/scan"
ANNOTATION_PREFIX = "rail.datrail.io/"
AGENT_CONTAINER_ANNOTATION = ANNOTATION_PREFIX + "scan-agent-container"
CONFIG_PATH_ANNOTATION = ANNOTATION_PREFIX + "scan-config-path"
RUN_AS_USER_ANNOTATION = ANNOTATION_PREFIX + "scan-run-as-user"
RUN_AS_GROUP_ANNOTATION = ANNOTATION_PREFIX + "scan-run-as-group"
# Set on the pod when the sidecar is added, with the sidecar's image, so
# `kubectl get pod -o yaml` shows which sidecar a pod got.
INJECTED_ANNOTATION = ANNOTATION_PREFIX + "scan-sidecar"
# What the webhook had to guess for this pod, one per line. Admission
# warnings reach only whoever created the pod (for a Deployment, the
# ReplicaSet controller), so they are kept on the pod too, for
# `kubectl describe pod`.
WARNINGS_ANNOTATION = ANNOTATION_PREFIX + "scan-sidecar-warnings"

GVISOR_RUNTIME_CLASS = "gvisor"
DEFAULT_CONTAINER_NAME = "rail-scan"


@dataclass
class PatchResult:
    patch: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # Why no patch was made, for the log; None when one was.
    skipped: str | None = None


def escape(key: str) -> str:
    """A JSON Pointer token (RFC 6901): `~` and `/` escaped."""
    return key.replace("~", "~0").replace("/", "~1")


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _agent_container(pod: dict[str, Any], sidecar_name: str) -> tuple[dict[str, Any] | None, str | None]:
    containers = [c for c in pod.get("spec", {}).get("containers") or [] if isinstance(c, dict)]
    wanted = (pod.get("metadata", {}).get("annotations") or {}).get(AGENT_CONTAINER_ANNOTATION)
    if wanted:
        for container in containers:
            if container.get("name") == wanted:
                return container, None
        others = [c for c in containers if c.get("name") != sidecar_name]
        warning = (f"{AGENT_CONTAINER_ANNOTATION} names container '{wanted}', which the pod doesn't have; "
                   f"using '{others[0].get('name')}'" if others else None)
        return (others[0] if others else None), warning
    for container in containers:
        if container.get("name") != sidecar_name:
            return container, None
    return None, None


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def config_mounts(agent: dict[str, Any], config_path: str) -> list[dict[str, Any]]:
    """The agent's volume mounts that hold the config path: the deepest one
    at or above it, and every one under it. Each is copied read-only."""
    config_path = posixpath.normpath(config_path)
    mounts = [m for m in agent.get("volumeMounts") or [] if isinstance(m, dict) and m.get("name") and m.get("mountPath")]
    above = [m for m in mounts if _within(config_path, posixpath.normpath(m["mountPath"]))]
    below = [m for m in mounts if _within(posixpath.normpath(m["mountPath"]), config_path)
             and posixpath.normpath(m["mountPath"]) != config_path]
    chosen: list[dict[str, Any]] = []
    if above:
        chosen.append(max(above, key=lambda m: len(posixpath.normpath(m["mountPath"]))))
    chosen.extend(sorted(below, key=lambda m: m["mountPath"]))
    copied = []
    for mount in chosen:
        item = {"name": mount["name"], "mountPath": mount["mountPath"], "readOnly": True}
        # Not mountPropagation: the sidecar never needs mounts the agent
        # makes later, and Bidirectional needs a privileged container.
        for key in ("subPath", "subPathExpr"):
            if mount.get(key):
                item[key] = mount[key]
        copied.append(item)
    return copied


def _run_as(pod: dict[str, Any], agent: dict[str, Any] | None, spec: dict[str, Any]) -> tuple[int | None, int | None, list[str]]:
    warnings: list[str] = []
    annotations = pod.get("metadata", {}).get("annotations") or {}
    pod_sc = pod.get("spec", {}).get("securityContext") or {}
    agent_sc = (agent or {}).get("securityContext") or {}
    uid_sources = [
        ("the agent container's securityContext", agent_sc.get("runAsUser")),
        ("the pod's securityContext", pod_sc.get("runAsUser")),
        (RUN_AS_USER_ANNOTATION, annotations.get(RUN_AS_USER_ANNOTATION)),
        ("the chart's sidecar.runAsUser", spec.get("runAsUser")),
    ]
    gid_sources = [
        ("the agent container's securityContext", agent_sc.get("runAsGroup")),
        ("the pod's securityContext", pod_sc.get("runAsGroup")),
        (RUN_AS_GROUP_ANNOTATION, annotations.get(RUN_AS_GROUP_ANNOTATION)),
        ("the chart's sidecar.runAsGroup", spec.get("runAsGroup")),
    ]
    uid = next((_int(v) for _, v in uid_sources if _int(v) is not None), None)
    gid = next((_int(v) for _, v in gid_sources if _int(v) is not None), None)
    # The annotations are free text, so say when one was ignored.
    for source, value in (uid_sources[2], gid_sources[2]):
        if value is not None and _int(value) is None:
            warnings.append(f"{source} '{value}' isn't a UID or GID; ignored")
    if uid is None:
        warnings.append(
            "the agent's UID isn't in the pod spec; the scan sidecar runs as the image's UID 65532 and "
            f"can't read the agent's process. Set runAsUser, or the {RUN_AS_USER_ANNOTATION} annotation"
        )
    elif gid is None:
        gid = uid
        warnings.append(
            f"the agent's GID isn't in the pod spec; the scan sidecar runs with GID {uid}, the same as its UID. "
            f"Set runAsGroup, or the {RUN_AS_GROUP_ANNOTATION} annotation, if the agent's differs"
        )
    return uid, gid, warnings


def _set_env(container: dict[str, Any], name: str, value: str) -> None:
    env = [e for e in container.get("env") or [] if not (isinstance(e, dict) and e.get("name") == name)]
    env.append({"name": name, "value": value})
    container["env"] = env


def config_paths(annotation: Any, spec_value: Any) -> list[str]:
    """The config paths for a pod: the annotation's, comma-separated, else
    the spec's `configPath` (a string, or a list from the chart). An agent
    whose files sit on several volumes (OpenClaw's openclaw.json apart from
    its state, Claude Code's project apart from its config) names each.
    Order kept, duplicates and empty entries dropped."""
    if isinstance(annotation, str) and annotation.strip():
        raw: list[Any] = annotation.split(",")
    elif isinstance(spec_value, str):
        raw = spec_value.split(",")
    elif isinstance(spec_value, list):
        raw = spec_value
    else:
        raw = []
    paths = [p.strip() for p in raw if isinstance(p, str) and p.strip()]
    return list(dict.fromkeys(paths))


def sidecar_container(pod: dict[str, Any], spec: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """The sidecar container for this pod: the spec's, with the per-pod parts filled in."""
    name = spec.get("containerName") or DEFAULT_CONTAINER_NAME
    container = copy.deepcopy(spec["container"])
    container["name"] = name
    warnings: list[str] = []

    agent, warning = _agent_container(pod, name)
    if warning:
        warnings.append(warning)

    annotations = pod.get("metadata", {}).get("annotations") or {}
    paths = config_paths(annotations.get(CONFIG_PATH_ANNOTATION), spec.get("configPath"))
    if paths:
        args = list(container.get("args") or [])
        for config_path in paths:
            args += ["--config-path", config_path]
        container["args"] = args
        # A copied mount at a path the spec mounts already (/tmp, say, for an
        # agent with HOME=/tmp) would make the API server refuse the pod.
        own = list(container.get("volumeMounts") or [])
        own_paths = {posixpath.normpath(m["mountPath"]) for m in own if isinstance(m, dict) and m.get("mountPath")}
        added: list[dict[str, Any]] = []
        for config_path in paths:
            mounts = config_mounts(agent, config_path) if agent else []
            clashing = [m for m in mounts if posixpath.normpath(m["mountPath"]) in own_paths]
            for m in clashing:
                warnings.append(
                    f"the agent's volume {m['name']} at {m['mountPath']} holds {config_path}, but the scan sidecar "
                    "mounts its own volume there; it can't read that part of the agent's config, and those config "
                    "fields will be BLIND"
                )
            kept = [m for m in mounts if m not in clashing]
            if not kept and not clashing:
                warnings.append(
                    f"no volume of the agent's container holds {config_path}; the scan sidecar can't read the "
                    "agent's config, and its config fields will be BLIND"
                )
            # Two paths on one volume mount it once.
            added += [m for m in kept if m not in added]
        if added:
            container["volumeMounts"] = own + added
    else:
        warnings.append(f"no config path: set sidecar.configPath in the chart, or the {CONFIG_PATH_ANNOTATION} annotation")

    sandbox_type = "gvisor" if pod.get("spec", {}).get("runtimeClassName") == GVISOR_RUNTIME_CLASS else "kubernetes"
    _set_env(container, "RAIL_SANDBOX_TYPE", sandbox_type)

    uid, gid, run_as_warnings = _run_as(pod, agent, spec)
    warnings.extend(run_as_warnings)
    security = dict(container.get("securityContext") or {})
    if uid is not None:
        security["runAsUser"] = uid
        security["runAsGroup"] = gid
        security["runAsNonRoot"] = uid != 0
    else:
        # The image's user (65532) isn't root. Pod Security `restricted` needs
        # runAsNonRoot on every container unless the pod sets it.
        security["runAsNonRoot"] = True
    if uid == 0:
        agent_caps = ((agent or {}).get("securityContext") or {}).get("capabilities")
        if agent_caps:
            security["capabilities"] = copy.deepcopy(agent_caps)
        else:
            security.pop("capabilities", None)
    container["securityContext"] = security

    if spec.get("nativeSidecar", True):
        container["restartPolicy"] = "Always"
    else:
        container.pop("restartPolicy", None)
    return container, warnings


def sidecar_patch(pod: dict[str, Any], spec: dict[str, Any]) -> PatchResult:
    name = spec.get("containerName") or DEFAULT_CONTAINER_NAME
    pod_spec = pod.get("spec") or {}
    existing = [c.get("name") for key in ("containers", "initContainers")
                for c in pod_spec.get(key) or [] if isinstance(c, dict)]
    if name in existing:
        return PatchResult(skipped=f"the pod already has a container named {name}")

    # The API server refuses shareProcessNamespace beside hostPID ("cannot both
    # be enabled"), so the patch would stop the pod.
    if pod_spec.get("hostPID") is True:
        return PatchResult(
            skipped="the pod sets hostPID, which shareProcessNamespace can't be used with",
            warnings=["the scan sidecar wasn't added: the pod sets hostPID, and Kubernetes refuses "
                      "shareProcessNamespace beside it"],
        )

    volumes = [copy.deepcopy(v) for v in spec.get("volumes") or []]
    pod_volume_names = {v.get("name") for v in pod_spec.get("volumes") or [] if isinstance(v, dict)}
    clash = sorted(pod_volume_names & {v.get("name") for v in volumes})
    if clash:
        return PatchResult(
            skipped=f"the pod already has volumes named {', '.join(clash)}",
            warnings=[f"the scan sidecar wasn't added: the pod already has volumes named {', '.join(clash)}"],
        )

    container, warnings = sidecar_container(pod, spec)
    patch: list[dict[str, Any]] = []

    if pod_spec.get("shareProcessNamespace") is None:
        patch.append({"op": "add", "path": "/spec/shareProcessNamespace", "value": True})
    elif pod_spec.get("shareProcessNamespace") is not True:
        patch.append({"op": "replace", "path": "/spec/shareProcessNamespace", "value": True})

    if volumes:
        if pod_spec.get("volumes") is None:
            patch.append({"op": "add", "path": "/spec/volumes", "value": volumes})
        else:
            patch.extend({"op": "add", "path": "/spec/volumes/-", "value": v} for v in volumes)

    target = "initContainers" if container.get("restartPolicy") == "Always" else "containers"
    if pod_spec.get(target) is None:
        patch.append({"op": "add", "path": f"/spec/{target}", "value": [container]})
    else:
        patch.append({"op": "add", "path": f"/spec/{target}/-", "value": container})

    added = {INJECTED_ANNOTATION: container.get("image") or ""}
    if warnings:
        added[WARNINGS_ANNOTATION] = "\n".join(warnings)
    if pod.get("metadata", {}).get("annotations") is None:
        patch.append({"op": "add", "path": "/metadata/annotations", "value": added})
    else:
        patch.extend({"op": "add", "path": f"/metadata/annotations/{escape(key)}", "value": value}
                     for key, value in added.items())

    return PatchResult(patch=patch, warnings=warnings)


def apply_patch(document: Any, patch: list[dict[str, Any]]) -> Any:
    """Apply `add` and `replace` operations, the only ones this webhook
    makes. For the tests and for adding the sidecar to a manifest by hand;
    the API server applies the patch itself in the cluster."""
    document = copy.deepcopy(document)
    for op in patch:
        tokens = [t.replace("~1", "/").replace("~0", "~") for t in op["path"].split("/")[1:]]
        parent = document
        for token in tokens[:-1]:
            parent = parent[int(token)] if isinstance(parent, list) else parent[token]
        last = tokens[-1]
        value = copy.deepcopy(op["value"])
        if op["op"] not in ("add", "replace"):
            raise ValueError(f"unsupported op {op['op']}")
        if isinstance(parent, list):
            if last == "-":
                parent.append(value)
            elif op["op"] == "add":
                parent.insert(int(last), value)
            else:
                parent[int(last)] = value
        else:
            if op["op"] == "replace" and last not in parent:
                raise KeyError(op["path"])
            parent[last] = value
    return document
