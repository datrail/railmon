"""gke-scan's view of a workload's pods (RC-551): which container is the
agent, the pod's revision and whether it has a sidecar, and the fields read
from the pod spec and the objects around it.

The resolver, beside workload.py's checked `sandbox_name`:

* **The workload key** is (`--cluster-name`, `sandbox_name`), the pair the
  sidecar reports under.
* **The agent container** is the one the `rail.datrail.io/scan-agent-container`
  annotation names, the annotation the webhook gives the sidecar the same
  container by. Without it, the first container that is neither the scan
  sidecar nor rail-proxy, with a note when there was more than one to choose
  from. An annotation naming a container the pod doesn't have falls back the
  same way, with a note, as the webhook does.
* **The revision** is the pod's `pod-template-hash` (a Deployment's or an
  Argo Rollout's ReplicaSet) or `controller-revision-hash` (a StatefulSet or
  DaemonSet).
* **The sidecar**: the webhook's `rail.datrail.io/scan-sidecar` annotation, or
  a container or native-sidecar init container that runs `scan --mode pod`
  or is named `rail-scan`.
* **`agent_type`**, for a workload with no sidecar: the
  `rail.datrail.io/agent-type` label, `personal` or `service`. Rail Center
  registers an agent only with `agent_type` ANSWERED.

The fields, over the workload's Ready pods on one revision (the caller picks
the revision, RC-555; a pod not yet Ready contributes nothing):

| Field | From |
|---|---|
| `image_digest` | The agent container's status `imageID`. PARTIAL, every digest listed, when the pods run different ones (a mutable tag that moved between pod starts) |
| `mounts` | The agent container's volumeMounts and the volumes behind them; for a claim, its storage class, access modes and capacity. The service account token is left out |
| `permissions` | The pod's and the agent container's securityContext, hostNetwork, hostPID, hostIPC, runtimeClassName and service account |
| `declared_ports` | The agent container's ports |
| `services_exposing_agent` | The Services whose selector matches the pod's labels |
| `sandbox_network_policy` | The NetworkPolicies whose podSelector selects the pod (`selecting_policies`), with their rules as written |

Each builder is evidence_bundle's (`answered`, `partial`, `blind`, `absent`),
handed in by the caller, so the attributes are the scanner's own shape. Tier
and method are set here; authored_by is added where the bundle is built
(RC-555).

A NetworkPolicy's podSelector is evaluated with matchLabels and every
matchExpressions operator (In, NotIn, Exists, DoesNotExist); an empty one
selects every pod in its namespace, as Kubernetes has it. One that can't be
evaluated (an unknown operator, a malformed expression) is kept, unmatched,
and the field is PARTIAL naming the policy. Peers (podSelector,
namespaceSelector, ipBlock) are kept as written: what they allow is
egress_containment's to say (RC-552).

Nothing here reads a Secret or a ConfigMap's contents, or an env value: a
volume is named by its kind and object name only.

Like the other central_service modules, it uses only the standard library.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable

AGENT_CONTAINER_ANNOTATION = "rail.datrail.io/scan-agent-container"
SIDECAR_INJECTED_ANNOTATION = "rail.datrail.io/scan-sidecar"
AGENT_TYPE_LABEL = "rail.datrail.io/agent-type"
AGENT_TYPES = ("personal", "service")
SIDECAR_CONTAINER_NAME = "rail-scan"
PROXY_CONTAINER_NAME = "rail-proxy"
REVISION_LABELS = ("pod-template-hash", "rollouts-pod-template-hash", "controller-revision-hash")
SERVICE_ACCOUNT_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount"
# The volume kinds named by an object, and the key that names it.
VOLUME_SOURCES = {
    "configMap": "name", "secret": "secretName", "persistentVolumeClaim": "claimName",
    "hostPath": "path", "nfs": "path", "csi": "driver", "ephemeral": None, "emptyDir": None,
    "downwardAPI": None, "projected": None, "image": "reference",
}

Builder = Callable[..., dict[str, Any]]


def _metadata(obj: Any) -> dict[str, Any]:
    metadata = obj.get("metadata") if isinstance(obj, dict) else None
    return metadata if isinstance(metadata, dict) else {}


def _labels(obj: Any) -> dict[str, str]:
    labels = _metadata(obj).get("labels")
    return labels if isinstance(labels, dict) else {}


def _annotations(obj: Any) -> dict[str, str]:
    annotations = _metadata(obj).get("annotations")
    return annotations if isinstance(annotations, dict) else {}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _spec(obj: Any) -> dict[str, Any]:
    return _dict(obj.get("spec")) if isinstance(obj, dict) else {}


def _name(obj: Any) -> str | None:
    name = _metadata(obj).get("name")
    return name if isinstance(name, str) and name else None


# ── the resolver ────────────────────────────────────────────────────────────

def workload_key(cluster_name: str, sandbox_name: str) -> tuple[str, str]:
    """gke-scan's key for a workload: the (host_id, sandbox_name) the sidecar reports under."""
    return cluster_name, sandbox_name


def is_sidecar(container: dict[str, Any]) -> bool:
    """The scan sidecar: named rail-scan, or running `scan --mode pod`."""
    if container.get("name") == SIDECAR_CONTAINER_NAME:
        return True
    words = [str(word) for word in _list(container.get("command")) + _list(container.get("args"))]
    return "scan" in words and any(a == "--mode" and b == "pod" for a, b in zip(words, words[1:]))


def _native_sidecars(pod: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for c in _list(_spec(pod).get("initContainers"))
            if isinstance(c, dict) and c.get("restartPolicy") == "Always"]


def has_sidecar(pod: dict[str, Any]) -> bool:
    if _annotations(pod).get(SIDECAR_INJECTED_ANNOTATION):
        return True
    containers = [c for c in _list(_spec(pod).get("containers")) if isinstance(c, dict)]
    return any(is_sidecar(c) for c in containers + _native_sidecars(pod))


def agent_container(pod: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """The agent's container, and a note when it had to be chosen."""
    containers = [c for c in _list(_spec(pod).get("containers")) if isinstance(c, dict) and c.get("name")]
    candidates = [c for c in containers if not is_sidecar(c) and c.get("name") != PROXY_CONTAINER_NAME]
    wanted = _annotations(pod).get(AGENT_CONTAINER_ANNOTATION)
    if wanted:
        for container in containers:
            if container.get("name") == wanted:
                return container, None
        if not candidates:
            return None, f"{AGENT_CONTAINER_ANNOTATION} names container '{wanted}', which the pod doesn't have"
        return candidates[0], (f"{AGENT_CONTAINER_ANNOTATION} names container '{wanted}', which the pod doesn't "
                               f"have; using '{candidates[0]['name']}'")
    if not candidates:
        return None, "the pod has no container other than the scan sidecar and rail-proxy"
    if len(candidates) > 1:
        names = ", ".join(f"'{c['name']}'" for c in candidates)
        return candidates[0], (f"the first of {names}; set {AGENT_CONTAINER_ANNOTATION} to name the agent's "
                               "container")
    return candidates[0], None


def pod_revision(pod: dict[str, Any]) -> str | None:
    labels = _labels(pod)
    for key in REVISION_LABELS:
        value = labels.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def is_ready(pod: dict[str, Any]) -> bool:
    status = _dict(pod.get("status"))
    if _metadata(pod).get("deletionTimestamp"):
        return False
    return any(isinstance(c, dict) and c.get("type") == "Ready" and c.get("status") == "True"
               for c in _list(status.get("conditions")))


def agent_type(pod: dict[str, Any]) -> tuple[str | None, str | None]:
    """The agent-type label's value, and a note when the label is there but
    isn't one Rail Center takes."""
    value = _labels(pod).get(AGENT_TYPE_LABEL)
    if value is None:
        return None, None
    if value in AGENT_TYPES:
        return value, None
    return None, f"{AGENT_TYPE_LABEL} is {value!r}, not one of {', '.join(AGENT_TYPES)}"


def agent_type_attribute(pods: list[dict[str, Any]], b: dict[str, Builder]) -> dict[str, Any] | None:
    """For a workload with no sidecar: ANSWERED from the label, or None
    (no attribute) when no pod carries one Rail Center takes."""
    for pod in pods:
        value, _ = agent_type(pod)
        if value:
            return b["answered"](value, "declared", method=f"the pod's {AGENT_TYPE_LABEL} label")
    return None


# ── NetworkPolicy selection ─────────────────────────────────────────────────

def label_selector_matches(selector: Any, labels: dict[str, str]) -> bool | None:
    """A LabelSelector (matchLabels, matchExpressions) against labels: True,
    False, or None when it can't be evaluated. An empty selector matches."""
    if selector is None:
        selector = {}
    if not isinstance(selector, dict):
        return None
    match_labels = selector.get("matchLabels") or {}
    expressions = selector.get("matchExpressions") or []
    if not isinstance(match_labels, dict) or not isinstance(expressions, list):
        return None
    result = all(labels.get(key) == value for key, value in match_labels.items())
    for expr in expressions:
        if not isinstance(expr, dict) or not isinstance(expr.get("key"), str):
            return None
        key, op = expr["key"], expr.get("operator")
        values = expr.get("values") or []
        if not isinstance(values, list):
            return None
        present = key in labels
        if op == "In":
            if not values:
                return None
            ok = present and labels[key] in values
        elif op == "NotIn":
            if not values:
                return None
            ok = not present or labels[key] not in values
        elif op == "Exists":
            ok = present
        elif op == "DoesNotExist":
            ok = not present
        else:
            return None
        result = result and ok
    return result


def policy_types(policy: dict[str, Any]) -> list[str]:
    """The policy's types; without policyTypes, Ingress, and Egress when it
    has egress rules, as Kubernetes defaults them."""
    spec = _spec(policy)
    types = spec.get("policyTypes")
    if isinstance(types, list) and types:
        return [str(t) for t in types]
    return ["Ingress"] + (["Egress"] if spec.get("egress") else [])


def selecting_policies(pod: dict[str, Any], policies: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """The NetworkPolicies in the pod's namespace that select it, rules as
    written, and the names of those whose podSelector can't be evaluated."""
    namespace = _metadata(pod).get("namespace")
    labels = _labels(pod)
    selecting, unevaluable = [], []
    for policy in policies:
        if _metadata(policy).get("namespace") != namespace or not _name(policy):
            continue
        spec = _spec(policy)
        match = label_selector_matches(spec.get("podSelector"), labels)
        if match is None:
            unevaluable.append(_name(policy))
            continue
        if match:
            selecting.append({
                "name": _name(policy),
                "policy_types": policy_types(policy),
                "ingress": _list(spec.get("ingress")),
                "egress": _list(spec.get("egress")),
            })
    return sorted(selecting, key=lambda p: p["name"]), sorted(unevaluable)


# ── the collectors ──────────────────────────────────────────────────────────

def _digest(image_id: Any) -> str | None:
    """sha256:... from a status imageID (`repo@sha256:...`, `docker-pullable://...`)."""
    if not isinstance(image_id, str) or "sha256:" not in image_id:
        return None
    return "sha256:" + image_id.rsplit("sha256:", 1)[1]


def _agent_status(pod: dict[str, Any], name: str) -> dict[str, Any]:
    for status in _list(_dict(pod.get("status")).get("containerStatuses")):
        if isinstance(status, dict) and status.get("name") == name:
            return status
    return {}


def image_digest_attribute(pods: list[dict[str, Any]], b: dict[str, Builder]) -> dict[str, Any]:
    digests: dict[str, list[str]] = {}
    images = set()
    for pod in pods:
        container, _ = agent_container(pod)
        if container is None:
            continue
        images.add(str(container.get("image")))
        digest = _digest(_agent_status(pod, container["name"]).get("imageID"))
        if digest:
            digests.setdefault(digest, []).append(str(_name(pod)))
    method = "the agent container's status imageID"
    if not digests:
        return b["blind"]("NO_SOURCE_ACCESS", "observed",
                          note="no Ready pod's agent container reports an image ID yet")
    if len(digests) == 1:
        return b["answered"](next(iter(digests)), "observed", method=method)
    listed = "; ".join(f"{d} in {', '.join(sorted(names))}" for d, names in sorted(digests.items()))
    return b["partial"](sorted(digests), "observed", "ORCHESTRATOR_MANAGED", method=method,
                        note=f"the pods of this revision run different digests of {', '.join(sorted(images))} "
                             f"(a tag that moved between pod starts): {listed}")


def _volume_entry(volume: dict[str, Any], claims: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], str | None]:
    """A volume's kind and the object it names; a claim's class, modes and
    size from the claim. The note says when the claim wasn't found."""
    kind = next((k for k in volume if k != "name"), None)
    entry: dict[str, Any] = {"volume": volume.get("name"), "type": kind}
    source = _dict(volume.get(kind)) if kind else {}
    key = VOLUME_SOURCES.get(kind or "")
    if key and isinstance(source.get(key), str):
        entry["source"] = source[key]
    if kind == "projected":
        entry["sources"] = sorted({next(iter(s)) for s in _list(source.get("sources")) if isinstance(s, dict) and s})
    if kind == "ephemeral":
        template = _spec(_dict(source.get("volumeClaimTemplate")))
        entry.update(storage_class=template.get("storageClassName"), access_modes=_list(template.get("accessModes")))
    if kind == "persistentVolumeClaim":
        claim = claims.get(str(source.get("claimName")))
        if claim is None:
            return entry, f"claim {source.get('claimName')} isn't in the copy"
        spec = _spec(claim)
        status = _dict(claim.get("status"))
        entry.update(storage_class=spec.get("storageClassName"),
                     access_modes=_list(status.get("accessModes")) or _list(spec.get("accessModes")),
                     capacity=_dict(status.get("capacity")).get("storage")
                     or _dict(_dict(spec.get("resources")).get("requests")).get("storage"))
    return entry, None


def mounts_attribute(pods: list[dict[str, Any]], claims: Iterable[dict[str, Any]], b: dict[str, Builder]) -> dict[str, Any]:
    pod = pods[0]
    container, _ = agent_container(pod)
    if container is None:
        return b["blind"]("NO_SOURCE_ACCESS", "declared", note="no agent container to read")
    namespace = _metadata(pod).get("namespace")
    by_name = {_name(c): c for c in claims if _metadata(c).get("namespace") == namespace and _name(c)}
    volumes = {v.get("name"): v for v in _list(_spec(pod).get("volumes")) if isinstance(v, dict)}
    mounts, missing = [], []
    for mount in _list(container.get("volumeMounts")):
        if not isinstance(mount, dict) or str(mount.get("mountPath", "")).startswith(SERVICE_ACCOUNT_TOKEN_PATH):
            continue
        volume = volumes.get(mount.get("name"))
        entry: dict[str, Any] = {"target": mount.get("mountPath"), "mode": "ro" if mount.get("readOnly") else "rw"}
        if mount.get("subPath") or mount.get("subPathExpr"):
            entry["sub_path"] = mount.get("subPath") or mount.get("subPathExpr")
        if volume is None:
            entry["volume"] = mount.get("name")
            missing.append(f"volume {mount.get('name')} isn't in the pod spec")
        else:
            volume_entry, problem = _volume_entry(volume, by_name)
            entry.update(volume_entry)
            if problem:
                missing.append(problem)
        mounts.append(entry)
    mounts.sort(key=lambda m: str(m.get("target")))
    method = "the agent container's volumeMounts, the pod's volumes and their claims"
    if missing:
        return b["partial"](mounts, "declared", "NO_SOURCE_ACCESS", method=method, note="; ".join(missing))
    return b["answered"](mounts, "declared", method=method,
                         **({} if mounts else {"note": "no volumes mounted apart from the service account token"}))


def _capabilities(context: dict[str, Any]) -> tuple[list[str], list[str]]:
    capabilities = _dict(context.get("capabilities"))
    return ([str(c) for c in _list(capabilities.get("add"))], [str(c) for c in _list(capabilities.get("drop"))])


def permissions_attribute(pods: list[dict[str, Any]], b: dict[str, Builder]) -> dict[str, Any]:
    pod = pods[0]
    container, _ = agent_container(pod)
    if container is None:
        return b["blind"]("NO_SOURCE_ACCESS", "declared", note="no agent container to read")
    spec = _spec(pod)
    pod_context = _dict(spec.get("securityContext"))
    context = _dict(container.get("securityContext"))

    def setting(key: str) -> Any:
        return context.get(key) if key in context else pod_context.get(key)

    cap_add, cap_drop = _capabilities(context)
    value = {
        # The keys docker mode also sets, first.
        "privileged": bool(context.get("privileged")),
        "cap_add": cap_add,
        "cap_drop": cap_drop,
        "allow_privilege_escalation": context.get("allowPrivilegeEscalation"),
        "read_only_root_filesystem": bool(context.get("readOnlyRootFilesystem")),
        "run_as_user": setting("runAsUser"),
        "run_as_group": setting("runAsGroup"),
        "run_as_non_root": setting("runAsNonRoot"),
        "seccomp_profile": setting("seccompProfile"),
        "app_armor_profile": setting("appArmorProfile"),
        "se_linux_options": setting("seLinuxOptions"),
        "proc_mount": context.get("procMount"),
        "host_network": bool(spec.get("hostNetwork")),
        "host_pid": bool(spec.get("hostPID")),
        "host_ipc": bool(spec.get("hostIPC")),
        "host_users": spec.get("hostUsers"),
        "runtime_class": spec.get("runtimeClassName"),
        "service_account": spec.get("serviceAccountName") or spec.get("serviceAccount") or "default",
        "automount_service_account_token": spec.get("automountServiceAccountToken"),
    }
    return b["answered"](value, "declared",
                         method="the pod's and the agent container's securityContext and host settings")


def declared_ports_attribute(pods: list[dict[str, Any]], b: dict[str, Builder]) -> dict[str, Any]:
    container, _ = agent_container(pods[0])
    if container is None:
        return b["blind"]("NO_SOURCE_ACCESS", "declared", note="no agent container to read")
    ports = []
    for port in _list(container.get("ports")):
        if not isinstance(port, dict) or not isinstance(port.get("containerPort"), int):
            continue
        entry: dict[str, Any] = {"port": port["containerPort"], "protocol": port.get("protocol") or "TCP"}
        if port.get("name"):
            entry["name"] = port["name"]
        if port.get("hostPort"):
            entry["host_port"] = port["hostPort"]
        ports.append(entry)
    ports.sort(key=lambda p: (p["port"], p["protocol"]))
    return b["answered"](ports, "declared", method="the agent container's ports",
                         **({} if ports else {"note": "the agent container declares no ports"}))


def service_selects(service: dict[str, Any], pod: dict[str, Any]) -> bool:
    selector = _spec(service).get("selector")
    if not isinstance(selector, dict) or not selector:
        return False
    if _metadata(service).get("namespace") != _metadata(pod).get("namespace"):
        return False
    labels = _labels(pod)
    return all(labels.get(k) == v for k, v in selector.items())


def services_exposing_attribute(pods: list[dict[str, Any]], services: Iterable[dict[str, Any]],
                                b: dict[str, Builder]) -> dict[str, Any]:
    services = list(services)
    exposing: dict[str, dict[str, Any]] = {}
    for pod in pods:
        for service in services:
            name = _name(service)
            if name and name not in exposing and service_selects(service, pod):
                spec = _spec(service)
                ports = []
                for port in _list(spec.get("ports")):
                    if not isinstance(port, dict):
                        continue
                    entry = {"port": port.get("port"), "target_port": port.get("targetPort", port.get("port")),
                             "protocol": port.get("protocol") or "TCP"}
                    for key, out in (("name", "name"), ("nodePort", "node_port")):
                        if port.get(key):
                            entry[out] = port[key]
                    ports.append(entry)
                entry: dict[str, Any] = {"name": name, "type": spec.get("type") or "ClusterIP", "ports": ports}
                ingress = [i.get("ip") or i.get("hostname") for i in
                           _list(_dict(_dict(service.get("status")).get("loadBalancer")).get("ingress"))
                           if isinstance(i, dict) and (i.get("ip") or i.get("hostname"))]
                if ingress:
                    entry["load_balancer_ingress"] = ingress
                if spec.get("externalIPs"):
                    entry["external_ips"] = _list(spec.get("externalIPs"))
                exposing[name] = entry
    value = sorted(exposing.values(), key=lambda s: s["name"])
    return b["answered"](value, "declared", method="the Services whose selector matches the pod's labels",
                         **({} if value else {"note": "no Service selects the agent's pods"}))


def sandbox_network_policy_attribute(pods: list[dict[str, Any]], policies: Iterable[dict[str, Any]],
                                     b: dict[str, Builder]) -> dict[str, Any]:
    policies = list(policies)
    selecting, unevaluable = selecting_policies(pods[0], policies)
    namespace = _metadata(pods[0]).get("namespace")
    in_namespace = sum(1 for p in policies if _metadata(p).get("namespace") == namespace)
    method = (f"the NetworkPolicies whose podSelector selects the pod ({len(selecting)} of {in_namespace} "
              "in its namespace), rules as written")
    if unevaluable:
        return b["partial"](selecting, "declared", "PARSE_FAILED", method=method,
                            note=f"podSelector can't be evaluated, so not counted: {', '.join(unevaluable)}")
    return b["answered"](selecting, "declared", method=method,
                         **({} if selecting else {"note": "no NetworkPolicy selects the pod, so Kubernetes "
                                                          "allows all its traffic"}))


def pod_spec_attributes(pods: Iterable[dict[str, Any]], services: Iterable[dict[str, Any]],
                        claims: Iterable[dict[str, Any]], policies: Iterable[dict[str, Any]],
                        b: dict[str, Builder]) -> dict[str, dict[str, Any]] | None:
    """The six attributes over one revision's pods, Ready ones only (newest
    first is the caller's order; the first Ready pod is read for the fields
    that come from one pod's spec). None when no pod is Ready."""
    ready = [pod for pod in pods if is_ready(pod)]
    if not ready:
        return None
    services, claims, policies = list(services), list(claims), list(policies)
    return {
        "image_digest": image_digest_attribute(ready, b),
        "mounts": mounts_attribute(ready, claims, b),
        "permissions": permissions_attribute(ready, b),
        "declared_ports": declared_ports_attribute(ready, b),
        "services_exposing_agent": services_exposing_attribute(ready, services, b),
        "sandbox_network_policy": sandbox_network_policy_attribute(ready, policies, b),
    }
