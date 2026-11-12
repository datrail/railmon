"""Pod mode (RC-504): the scanner as a sidecar in a Kubernetes pod.

Everything specific to running in a pod lives here: reading the downward
API, naming the workload so the agent keeps one key across restarts, and the
pod-mode values of the deployment, owner and agent_instance attributes.
scan_agent_environment.py and evidence_bundle.py call into this module only
when the scan's mode is "pod", so self and docker scans never load it.

The sidecar learns which pod it is in from the downward API: environment
variables the manifest maps from the pod's fields, and a volume holding the
pod's labels. The kubelet writes both, so the agent process cannot change
them while it runs. The pod's name and labels are still whatever the pod's
creator chose; only the namespace and UID are the cluster's own, which is
why gke-scan checks the key against the pod's owner before relaying a bundle.

This module imports nothing of railmon's, so it loads by path without a
cycle. The attribute builders take evidence_bundle's `answered` and `blind`
status constructors as arguments.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Callable

POD_ENV_KEYS = {"name": "POD_NAME", "namespace": "POD_NAMESPACE", "uid": "POD_UID", "node": "NODE_NAME"}
POD_INFO_DIR_ENV = "RAIL_POD_INFO_DIR"
DEFAULT_POD_INFO_DIR = Path("/etc/podinfo")
POD_LABELS_MAX_BYTES = 64_000
SANDBOX_NAME_MAX = 255

# The labels a controller stamps on its pods, which say which kind of
# workload a pod belongs to.
POD_TEMPLATE_HASH_LABELS = ("pod-template-hash", "rollouts-pod-template-hash")  # Deployment, Argo Rollout
STATEFULSET_POD_NAME_LABEL = "statefulset.kubernetes.io/pod-name"
CONTROLLER_REVISION_HASH_LABEL = "controller-revision-hash"  # StatefulSet and DaemonSet
JOB_NAME_LABELS = ("batch.kubernetes.io/job-name", "job-name")
WORKLOAD_LABELS = (*POD_TEMPLATE_HASH_LABELS, STATEFULSET_POD_NAME_LABEL,
                   CONTROLLER_REVISION_HASH_LABEL, *JOB_NAME_LABELS)
# Labels that change from one rollout or replica to the next, left out of the
# pod's labels (workload_name still reads them).
POD_ROLLOUT_LABELS = frozenset({
    *POD_TEMPLATE_HASH_LABELS, CONTROLLER_REVISION_HASH_LABEL, STATEFULSET_POD_NAME_LABEL,
    "apps.kubernetes.io/pod-index", "pod-template-generation",
})

# A CronJob names each Job <cronjob>-<scheduled time in minutes since the
# epoch>, cut so each run keeps one name. Only an eight-digit number in the
# range those minutes can take (2019 to 2160) is cut: a date (report-20240115)
# or Unix seconds (backup-1700000000) is part of a Job's own name.
JOB_RUN_SUFFIX = re.compile(r"^(?P<name>.+)-(?P<run>\d{8})$")
CRONJOB_RUN_MINUTES = range(26_000_000, 100_000_000)

# Kubernetes names a controller's pod <base><5 random characters>, cutting
# the base to 58 characters first, so a generated pod name is at most 63.
GENERATED_NAME_SUFFIX = 5
GENERATED_NAME_MAX = 63

# The workload sources that mean the pod name can't name the workload, and
# --sandbox-name is needed.
HASH_NOT_IN_NAME = "pod-template-hash not found in the pod name"
DAEMONSET_NAME_CUT = "DaemonSet pod name cut by Kubernetes"
NOT_A_DAEMONSET_NAME = "controller-revision-hash on a pod name no DaemonSet generates"
NEEDS_SANDBOX_NAME = frozenset({HASH_NOT_IN_NAME, DAEMONSET_NAME_CUT, NOT_A_DAEMONSET_NAME})


def _first(*values: str | None) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def read_downward_api_labels(path: Path) -> tuple[dict[str, str] | None, bool]:
    """The pod's labels from the downward API's labels file, and whether the
    file was over the size cap.

    The kubelet writes one `key="value"` line per label, the value quoted
    the way Go's %q quotes it. A missing or unreadable file is None, not an
    empty dict: a pod with no labels still gets an (empty) file, so no file
    means the manifest didn't mount it, and the labels are unknown. A file
    over the cap keeps its whole lines up to the cap.
    """
    try:
        with path.open("rb") as handle:
            raw = handle.read(POD_LABELS_MAX_BYTES + 1)
    except OSError:
        return None, False
    truncated = len(raw) > POD_LABELS_MAX_BYTES
    text = raw[:POD_LABELS_MAX_BYTES].decode("utf-8", errors="replace")
    if truncated:
        text = text.rpartition("\n")[0]
    labels: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            try:
                decoded = json.loads(value)
            except json.JSONDecodeError:
                decoded = value[1:-1]
            value = decoded if isinstance(decoded, str) else value[1:-1]
        labels[key] = value
    return labels, truncated


def workload_name(pod_name: str | None, labels: dict[str, str]) -> tuple[str | None, str]:
    """The name that stays the same when the pod is replaced, and its source.

    - A StatefulSet's pod name is already stable (<name>-<ordinal>).
    - A Deployment's pod is <deployment>-<pod-template-hash>-<5 characters>,
      and an Argo Rollout's the same with rollouts-pod-template-hash, so the
      name is everything before the hash.
    - A DaemonSet's pod (controller-revision-hash, no StatefulSet label) is
      <daemonset>-<5 characters>, so the name is everything before them.
    - A Job's pods carry its name as a label, less a CronJob's run number.
    - Any other pod, a bare one included, keeps its own name: guessing at a
      generated suffix would cut a real name such as `debug-agent` in half.
      (A bare ReplicaSet's pod carries no label that tells it from a bare
      pod; ReplicaSets are run through Deployments.)

    Where Kubernetes has cut the pod name so the workload's name can't be
    read back exactly, no name is guessed: the webhook passes --sandbox-name.
    The caller passes labels only when the labels file was read.
    """
    pod_name = _first(pod_name)
    if not pod_name:
        return None, "unset"
    if labels.get(STATEFULSET_POD_NAME_LABEL) == pod_name:
        return pod_name, "statefulset pod name"
    for key in POD_TEMPLATE_HASH_LABELS:
        template_hash = _first(labels.get(key))
        if template_hash:
            marker = f"-{template_hash}-"
            if marker in pod_name:
                return pod_name.split(marker, 1)[0], f"pod name without its {key}"
            # The base (<deployment>-<hash>-) was cut to 58 characters: what
            # is left of the hash can't be told apart from a longer name
            # that happens to end the same way.
            return None, HASH_NOT_IN_NAME
    if _first(labels.get(CONTROLLER_REVISION_HASH_LABEL)):
        # A DaemonSet's pod. Its base is <daemonset>- and is cut only when
        # the DaemonSet's name is 58 characters or more, which makes the pod
        # name 63; a 57-character name gives 63 too, so 63 is not guessed.
        if len(pod_name) >= GENERATED_NAME_MAX:
            return None, DAEMONSET_NAME_CUT
        if len(pod_name) > GENERATED_NAME_SUFFIX + 1 and pod_name[-GENERATED_NAME_SUFFIX - 1] == "-":
            return pod_name[:-GENERATED_NAME_SUFFIX - 1], "DaemonSet pod name without its generated suffix"
        return None, NOT_A_DAEMONSET_NAME
    for key in JOB_NAME_LABELS:
        job = _first(labels.get(key))
        if job:
            run = JOB_RUN_SUFFIX.match(job)
            if run and int(run.group("run")) in CRONJOB_RUN_MINUTES:
                return run.group("name"), f"label {key} without its CronJob run number"
            return job, f"label {key}"
    return pod_name, "pod name"


def read_pod_metadata(env: dict[str, str], info_dir: Path) -> dict[str, Any]:
    """Which pod this scan runs in: the downward API's variables and labels
    file, and the workload name derived from them."""
    pod: dict[str, Any] = {field: _first(env.get(key)) for field, key in POD_ENV_KEYS.items()}
    labels, truncated = read_downward_api_labels(info_dir / "labels")
    if labels is None:
        # No labels file: the pod name alone can't say whether it ends in a
        # controller's hash or suffix, so no workload is guessed from it.
        workload, source = None, "no labels file"
    elif truncated and not any(key in labels for key in WORKLOAD_LABELS):
        # The kubelet sorts labels by key, so the ones that name the workload
        # may be past the cap: the same unknown as no file at all.
        workload, source = None, "labels file over the cap, before any workload label"
    else:
        workload, source = workload_name(pod["name"], labels)
    pod["labels"] = {key: value for key, value in sorted((labels or {}).items())
                     if key not in POD_ROLLOUT_LABELS}
    pod["labels_file"] = labels is not None
    pod["labels_truncated"] = truncated
    pod["workload"] = workload
    pod["workload_source"] = source
    return pod


def info_dir() -> Path:
    return Path(_first(os.environ.get(POD_INFO_DIR_ENV)) or DEFAULT_POD_INFO_DIR)


def gaps(pod: dict[str, Any], env: dict[str, str], folder: Path) -> list[str]:
    """Log lines for what the downward API left out. Names only: the values
    are the pod's, and the bundle carries them."""
    lines = []
    missing = [key for key in POD_ENV_KEYS.values() if not _first(env.get(key))]
    if not pod["labels_file"]:
        missing.append(f"the labels file ({folder / 'labels'})")
    if missing:
        lines.append(f"pod mode: the downward API is missing {', '.join(missing)}; agent_instance, "
                     "deployment and owner are BLIND where their source is missing, and without "
                     "POD_NAMESPACE, POD_NAME and the labels file no sandbox_name is derived")
    if pod["labels_truncated"]:
        lines.append(f"pod mode: the labels file is over {POD_LABELS_MAX_BYTES} bytes; only the "
                     "labels before the cap were read")
    if pod["workload_source"] in NEEDS_SANDBOX_NAME:
        lines.append("pod mode: the workload's name can't be read from the pod name "
                     f"({pod['workload_source']}); set --sandbox-name to namespace/<workload>")
    return lines


def sandbox_name(pod: dict[str, Any]) -> tuple[str | None, str]:
    """namespace/workload, the same key gke-scan derives from the Kubernetes
    API. Never the hostname: that is the pod's name, which changes every time
    the pod is replaced."""
    namespace, workload = _first(pod.get("namespace")), _first(pod.get("workload"))
    if namespace and workload:
        return f"{namespace}/{workload}"[:SANDBOX_NAME_MAX], f"downward API ({pod.get('workload_source')})"
    return None, "unset"


def missing_key(identity: dict[str, Any]) -> str | None:
    """Why the agent can't be named, or None. A pod-mode bundle is only
    useful under the key gke-scan derives for the same pod; one filed under a
    guessed or empty key is a phantom agent."""
    needs = {"host_id": "--host-id or RAIL_HOST_ID",
             "sandbox_name": "POD_NAMESPACE, POD_NAME and the labels file from the downward API, "
                             "or --sandbox-name"}
    missing = [f"no {name} (set {source})" for name, source in needs.items() if not identity[name]]
    if not missing:
        return None
    return f"--mode pod cannot name the agent: {'; '.join(missing)}; nothing was written or sent"


# ── bundle attributes ───────────────────────────────────────────────────────
# Built here in full and handed to evidence_bundle.py, which puts them in
# place of its generic deployment, owner and agent_instance in pod mode.

Builder = Callable[..., dict[str, Any]]
DEPLOYMENT_ENV_KEYS = ("RAIL_DEPLOYMENT", "RAIL_NAMESPACE")


def bundle_attributes(context: dict[str, Any], payload: dict[str, Any],
                      answered: Builder, blind: Builder) -> dict[str, Any]:
    pod = context.get("pod") or {}
    user_info = (payload.get("environment") or {}).get("user_info") or {}
    return {
        "deployment": deployment_attribute(answered, blind, pod, context.get("env") or {}),
        "owner": owner_attribute(answered, blind, payload.get("owner"),
                                 user_info.get("owner_source") or "unset"),
        "agent_instance": agent_instance_attribute(answered, blind, pod),
    }


def deployment_attribute(answered: Builder, blind: Builder, pod: dict[str, Any],
                         env: dict[str, str]) -> dict[str, Any]:
    """RAIL_DEPLOYMENT and RAIL_NAMESPACE, the pair Rail Center groups
    copies of an agent by: from the downward API (the workload and the
    namespace) where the environment doesn't set them, with each key's
    source in the method."""
    value = {key: env[key].strip() for key in DEPLOYMENT_ENV_KEYS
             if isinstance(env.get(key), str) and env[key].strip()}
    sources = {key: "the environment" for key in value}
    derived = {
        "RAIL_DEPLOYMENT": (pod.get("workload"), f"the downward API (the {pod.get('workload_source')})"),
        "RAIL_NAMESPACE": (pod.get("namespace"), "the downward API (POD_NAMESPACE)"),
    }
    for key, (found, source) in derived.items():
        if key not in value and isinstance(found, str) and found.strip():
            value[key] = found.strip()
            sources[key] = source
    if not value:
        return blind(
            "NO_SOURCE_ACCESS", "declared",
            note="the downward API gave no POD_NAMESPACE or workload (POD_NAME and the labels file), "
                 "and neither RAIL_DEPLOYMENT nor RAIL_NAMESPACE is set",
        )
    complete = all(key in value for key in DEPLOYMENT_ENV_KEYS)
    return answered(
        value, "declared",
        # The kubelet's values, or the sidecar's own variables, which the
        # agent can't rewrite.
        authored_by="platform",
        method="; ".join(f"{key} from {sources[key]}" for key in sorted(sources)),
        note="operator-set deployment signal; "
             + ("complete environment pair is the deployment key" if complete
                else "a half-pair supplies no deployment key"),
    )


def owner_attribute(answered: Builder, blind: Builder, owner: str | None, source: str) -> dict[str, Any]:
    """RAIL_OWNER is the sidecar's own variable, mapped from the pod's owner
    label, which the agent cannot rewrite; there is no git or login-user
    fallback, which would name the sidecar image's user."""
    if owner and owner != "unknown":
        return answered(
            {"owner": owner, "source": source}, "declared", authored_by="platform",
            method="--owner, then RAIL_OWNER (the pod's owner label), first set wins",
            note="the label the operator files the agent under; not part of its identity",
        )
    return blind(
        "NO_SOURCE_ACCESS", "declared",
        note="no --owner or RAIL_OWNER; pod mode does not fall back to git or the login "
             "user, which name the sidecar image's user, not an owner",
    )


def agent_instance_attribute(answered: Builder, blind: Builder, pod: dict[str, Any]) -> dict[str, Any]:
    """Where this copy runs is the pod: the sidecar's own container id, pid
    and cwd describe the scanner, not the agent."""
    instance = {key: pod[key] for key in ("name", "uid", "node")
                if isinstance(pod.get(key), str) and pod[key].strip()}
    if instance:
        return answered(
            {"pod": instance}, "observed", authored_by="platform",
            method="downward API: POD_NAME, POD_UID and NODE_NAME",
            note="dynamic (schemas/attribute-groups.json): the pod this copy runs in."
                 " A restart or reschedule changes it, so it is not drift",
        )
    return blind("NO_SOURCE_ACCESS", "observed",
                 note="no POD_NAME, POD_UID or NODE_NAME from the downward API")
