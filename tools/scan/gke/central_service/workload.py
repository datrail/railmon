"""The workload a pod belongs to, checked against the Kubernetes API: the
second half of the agent key, namespace/workload, as the sidecar must have
written it for gke-scan to relay its bundle.

A pod's name, labels and ownerReferences are all written by whoever creates
it, and the API server doesn't check that an owner exists. So nothing the pod
says about itself is taken as is. Each owner it names is read from the API
and must be a kind gke-scan checks, exist with the UID the pod names, and
select the pod (its label selector matches the pod's labels), and so on up
the chain:

| The pod's controller | Its workload, as the sidecar keys it |
|---|---|
| ReplicaSet, controlled by a Deployment or Argo Rollout | the Deployment or Rollout |
| ReplicaSet with no controller | the pod itself, by its own name |
| StatefulSet | the pod itself, `<statefulset>-<ordinal>` |
| DaemonSet | the DaemonSet |
| Job, controlled by a CronJob that lists it in `status.active` | the CronJob |
| Job with no controller | the Job |
| None (a bare pod) | the pod itself |
| Any other kind, at any step | none: gke-scan can't check it |

Whatever the key, no other workload may be keyed the same way: a
Deployment, DaemonSet, Job, CronJob or Rollout of that name, or a StatefulSet
whose pod would be named so. A shared key is refused for every pod that
works it out, since it would file one workload's bundle as another's.

What this stops: a pod claiming a workload by its name, a label, an owner
that doesn't exist, has another UID or doesn't select it, a made-up Job under
someone's CronJob, or a workload of its own with someone else's name (except
an Argo Rollout whose workloadRef names that Deployment, which counts as it).

What it can't stop, and the trust boundary: anyone who may create pods in an
enrolled namespace. A pod that copies a real replica's owner reference (its
ReplicaSet's UID is on any sibling pod) and its labels is, to Kubernetes, one
of that workload's replicas until the controller removes it, and its
termination grace period (30 seconds by default) is long enough for its
sidecar to post. gke-scan can't tell it from any other replica. Anyone who
may create or change workloads (Kubernetes' `edit` role) can do the same
more lastingly. So give pod creation in an enrolled namespace only to those
trusted to report as any of its workloads.

Like the rest of gke-scan's modules, it imports nothing of railmon's.
"""

from __future__ import annotations

import re
from typing import Any, Protocol

# The sidecar's limit on sandbox_name, and its rule for a CronJob's Job name.
SANDBOX_NAME_MAX = 255
JOB_RUN_SUFFIX = re.compile(r"^(?P<name>.+)-(?P<run>\d{8})$")
CRONJOB_RUN_MINUTES = range(26_000_000, 100_000_000)

# The kinds gke-scan reads to check an owner: (API group, kind) -> (apiVersion, plural).
KINDS: dict[tuple[str, str], tuple[str, str]] = {
    ("apps", "ReplicaSet"): ("apps/v1", "replicasets"),
    ("apps", "Deployment"): ("apps/v1", "deployments"),
    ("apps", "StatefulSet"): ("apps/v1", "statefulsets"),
    ("apps", "DaemonSet"): ("apps/v1", "daemonsets"),
    ("batch", "Job"): ("batch/v1", "jobs"),
    ("batch", "CronJob"): ("batch/v1", "cronjobs"),
    ("argoproj.io", "Rollout"): ("argoproj.io/v1alpha1", "rollouts"),
}
# Workloads keyed by their own name: no other workload's key may be one of these names.
NAMED_WORKLOADS = [("apps", "Deployment"), ("apps", "DaemonSet"), ("batch", "Job"), ("batch", "CronJob"),
                   ("argoproj.io", "Rollout")]


class Objects(Protocol):
    def get_object(self, api_version: str, plural: str, namespace: str, name: str) -> dict[str, Any] | None: ...


class Unverified(Exception):
    """The pod's claim to a workload doesn't hold up against the API."""


def _metadata(obj: dict[str, Any]) -> dict[str, Any]:
    metadata = obj.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _labels(obj: dict[str, Any]) -> dict[str, str]:
    labels = _metadata(obj).get("labels")
    return labels if isinstance(labels, dict) else {}


def _name(obj: dict[str, Any], fallback: str) -> str:
    name = _metadata(obj).get("name")
    return name if isinstance(name, str) and name else fallback


def controller_ref(obj: dict[str, Any]) -> dict[str, Any] | None:
    """The object's one controller reference, None when it has none."""
    refs = _metadata(obj).get("ownerReferences")
    owners = [ref for ref in (refs if isinstance(refs, list) else [])
              if isinstance(ref, dict) and ref.get("controller") is True]
    if len(owners) > 1:
        raise Unverified("it has more than one controller")
    return owners[0] if owners else None


def selects(selector: Any, labels: dict[str, str]) -> bool:
    """A Kubernetes label selector against `labels`. An empty or missing
    selector selects nothing here: every controller gke-scan checks has one."""
    if not isinstance(selector, dict):
        return False
    match_labels = selector.get("matchLabels") or {}
    expressions = selector.get("matchExpressions") or []
    if not isinstance(match_labels, dict) or not isinstance(expressions, list) or not (match_labels or expressions):
        return False
    if any(labels.get(key) != value for key, value in match_labels.items()):
        return False
    for expr in expressions:
        if not isinstance(expr, dict):
            return False
        key, op, values = expr.get("key"), expr.get("operator"), expr.get("values") or []
        present = key in labels
        if op == "In":
            ok = present and labels[key] in values
        elif op == "NotIn":
            ok = not present or labels[key] not in values
        elif op == "Exists":
            ok = present
        elif op == "DoesNotExist":
            ok = not present
        else:
            ok = False
        if not ok:
            return False
    return True


def owner(objects: Objects, namespace: str, ref: dict[str, Any], child_labels: dict[str, str]) -> tuple[str, dict[str, Any]]:
    """The owner `ref` names, read from the API: a kind gke-scan checks, that
    exists with the UID `ref` names and selects the child. A CronJob has no
    selector, so the Job's name is checked against it by the caller."""
    api_version = ref.get("apiVersion")
    group = api_version.split("/", 1)[0] if isinstance(api_version, str) and "/" in api_version else ""
    kind, name = str(ref.get("kind")), ref.get("name")
    if (group, kind) not in KINDS:
        raise Unverified(f"its controller is a {kind} ({api_version}), which gke-scan can't check")
    if not isinstance(name, str) or not name:
        raise Unverified(f"its {kind} controller has no name")
    found = objects.get_object(*KINDS[(group, kind)], namespace, name)
    if found is None:
        raise Unverified(f"its {kind} {name} doesn't exist")
    uid = _metadata(found).get("uid")
    if not uid or uid != ref.get("uid"):
        raise Unverified(f"its {kind} {name} has another UID")
    if kind != "CronJob":
        spec = found.get("spec") if isinstance(found.get("spec"), dict) else {}
        if not selects(spec.get("selector"), child_labels):
            raise Unverified(f"its {kind} {name} doesn't select it")
    return kind, {**found, "kind": kind}


def workload(objects: Objects, namespace: str, pod: dict[str, Any]) -> tuple[str | None, str]:
    """The pod's workload name, checked, and how it was found; None, with the
    reason, when the pod's claim doesn't hold up or its key is another
    workload's too. The API being unreachable raises the client's own error."""
    try:
        key, how, owner = _workload(objects, namespace, pod)
        _only_key(objects, namespace, key, owner)
        return key, how
    except Unverified as exc:
        return None, str(exc)


def _workload(objects: Objects, namespace: str, pod: dict[str, Any]) -> tuple[str, str, dict[str, Any] | None]:
    """(key, how it was found, the workload object the key names, or None
    when the key is the pod's own name)."""
    pod_name = _metadata(pod).get("name")
    if not isinstance(pod_name, str) or not pod_name:
        raise Unverified("the pod has no name")
    pod_labels = _labels(pod)
    ref = controller_ref(pod)
    if ref is None:
        return pod_name, "the pod itself, which no controller owns", None
    kind, found = owner(objects, namespace, ref, pod_labels)
    name = _name(found, ref["name"])
    if kind == "ReplicaSet":
        up = controller_ref(found)
        if up is None:
            return pod_name, f"the pod itself, as ReplicaSet {name} has no controller", None
        up_kind, top = owner(objects, namespace, up, pod_labels)
        if up_kind not in ("Deployment", "Rollout"):
            raise Unverified(f"its ReplicaSet {name} is controlled by a {up_kind}")
        top_name = _name(top, up["name"])
        return top_name, f"{up_kind} {top_name}, through ReplicaSet {name}", top
    if kind == "StatefulSet":
        if not re.fullmatch(re.escape(name) + r"-\d+", pod_name):
            raise Unverified(f"it isn't named as StatefulSet {name}'s pods are")
        return pod_name, f"StatefulSet {name}'s pod", found
    if kind == "DaemonSet":
        return name, f"DaemonSet {name}", found
    if kind == "Job":
        up = controller_ref(found)
        if up is None:
            return name, f"Job {name}", found
        up_kind, top = owner(objects, namespace, up, _labels(found))
        if up_kind != "CronJob":
            raise Unverified(f"its Job {name} is controlled by a {up_kind}")
        cronjob = _name(top, up["name"])
        run = JOB_RUN_SUFFIX.match(name)
        if not (run and run.group("name") == cronjob and int(run.group("run")) in CRONJOB_RUN_MINUTES):
            raise Unverified(f"its Job {name} isn't named as CronJob {cronjob}'s runs are")
        # A Job names its CronJob as controller by its own creator's say-so;
        # only the CronJob's controller writes status.active, so the run must
        # be listed there.
        status = top.get("status") if isinstance(top.get("status"), dict) else {}
        active = status.get("active") if isinstance(status.get("active"), list) else []
        job_uid = _metadata(found).get("uid")
        if not job_uid or not any(isinstance(a, dict) and a.get("uid") == job_uid for a in active):
            raise Unverified(f"CronJob {cronjob} doesn't list Job {name} as one of its active runs")
        return cronjob, f"CronJob {cronjob}, through its active Job {name}", top
    raise Unverified(f"a pod isn't controlled by a {kind} directly")


def workload_ref(rollout: dict[str, Any]) -> str | None:
    """The Deployment an Argo Rollout's spec.workloadRef names, if any: Argo's
    way of moving a Deployment to a Rollout, which keeps the Deployment
    (usually scaled to 0) under the same name."""
    spec = rollout.get("spec") if isinstance(rollout.get("spec"), dict) else {}
    ref = spec.get("workloadRef")
    if (isinstance(ref, dict) and ref.get("kind") == "Deployment"
            and str(ref.get("apiVersion", "apps/v1")).split("/", 1)[0] == "apps"
            and isinstance(ref.get("name"), str) and ref["name"]):
        return ref["name"]
    return None


def _only_key(objects: Objects, namespace: str, key: str, owner: dict[str, Any] | None) -> None:
    """No other workload is keyed `key`: a Deployment, DaemonSet, Job,
    CronJob or Rollout of that name, or a StatefulSet that would name a pod
    that way, other than `owner`, the one the key was worked out from. A key
    two workloads share would file one's bundle as the other's, so it isn't
    relayed for either. A Rollout and the Deployment its workloadRef names are
    one workload, from either side."""
    owner_uid = _metadata(owner).get("uid") if owner is not None else None
    found_by_kind: dict[str, dict[str, Any]] = {}
    for group_kind in NAMED_WORKLOADS:
        found = objects.get_object(*KINDS[group_kind], namespace, key)
        if found is not None and _metadata(found).get("uid") != owner_uid:
            found_by_kind[group_kind[1]] = found
    owner_is = lambda kind: owner is not None and owner_uid is not None and _kind_of(owner) == kind
    if "Deployment" in found_by_kind and owner_is("Rollout") and workload_ref(owner) == key:
        del found_by_kind["Deployment"]
    if "Rollout" in found_by_kind and owner_is("Deployment") and workload_ref(found_by_kind["Rollout"]) == key:
        del found_by_kind["Rollout"]
    for kind in found_by_kind:
        raise Unverified(f"{key} is also {kind} {key}'s key")
    ordinal = re.fullmatch(r"(?P<set>.+)-\d+", key)
    if ordinal:
        found = objects.get_object(*KINDS[("apps", "StatefulSet")], namespace, ordinal.group("set"))
        if found is not None and _metadata(found).get("uid") != owner_uid:
            raise Unverified(f"{key} is also StatefulSet {ordinal.group('set')}'s pod's key")


def _kind_of(obj: dict[str, Any]) -> str | None:
    kind = obj.get("kind")
    return kind if isinstance(kind, str) else None


def sandbox_name(objects: Objects, namespace: str, pod: dict[str, Any]) -> tuple[str | None, str]:
    """namespace/workload, checked and cut to the sidecar's limit, or None."""
    name, how = workload(objects, namespace, pod)
    if name is None:
        return None, how
    return f"{namespace}/{name}"[:SANDBOX_NAME_MAX], how
