"""Whether the cluster enforces NetworkPolicies (RC-552), for
egress_containment: a policy restricts a pod's traffic only where a node
agent enforces it.

On GKE that is anetd (Dataplane V2, Autopilot's and many Standard clusters'
dataplane) or calico-node (the older network policy add-on), each a
DaemonSet in kube-system. gke-scan reads them by name, once per interval.
A DaemonSet that exists enforces only through its pods, so its status is
read too:

| Answer | enforced | by |
|---|---|---|
| anetd exists, with every scheduled pod Ready | true | anetd |
| calico-node exists, with every scheduled pod Ready (and anetd doesn't) | true | calico-node |
| neither exists, or each that does is scheduled on no node | false | null |
| one exists with a pod not Ready or no status yet, and none is Ready | null | null |
| a read is refused (403) or fails | null | null |

A refused or failed read, or an enforcer not every node is running, is
unknown, never "not enforced": egress_containment is PARTIAL then, and never
contained. It needs `get` on daemonsets in kube-system (the chart's Role,
RC-557); the status comes with the same read. Like the other central_service
modules, it uses only the standard library.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Protocol

ENFORCERS = (("anetd", "GKE Dataplane V2"), ("calico-node", "Calico"))
NAMESPACE = "kube-system"


class Objects(Protocol):
    def get_object(self, api_version: str, plural: str, namespace: str, name: str) -> dict[str, Any] | None: ...


def _readiness(daemonset: dict[str, Any]) -> tuple[int, int] | None:
    """(Ready pods, scheduled pods) from the DaemonSet's status, or None
    when the controller hasn't written one."""
    status = daemonset.get("status")
    if not isinstance(status, dict):
        return None
    desired, ready = status.get("desiredNumberScheduled"), status.get("numberReady")
    if not isinstance(desired, int) or isinstance(desired, bool):
        return None
    return (ready if isinstance(ready, int) and not isinstance(ready, bool) else 0), desired


def check(kube: Objects) -> dict[str, Any]:
    """{"enforced": True/False/None, "by": name or None, "detail": ...}."""
    not_ready: list[str] = []
    unscheduled: list[str] = []
    for name, what in ENFORCERS:
        try:
            found = kube.get_object("apps/v1", "daemonsets", NAMESPACE, name)
        except Exception as exc:  # noqa: BLE001 - unknown, never "not enforced"
            refused = getattr(exc, "status", None) == 403
            return {"enforced": None, "by": None,
                    "detail": (f"gke-scan's role may not read DaemonSet {name} in {NAMESPACE}" if refused
                               else f"reading DaemonSet {name} in {NAMESPACE} failed: {exc}")}
        if found is None:
            continue
        readiness = _readiness(found)
        if readiness is None:
            not_ready.append(f"{what}: DaemonSet {name} in {NAMESPACE} has no status yet")
            continue
        ready, desired = readiness
        if desired == 0:
            unscheduled.append(f"DaemonSet {name} in {NAMESPACE} is scheduled on no node")
        elif ready < desired:
            not_ready.append(f"{what}: DaemonSet {name} in {NAMESPACE} has {ready} of {desired} pods Ready")
        else:
            return {"enforced": True, "by": name, "detail": f"{what}: DaemonSet {name} in {NAMESPACE}"}
    if not_ready:
        return {"enforced": None, "by": None, "detail": "; ".join(not_ready)}
    if unscheduled:
        return {"enforced": False, "by": None, "detail": "; ".join(unscheduled)}
    return {"enforced": False, "by": None,
            "detail": f"no {' or '.join(name for name, _ in ENFORCERS)} DaemonSet in {NAMESPACE}"}


class EnforcementCheck:
    """check(), at most once per interval; a failed check is tried again on
    the next call."""

    def __init__(self, kube: Objects, interval: float, clock: Callable[[], float] = time.monotonic):
        self.kube = kube
        self.interval = interval
        self.clock = clock
        self._answer: dict[str, Any] | None = None
        self._at: float | None = None

    def current(self) -> dict[str, Any]:
        now = self.clock()
        if self._answer is None or self._at is None or now - self._at >= self.interval:
            answer = check(self.kube)
            if answer["enforced"] is None:
                return answer
            self._answer, self._at = answer, now
        return self._answer
