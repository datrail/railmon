"""gke-scan's Kubernetes API calls for the sidecar intake (RC-515): a
TokenReview of a sidecar's token, and a read of the pod it names.

In the cluster, it uses gke-scan's own service account: the token, CA and API
address Kubernetes mounts in every pod. The token file is read on every call,
so a token the kubelet rotates is picked up. Outside a cluster, or in tests,
`--kube-api-url`, `--kube-token-file` and `--kube-ca-file` name them instead.

It needs `create` on tokenreviews (the system:auth-delegator ClusterRole), and
`get` in enrolled namespaces on pods and on the controllers a pod's owner is
checked against (workload.py): replicasets, deployments, statefulsets,
daemonsets, jobs, cronjobs, and Argo's rollouts.argoproj.io. The rollouts
rule is needed even where Argo isn't installed: the API server checks
permission before it looks for the resource, so without the rule the read is
refused (403) rather than not found (404), and every post is answered 503. Redirects
are refused, so gke-scan's token never reaches another host.

Like the sidecar's modules, it imports nothing of railmon's and uses only the
standard library: the Kubernetes API is plain HTTPS and JSON.
"""

from __future__ import annotations

import json
import os
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

SERVICE_ACCOUNT_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
# Each Kubernetes API call gets this long (the gke-scan design's timeouts).
KUBE_TIMEOUT_SECONDS = 10.0
# The extra claims a projected service account token carries for the pod it
# was issued to, as TokenReview returns them.
POD_NAME_CLAIM = "authentication.kubernetes.io/pod-name"
POD_UID_CLAIM = "authentication.kubernetes.io/pod-uid"
SERVICE_ACCOUNT_PREFIX = "system:serviceaccount:"


class KubeError(RuntimeError):
    """The Kubernetes API couldn't answer: unreachable, timed out, or an
    answer gke-scan can't use. Never the sidecar's to fix."""


@dataclass(frozen=True)
class TokenIdentity:
    """Who a token belongs to, as TokenReview says. `pod_name` and `pod_uid`
    are None for a token that isn't bound to a pod."""

    namespace: str
    service_account: str
    pod_name: str | None
    pod_uid: str | None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def in_cluster_api_url() -> str | None:
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "").strip()
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "").strip() or "443"
    if not host:
        return None
    if ":" in host and not host.startswith("["):  # IPv6
        host = f"[{host}]"
    return f"https://{host}:{port}"


class KubeClient:
    """The two calls the intake makes, with gke-scan's own credential."""

    def __init__(self, api_url: str | None = None, token_file: str | None = None,
                 ca_file: str | None = None, timeout: float = KUBE_TIMEOUT_SECONDS):
        url = api_url or in_cluster_api_url()
        if not url:
            raise KubeError("no Kubernetes API: KUBERNETES_SERVICE_HOST is unset and --kube-api-url isn't given")
        self.api_url = url.rstrip("/")
        self.token_file = Path(token_file) if token_file else SERVICE_ACCOUNT_DIR / "token"
        ca = Path(ca_file) if ca_file else SERVICE_ACCOUNT_DIR / "ca.crt"
        self.timeout = timeout
        handlers: list[Any] = [_NoRedirect]
        if self.api_url.startswith("https://"):
            context = ssl.create_default_context()
            if ca.exists():
                context.load_verify_locations(cafile=str(ca))
            handlers.append(HTTPSHandler(context=context))
        self._opener = build_opener(*handlers)

    def _token(self) -> str:
        try:
            token = self.token_file.read_text().strip()
        except OSError as exc:
            raise KubeError(f"gke-scan's service account token {self.token_file}: {exc.__class__.__name__}") from None
        if not token:
            raise KubeError(f"gke-scan's service account token {self.token_file} is empty")
        return token

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
        """(status, parsed JSON) for 2xx and 404; KubeError for anything else."""
        data = json.dumps(body).encode() if body is not None else None
        req = Request(self.api_url + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self._token()}",
            "Accept": "application/json",
            **({"Content-Type": "application/json"} if data is not None else {}),
        })
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except HTTPError as exc:
            if exc.code == 404:
                return 404, None
            if exc.code == 403:
                raise KubeError(f"{method} {path}: HTTP 403: gke-scan's role doesn't allow this; "
                                "grant it (tools/scan/gke/central_service/README.md#running-it)") from None
            raise KubeError(f"{method} {path}: HTTP {exc.code}") from None
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise KubeError(f"{method} {path}: {exc.__class__.__name__}: {exc}") from None

    def token_review(self, token: str, audience: str) -> TokenIdentity | None:
        """The token's identity when the API server accepts it for `audience`
        (signature, audience and expiry), else None."""
        status, review = self._call("POST", "/apis/authentication.k8s.io/v1/tokenreviews", {
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenReview",
            "spec": {"token": token, "audiences": [audience]},
        })
        if status == 404 or not isinstance(review, dict):
            raise KubeError("TokenReview: the API server returned no review")
        return identity_from_review(review, audience)

    def get_pod(self, namespace: str, name: str) -> dict[str, Any] | None:
        """The pod, or None when there is no such pod."""
        return self.get_object("v1", "pods", namespace, name)

    def get_object(self, api_version: str, plural: str, namespace: str, name: str) -> dict[str, Any] | None:
        """A namespaced object (`apps/v1`, `replicasets`, ...), or None when
        there is no such object, or no such kind in this cluster."""
        prefix = "/api/v1" if api_version == "v1" else f"/apis/{api_version}"
        path = (f"{prefix}/namespaces/{quote(namespace, safe='')}/{quote(plural, safe='')}/"
                f"{quote(name, safe='')}")
        status, found = self._call("GET", path)
        if status == 404:
            return None
        if not isinstance(found, dict):
            raise KubeError(f"GET {plural} {namespace}/{name}: not an object")
        return found


def identity_from_review(review: dict[str, Any], audience: str) -> TokenIdentity | None:
    """A TokenReview's answer read strictly: authenticated, issued for
    `audience`, and a service account's. Anything else is None."""
    status = review.get("status")
    if not isinstance(status, dict) or status.get("authenticated") is not True or status.get("error"):
        return None
    audiences = status.get("audiences")
    # The API server lists the audiences the token was accepted for; one that
    # answers without them predates bound tokens, so the audience is unproven.
    if not isinstance(audiences, list) or audience not in audiences:
        return None
    user = status.get("user")
    if not isinstance(user, dict):
        return None
    username = user.get("username")
    if not isinstance(username, str) or not username.startswith(SERVICE_ACCOUNT_PREFIX):
        return None
    namespace, _, account = username[len(SERVICE_ACCOUNT_PREFIX):].partition(":")
    if not namespace or not account:
        return None
    extra = user.get("extra") if isinstance(user.get("extra"), dict) else {}

    def claim(key: str) -> str | None:
        values = extra.get(key)
        if isinstance(values, list) and len(values) == 1 and isinstance(values[0], str) and values[0]:
            return values[0]
        return None

    return TokenIdentity(namespace, account, claim(POD_NAME_CLAIM), claim(POD_UID_CLAIM))
