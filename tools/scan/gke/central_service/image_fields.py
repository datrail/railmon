"""gke-scan's image fields (RC-553): `user`, `framework_identity`,
`credential_provenance` and `in_layer_deleted_secrets`, from the agent
container's pod spec and its image as the registry reader read it
(registry.py), by the digest the kubelet pulled.

| Field | From |
|---|---|
| `user` | The agent container's `runAsUser`, else the pod's, else the image config's `User`, where empty is root |
| `framework_identity` | The runtime-version variables in the image config's `Env` (NODE_VERSION, PYTHON_VERSION, ...) |
| `credential_provenance` | Each credential the agent gets: baked into the image (its config's `Env`) or injected at run time (the pod spec's `secretKeyRef`, a literal value, `envFrom`), by name |
| `in_layer_deleted_secrets` | Secret-looking files a layer adds and a later layer deletes: names, sizes and layer indexes, never content |

When the image can't be read, each field says why: with `--no-registry-access`
BLIND with NO_SOURCE_ACCESS; a private image, PRIVATE_STORE; and `user`
still answers from a `runAsUser`. Layers past `--layer-budget` give
`in_layer_deleted_secrets` PARTIAL with SIZE_CAP_EXCEEDED, keeping what the
layers read found; a layer that couldn't be read gives PARTIAL with its
reason, keeping what the layers before it found, so a failing last layer
can't hide a secret an earlier one deleted, and FAILED only when no layer
was read. An empty layer is an empty tar, as it is to containerd.

No env value reaches a field but the runtime-version variables'
(`framework_identity`), and those only when they read as a version (digits,
letters and `.+_~-`, at most 64 characters). A credential is a name (at most
256 characters), its kind and where it came from; an env value is read
only when it is URL-shaped and carries a credential, and is then given as
the scanner's `redact_url` leaves it. The image config's `User` is given only
when it reads as a user or `user:group` (at most 64 characters each).
Whatever an image holds past what a field lists (more than 256 credentials
or deleted files, a name too long) makes the field PARTIAL with
SIZE_CAP_EXCEEDED, so a list cut short never reads as the whole of it. A
Secret is never read: an `envFrom` of a whole Secret can't say which keys it
gives, so `credential_provenance` is PARTIAL naming the Secret.

The secret-name rules are the scanner's own (`looks_secret`,
`is_benign_secret_name`, `classify_secret_type`, `url_carries_credential`,
`redact_url`), handed in as `shapers`, so a credential means the same here as
in `credential_inventory`. The attribute builders are evidence_bundle's,
handed in as `b`; authored_by is added where the bundle is built (RC-555).

Like the other central_service modules, it uses only the standard library.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Iterable

# The image config's runtime-version variables, and how the sidecar names
# each runtime in framework_identity (agent_process.runtime_versions).
RUNTIME_ENV = {
    "NODE_VERSION": ("node", lambda v: "v" + v.lstrip("v")),
    "PYTHON_VERSION": ("python", lambda v: "Python " + v),
    "GOLANG_VERSION": ("go", lambda v: "go" + v.lstrip("go")),
    "JAVA_VERSION": ("java", lambda v: v),
    "RUBY_VERSION": ("ruby", lambda v: v),
    "YARN_VERSION": ("yarn", lambda v: v),
}
URL_SHAPED = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://\S+$")
MAX_LIST = 256
# What an image-controlled string must look like to reach a field: a version
# (NODE_VERSION=24.18.1), a user or user:group (node, 1000:1000), and a
# credential's name, which is listed only up to MAX_NAME characters.
VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_~-]{0,63}")
USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}(:[A-Za-z0-9_][A-Za-z0-9._-]{0,63})?")
MAX_NAME = 256

Builder = Callable[..., dict[str, Any]]


def _pod_fields() -> ModuleType:
    """pod_fields.py beside this file, for the agent container (RC-551)."""
    module = sys.modules.get("gke_scan_pod_fields")
    if module is None:
        spec = importlib.util.spec_from_file_location("gke_scan_pod_fields", Path(__file__).with_name("pod_fields.py"))
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules["gke_scan_pod_fields"] = module
        spec.loader.exec_module(module)
    return module


def _registry() -> ModuleType:
    module = sys.modules.get("gke_scan_registry")
    if module is None:
        spec = importlib.util.spec_from_file_location("gke_scan_registry", Path(__file__).with_name("registry.py"))
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules["gke_scan_registry"] = module
        spec.loader.exec_module(module)
    return module


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def agent_image_ref(pod: dict[str, Any]) -> Any:
    """The agent container's image as the kubelet pulled it (a registry.ImageRef), or None."""
    container, _ = _pod_fields().agent_container(pod)
    if container is None:
        return None
    for status in _list(_dict(pod.get("status")).get("containerStatuses")):
        if isinstance(status, dict) and status.get("name") == container.get("name"):
            return _registry().parse_image_id(status.get("imageID"))
    return None


def image_env(config: dict[str, Any] | None) -> dict[str, str]:
    """The image config's Env as a dict (a later entry wins, as at run time)."""
    env: dict[str, str] = {}
    for entry in _list(_dict(_dict(config).get("config")).get("Env")):
        if isinstance(entry, str) and "=" in entry:
            key, _, value = entry.partition("=")
            env[key] = value
    return env


def _unread(report: Any, registry_access: bool) -> tuple[str, str] | None:
    """(reason, note) when the image's config wasn't read, else None."""
    if not registry_access:
        return "NO_SOURCE_ACCESS", "--no-registry-access: the image isn't read"
    if report is None:
        return "NO_SOURCE_ACCESS", "the agent container reports no image digest yet"
    if report.config is None:
        error = report.config_error
        return (error.reason if error else "NO_SOURCE_ACCESS"), f"the image couldn't be read: {error}"
    return None


# ── user ────────────────────────────────────────────────────────────────────

def user_attribute(pod: dict[str, Any], report: Any, registry_access: bool, b: dict[str, Builder]) -> dict[str, Any]:
    """The container's runAsUser, then the pod's, then the image config's User."""
    container, _ = _pod_fields().agent_container(pod)
    spec = _dict(pod.get("spec"))
    for where, context in (("the agent container's securityContext.runAsUser", _dict(_dict(container).get("securityContext"))),
                           ("the pod's securityContext.runAsUser", _dict(spec.get("securityContext")))):
        uid = context.get("runAsUser")
        if isinstance(uid, int) and not isinstance(uid, bool):
            return b["answered"]("root" if uid == 0 else str(uid), "declared", method=where)
    unread = _unread(report, registry_access)
    if unread is not None:
        reason, note = unread
        return b["blind"](reason, "declared", note="no runAsUser in the pod spec, and " + note[0].lower() + note[1:])
    user = str(_dict(_dict(report.config).get("config")).get("User") or "")
    if user and not USER.fullmatch(user):
        return b["failed"]("PARSE_FAILED", "declared",
                           method=f"the image config's User at {report.manifest_digest or report.ref.digest}",
                           note="no runAsUser in the pod spec, and the image config's User isn't a user or "
                                "user:group (letters, digits and ._-, at most 64 characters each), so it isn't given")
    return b["answered"](user or "root", "declared",
                         method=f"the image config's User at {report.manifest_digest or report.ref.digest}",
                         note="no runAsUser in the pod spec; an empty User is root" if not user else
                              "no runAsUser in the pod spec")


# ── framework_identity ─────────────────────────────────────────────────────

def framework_identity_attribute(report: Any, registry_access: bool, b: dict[str, Builder]) -> dict[str, Any]:
    unread = _unread(report, registry_access)
    if unread is not None:
        return b["blind"](unread[0], "declared", note=unread[1])
    env = image_env(report.config)
    set_ = {key: env[key].strip() for key in RUNTIME_ENV if env.get(key, "").strip()}
    runtimes = {RUNTIME_ENV[key][0]: RUNTIME_ENV[key][1](value) for key, value in set_.items() if VERSION.fullmatch(value)}
    unreadable = sorted(key for key, value in set_.items() if not VERSION.fullmatch(value))
    method = "the runtime-version variables in the image config's Env"
    note = "the runtime versions the image declares; the framework build identity is not collected"
    if unreadable:
        note += (f"; {', '.join(unreadable)} isn't a version (digits, letters and .+_~-, at most 64 characters), "
                 "so it isn't given")
        return b["partial"](dict(sorted(runtimes.items())), "declared", "PARSE_FAILED", method=method, note=note)
    if not runtimes:
        return b["absent"](method + ": none set", "declared")
    return b["answered"](dict(sorted(runtimes.items())), "declared", method=method, note=note)


# ── credential_provenance ──────────────────────────────────────────────────

def _credential_url(value: str, shapers: dict[str, Callable[..., Any]]) -> str | None:
    """A URL-shaped value that carries a credential, as redact_url leaves it."""
    if URL_SHAPED.match(value.strip()) and shapers["url_carries_credential"](value.strip()):
        return shapers["redact_url"](value.strip())
    return None


def _is_credential(name: str, value: str, shapers: dict[str, Callable[..., Any]]) -> bool:
    return bool(shapers["looks_secret"](name)) and not shapers["is_benign_secret_name"](name, value)


def credential_provenance_attribute(pod: dict[str, Any], report: Any, registry_access: bool,
                                    b: dict[str, Builder], shapers: dict[str, Callable[..., Any]]) -> dict[str, Any]:
    container, _ = _pod_fields().agent_container(pod)
    if container is None:
        return b["blind"]("NO_SOURCE_ACCESS", "declared", note="no agent container to read")
    credentials: list[dict[str, Any]] = []
    unlisted: list[dict[str, Any]] = []
    injected_names = set()
    long_names = 0
    for var in _list(container.get("env")):
        if not isinstance(var, dict) or not isinstance(var.get("name"), str):
            continue
        name = var["name"]
        if len(name) > MAX_NAME:
            long_names += 1
            continue
        source = _dict(var.get("valueFrom"))
        entry: dict[str, Any] | None = None
        if isinstance(source.get("secretKeyRef"), dict):
            ref = source["secretKeyRef"]
            entry = {"source": {"secret": ref.get("name"), "key": ref.get("key")}}
        elif isinstance(source.get("configMapKeyRef"), dict) and shapers["looks_secret"](name):
            ref = source["configMapKeyRef"]
            entry = {"source": {"config_map": ref.get("name"), "key": ref.get("key")}}
        elif isinstance(var.get("value"), str):
            url = _credential_url(var["value"], shapers)
            if url is not None:
                entry = {"source": "the pod spec's value", "url": url}
            elif _is_credential(name, var["value"], shapers):
                entry = {"source": "the pod spec's value"}
        if entry is not None:
            injected_names.add(name)
            credentials.append({"name": name, "provenance": "injected", "type": shapers["classify_secret_type"](name),
                                **entry})
    for source in _list(container.get("envFrom")):
        if not isinstance(source, dict):
            continue
        for kind, key in (("secret", "secretRef"), ("config_map", "configMapRef")):
            ref = source.get(key)
            if isinstance(ref, dict) and ref.get("name"):
                unlisted.append({"kind": kind, "name": ref["name"],
                                 **({"prefix": source["prefix"]} if source.get("prefix") else {})})
    unread = _unread(report, registry_access)
    if unread is None:
        for name, value in sorted(image_env(report.config).items()):
            if len(name) > MAX_NAME:
                long_names += 1
                continue
            url = _credential_url(value, shapers)
            if url is None and not _is_credential(name, value, shapers):
                continue
            credentials.append({"name": name, "provenance": "baked", "type": shapers["classify_secret_type"](name),
                                "source": "the image config's Env", **({"url": url} if url else {}),
                                **({"overridden": True} if name in injected_names else {})})
    credentials.sort(key=lambda c: (c["name"], c["provenance"]))
    value = {"credentials": credentials[:MAX_LIST], "unlisted_sources": unlisted[:MAX_LIST]}
    method = "the agent container's env and envFrom, and the image config's Env, by name"
    notes = []
    secrets = [u["name"] for u in unlisted if u["kind"] == "secret"]
    if secrets:
        notes.append(f"envFrom gives every key of Secret {', '.join(secrets)}, which gke-scan doesn't read, "
                     "so those credentials aren't listed")
    # A list cut short never reads as the whole of it: an image can bake
    # decoys that sort ahead of a real credential.
    cut = []
    if _dict(_dict(getattr(report, "config", None)).get("config")).get("EnvTruncated"):
        cut.append("the image config's Env is longer than gke-scan keeps (1,024 entries, 128 KiB), "
                   "so what it bakes in past that isn't listed")
    if len(credentials) > MAX_LIST:
        cut.append(f"{len(credentials)} credentials, of which the first {MAX_LIST} by name are listed")
    if len(unlisted) > MAX_LIST:
        cut.append(f"{len(unlisted)} envFrom sources, of which the first {MAX_LIST} are listed")
    if long_names:
        cut.append(f"{long_names} names longer than {MAX_NAME} characters aren't listed")
    if unread is not None:
        notes.append(f"what the image bakes in isn't known: {unread[1]}")
        return b["partial"](value, "declared", unread[0], method=method, note="; ".join(notes + cut))
    if cut:
        return b["partial"](value, "declared", "SIZE_CAP_EXCEEDED", method=method, note="; ".join(notes + cut))
    if secrets:
        return b["partial"](value, "declared", "NO_SOURCE_ACCESS", method=method, note="; ".join(notes))
    return b["answered"](value, "declared", method=method,
                         **({} if credentials else {"note": "no credential is baked into the image or injected"}))


# ── in_layer_deleted_secrets ───────────────────────────────────────────────

def in_layer_deleted_secrets_attribute(report: Any, registry_access: bool, b: dict[str, Builder]) -> dict[str, Any]:
    unread = _unread(report, registry_access)
    if unread is not None:
        return b["blind"](unread[0], "observed", note=unread[1])
    value = {"layers": report.layers, "layers_read": report.layers_read, "deleted": report.deleted[:MAX_LIST]}
    method = (f"each layer of {report.manifest_digest or report.ref.digest} streamed in order: a secret-looking "
              "file a layer adds that a later layer deletes; names, sizes and layer indexes, never content")
    error = report.layers_error
    total = max(report.deleted_total, len(report.deleted))
    cut = (f"{total} secret-looking files are added and later deleted, of which the first {MAX_LIST} are listed"
           if total > MAX_LIST else None)
    if error is None and cut is None:
        return b["answered"](value, "observed", method=method,
                             **({} if report.deleted else {"note": "no secret-looking file is added and later deleted"}))
    if error is None:
        return b["partial"](value, "observed", "SIZE_CAP_EXCEEDED", method=method, note=cut)
    if error.reason == "SIZE_CAP_EXCEEDED" or report.layers_read or report.deleted:
        # What the layers read show is kept, whatever stopped the next one: a
        # later layer that fails can't hide a secret an earlier one deleted.
        note = (f"{error.detail}; what layers 0 to {report.layers_read - 1} show is listed"
                if report.layers_read else error.detail)
        return b["partial"](value, "observed", error.reason, method=method,
                            note=f"{note}; {cut}" if cut else note)
    return b["failed"](error.reason, "observed", method=method,
                       note=f"layer {report.layers_read} couldn't be read: {error.detail}")


def image_field_attributes(pod: dict[str, Any], report: Any, registry_access: bool, b: dict[str, Builder],
                           shapers: dict[str, Callable[..., Any]]) -> dict[str, dict[str, Any]]:
    """The four image fields for one pod and the report of its image (None
    when it wasn't read). `b` needs answered, partial, blind, absent and failed."""
    return {
        "user": user_attribute(pod, report, registry_access, b),
        "framework_identity": framework_identity_attribute(report, registry_access, b),
        "credential_provenance": credential_provenance_attribute(pod, report, registry_access, b, shapers),
        "in_layer_deleted_secrets": in_layer_deleted_secrets_attribute(report, registry_access, b),
    }


def read_agent_image(reader: Any, pod: dict[str, Any], registry_access: bool, os: str = "linux",
                     arch: str = "amd64") -> Any:
    """The report of the pod's agent image, or None when it isn't read
    (`--no-registry-access`, or no digest yet)."""
    if not registry_access:
        return None
    ref = agent_image_ref(pod)
    return reader.read_image(ref, os, arch) if ref is not None else None
