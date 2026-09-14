#!/usr/bin/env python3
"""The v1 evidence bundle: the artifact, the closed sets, and the check that keeps them.

The bundle is the standalone input to the profile brain (the DR-107 shape,
published in Confluence "Evidence Bundle Reason Codes" / "Agent Attribute
Availability"): one attribute per collected signal, each carrying status,
tier, authored_by and a reason for whatever it did not answer. The envelope
names the container it was collected from with the host_id / sandbox_name
pair - the same pair the scan registers it under (RC-318). It carries no
registration id: the control plane files the bundle by pair lookup, and the closed sets below are
mirrored from that published contract; `verify_bundle` is this module's check
of an emitted bundle - the guard a guard needs, so a broken bundle is a
ScannerError rather than a file a scorer reads.

Import direction: mutual and deliberately lazy on both sides, so the closed
sets have one home here. The scanner imports this module inside its `finally`
block; this module imports the scanner inside the few functions that need it
(`verify_bundle`, `_redact_harness_values`, `build_evidence_bundle`,
`write_evidence_bundle`) - the function-local imports are what break the
cycle. The builder is therefore not a pure transform of pre-computed inputs:
it calls the scanner's own collectors and classifiers, which is what keeps a
signal's meaning identical on both paths. Everything else it needs is passed
in, which is why a test can build and verify a bundle without a container, a
network or a clone of the consumer.
"""

from __future__ import annotations

import json
import os
import re
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── closed sets ─────────────────────────────────────────────────────────────
# Mirrored, not re-derived, from the published contract: Confluence
# "Evidence Bundle Reason Codes" (the 13-code enum) and DR-107. A divergence
# between the two is a bug, not a choice — update both sides of the mirror
# (the consumer's `contract_problems` is the other half).
STATUSES = frozenset({"ANSWERED", "ABSENT", "TEMPLATED", "PARTIAL", "BLIND", "FAILED"})
REASONS = frozenset(
    {
        "NO_SOURCE_ACCESS",
        "NOT_FIRST_PARTY",
        "SOURCE_OK_NOT_PRESENT",
        "UNKNOWN_HARNESS",
        "NOT_COLLECTED_BY_PACK",
        "PRIVATE_STORE",
        "CODE_CONSTRUCTED",
        "GATEWAY_MANAGED",
        "ORCHESTRATOR_MANAGED",
        "PROVIDER_HOSTED",
        "TEMPLATE_UNRESOLVED",
        "PARSE_FAILED",
        "SIZE_CAP_EXCEEDED",
    }
)
TIERS = frozenset({"declared", "interrogated", "observed"})
AUTHORED_BY = frozenset({"subject", "platform", "external", "none"})
# Mirrored from the published schema's maxLength, which is what the consumer
# validates against; the scanner truncates to the same numbers.
HOST_ID_MAX = 64
SANDBOX_NAME_MAX = 255

# The shared version is 1: Eason reset the mock's 2 back to 1, because the
# first version was never published ("let's call this version version 1").
BUNDLE_VERSION = 1
# Ours, not the consumer's: the consumer's mock numbers its own packs; pack 1
# is this collector's attribute set, and x-rail-spec's additions-version rule
# applies when the set grows.
RULE_PACK_VERSION = 1

# The keys whose presence in a harness config counts as a declared permission
# / approval setting, under their common case. `model`, `mcpServers` and
# friends are deliberately absent: the value the containment category reads
# is the permission and approval configuration, and nothing else in the file
# is one.
PERMISSION_KEY_ALIASES = frozenset(
    {
        "permissions",
        "permission",
        "approval_policy",
        "approvalpolicy",
        "approval",
        "security",
        "securityopt",
        "security_opts",
        "sandbox_network_policy",
        "allowtools",
        "denytools",
        "allow_tools",
        "deny_tools",
    }
)

# Labels that identify a deployment. The compose project/service pair is a
# deployment name exactly; K8s pod labels do not reach Config.Labels, and
# the image name alone is not a candidate - two agents can share an image.
DEPLOYMENT_LABEL_KEYS = frozenset(
    {
        "com.docker.compose.project",
        "com.docker.compose.service",
    }
)

# Credential-carrying value shapes: a DSN/URL embedding user:pass@ and a
# base64 Basic-auth header. Caught on the value alone, independent of the key
# name, because the marker-key check misses keys with no marker (a key named
# "auth" under "security", a "DATABASE_URL" that carries no marker). Both
# shapes can never be a legitimate declarative value: a harness permission
# block is allow/deny/approval-shaped, never a connection string or an
# encoded credential.
# Either side of the colon may be empty: `redis://:hunter2@…` (empty user,
# real password) and `postgres://admin:@…` (real user, empty password) are
# both credentials, and the original both-sides-required form missed them.
# A bare userinfo with no colon (`https://token@api.internal/v1`) is a token
# in the user position, also impossible in a declarative block.
_DSN_WITH_CREDENTIALS = re.compile(
    r"^[a-z][a-z0-9+.\-]*://[^/?#\s:@]*:[^/?#\s@]*@", re.IGNORECASE
)
_URL_USERINFO_WITHOUT_PASSWORD = re.compile(
    r"^[a-z][a-z0-9+.\-]*://[^/?#\s:@]+@", re.IGNORECASE
)
_BASIC_AUTH_HEADER = re.compile(r"^basic\s+[a-z0-9+/=]+$", re.IGNORECASE)


def _credential_carrying_value(value: Any) -> bool:
    """True when the value's shape carries credentials regardless of key.

    Three shapes, none legitimate in a declarative permission block:
    - a URL/DSN embedding userinfo with a password (postgres://user:pass@…,
      including the empty-user and empty-password forms),
    - a URL embedding a bare token as userinfo (https://token@…),
    - a base64-encoded Basic auth header.
    """
    if not isinstance(value, str):
        return False
    return bool(
        _DSN_WITH_CREDENTIALS.match(value)
        or _URL_USERINFO_WITHOUT_PASSWORD.match(value)
        or _BASIC_AUTH_HEADER.match(value)
    )


# ── the contract check ──────────────────────────────────────────────────────


# The envelope the published schema closes: exactly these keys, plus the
# optional attestations array. `inputs_attempted` always holds exactly the
# four sources, and an attribute holds exactly the fields below.
ENVELOPE_KEYS = (
    "bundle_version",
    "bundle_id",
    "host_id",
    "sandbox_name",
    "collected_at",
    "rule_pack_version",
    "inputs_attempted",
    "attributes",
)
OPTIONAL_ENVELOPE_KEYS = ("attestations",)
INPUT_SOURCES = ("runtime", "image", "manifest", "repo")
SOURCE_FIELDS = frozenset({"attempted", "reached", "reason", "window_seconds"})
ATTRIBUTE_FIELDS = frozenset(
    {"value", "status", "reason", "tier", "authored_by", "method", "note", "attestation_ref"}
)
# The statuses that carry authored_by, and the ones the schema forbids it on.
AUTHORED_STATUSES = ("ANSWERED", "PARTIAL", "TEMPLATED")
UNAUTHORED_STATUSES = ("ABSENT", "BLIND", "FAILED")


def _envelope_problems(bundle: dict[str, Any]) -> list[str]:
    """The envelope's required keys, its closed set, and the naming pair.

    The pair is not optional in the schema, so a bundle carries no `None`
    here: a scan that could not derive one is a problem the caller reports,
    never a bundle the control plane has to guess an owner for.
    """
    problems: list[str] = []
    for key in ENVELOPE_KEYS:
        if key not in bundle:
            problems.append(f"{key}: required envelope field is missing")
    for key in bundle:
        if key not in ENVELOPE_KEYS and key not in OPTIONAL_ENVELOPE_KEYS:
            problems.append(f"{key}: not a field of the envelope")
    if bundle.get("bundle_version") != BUNDLE_VERSION:
        problems.append(f"bundle_version: {bundle.get('bundle_version')!r} is not {BUNDLE_VERSION}")
    for key, limit in (("host_id", HOST_ID_MAX), ("sandbox_name", SANDBOX_NAME_MAX)):
        value = bundle.get(key)
        if not isinstance(value, str) or not value.strip():
            problems.append(f"{key}: must be a non-empty string, not {value!r}")
        elif len(value) > limit:
            problems.append(f"{key}: {len(value)} characters is past the {limit} cap")
    return problems


def _source_problems(sources: Any) -> list[str]:
    """The four sources, and the reachable reason rules."""
    problems: list[str] = []
    if not isinstance(sources, dict):
        return ["inputs_attempted: not an object"]
    for src in INPUT_SOURCES:
        if src not in sources:
            problems.append(f"inputs_attempted.{src}: source is missing")
    for src, entry in sources.items():
        if src not in INPUT_SOURCES:
            problems.append(f"inputs_attempted.{src}: not one of the four sources")
            continue
        if not isinstance(entry, dict):
            problems.append(f"inputs_attempted.{src}: entry is not an object")
            continue
        for key in entry:
            if key not in SOURCE_FIELDS:
                problems.append(f"inputs_attempted.{src}: {key!r} is not a field of a source")
        if not isinstance(entry.get("attempted"), bool):
            problems.append(f"inputs_attempted.{src}: attempted must be a boolean")
        if entry.get("reason") not in (None, *REASONS):
            problems.append(f"inputs_attempted.{src}: unknown reason {entry.get('reason')!r}")
        if entry.get("attempted") and "reached" not in entry:
            problems.append(f"inputs_attempted.{src}: attempted without reached")
        if entry.get("attempted") is False and not entry.get("reason"):
            problems.append(f"inputs_attempted.{src}: not attempted without a reason")
        if entry.get("reached") is False and not entry.get("reason"):
            problems.append(f"inputs_attempted.{src}: not reached without a reason")
        if "window_seconds" in entry and src != "runtime":
            problems.append(f"inputs_attempted.{src}: window_seconds is only on runtime")
    return problems


def contract_problems(bundle: dict[str, Any]) -> list[str]:
    """Everything in a bundle the published v1 schema would reject.

    The schema's rules, in code: the envelope's required keys and closed set,
    the four sources with a reason whenever one was not attempted or not
    reached, and each attribute's closed sets, method-on-ABSENT and
    authored_by placement. It is the whole contract, not the consumer's
    lenient load gate, on purpose: `verify_bundle` is the guard that keeps a
    broken bundle from reaching a scorer, and a check that passes what the
    consumer rejects is worse than none. The one rule the schema cannot
    express - every attestation_ref names an attestation - is checked here.
    """
    problems = _envelope_problems(bundle)
    problems += _source_problems(bundle.get("inputs_attempted"))
    attestations = {a.get("id") for a in (bundle.get("attestations") or [])}
    for name, f in (bundle.get("attributes") or {}).items():
        where = f"attributes.{name}"
        if not isinstance(f, dict):
            problems.append(f"{where}: not an object")
            continue
        for key in f:
            if key not in ATTRIBUTE_FIELDS:
                problems.append(f"{where}: {key!r} is not a field of an attribute")
        if "value" not in f:
            problems.append(f"{where}: value is required")
        status = f.get("status")
        if status not in STATUSES:
            problems.append(f"{where}: unknown status {status!r}")
        if f.get("reason") not in (None, *REASONS):
            problems.append(f"{where}: unknown reason {f.get('reason')!r}")
        if f.get("tier") not in TIERS:
            problems.append(f"{where}: unknown tier {f.get('tier')!r}")
        if f.get("authored_by") not in (None, *AUTHORED_BY):
            problems.append(f"{where}: unknown authored_by {f.get('authored_by')!r}")
        # A "we looked and it is not there" claim is only as good as where it
        # looked; a blind or errored one has to say why it could not answer.
        if status == "ABSENT" and not f.get("method"):
            problems.append(f"{where}: ABSENT without method")
        if status in ("BLIND", "FAILED") and not f.get("reason"):
            problems.append(f"{where}: {status} without reason")
        if status == "ANSWERED" and f.get("reason"):
            problems.append(f"{where}: ANSWERED carries a reason")
        # authored_by describes a value, so it is stated exactly when there is
        # one to attribute, and nowhere else.
        if status in AUTHORED_STATUSES and not f.get("authored_by"):
            problems.append(f"{where}: {status} without authored_by")
        if status in UNAUTHORED_STATUSES and "authored_by" in f:
            problems.append(f"{where}: {status} is not an authored value")
        if f.get("attestation_ref") not in (None, *attestations):
            problems.append(f"{where}: attestation_ref {f.get('attestation_ref')!r} points at nothing")
    return problems


def verify_bundle(bundle: dict[str, Any]) -> None:
    """The guard with teeth: an emitted bundle that breaks its own contract
    is a ScannerError, not a file on disk. Every write goes through this."""
    problems = contract_problems(bundle)
    if problems:
        from scan_agent_environment import ScannerError  # lazy: no cycle at load

        raise ScannerError(f"evidence bundle failed its contract: {problems[:5]}")


# ── field builders ──────────────────────────────────────────────────────────


def _answered(value: Any, tier: str, **extra: Any) -> dict[str, Any]:
    field: dict[str, Any] = {"value": value, "status": "ANSWERED", "tier": tier}
    field.update(extra)
    return field


def _absent(method: str, tier: str, **extra: Any) -> dict[str, Any]:
    field: dict[str, Any] = {"value": None, "status": "ABSENT", "tier": tier, "method": method}
    field.update(extra)
    return field


def _blind(reason: str, tier: str, **extra: Any) -> dict[str, Any]:
    field: dict[str, Any] = {"value": None, "status": "BLIND", "reason": reason, "tier": tier}
    field.update(extra)
    return field

def _partial(value: Any, tier: str, reason: str, **extra: Any) -> dict[str, Any]:
    field: dict[str, Any] = {
        "value": value,
        "status": "PARTIAL",
        "tier": tier,
        "reason": reason,
    }
    field.update(extra)
    return field


def _source(attempted: bool, reached: bool, reason: str) -> dict[str, Any]:
    """One `inputs_attempted` entry, with `reached` and a `reason` exactly
    where the schema wants them: `reached` on anything attempted, and the
    reason whenever the source was not attempted or not reached."""
    entry: dict[str, Any] = {"attempted": attempted}
    if attempted:
        entry["reached"] = reached
    if not attempted or not reached:
        entry["reason"] = reason
    return entry


def _failure_note(failures: dict[str, str]) -> str:
    """One line per unreadable config file; the status's reason is the worst of them."""
    if not failures:
        return ""
    parts = []
    for path, reason in sorted(failures.items()):
        if reason == "NO_SOURCE_ACCESS":
            parts.append(f"{Path(path).name} is not readable")
        elif reason == "SIZE_CAP_EXCEEDED":
            parts.append(f"{Path(path).name} exceeds the 64KB read cap")
        else:
            parts.append(f"{Path(path).name} is not valid JSON")
    return "some config files were not read: " + "; ".join(parts)


def _worst_failure_reason(failures: dict[str, str]) -> str:
    """The worst closed-set reason among several; names the attribute's floor."""
    return max(
        failures.values(),
        key=lambda r: FAILURE_SEVERITY.get(r, 0),
    )


def _permission_keys(data: Any, found: dict[str, Any]) -> None:
    """Permission-shaped keys, found at any depth, under their original case.

    Everything else in the file — models, endpoints, skills — is not a
    permission and is left out of the value: it would read as a permission
    that does not exist.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() in PERMISSION_KEY_ALIASES:
                found[key] = value
            else:
                _permission_keys(value, found)
    elif isinstance(data, list):
        for item in data:
            _permission_keys(item, found)


# The shape sets a captured permission block is judged against: what counts
# as a declared approval gate vs. a declared tool allow/deny. Named once,
# shared by the two attributes, so the two cannot drift apart.
_APPROVAL_SHAPES = ("approval",)
_ALLOW_DENY_SHAPES = ("allow", "deny", "security", "permission")


def _block_shaped(block_key: str, value: Any, shapes: tuple[str, ...]) -> bool:
    """Whether a captured permission block is shaped material for `shapes`.

    Judging on the outer key name alone misses the dominant shape: a
    "permissions" block carrying its allow/deny lists nested. The block
    counts when its own key says so, or when a nested key says so — one level
    in, including under a list of blocks.

    `block_key` must be the block's own key, never the `<source>:<key>` form
    the captured value is stored under: the source filename is not part of the
    block, and letting it in would make every permission block in
    `permissions.json` match the allow/deny shapes regardless of its content.
    """
    if any(tok in block_key.lower() for tok in shapes):
        return True
    blocks = value if isinstance(value, list) else [value]
    for block in blocks:
        if not isinstance(block, dict):
            continue
        for nested in block:
            if any(tok in str(nested).lower() for tok in shapes):
                return True
    return False


def read_harness_permission_config(
    config_paths: list[Path], named: set[str] | None = None
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Permission-shaped keys, read out of the harness config files.

    Returns `({str(file): {key: value}}, failures)`, keyed by the file
    actually read: a file root by its own path, a directory root by each
    `*.json` child it holds - mirroring the scanner's
    `find_models_in_openclaw_config`, which is what a `--config-path`
    directory means on the model-detection side. The second return is
    `{str(file): reason}` for the files we looked at and could not turn
    into a value: a missing or unreadable file records NO_SOURCE_ACCESS and
    a file that does not parse records PARSE_FAILED. The builder turns that
    set into the attribute's status - a PARTIAL when some of it was read
    and some failed, a BLIND when nothing was - with the reasons in the
    note, so a failure is evidence of where it failed, not a silent
    "nothing there".
    """
    named = named or set()
    found: dict[str, dict[str, Any]] = {}
    failures: dict[str, str] = {}
    for path in config_paths:
        if path.is_dir():
            for file in sorted(path.glob("*.json")):
                _read_permission_file(file, found, failures)
        elif path.exists():
            _read_permission_file(path, found, failures)
        elif str(path) in named:
            failures[str(path)] = "NO_SOURCE_ACCESS"
    return found, failures


def _read_permission_file(
    file: Path, found: dict[str, dict[str, Any]], failures: dict[str, str]
) -> None:
    """One config file into `found`; its closed-set failure reason into `failures`."""
    data, reason = _read_json_capped(file)
    if reason:
        failures[str(file)] = reason
        return
    if not isinstance(data, dict):
        # A parseable file that is not an object (a JSON `null`, a bare list
        # or scalar) holds no permission keys; that is not a read failure.
        return
    keys: dict[str, Any] = {}
    _permission_keys(data, keys)
    if keys:
        found[str(file)] = keys


def _redact_harness_values(value: Any, key: str | None = None) -> Any:
    """Credentials that could ride along in a declared permission block.

    The harness config is the agent's own file, and the security block next
    to a `permissions` block is where an operator pastes the key. The
    scanner's own classifier is the single source of what counts as secret
    material: a value under a key the scanner names as secret, a string in
    a vendor token shape, or a string in a credential-carrying value shape
    (a DSN/URL embedding user:pass@, a base64 Basic-auth header) - the last
    two caught on the value alone, because an operator's DSN or auth header
    sits under a key with no marker. A key the scanner names secret is
    never carried - not even plainly-shaped - the same call the env scanner
    makes when it reports the class of a variable and not its value. A
    reference (a vault pointer) stays: what the profile should see is that
    the security block points somewhere, and where.
    """
    import scan_agent_environment as scanner  # the classifier is the scanner's

    if isinstance(value, dict):
        return {child: _redact_harness_values(item, child) for child, item in value.items()}
    if isinstance(value, list):
        return [_redact_harness_values(item, key) for item in value]
    if isinstance(value, str):
        if (
            scanner.is_secret_token(value)
            or (key is not None and scanner.looks_secret(key))
            or _credential_carrying_value(value)
        ):
            return "[redacted]"
    return value


def _read_json_capped(path: Path) -> tuple[Any, str]:
    """Parse a config file under the scanner's 64KB read cap, classifying failure.

    Returns `(data, reason)`: on success `reason` is `""`; on failure `data`
    is None and `reason` is the closed-set code for what failed —
    NO_SOURCE_ACCESS for a file that cannot be read, SIZE_CAP_EXCEEDED for a
    read truncated at the cap whose tail no longer parses, and PARSE_FAILED
    for a read that parsed nothing. The scanner's own `load_json_file` reads
    with this same cap; the classification is what the caller's note names,
    so "we looked" says what it actually found.
    """
    try:
        with path.open("rb") as f:
            raw = f.read(64_000)
        text = raw.decode("utf-8", errors="replace")
    except OSError:
        return None, "NO_SOURCE_ACCESS"
    try:
        return json.loads(text), ""
    except json.JSONDecodeError:
        if len(raw) == 64_000:
            return None, "SIZE_CAP_EXCEEDED"
        return None, "PARSE_FAILED"
    except RecursionError:
        # Deeply nested but under the cap: the reader raises, the document
        # never parses. It is a parse failure like any other, and catching it
        # here keeps it inside the writer's report-failure-don't-raise path.
        return None, "PARSE_FAILED"


# The closed-set reason codes' severity, for the builder's floor: when one
# attribute carries several failure reasons, the worst one names the
# attribute; the rest still ride in the note.
FAILURE_SEVERITY = {"NO_SOURCE_ACCESS": 0, "PARSE_FAILED": 1, "SIZE_CAP_EXCEEDED": 2}


# ── the builder ──────────────────────────────────────────────────────────────


def build_evidence_bundle(
    args: Any,
    context: dict[str, Any],
    payload: dict[str, Any],
    identity: dict[str, Any],
) -> dict[str, Any]:
    """Assemble the v1 bundle from the scanner's already-computed sources.

    Every status chosen below is one the consumer can judge — UNUSABLE is
    only {BLIND, FAILED}, so a PARTIAL with a floor, or an ABSENT that names
    where it looked, is evidence, not a hole. Honesty over completeness: an
    attribute this pack cannot collect is emitted BLIND with the reason why,
    never an empty ANSWERED that reads as "none exists".
    """
    import scan_agent_environment as scanner  # lazy: breaks the import cycle

    env = context["env"]
    mode = context["mode"]
    docker = context.get("docker_inspect") or {} if mode == "docker" else {}
    host_config = docker.get("HostConfig") or {}
    environment = payload.get("environment") or {}
    system_info = environment.get("system_info") or {}
    egress = scanner.collect_model_egress(env)
    base_url = egress.get("base_url")
    egress_host = scanner.url_host(base_url) if base_url else None
    mcp: list[dict[str, Any]] = identity.get("mcp_servers") or []
    reach: dict[str, Any] = identity.get("observed_reach") or {}
    # ── inputs_attempted: the sources, and whether each was reached ──────
    raw_named = getattr(args, "config_path", []) or []
    config_paths = [Path(p).expanduser() for p in raw_named] \
        or scanner.default_config_paths(env)
    # Roots the operator named are a promise: one that does not exist is a
    # failure the bundle names, unlike the pack's own default directory
    # guesses, whose absence is just "we looked and nothing was there". The
    # set holds the same expansion the reader compares against.
    named = {str(Path(p).expanduser()) for p in raw_named}
    mcp_paths = [Path(p).expanduser() for p in (getattr(args, "mcp_config", []) or [])] \
        or scanner.default_mcp_paths(env)
    scanned_roots = list(dict.fromkeys([str(p) for p in mcp_paths] + [str(p) for p in config_paths]))

    # The object is closed to runtime / image / manifest / repo. An entry holds
    # `reached` whenever it was attempted and a closed-set `reason` whenever it
    # was not attempted or not reached; the free-text `method` that used to ride
    # here has no home in the schema - what was looked at belongs to the
    # attribute that makes the claim, not to the source. A source has no
    # "reached but empty" spelling, so an empty source is simply reached: the
    # detail of what it held is the attribute's to state.
    #
    # Read the roots once, here, because the manifest source's reason and the
    # permissions attribute below both need the same result.
    found, failures = read_harness_permission_config(config_paths, named)
    inputs: dict[str, Any] = {
        # We are the runtime observation source when the scan happens inside the
        # runtime; a docker-mode scan reads its container, not itself, so its
        # runtime source is the wire - and this pack ships without a tap.
        "runtime": _source(True, mode == "self" or bool(reach), "NO_SOURCE_ACCESS"),
        # A root the operator named and we could not read is the failure the
        # permissions attribute names precisely; any failure means this source
        # was not fully reached, so the source's reason is the worst of them.
        "manifest": _source(
            True,
            not failures,
            _worst_failure_reason(failures) if failures else "NO_SOURCE_ACCESS",
        ),
        "image": (
            _source(True, bool(docker.get("Image") or docker.get("Id")), "NO_SOURCE_ACCESS")
            if mode == "docker"
            else _source(False, False, "NO_SOURCE_ACCESS")
        ),
        "repo": _source(False, False, "NOT_FIRST_PARTY"),
    }

    attributes: dict[str, Any] = {}

    # ── identity (RC-318: the container pair, not a registration id) ────
    host_id = (payload.get("host_id") or "").strip() or None
    sandbox_name = (payload.get("sandbox_name") or "").strip() or None
    if host_id or sandbox_name:
        attributes["container_identity"] = _answered(
            {"host_id": host_id, "sandbox_name": sandbox_name},
            "declared",
            authored_by="platform",
            method=(f"host_id: {identity.get('host_id_source', 'unset')}; "
                    f"sandbox_name: {identity.get('sandbox_name_source', 'unset')}"),
            note="the pair rail-center files the bundle under; a registration id, "
                 "when one exists, is the control plane's own record of this pair",
        )
    else:
        attributes["container_identity"] = _absent(
            "detection ran; all sources unset", "declared",
            note="no host_id or sandbox_name could be derived from flag, env, label or name",
        )

    image_id = docker.get("Image") if mode == "docker" else None
    if isinstance(image_id, str) and image_id.startswith("sha256:"):
        attributes["image_digest"] = _answered(image_id, "observed", authored_by="none",
                                               method="docker inspect: the image identity")
    elif isinstance(image_id, str):
        attributes["image_digest"] = _blind(
            "NO_SOURCE_ACCESS", "observed",
            note=f"the image name only ({image_id}); the digest is held by the registry, "
                 "which this pack does not pull",
        )
    else:
        attributes["image_digest"] = _blind("NO_SOURCE_ACCESS", "observed",
                                            note="no image layer access in this mode")

    runtimes: dict[str, Any] = system_info.get("runtimes") or {}
    openclaw_version = runtimes.get("openclaw")
    if openclaw_version:
        attributes["harness_identity"] = _answered(
            f"openclaw/{openclaw_version}", "declared", authored_by="subject",
            method="openclaw --version in the runtime",
            note="declared: the harness answers for itself, and the version is a claim until the runtime proves it",
        )
    else:
        attributes["harness_identity"] = _blind(
            "UNKNOWN_HARNESS", "declared",
            note="no versioned harness in the runtime; the version is an interrogation this pack does not make",
        )

    if runtimes:
        attributes["framework_identity"] = _answered(
            {name: str(version) for name, version in sorted(runtimes.items())}, "observed",
            authored_by="subject",
            method="the runtime versions the harness reports for itself",
            note="the runtime versions observed; the framework build identity is not collected",
        )
    else:
        attributes["framework_identity"] = _blind("NOT_COLLECTED_BY_PACK", "declared")

    llm_model = str(environment.get("llm_model") or "").strip()
    if llm_model and llm_model != "unknown":
        # The agent's own env or config is the agent's to write, so a name read
        # there is subject; a name recovered from a captured session was measured
        # off the wire, so none.
        model_source = system_info.get("model_source")
        attributes["model_name"] = _answered(
            llm_model, "observed",
            authored_by="none" if model_source == "capture_file" else "subject",
            method=f"model detection source: {model_source or 'unset'}",
            note="the model name as configured; observed, not declared",
        )
    else:
        attributes["model_name"] = _absent("model not detected in env, config or capture files", "observed")

    if base_url:
        attributes["inference_endpoint"] = _answered(
            base_url, "observed", authored_by="subject",
            method="the base URL the scanned environment declares",
            note="the one hop the model calls go to; where prompts go past this hop is not established by this bundle",
        )
    else:
        attributes["inference_endpoint"] = _absent("no base URL in the env", "observed")

    # ── tool and MCP reach ────────────────────────────────────────────────
    if mcp:
        attributes["mcp_servers_declared"] = _answered(
            mcp, "declared", authored_by="subject", method="MCP config parsed for mcpServers",
        )
    elif base_url:
        attributes["mcp_servers_declared"] = _blind(
            "GATEWAY_MANAGED", "declared",
            method="MCP config holds one gateway URL only",
            note="the gateway holds the server list, not this agent — the lower bound is >= 1, not 0",
        )
    else:
        attributes["mcp_servers_declared"] = _absent(
            "scanned " + (", ".join(scanned_roots) or "no MCP config roots"), "declared",
            note="no MCP config found at the scanned roots",
        )

    if reach:
        attributes["mcp_servers_observed"] = _blind(
            "NOT_COLLECTED_BY_PACK", "observed",
            note="MCP session-level observation is a separate collection; the AgentSight snapshot carries reach, not sessions",
        )
    else:
        attributes["mcp_servers_observed"] = _blind(
            "NOT_COLLECTED_BY_PACK", "observed",
            note="no AgentSight snapshot was provided to this scan",
        )

    tools_used = sorted(reach.get("tools_used") or [])
    if reach:
        attributes["tool_names"] = (
            _answered(tools_used, "observed", authored_by="none",
                      note="floor, not a count — tools not exercised in the window are absent here")
            if tools_used
            else _absent("the snapshot carried no tool calls in the window", "observed")
        )
    else:
        attributes["tool_names"] = _blind(
            "NOT_COLLECTED_BY_PACK", "observed",
            note="wire observation requires an AgentSight snapshot; this pack ships without one",
        )

    declared_hosts = sorted(
        {host for host in (scanner.url_host(s.get("url")) for s in mcp if s.get("url")) if host}
        | ({egress_host} if egress_host else set())
    )
    if mcp or base_url:
        attributes["declared_destinations"] = _answered(
            declared_hosts, "declared", authored_by="subject",
            method="hosts from the MCP server URLs and the model egress base URL",
        )
    else:
        attributes["declared_destinations"] = _absent("no declared hosts in the MCP config or env", "declared")

    if reach:
        attributes["observed_destinations"] = _answered(
            reach.get("destinations") or [], "observed", authored_by="none",
            method="AgentSight snapshot, names and counts only",
            note="a finite window; destinations unseen in it are not destinations that do not exist",
        )
    else:
        attributes["observed_destinations"] = _absent("no AgentSight snapshot was provided to this scan", "observed")

    if reach:
        undeclared = sorted(set(reach.get("undeclared_destinations") or []))
        attributes["undeclared_destinations"] = (
            _answered(undeclared, "observed", authored_by="none",
                      method="observed hosts minus declared hosts")
            if undeclared
            else _absent("no observed host fell outside the declared set", "observed")
        )
    else:
        attributes["undeclared_destinations"] = _blind(
            "NOT_COLLECTED_BY_PACK", "declared",
            note="NOT COMPUTABLE — needs declared AND observed; observed is blind without a snapshot",
        )

    # ── credentials ───────────────────────────────────────────────────────
    secrets = scanner.collect_secret_hygiene(
        env,
        scanner.container_path_checker(str(context["container_name"])) if mode == "docker" else None,
    )
    attributes["credential_inventory"] = (
        _answered(
            [{"name": s["key"], "class": s["secret_class"], "type": s["secret_type"]} for s in secrets],
            "observed", authored_by="none",
            note="name + class + type only; values never collected",
        )
        if secrets
        else _answered([], "observed", authored_by="none",
                       method="env scan; no secret-looking variables",
                       note="an empty list that means 'none', not 'unobserved'")
    )
    attributes["credential_provenance"] = _blind(
        "NOT_COLLECTED_BY_PACK", "declared",
        note="injected-vs-baked provenance needs image layer analysis; this pack does not have layer access",
    )
    attributes["in_layer_deleted_secrets"] = _blind(
        "NO_SOURCE_ACCESS", "observed",
        note="deleted-secret detection reads registry image layers, which this pack does not pull",
    )
    attributes["tool_capability_envelope"] = _blind(
        "NO_SOURCE_ACCESS", "declared",
        note="repo AST only; untaken branches are unknowable here",
    )

    # ── containment: mounts, user, permissions ───────────────────────────
    mounts: list[dict[str, Any]] = []
    for bind in host_config.get("Binds") or []:
        parts = str(bind).split(":", 2)
        mounts.append(
            {
                "source": parts[0] if parts[0] else None,
                "target": parts[1] if len(parts) > 1 else None,
                "mode": parts[2] if len(parts) > 2 else "rw",
            }
        )
    for volume in host_config.get("Volumes") or []:
        mounts.append({"source": None, "target": str(volume), "mode": "rw"})
    if mounts:
        attributes["mounts"] = _answered(mounts, "declared", authored_by="none",
                                         method="docker inspect: HostConfig binds and volumes")
    else:
        attributes["mounts"] = (
            _answered([], "declared", authored_by="none", method="docker inspect: HostConfig",
                      note="no bind or volume mounts declared")
            if mode == "docker"
            else _blind("NO_SOURCE_ACCESS", "declared",
                        note="the container mount layout is not observable from a bare process")
        )

    if mode == "docker":
        user = host_config.get("User") or "root"
        attributes["user"] = _answered(
            user, "observed", authored_by="none", method="docker inspect: HostConfig.User",
            note="root is the docker default when User is unset",
        )
    else:
        attributes["user"] = _blind(
            "NOT_COLLECTED_BY_PACK", "observed",
            note="the process user is not reported by this pack; the uid is in the scan's "
                 "user_info field, the sibling feature file",
        )

    # ── deployment: the signal that groups copies of the same agent ─────
    # What RailMon can see: operator-set labels the runtime carries on the
    # container. In the compose world the project/service pair is the
    # deployment name exactly. On K8s the pod labels do not reach
    # Config.Labels, so the attribute stays ABSENT until an operator sets
    # a label this pack can read; the image name is not a candidate - two
    # agents can share an image.
    if mode == "docker":
        labels = scanner.container_labels(context)
        deployment_labels = {k: v for k, v in labels.items() if k in DEPLOYMENT_LABEL_KEYS}
        if deployment_labels:
            attributes["deployment"] = _answered(
                deployment_labels, "declared", authored_by="platform",
                method="docker inspect: Config.Labels",
                note="operator-set deployment signal; copies carrying these labels are one deployment",
            )
        else:
            attributes["deployment"] = _absent(
                "docker inspect: Config.Labels", "declared",
                note="no deployment-identifying labels on the container; K8s pod labels are not visible via the docker API",
            )
    else:
        attributes["deployment"] = _blind(
            "NO_SOURCE_ACCESS", "declared",
            note="container labels are not readable from inside a bare process",
        )

    # The declared-tier harness permission/approval attribute - the one that
    # moves containment from INSUFFICIENT_EVIDENCE to evaluable in the brain.
    # The value carries exactly what was read: docker mode joins the
    # container HostConfig part (privileged flag, Linux caps) with the
    # declared permission blocks; self mode carries the declared blocks
    # alone, because a bare process has no HostConfig to read and an
    # invented unprivileged one would read as "no container privilege".
    # (`found, failures` were read once, above, for the manifest source.)
    # Qualifier the value keys a block by: the source it was read from, so
    # two roots holding a same-named file cannot overwrite each other. A
    # unique basename stays short; a basename shared across sources takes
    # the full path, and every source under the collision keeps its entry
    # - there is no last-wins.
    stems = Counter(Path(s).name for s in found)
    harness_block: dict[str, Any] = {}
    # The block's own key, kept beside the qualified one: shape classification
    # reads the key, and the qualifier is the source filename, which must not
    # drive it (a `permissions.json` would otherwise match every shape).
    block_own_key: dict[str, str] = {}
    for source, keys in found.items():
        for key, value in keys.items():
            qualifier = source if stems[Path(source).name] > 1 else Path(source).name
            qualified = f"{qualifier}:{key}"
            harness_block[qualified] = _redact_harness_values(value, key)
            block_own_key[qualified] = key
    harness_note = "no permission-shaped keys in the harness config at the scanned roots"
    failure_note = _failure_note(failures)
    worst = _worst_failure_reason(failures) if failures else None
    if mode == "docker":
        hostconfig_value: dict[str, Any] = {
            "privileged": bool(host_config.get("Privileged")),
            "cap_add": [str(c) for c in host_config.get("CapAdd") or []],
            "cap_drop": [str(c) for c in host_config.get("CapDrop") or []],
            "security_opt": [str(o) for o in host_config.get("SecurityOpt") or []],
        }
        # The HostConfig is the floor of what a bare process could not say:
        # the attribute is a PARTIAL with the floor when some config failed,
        # an ANSWERED on the floor alone when nothing was there.
        if failures:
            value = {**hostconfig_value}
            if harness_block:
                value["harness"] = harness_block
            attributes["permissions"] = _partial(
                value, "declared", worst, authored_by="platform",
                method="container HostConfig (docker inspect)"
                       + (" + harness config permission keys" if harness_block else ""),
                note=failure_note,
            )
        elif harness_block:
            attributes["permissions"] = _answered(
                {**hostconfig_value, "harness": harness_block}, "declared",
                authored_by="platform",
                method="container HostConfig (docker inspect) + harness config permission keys",
            )
        else:
            attributes["permissions"] = _answered(
                hostconfig_value, "declared", authored_by="platform",
                method="docker inspect: HostConfig",
                note=harness_note,
            )
    elif harness_block:
        # A bare process reads only its own files: what was read is the
        # whole value, and a failure in it makes the read partial, not blind
        # - a blind is "there is nothing to read here at all".
        if failures:
            attributes["permissions"] = _partial(
                {"harness": harness_block}, "declared", worst,
                authored_by="platform",
                method="harness config permission keys",
                note=failure_note,
            )
        else:
            attributes["permissions"] = _answered(
                {"harness": harness_block}, "declared", authored_by="platform",
                method="harness config permission keys",
            )
    else:
        attributes["permissions"] = _blind(
            worst or "NO_SOURCE_ACCESS", "declared",
            note="privileged flag / Linux caps / RBAC are not readable from a bare process; "
                 + (failure_note or harness_note),
        )
    # The approval and allow/deny gates are the permission-shaped keys of the
    # same blocks, judged on each block's own key (never the source-qualified
    # form): a key whose name says the shape, or a block whose nested keys do.
    approval = {
        k: v
        for k, v in harness_block.items()
        if _block_shaped(block_own_key[k], v, _APPROVAL_SHAPES)
    }
    allow_deny = {
        k: v
        for k, v in harness_block.items()
        if _block_shaped(block_own_key[k], v, _ALLOW_DENY_SHAPES)
    }
    if approval:
        attributes["approval_policy"] = _answered(
            approval, "declared", authored_by="platform", method="harness config permission keys",
        )
    elif failures:
        attributes["approval_policy"] = _blind(
            worst, "declared",
            note=failure_note,
        )
    else:
        attributes["approval_policy"] = _blind(
            "GATEWAY_MANAGED", "declared",
            note="absence is NOT evidence of restriction — assume no approval gate",
        )
    if allow_deny:
        attributes["tool_allow_deny"] = _answered(
            allow_deny, "declared", authored_by="platform", method="harness config permission keys",
        )
    elif failures:
        attributes["tool_allow_deny"] = _blind(
            worst, "declared",
            note=failure_note,
        )
    else:
        attributes["tool_allow_deny"] = _blind("GATEWAY_MANAGED", "declared")

    network_mode = host_config.get("NetworkMode")
    if mode == "docker" and network_mode:
        attributes["sandbox_network_policy"] = _answered(
            network_mode, "observed", authored_by="none",
            method="docker inspect: HostConfig.NetworkMode",
        )
    else:
        attributes["sandbox_network_policy"] = _absent(
            "container network mode not observable in this mode", "observed",
        )

    # ── text signals: agent-authored, fenced as untrusted by the consumer ─
    attributes["system_prompt_present"] = _blind("NOT_COLLECTED_BY_PACK", "observed",
                                                 note="the prompt is not read by this pack")
    attributes["system_prompt_text"] = _blind("NOT_COLLECTED_BY_PACK", "observed")

    skills = payload.get("skills") or []
    if skills:
        attributes["skills_inventory"] = _answered(
            skills, "declared", authored_by="subject",
            method="SKILL.md frontmatter + MCP config; skills constructed in code are not visible",
            note="PARTIAL in effect: a code-built skill does not appear in these files",
        )
    else:
        attributes["skills_inventory"] = _absent(
            "scanned " + (", ".join(scanned_roots) or "no config roots"), "declared",
            note="no skills in the MCP config or skills files",
        )

    return {
        "bundle_version": BUNDLE_VERSION,
        "bundle_id": "bnd-" + uuid.uuid4().hex[:12],
        # RC-318: the bundle names the container it was collected from with
        # the pair the scan registers it under. The agent_id the registration
        # returns is no longer in the envelope: the control plane files the
        # bundle by pair lookup, so the builder stays decoupled from the
        # scan job's output.
        "host_id": host_id,
        "sandbox_name": sandbox_name,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "rule_pack_version": RULE_PACK_VERSION,
        "inputs_attempted": inputs,
        # Reserved: the schema field, not a claim. This pack has no
        # attestation producer, and an empty list is not a missing one —
        # attestation_ref is the check that keeps the two apart.
        "attestations": [],
        "attributes": attributes,
    }
# ── the write path ──────────────────────────────────────────────────────────
# Mirrors the feature file's guarantee: the bundle is written from the
# scanner's `finally`, so it lands even when the registration fails. It is
# the brain's input, not the scan's primary artifact, so a write failure is
# reported without changing the exit code - the feature file owns that.

DEFAULT_EVIDENCE_BUNDLE_OUTPUT = Path(".rail") / "railscan" / "evidence-bundle.json"


def evidence_bundle_output_path(args: Any) -> Path:
    configured = (
        getattr(args, "evidence_bundle_output", None) or os.environ.get("RAIL_EVIDENCE_BUNDLE_OUTPUT")
    )
    return Path(configured).expanduser() if configured else DEFAULT_EVIDENCE_BUNDLE_OUTPUT


def write_evidence_bundle(
    args: Any,
    context: dict[str, Any],
    payload: dict[str, Any],
    identity: dict[str, Any],
) -> bool:
    """Build, check and write the bundle, reporting failure rather than raising.

    It runs from a `finally`, so raising here would replace whatever error is
    already on its way out; the failure is still reported, and it still keeps
    a broken bundle from reaching a scorer.
    """
    from scan_agent_environment import ScannerError, store_json  # lazy: no cycle at load

    bundle = build_evidence_bundle(args, context, payload, identity)
    path = evidence_bundle_output_path(args)
    try:
        verify_bundle(bundle)
        store_json(path, bundle, args.compact)
    except ScannerError as exc:
        print(f"agent-environment-scanner: {exc}", file=sys.stderr)
        return False
    print(f"[agent-environment-scanner] evidence bundle: {path}", file=sys.stderr)
    return True
