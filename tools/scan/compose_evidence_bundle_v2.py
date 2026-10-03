#!/usr/bin/env python3
"""Compose keyed scanner results into one evidence-bundle-v2 collection.

The scanner remains the collector. This step only normalizes scope: sandbox facts are
stored once, while agent facts remain under their stable keys. It deliberately refuses
disagreement in shared facts and never converts v2 back to v1.
"""

from __future__ import annotations

import argparse
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
# Design §4.3: "Image identity, container labels, mounts, container network
# policy, and deployment identity are sandbox-scoped." `container_identity`
# carries the host_id/sandbox_name pair (the closest existing attribute to
# "container labels"); `sandbox_network_policy` was missing here even though
# it is named explicitly in that sentence — an omission that would have let
# it ride into `agents[].attributes` as if it varied per agent, when a
# container has exactly one network mode for every process inside it.
#
# `observed_listeners` (DR-125) is here for a different reason: listensnoop
# runs per PID namespace, which is the sandbox, and nothing maps its events
# to one agent. Agent-scoped, one agent opening a port would read as drift
# on every sibling's ASP. In `compose()`, per-agent scans taken while
# listensnoop appended can disagree on it; that fails closed like any other
# sandbox attribute that differs between agents. `observed_ingress_peers`
# (DR-145) comes from the same events and is sandbox-scoped for the same
# reason.
SANDBOX_ATTRIBUTES = frozenset(
    {
        "container_identity", "image_digest", "mounts", "deployment",
        "sandbox_network_policy", "observed_listeners", "observed_ingress_peers",
    }
)


def agent_scoped_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    """The subset of a v1-shaped attribute dict that belongs under one
    agent's scope rather than the shared sandbox scope — the same filter
    `compose()` already applied inline, factored out so the real
    `--target-manifest` collection path (`run_one_collection`) can reuse it
    without going through `compose()`'s whole-bundle-merge contract."""
    return {name: value for name, value in attributes.items() if name not in SANDBOX_ATTRIBUTES}


def validate_agent_keys(agent_keys: list[str]) -> None:
    """The two rules the v2 schema's own `$comment` names as code-only:
    every `agent_key` is a valid, non-`default` multi-agent key, and no key
    repeats. Shared by `compose()` and `compose_from_scopes()` so both entry
    points fail closed the same way."""
    seen: set[str] = set()
    for key in agent_keys:
        if key == "default" or KEY.fullmatch(key) is None:
            raise ValueError(f"invalid multi-agent key: {key!r}")
        if key in seen:
            raise ValueError(f"duplicate agent_key: {key!r}")
        seen.add(key)


def compose_from_scopes(
    host_id: str,
    sandbox_name: str,
    rule_pack_version: int,
    sandbox_inputs: dict[str, Any],
    sandbox_attributes: dict[str, Any],
    agent_entries: list[dict[str, Any]],
    attestations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble one v2 collection from pieces a caller already scoped
    correctly — the real `--target-manifest` collection path (DR-109 M2).

    Unlike `compose()`, which derives the sandbox scope by merging N full v1
    bundles and failing closed on any disagreement between them, a real
    collection already has exactly one authoritative sandbox-wide scan (this
    function takes its `inputs_attempted`/`attributes` directly) plus zero or
    more agent entries — some `available` with real agent-scoped attributes,
    some `not_found`/`ambiguous`/scope-unresolved placeholders `run_one_collection`
    builds for a declared agent it could not (yet) isolate evidence for. There
    is nothing left to merge or agree on, only to validate, sort, and wrap.
    """
    if not agent_entries:
        raise ValueError("at least one agent entry is required")
    validate_agent_keys([entry["agent_key"] for entry in agent_entries])
    return {
        "bundle_version": 2,
        "bundle_id": f"bnd-{uuid.uuid4()}",
        "host_id": host_id,
        "sandbox_name": sandbox_name,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "rule_pack_version": rule_pack_version,
        "sandbox": {"inputs_attempted": sandbox_inputs, "attributes": sandbox_attributes},
        "agents": sorted(agent_entries, key=lambda entry: entry["agent_key"]),
        "attestations": list(attestations or []),
    }


def compose(
    host_id: str,
    sandbox_name: str,
    agents: dict[str, dict[str, Any]],
    discovery_status: dict[str, str] | None = None,
) -> dict[str, Any]:
    """`discovery_status` defaults every key to `"available"` — right for
    this function's own contract, since every source here is a real v1
    bundle a scan actually produced for that key, not a placeholder for a
    target that was never resolved. A caller that does know a finer-grained
    outcome (e.g. one recomputed after the source bundle was built) can
    override it per key; an unnamed key still defaults to `"available"`."""
    if not agents:
        raise ValueError("at least one keyed agent bundle is required")
    discovery_status = discovery_status or {}
    entries: list[dict[str, Any]] = []
    shared: dict[str, Any] = {}
    shared_inputs: dict[str, Any] | None = None
    rule_pack: int | None = None
    attestations: dict[str, dict[str, Any]] = {}
    validate_agent_keys(list(agents))
    for key in sorted(agents):
        bundle = agents[key]
        if bundle.get("bundle_version") != 1:
            raise ValueError(f"{key}: source must be an evidence bundle v1")
        if bundle.get("host_id") != host_id or bundle.get("sandbox_name") != sandbox_name:
            raise ValueError(f"{key}: source names a different sandbox")
        current_pack = bundle.get("rule_pack_version")
        if rule_pack is None:
            rule_pack = current_pack
        elif current_pack != rule_pack:
            raise ValueError("all source bundles must use one rule_pack_version")
        attributes = bundle.get("attributes") or {}
        for name in SANDBOX_ATTRIBUTES:
            if name not in attributes:
                continue
            if name in shared and shared[name] != attributes[name]:
                raise ValueError(f"sandbox attribute {name!r} disagrees between agents")
            shared[name] = attributes[name]
        inputs = bundle.get("inputs_attempted") or {}
        if shared_inputs is None:
            shared_inputs = inputs
        elif inputs != shared_inputs:
            raise ValueError("all source bundles must agree on sandbox input provenance")
        for attestation in bundle.get("attestations") or []:
            attestation_id = attestation.get("id")
            if not isinstance(attestation_id, str) or not attestation_id:
                raise ValueError(f"{key}: attestation has no non-empty id")
            if attestation_id in attestations and attestations[attestation_id] != attestation:
                raise ValueError(f"attestation {attestation_id!r} disagrees between agents")
            attestations[attestation_id] = attestation
        agent_attributes = agent_scoped_attributes(attributes)
        entries.append(
            {
                "agent_key": key,
                "discovery_status": discovery_status.get(key, "available"),
                "inputs_attempted": inputs,
                "attributes": agent_attributes,
            }
        )
    return {
        "bundle_version": 2,
        "bundle_id": f"bnd-{uuid.uuid4()}",
        "host_id": host_id,
        "sandbox_name": sandbox_name,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "rule_pack_version": rule_pack,
        "sandbox": {"inputs_attempted": shared_inputs or {}, "attributes": shared},
        "agents": entries,
        "attestations": [attestations[key] for key in sorted(attestations)],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--sandbox-name", required=True)
    parser.add_argument("--agent", action="append", default=[], metavar="KEY=V1_JSON", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    sources: dict[str, dict[str, Any]] = {}
    for spec in args.agent:
        key, separator, filename = spec.partition("=")
        if not separator or key in sources:
            parser.error("each --agent must be a unique KEY=V1_JSON")
        sources[key] = json.loads(Path(filename).read_text(encoding="utf-8"))
    output = compose(args.host_id, args.sandbox_name, sources)
    Path(args.output).write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
