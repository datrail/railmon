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
SANDBOX_ATTRIBUTES = frozenset({"container_identity", "image_digest", "mounts", "deployment"})


def compose(host_id: str, sandbox_name: str, agents: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if not agents:
        raise ValueError("at least one keyed agent bundle is required")
    entries: list[dict[str, Any]] = []
    shared: dict[str, Any] = {}
    shared_inputs: dict[str, Any] | None = None
    rule_pack: int | None = None
    attestations: dict[str, dict[str, Any]] = {}
    for key in sorted(agents):
        if key == "default" or KEY.fullmatch(key) is None:
            raise ValueError(f"invalid multi-agent key: {key!r}")
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
        agent_attributes = {name: value for name, value in attributes.items() if name not in SANDBOX_ATTRIBUTES}
        entries.append(
            {
                "agent_key": key,
                "discovery_status": "available",
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
