#!/usr/bin/env python3
"""Print the sidecar spec (sidecar.json) from a rendered railmon-gke chart.

`helm template` output is YAML, and the runner's Python has no YAML library,
so this reads the one block it needs: the `sidecar.json: |` literal in the
rail-scan-sidecar-spec ConfigMap, whose lines are JSON.

  python3 tests/extract_sidecar_spec.py rendered.yaml > sidecar.json
"""

from __future__ import annotations

import json
import sys


def extract(text: str) -> dict:
    for document in text.split("\n---"):
        if "name: rail-scan-sidecar-spec" not in document:
            continue
        lines = document.splitlines()
        for index, line in enumerate(lines):
            if line.strip() == "sidecar.json: |":
                key_indent = len(line) - len(line.lstrip())
                block = []
                for item in lines[index + 1:]:
                    if item.strip() and len(item) - len(item.lstrip()) <= key_indent:
                        break
                    block.append(item)
                return json.loads("\n".join(block))
    raise SystemExit("no rail-scan-sidecar-spec ConfigMap with sidecar.json in the rendered chart")


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as handle:
        print(json.dumps(extract(handle.read()), indent=2))
