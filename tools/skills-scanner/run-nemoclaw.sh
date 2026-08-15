#!/usr/bin/env bash
# Run the real NemoClaw example container and scan its loaded SKILL.md files.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HARDENING_ROOT="${RAIL_AGENT_HARDENING_ROOT:-$REPO_ROOT/../agent-hardening}"
EXAMPLE_DIR="$HARDENING_ROOT/nemoclaw"
OUTPUT_DIR="$EXAMPLE_DIR/output"
OUTPUT_FILE="$OUTPUT_DIR/nemoclaw-skills.json"

mkdir -p "$EXAMPLE_DIR/nemoclaw-data" "$OUTPUT_DIR"

if [[ ! -f "$EXAMPLE_DIR/docker-compose.yml" ]]; then
  echo "run-nemoclaw: set RAIL_AGENT_HARDENING_ROOT to an agent-hardening checkout" >&2
  exit 2
fi

cd "$EXAMPLE_DIR"
docker compose up -d nemoclaw
CONTAINER_ID="$(docker compose ps -q nemoclaw)"

if [[ -z "$CONTAINER_ID" ]]; then
  echo "run-nemoclaw: NemoClaw container did not start" >&2
  exit 1
fi

for _ in $(seq 1 60); do
  STATUS="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER_ID")"
  if [[ "$STATUS" == "healthy" || "$STATUS" == "running" ]]; then
    break
  fi
  sleep 1
done

sleep "${SKILL_SCANNER_STARTUP_DELAY:-5}"

python3 "$SCRIPT_DIR/skill_scanner.py" \
  --agent nemoclaw \
  --container "$CONTAINER_ID" \
  --root "$EXAMPLE_DIR/nemoclaw-data" \
  --output "$OUTPUT_FILE"

echo "NemoClaw skills written to $OUTPUT_FILE"
