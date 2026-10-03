#!/usr/bin/env bash
# Run the real NemoClaw example container and scan its loaded SKILL.md files.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The Compose service ships beside this script (examples/nemoclaw/). An
# agent-hardening checkout named by RAIL_AGENT_HARDENING_ROOT is still honoured,
# but that repository is deprecated and no longer needed.
if [[ -n "${RAIL_AGENT_HARDENING_ROOT:-}" ]]; then
  echo "run-nemoclaw: RAIL_AGENT_HARDENING_ROOT is deprecated; the Compose file now ships in $SCRIPT_DIR/examples/nemoclaw" >&2
  EXAMPLE_DIR="$RAIL_AGENT_HARDENING_ROOT/nemoclaw"
else
  EXAMPLE_DIR="$SCRIPT_DIR/examples/nemoclaw"
fi
OUTPUT_DIR="$EXAMPLE_DIR/output"
OUTPUT_FILE="$OUTPUT_DIR/nemoclaw-skills.json"

if [[ ! -f "$EXAMPLE_DIR/docker-compose.yml" ]]; then
  echo "run-nemoclaw: no docker-compose.yml in $EXAMPLE_DIR" >&2
  exit 2
fi

mkdir -p "$OUTPUT_DIR"

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
  --output "$OUTPUT_FILE"

echo "NemoClaw skills written to $OUTPUT_FILE"
