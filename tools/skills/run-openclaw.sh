#!/usr/bin/env bash
# Run the real OpenClaw example container and scan its loaded SKILL.md files.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The Compose service ships beside this script (examples/openclaw/). An
# agent-hardening checkout named by RAIL_AGENT_HARDENING_ROOT is still honoured,
# but that repository is deprecated and no longer needed.
if [[ -n "${RAIL_AGENT_HARDENING_ROOT:-}" ]]; then
  echo "run-openclaw: RAIL_AGENT_HARDENING_ROOT is deprecated; the Compose file now ships in $SCRIPT_DIR/examples/openclaw" >&2
  EXAMPLE_DIR="$RAIL_AGENT_HARDENING_ROOT/openclaw"
else
  EXAMPLE_DIR="$SCRIPT_DIR/examples/openclaw"
fi
OUTPUT_DIR="$EXAMPLE_DIR/output"
OUTPUT_FILE="$OUTPUT_DIR/openclaw-skills.json"

if [[ ! -f "$EXAMPLE_DIR/docker-compose.yml" ]]; then
  echo "run-openclaw: no docker-compose.yml in $EXAMPLE_DIR" >&2
  exit 2
fi

mkdir -p "$OUTPUT_DIR"

cd "$EXAMPLE_DIR"
docker compose up -d openclaw
CONTAINER_ID="$(docker compose ps -q openclaw)"

if [[ -z "$CONTAINER_ID" ]]; then
  echo "run-openclaw: OpenClaw container did not start" >&2
  exit 1
fi

for _ in $(seq 1 60); do
  STATUS="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER_ID")"
  if [[ "$STATUS" == "healthy" || "$STATUS" == "running" ]]; then
    break
  fi
  sleep 1
done

# OpenClaw can finish installing plugin runtime dependencies shortly after the
# container reports healthy. Delay is configurable for slower machines.
sleep "${SKILL_SCANNER_STARTUP_DELAY:-5}"

python3 "$SCRIPT_DIR/skill_scanner.py" \
  --agent openclaw \
  --container "$CONTAINER_ID" \
  --output "$OUTPUT_FILE"

echo "OpenClaw skills written to $OUTPUT_FILE"
