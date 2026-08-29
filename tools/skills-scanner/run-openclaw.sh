#!/usr/bin/env bash
# Run the real OpenClaw example container and scan its loaded SKILL.md files.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HARDENING_ROOT="${RAIL_AGENT_HARDENING_ROOT:-$REPO_ROOT/../agent-hardening}"
EXAMPLE_DIR="$HARDENING_ROOT/openclaw"
OUTPUT_DIR="$EXAMPLE_DIR/output"
OUTPUT_FILE="$OUTPUT_DIR/openclaw-skills.json"

mkdir -p "$EXAMPLE_DIR/openclaw-data" "$OUTPUT_DIR"

if [[ ! -f "$EXAMPLE_DIR/docker-compose.yml" ]]; then
  echo "run-openclaw: set RAIL_AGENT_HARDENING_ROOT to an agent-hardening checkout" >&2
  exit 2
fi

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
  --root "$EXAMPLE_DIR/openclaw-data" \
  --output "$OUTPUT_FILE"

echo "OpenClaw skills written to $OUTPUT_FILE"
