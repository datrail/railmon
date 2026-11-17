#!/usr/bin/env bash
# Regenerates the Claude Code fixtures beside this file (README.md): installs
# the pinned Claude Code in a throwaway container, sets it up with
# claude-code-setup.sh using placeholder values, has it take one turn against
# stub_messages_api.py (no model call), and copies out what it wrote.
#
#   tests-python/fixtures/claude-code/regenerate.sh [version]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
VERSION="${1:-2.1.325}"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

docker run --rm -v "$HERE:/fixtures:ro" -v "$OUT:/out" node:22-bookworm-slim bash -euo pipefail -c "
  apt-get update -qq >/dev/null && apt-get install -y -qq python3 >/dev/null
  npm install -g @anthropic-ai/claude-code@$VERSION >/dev/null 2>&1
  printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/agent-bash-guard && chmod +x /usr/local/bin/agent-bash-guard
  python3 /fixtures/stub_messages_api.py 8787 2>/out/stub.log &
  sleep 1
  export AGENT_NAME=fixture-agent AGENT_MCP_NAME=finretail \
         AGENT_MCP_URL=http://finretail-mcp-server:23004/mcp \
         AGENT_LLM_BASE_URL=https://llm-gateway.example.internal:8443 \
         AGENT_LLM_MODEL=claude-sonnet-4-5 \
         AGENT_LLM_API_KEY=fixture-placeholder-not-a-key \
         AGENT_WORKDIR=/work
  bash /fixtures/claude-code-setup.sh
  (cd /work && claude doctor </dev/null >/out/doctor.txt 2>&1 || true)
  # The turn goes to the stub: --settings is a higher scope than the user's.
  bash /fixtures/claude-code-setup.sh -p 'Check the stock lookup setup.' \
    --settings '{\"env\":{\"ANTHROPIC_BASE_URL\":\"http://127.0.0.1:8787\",\"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC\":\"1\"}}' \
    >/out/turn.txt 2>&1 || true
  cp /usr/local/lib/node_modules/@anthropic-ai/claude-code/package.json /out/package.json
  cp ~/.claude/settings.json /out/user-settings.json
  cp ~/.claude.json /out/claude.json
  cp /work/.claude/settings.json /out/project-settings.json
  find ~/.claude/projects -name '*.jsonl' -exec cp {} /out/transcript.jsonl \;
  cat /out/turn.txt
"
cp "$OUT"/package.json "$OUT"/user-settings.json "$OUT"/project-settings.json "$OUT"/claude.json "$HERE/"
chmod 644 "$HERE"/*.json
# The transcript without the lines that copy what Claude Code sent the model
# (api-request, api-request-blob, api-request-shape: its whole system prompt and tool schemas), the context it
# attached (attachment), and an internal latch: what is kept is the
# conversation, with the assistant's tool_use entries, as Claude Code wrote it.
python3 -I - "$OUT/transcript.jsonl" "$HERE/transcript.jsonl" <<'EOF'
import json, sys
dropped = {"api-request", "api-request-blob", "api-request-shape", "attachment", "atis-latch"}
with open(sys.argv[1]) as source, open(sys.argv[2], "w") as kept:
    for line in source:
        if json.loads(line).get("type") not in dropped:
            kept.write(line)
EOF
echo "fixtures written to $HERE"
