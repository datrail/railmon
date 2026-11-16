#!/usr/bin/env bash
# Sets up a Claude Code agent the way rail-center's
# demo/agent-zone-files/agent/agent-setup.sh sets up an OpenClaw one, for the
# fixtures beside this file (RC-526): the same model contract (base URL, model,
# key), the agent's one MCP server, and a tool policy, written where Claude
# Code itself reads them.
#
# Claude Code 2.1 has no `config set`: settings are files it reads at start.
# The MCP server goes through `claude mcp add`, so ~/.claude.json is written
# by Claude Code. The settings files are written here as Claude Code's
# settings documentation describes them; `claude doctor` checks them.
#
#   ~/.claude/settings.json          model, env (base URL, key)    user scope
#   ~/.claude.json                   mcpServers (claude mcp add)   user scope
#   $AGENT_WORKDIR/.claude/settings.json  permissions, hooks        project scope
#   $AGENT_WORKDIR/CLAUDE.md         the agent's instructions
#   $AGENT_WORKDIR/.claude/skills/   one skill
#
# With no argument it stops after the setup; given arguments, it runs
# `claude "$@"` from $AGENT_WORKDIR, as agent-setup.sh ends by running the
# gateway.
set -euo pipefail

die() { echo "✗ $*" >&2; exit 1; }

: "${AGENT_NAME:?AGENT_NAME is required — the name this agent announces}"
: "${AGENT_MCP_URL:?AGENT_MCP_URL is required — the proxy that belongs to this agent}"
: "${AGENT_MCP_NAME:?AGENT_MCP_NAME is required — the namespace this agent mounts that proxy under}"
: "${AGENT_LLM_API_KEY:?AGENT_LLM_API_KEY is required — the model endpoint credential}"

AGENT_LLM_BASE_URL="${AGENT_LLM_BASE_URL:-https://api.anthropic.com}"
AGENT_LLM_MODEL="${AGENT_LLM_MODEL:-claude-sonnet-4-5}"
AGENT_WORKDIR="${AGENT_WORKDIR:-/work}"

[[ "$AGENT_LLM_MODEL" =~ ^[A-Za-z0-9._:/@-]+$ ]] ||
  die "AGENT_LLM_MODEL='$AGENT_LLM_MODEL' has characters not allowed in a model id"
[[ "$AGENT_LLM_BASE_URL" =~ ^https?://[A-Za-z0-9._:/-]+$ ]] ||
  die "AGENT_LLM_BASE_URL='$AGENT_LLM_BASE_URL' must be an http(s):// URL"
[[ "$AGENT_LLM_API_KEY" =~ ^[A-Za-z0-9._-]+$ ]] ||
  die "AGENT_LLM_API_KEY contains characters not allowed in a bearer token"
[[ "$AGENT_MCP_NAME" =~ ^[A-Za-z0-9_-]+$ ]] ||
  die "AGENT_MCP_NAME='$AGENT_MCP_NAME' must be letters, digits, _ or -"
[[ "$AGENT_MCP_URL" =~ ^https?://[A-Za-z0-9._:/-]+$ ]] ||
  die "AGENT_MCP_URL='$AGENT_MCP_URL' must be an http(s):// URL"

mkdir -p "$HOME/.claude" "$AGENT_WORKDIR/.claude/skills/stock-lookup"

# User scope: the model contract. The key travels in the settings' env block,
# where Claude Code reads it; it is never printed.
cat > "$HOME/.claude/settings.json" <<EOF
{
  "\$schema": "https://json.schemastore.org/claude-code-settings.json",
  "model": "$AGENT_LLM_MODEL",
  "env": {
    "ANTHROPIC_BASE_URL": "$AGENT_LLM_BASE_URL",
    "ANTHROPIC_API_KEY": "$AGENT_LLM_API_KEY",
    "DISABLE_TELEMETRY": "1",
    "DISABLE_AUTOUPDATER": "1"
  }
}
EOF

# Project scope: the tool policy. The counterpart of the OpenClaw agent's
# tools.deny ["browser"] and cautious exec preset: no web fetches, the agent's
# MCP tools and harmless reads allowed, anything else refused without a
# prompt (dontAsk, as a headless agent has no one to ask), and every Bash
# call passed to a hook first.
cat > "$AGENT_WORKDIR/.claude/settings.json" <<EOF
{
  "permissions": {
    "allow": ["mcp__$AGENT_MCP_NAME", "Read", "Bash(echo:*)"],
    "deny": ["WebFetch", "WebSearch", "Bash(curl:*)"],
    "ask": ["Bash(rm:*)"],
    "defaultMode": "dontAsk"
  },
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/agent-bash-guard"}]}
    ]
  }
}
EOF

cat > "$AGENT_WORKDIR/CLAUDE.md" <<EOF
# $AGENT_NAME
You answer questions about stock prices and statements with the $AGENT_MCP_NAME tools.
EOF

cat > "$AGENT_WORKDIR/.claude/skills/stock-lookup/SKILL.md" <<'EOF'
---
name: stock-lookup
description: Look up a stock price
---
Call the getStockPrice tool with the symbol.
EOF

# The agent's one MCP server is its proxy, in user scope (~/.claude.json),
# written by Claude Code itself.
# Removed first, so the script can run again on the same home.
(cd "$AGENT_WORKDIR" && claude mcp remove --scope user "$AGENT_MCP_NAME" >/dev/null 2>&1 || true)
(cd "$AGENT_WORKDIR" && claude mcp add --scope user --transport http "$AGENT_MCP_NAME" "$AGENT_MCP_URL" >/dev/null)

# Claude Code ignores a project's permissions.allow until the workspace is
# trusted, which an interactive user does at its trust dialog. A headless
# agent has no one to accept it, so it is accepted here, in ~/.claude.json
# where Claude Code keeps it (node is there: Claude Code was installed by npm).
CLAUDE_JSON="${CLAUDE_CONFIG_DIR:-$HOME}/.claude.json" AGENT_WORKDIR="$AGENT_WORKDIR" node -e '
  const fs = require("fs"), path = process.env.CLAUDE_JSON;
  const config = JSON.parse(fs.readFileSync(path, "utf8"));
  config.projects = config.projects || {};
  config.projects[process.env.AGENT_WORKDIR] = {...(config.projects[process.env.AGENT_WORKDIR] || {}), hasTrustDialogAccepted: true};
  fs.writeFileSync(path, JSON.stringify(config, null, 2));
'

echo "[claude-code-setup] $AGENT_NAME ready — model $AGENT_LLM_MODEL via $AGENT_LLM_BASE_URL ; $AGENT_MCP_NAME -> $AGENT_MCP_URL"
if [ "$#" -gt 0 ]; then
  cd "$AGENT_WORKDIR"
  exec claude "$@"
fi
