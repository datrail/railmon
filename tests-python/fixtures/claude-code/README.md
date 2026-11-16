# Claude Code fixtures

Written by Claude Code itself, or by its setup, not by hand: Claude Code
2.1.325 from npm (`@anthropic-ai/claude-code`), in `node:22-bookworm-slim`,
set up by [`claude-code-setup.sh`](claude-code-setup.sh) with placeholder
values. That script is the counterpart of rail-center's
`demo/agent-zone-files/agent/agent-setup.sh` for an OpenClaw agent: the same
model contract (base URL, model, key), the agent's one MCP server, and a tool
policy. Claude Code then takes one turn against
[`stub_messages_api.py`](stub_messages_api.py), a stand-in for the Messages
API on `127.0.0.1` that answers with a `Read` and a `Bash` call, so the
transcript is real and no model call is made.

```bash
tests-python/fixtures/claude-code/regenerate.sh          # or: regenerate.sh <version>
```

| File | What it is |
|---|---|
| `user-settings.json` | `~/.claude/settings.json` as the setup wrote it: `model`, and an `env` block with `ANTHROPIC_BASE_URL` and the placeholder `ANTHROPIC_API_KEY` |
| `project-settings.json` | `/work/.claude/settings.json` as the setup wrote it: `permissions` (allow, deny, ask, `defaultMode: dontAsk`) and a `PreToolUse` hook on `Bash` |
| `claude.json` | `~/.claude.json` as Claude Code wrote it: `mcpServers` from `claude mcp add --scope user`, and the workspace marked trusted by the setup |
| `transcript.jsonl` | `~/.claude/projects/-work/<session>.jsonl` from the turn, without the lines that copy what Claude Code sent the model (`api-request`, `api-request-blob`, `api-request-shape`: its whole system prompt and tool schemas), the context it attached (`attachment`) and an internal latch. The `assistant` entries' `tool_use` blocks are as written |
| `package.json` | The installed package's `package.json` |

Claude Code 2.1 has no `config set`, so the settings files are written by the
setup as Claude Code's settings documentation describes them, and
`claude doctor` checks them ("No installation issues found").

## What was checked in the same container

Each by changing one file and seeing which value the next request to the
stub carried, or what Claude Code printed:

| Check | Result |
|---|---|
| `model` in user, project, local, `managed-settings.json`, `managed-settings.d/` | Each overrides the one before; a later drop-in (`20-b.json`) over an earlier one (`10-a.json`) |
| `--model`, `ANTHROPIC_MODEL` | Both override `model` in every file, managed included; a settings `env` block's `ANTHROPIC_MODEL` overrides the process's |
| `CLAUDE_CONFIG_DIR=/cfg` | `settings.json`, `.claude.json` and `projects/` all move under `/cfg` |
| `claude mcp add` (default scope) | `~/.claude.json`, `projects["<cwd>"].mcpServers` |
| An untrusted workspace | The allow rules of `.claude/settings.json` are ignored, and Claude Code says so; those of `.claude/settings.local.json` and `~/.claude/settings.json` apply |
| Invalid JSON | In `.claude/settings.json`: skipped, the user's setting applies. In `managed-settings.json` or a drop-in: Claude Code makes no request at all |
| The npm package's command | `bin/claude.exe`, a native binary: the process's command word is `claude.exe` |
