# OpenClaw fixtures

Written by OpenClaw itself, not by hand: OpenClaw 2026.9.2 (3928bad), the
version on the GKE test bed, in NemoClaw's `ghcr.io/nvidia/nemoclaw/sandbox-base`
image, configured with the commands of rail-center's
`demo/agent-zone-files/agent/agent-setup.sh` (the test agent's setup), with
placeholder values. No model call is made.

```bash
openclaw config set models.mode merge
openclaw config set models.providers.external '{"baseUrl":"https://generativelanguage.googleapis.com/v1beta/openai","apiKey":"fixture-placeholder-not-a-key","api":"openai-completions","models":[{"id":"gemini-flash-latest","name":"gemini-flash-latest","maxTokens":8192}]}' --strict-json
openclaw config set agents.defaults.model.primary "external/gemini-flash-latest"
openclaw plugins disable bonjour
openclaw mcp set finretail '{"type":"http","transport":"streamable-http","url":"http://finretail-mcp-server:23004/mcp"}'
openclaw config set tools.deny '["browser"]' --strict-json   # set by hand on the test agent
openclaw exec-policy preset cautious                         # the test bed's cautious preset
```

| File | What it is |
|---|---|
| `openclaw.json` | `~/.openclaw/openclaw.json` as OpenClaw wrote it. The API key is the placeholder passed in |
| `exec_approvals_config.sql` | The `exec_approvals_config` table of `~/.openclaw/state/openclaw.sqlite`: its schema and row as OpenClaw wrote them, with a placeholder socket token in `raw_json` (the real database is 1.5 MB, so the tests build it from this) |

The session transcript database, `agents/<id>/agent/openclaw-agent.sqlite`,
only appears once the agent takes a turn, which needs a model call, so the
tests build its `transcript_events` table as OpenClaw 2026.9 writes it.

## Which folder OpenClaw uses

Checked in the same image by running `openclaw config set tools.deny …` each
way and seeing where `openclaw.json` was written. The profile derives this
folder as `$OPENCLAW_DIR`:

| Started with | Folder |
|---|---|
| nothing | `~/.openclaw` |
| `--profile x` or `--profile=x` | `~/.openclaw-x` |
| `--dev` | `~/.openclaw-dev` |
| `OPENCLAW_HOME=/h` | `/h/.openclaw` (`/h/.openclaw-x` with `--profile x`, `/h/.openclaw-dev` with `--dev`) |
| `OPENCLAW_STATE_DIR=/s`, with or without `--profile` | `/s` |
| `OPENCLAW_PROFILE=x` in the environment only | `~/.openclaw` (unchanged) |

To regenerate after an OpenClaw upgrade, run the commands above in the new
image and copy the two files out.
