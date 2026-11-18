# Generic reader fixtures (RC-520)

The config folder of an agent on a harness no profile knows: a made-up
`plainagent`, run as `python3 -m plainagent serve`, so neither OpenClaw's nor
Claude Code's markers match it and the generic reader
(`tools/scan/gke/harness/generic.py`) reads it. Written by hand, in the
shapes any harness may use; the key is a placeholder.

| File | Laid out as | What it is |
|---|---|---|
| `config.json` | `<config-path>/config.json` | The harness's own top-level config: a model, its provider and base URL under `llm`, a tool allow/deny list under `tools`, an `approvalMode`, and a telemetry endpoint that is not the model's |
| `mcp.json` | `<config-path>/.mcp.json` | The standard MCP config: one HTTP server with an auth header, one command server with a token in its `env` |
| `AGENTS.md` | `<config-path>/AGENTS.md` | The standard agent instructions file |
