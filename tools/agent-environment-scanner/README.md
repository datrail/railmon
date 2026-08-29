# Agent Environment Scanner

Scans a running agent environment and emits JSON compatible with rail-center's
`POST /v1/agents/register` request body.

This tool is meant to run before registration. It does not capture traffic and
does not require eBPF privileges. It reads container metadata, safe environment
metadata, system/runtime information, owner identity, and optional MCP config.

## Output Schema

The output matches `RegisterAgentRequest` in rail-center:

```json
{
  "type": "personal",
  "owner": "user-or-team",
  "host_id": "vm-7f3c",
  "sandbox_name": "openclaw-1",
  "environment": {
    "sandbox_type": "openclaw",
    "llm_provider": "local",
    "llm_model": "tinyllama",
    "system_info": {},
    "user_info": {}
  },
  "skills": []
}
```

`host_id` and `sandbox_name` are optional; they are omitted when the scanner has
nothing it can stand behind. See [Agent identity](#agent-identity).

The scanner uses secret-bearing environment variables to infer the provider, but
it only records environment variable names. API key values are not written into
the payload. The container's entrypoint is recorded as `system_info.process
.proc1_cmdline` with credential-bearing arguments — `--api-key=…`, `--token …`,
an inline `API_KEY=…` — stripped, since an entrypoint routinely carries one.

Every file the scanner writes — the payload under `--output`, the registration
state, and the feature file — is created `0600`.

## Registration Flow

RC-41 flow is supported directly:

```text
collect environment data + skills data
  -> POST /v1/agents/register        (optional)
  -> store the returned agent id     (the response token is discarded)
  -> write the feature file          (always, and last, so it records the outcome)
```

Run the skills scanner first if the agent uses OpenClaw/NemoClaw `SKILL.md`
files:

```bash
tools/skills-scanner/run-openclaw.sh
```

Then register the agent with Rail Center:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --mode docker \
  --container openclaw-monitoring-openclaw-1 \
  --skills-file examples/openclaw-monitoring/output/openclaw-skills.json \
  --register \
  --center-url http://localhost:23001
```

Rail Center must be running with database migrations applied before this POST.

The scanner accepts either a raw `SkillInput[]` JSON file or a full
`RegisterAgentRequest` JSON object with a `skills` field. It merges those skills
with any MCP skills discovered from `.mcp.json`.

By default, Rail Center's response is stored at:

```text
.datrail/rail-guardian/registration.json
```

The stored file contains:

```json
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "sandbox_id": "a1b2c3d4e5f6",
  "host_id": "vm-7f3c",
  "sandbox_name": "openclaw-1",
  "environment_fingerprint": "f6e5d4c3b2a1"
}
```

**No ticket is stored.** Rail Center's response carries a `token`, and the
scanner discards it: it is a placeholder minted with a null posture, because
posture is scored asynchronously after the response returns. Storing or
forwarding it would pin the fleet to a posture that was never computed. The
proxy fetches its own ticket; the scanner is the registrar, and a registrar
holds no credentials.

Override the state file with:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --register \
  --center-url http://localhost:23001 \
  --registration-output /var/lib/datrail/rail-guardian-registration.json
```

Use `RAIL_CENTER_URL` instead of `--center-url` when running as a service.
The `DATRAIL_*` names it used to accept were removed in DR-74 — there is no
fallback, so a deployment still setting an old name gets no value at all rather
than a silently ignored one.
Rail Center unreachable errors, invalid payload responses, and invalid response
bodies are reported as scanner errors with exit code `2`.

## Feature file

The feature file is the scanner's primary output and needs no control plane. It
is written to `.rail/railscan/features.json` (override with `--feature-output`
or `RAIL_FEATURE_OUTPUT`; skip with `--no-feature-file`) and covers dimensions
1–5 at inventory depth:

| Section | Contents |
|---|---|
| `host_and_identity` | `sandbox_type`, `host_class`, `host_id` (+ source), `sandbox_name` (+ source), image, container id, owner |
| `secrets_hygiene` | env key *names*, plus one entry per secret-looking variable with its `secret_type` and `secret_class` (`plaintext` / `reference` / `mount`) |
| `model_and_egress` | provider, model, `base_url` and whether it is `canonical`, `local` or an `unknown_proxy` |
| | URLs are recorded with userinfo, query strings, fragments and key-shaped path segments redacted — gateways routinely carry the key in the URL. A path segment is key-shaped if it is 20 characters or longer, or matches a known vendor key format (`sk-…`, `ghp_…`, `xoxb-…`, `AKIA…`, …) at any length |
| `tool_and_mcp_reach` | MCP inventory: name, the command's executable (not its arguments, which carry tokens), redacted url, transport |
| `skills` | name, description, destination endpoints, source type. A skills file is operator-written free text, so strings matching a known vendor key format are stripped from all three before they are recorded or POSTed. The formats carry their length and character shape, not just a prefix, so a skill called `asian-markets` keeps its name |
| `observed_reach` | only with `--observed-file`: hosts actually reached, with counts, errors and a redacted path; the tool *names* used; the models seen; and `undeclared_destinations` |

Metadata only — never a secret value. That is what makes the file safe to
persist and hand to a scorer. It is written `0600`: the inventory names an
agent's tools, endpoints and which of its secrets sit in plaintext, which is a
map worth reading for anyone who wants to attack that agent.

`registration_status` reports what happened, not what was asked for: with
`--register` it stays `registration_failed` until the POST actually succeeds.

The feature file is written even when a registration or an `--output` write
fails, and failing to write it is itself an exit code `2` — it is the primary
artifact, not a side effect. A registration error is never replaced by a
feature-file error: both are printed, the registration one last, since that is
the one the operator has to act on.

`secret_class` distinguishes `mount` from `reference` by asking the filesystem
the value refers to: in `--mode docker` that is the scanned container's, so a
secret mounted into the container is not reported as a dangling pointer.

## Observed reach (optional)

The other dimensions describe what an agent is *configured* to reach.
`--observed-file` adds what it *actually* reached, from an
[AgentSight](https://github.com/eunomia-bpf/agentsight) snapshot:

```bash
sudo agentsight record -- claude          # or: agentsight report --local  (no sudo)
agentsight report export -o snapshot.json
python3 .../scan_agent_environment.py --observed-file snapshot.json
```

AgentSight has already done the parsing and the aggregation, so the scanner only
classifies, redacts and diffs — it grows no parser of its own. The payoff is
`undeclared_destinations`: hosts the agent reached that nothing in its
configuration declared.

It reads `network_targets`, `tool_calls[].tool_name`, `token_summary[].group`
and the summary counts, and deliberately nothing else. `tool_calls` also carries
`input`/`output` and `process_nodes` carries full `argv` — conversation and
command-line *contents*, not metadata — which must never reach a file that is
persisted and handed to a scorer.

## Agent identity

| Field | Where it comes from |
|---|---|
| `host_id` | `RAIL_HOST_ID` (or `--host-id`), the same value every Rail component on the host reads. The scanner's own environment is read before the scanned container's, so a container cannot relabel the host it runs on; `host_id_source` distinguishes `flag`, `env` and `container_env`. **No fallback is invented** — an id this scanner made up would disagree with the proxy and the collector, so an unset variable is reported as unset. |
| `sandbox_name` | the `rail.sandbox_name` container label, else the container name, else the hostname. **Never an environment variable**: an agent nobody onboarded carries no Rail configuration, and those are exactly the ones worth discovering. |
| `host_class` | DMI vendor/product — `gce_vm`, `ec2_vm`, `azure_vm`, `virtual_machine`, `bare_metal`, `container`, or `unknown` when the DMI is unreadable. |

Both identity fields are optional on Rail Center's side and bounded to its
storage width (64 and 255), so the scanner truncates rather than letting a long
value surface as a server error.

## Authentication

`RAIL_AUTH_MODE` (or `--auth-mode`) selects the credential presented when
registering, mirroring Rail Center's `RAIL_AUTH_MODES_ACCEPTED`:

- `none` (default) — sends nothing; accepted while the control plane still
  lists `none`.
- `bearer` — sends `RAIL_AUTH_TOKEN` as `Authorization: Bearer …`.
- `gcp` — belongs to DR-10's shared token client; it fails loudly here rather
  than degrading to an anonymous call an operator believes is authenticated.

## Local Machine Scan

From the repository root:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py
```

Write the payload to a file:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --output output/registration-payload.json
```

Use explicit values when the model or provider cannot be inferred:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --sandbox-type bare_metal \
  --llm-provider anthropic \
  --llm-model claude-sonnet-4-20250514
```

## OpenClaw Integration

Start the real OpenClaw example container:

```bash
cd examples/openclaw-monitoring
mkdir -p openclaw-data output
docker compose up -d openclaw
```

Run the scanner against the running OpenClaw container:

```bash
cd ../..
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --mode docker \
  --container openclaw-monitoring-openclaw-1 \
  --output examples/openclaw-monitoring/output/registration-payload.json
```

If Compose uses a different container name, get it with:

```bash
docker compose -f examples/openclaw-monitoring/docker-compose.yml ps openclaw
```

Expected detection for the bundled OpenClaw compose file:

| Field | Expected value |
| --- | --- |
| `environment.sandbox_type` | `openclaw` |
| `environment.llm_provider` | `local` |
| `environment.llm_model` | `unknown` unless a model is configured or a capture file is provided |

To infer model from an actual monitor capture:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --mode docker \
  --container openclaw-monitoring-openclaw-1 \
  --capture-file examples/openclaw-monitoring/output/openclaw-capture.jsonl
```

## NemoClaw Integration

Start the real NemoClaw example container:

```bash
cd examples/nemoclaw-monitoring
mkdir -p nemoclaw-data output
docker compose up -d nemoclaw
```

Run the scanner against the running NemoClaw container:

```bash
cd ../..
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --mode docker \
  --container nemoclaw-monitoring-nemoclaw-1 \
  --output examples/nemoclaw-monitoring/output/registration-payload.json
```

If Compose uses a different container name, get it with:

```bash
docker compose -f examples/nemoclaw-monitoring/docker-compose.yml ps nemoclaw
```

Expected detection for the bundled NemoClaw compose file:

| Field | Expected value |
| --- | --- |
| `environment.sandbox_type` | `nemo_claw` |
| `environment.llm_provider` | `local` |
| `environment.llm_model` | `unknown` unless a model is configured or a capture file is provided |

To infer model from an actual monitor capture:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --mode docker \
  --container nemoclaw-monitoring-nemoclaw-1 \
  --capture-file examples/nemoclaw-monitoring/output/nemoclaw-capture.jsonl
```

## MCP Skills

The scanner looks for MCP config in:

```text
.mcp.json
/workdir/.mcp.json
~/.mcp.json
```

Each `mcpServers` entry becomes a registration `SkillInput` with
`source_type: "mcp_config"`. Pass custom paths with:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --mcp-config /path/to/.mcp.json
```

Merge external skills from the skills scanner:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --skills-file examples/openclaw-monitoring/output/openclaw-skills.json
```

## Validate Against rail-center

From the `rail-center` repository, validate a generated payload with the current
Pydantic schema:

```bash
uv run --python 3.13 --with pydantic --with typing-extensions python -c '
import json, sys
sys.path.insert(0, "api/src")
from registry.schemas import RegisterAgentRequest
RegisterAgentRequest.model_validate(json.load(open("../datrail-agent-monitor/output/registration-payload.json")))
print("valid")
'
```
