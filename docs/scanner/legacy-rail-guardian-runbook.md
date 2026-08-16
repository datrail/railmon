# Rail Guardian

Rail Guardian is the local registration and posture discovery module inside
`datrail-agent-monitor`.

It prepares the registration contract consumed by Rail Center:

```text
collect environment data + collect skills data
  -> POST /v1/agents/register
  -> receive agent UUID + x-rail token
  -> store registration state locally
```

Rail Guardian does not capture network traffic and does not require eBPF
privileges. Traffic capture remains the responsibility of RailMon in
`collector/`; RailCollector forwards RailMon output to Rail Center.

For the unified Rail Center integration guide and ticket-to-component map, see
`../docs/rail-center-runtime-integration.md`.

For the all-in-one sidecar container that scans OpenClaw/NemoClaw, registers
with Rail Center, starts RailMon, and starts RailCollector, see
`../docs/rail-guardian-all-in-one-container.md`.

## Components

| Component | Path | Responsibility |
| --- | --- | --- |
| Agent environment scanner | `rail-guardian/tools/agent-environment-scanner/` | Collects sandbox type, LLM provider/model, OS/runtime/host identifiers, owner identity, MCP config, and posts registration payloads to Rail Center. |
| Skills scanner | `rail-guardian/tools/skills-scanner/` | Reads real OpenClaw/NemoClaw `SKILL.md` files and emits Rail Center `SkillInput` JSON. |
| RailMon | `collector/` | Captures SSL/TLS traffic with eBPF, parses HTTP interactions, redacts auth headers, and writes legacy JSONL or Rail Center `RuntimeInteraction` JSONL. |
| RailCollector | `rail-guardian/rail-collector/` | Runs as the Rail Guardian runtime forwarder, reads RailMon `RuntimeInteraction` JSONL, durably spools events, and forwards them to `POST /v1/interactions` in Rail Center. |

## Registration Schema

Rail Guardian emits the `RegisterAgentRequest` schema implemented in Rail
Center:

```json
{
  "type": "personal",
  "owner": "user-or-team",
  "environment": {
    "sandbox_type": "openclaw",
    "llm_provider": "local",
    "llm_model": "unknown",
    "system_info": {},
    "user_info": {}
  },
  "skills": [
    {
      "name": "skill-name",
      "description": "What the skill does",
      "destination_endpoints": ["https://service.example/api"],
      "source_type": "skills_config"
    }
  ]
}
```

Field mapping:

| Rail Center field | Rail Guardian source |
| --- | --- |
| `type` | `--agent-type`, defaults to `personal` |
| `owner` | `--owner`, `RAIL_OWNER`, Git email, or local username |
| `environment.sandbox_type` | `--sandbox-type`, container image/name/cmd markers, or local container detection |
| `environment.llm_provider` | `--llm-provider`, provider env vars, API key env var names, local base URL, or model inference |
| `environment.llm_model` | `--llm-model`, model env vars, OpenClaw/NemoClaw config files, or capture JSONL |
| `environment.system_info` | OS, kernel, arch, runtime versions, hostname, container metadata, process metadata, non-secret env key names |
| `environment.user_info` | owner source, username, uid/gid, home, Git identity, container user identity |
| `skills` | MCP config entries plus optional `--skills-file` output from the skills scanner |

`system_info` and `user_info` are free-form JSON fields in Rail Center. Rail
Guardian fills the OS/runtime/host and owner identity details needed by the
current contract.

## Start Rail Center

From the Rail Center API repository:

`$RAIL_WORKSPACE_HOME` is where `dev-toolkits/dev-setup.sh` clones the repositories as flat siblings; it defaults to `~/workspace`.

```bash
cd $RAIL_WORKSPACE_HOME/rail-center/api
docker compose up -d db api
```

Apply database migrations from the host checkout:

```bash
PYTHONPATH=src uv run --python 3.13 alembic -c migrations/alembic.ini upgrade head
```

Check the API is reachable:

```bash
curl -fsS http://localhost:23001/docs >/dev/null
```

Current note: `migrations/alembic.ini` points to
`postgresql://railcenter:railcenter@localhost:25432/railcenter`, so run the
migration from the host checkout where Docker publishes port `25432`. Running
Alembic inside the API container will try the container's own localhost unless
the DB URL is overridden.

## Rail Center Integration

Rail Guardian integrates with Rail Center through one HTTP contract:

| Direction | API |
| --- | --- |
| Rail Guardian -> Rail Center | `POST /v1/agents/register` |
| RailCollector -> Rail Center | `POST /v1/interactions` |
| Rail Center -> Rail Guardian | `RegisterAgentResponse` containing `agent.id`, `sandbox_id`, `environment_fingerprint`, and `token` |

The `token` returned by Rail Center is the value that managed clients should
send in the `x-rail` header. Rail Guardian stores the token locally; it does not
inject the header into OpenClaw/NemoClaw by itself.

Minimum integration sequence:

1. Start Rail Center API and DB.
2. Apply Rail Center migrations.
3. Run the skills scanner for the target agent environment.
4. Run the environment scanner with `--skills-file`, `--register`, and `--center-url`.
5. Read the stored `token` from the registration state file.
6. Configure the managed agent, proxy, or caller to send `x-rail: <token>`.
7. Verify the agent appears in Rail Center with `GET /v1/agents/{id}`.
8. Run RailMon with `--output-format runtime-interaction`.
9. Run RailCollector against the RailMon JSONL file.
10. Verify runtime events with `GET /v1/interactions`.

Choose the Rail Center URL based on where Rail Guardian runs:

| Rail Guardian location | `--center-url` value |
| --- | --- |
| Host process, Rail Center compose publishes port `23001` | `http://localhost:23001` |
| Container on Docker Desktop reaching host-published Rail Center | `http://host.docker.internal:23001` |
| Container on the same Compose network as Rail Center API service `api` | `http://api:23001` |
| Container on the alpha Compose network with service `rail-center-api` | `http://rail-center-api:23001` |

For a service deployment, prefer environment variables:

```bash
export RAIL_CENTER_URL=http://localhost:23001
export RAIL_REGISTRATION_OUTPUT=/var/lib/datrail/rail-guardian-registration.json
```

Then run:

```bash
python3 rail-guardian/tools/agent-environment-scanner/scan_agent_environment.py \
  --mode docker \
  --container openclaw-monitoring-openclaw-1 \
  --skills-file examples/openclaw-monitoring/output/openclaw-skills.json \
  --register
```

Use the stored token as an `x-rail` header:

```bash
X_RAIL_TOKEN="$(python3 - <<'PY'
import json
print(json.load(open('/var/lib/datrail/rail-guardian-registration.json'))['token'])
PY
)"

curl -H "x-rail: $X_RAIL_TOKEN" http://example-service/path
```

In local testing, replace `/var/lib/datrail/rail-guardian-registration.json`
with the path passed to `--registration-output`.

## Scan Real OpenClaw Skills

From the `datrail-agent-monitor` repository root:

```bash
cd $RAIL_WORKSPACE_HOME/datrail-agent-monitor
rail-guardian/tools/skills-scanner/run-openclaw.sh
```

This starts the real OpenClaw container from
`examples/openclaw-monitoring/docker-compose.yml`, scans real `SKILL.md` files,
and writes:

```text
examples/openclaw-monitoring/output/openclaw-skills.json
```

Manual equivalent:

```bash
cd examples/openclaw-monitoring
mkdir -p openclaw-data output
docker compose up -d openclaw
OPENCLAW_CONTAINER="$(docker compose ps -q openclaw)"

cd ../..
python3 rail-guardian/tools/skills-scanner/skill_scanner.py \
  --agent openclaw \
  --container "$OPENCLAW_CONTAINER" \
  --root examples/openclaw-monitoring/openclaw-data \
  --output examples/openclaw-monitoring/output/openclaw-skills.json
```

## Scan Real NemoClaw Skills

From the `datrail-agent-monitor` repository root:

```bash
cd $RAIL_WORKSPACE_HOME/datrail-agent-monitor
rail-guardian/tools/skills-scanner/run-nemoclaw.sh
```

This starts the real NemoClaw container from
`examples/nemoclaw-monitoring/docker-compose.yml`, scans real `SKILL.md` files,
and writes:

```text
examples/nemoclaw-monitoring/output/nemoclaw-skills.json
```

Manual equivalent:

```bash
cd examples/nemoclaw-monitoring
mkdir -p nemoclaw-data output
docker compose up -d nemoclaw
NEMOCLAW_CONTAINER="$(docker compose ps -q nemoclaw)"

cd ../..
python3 rail-guardian/tools/skills-scanner/skill_scanner.py \
  --agent nemoclaw \
  --container "$NEMOCLAW_CONTAINER" \
  --root examples/nemoclaw-monitoring/nemoclaw-data \
  --output examples/nemoclaw-monitoring/output/nemoclaw-skills.json
```

## Generate Registration Payload

OpenClaw:

```bash
python3 rail-guardian/tools/agent-environment-scanner/scan_agent_environment.py \
  --mode docker \
  --container openclaw-monitoring-openclaw-1 \
  --skills-file examples/openclaw-monitoring/output/openclaw-skills.json \
  --output /tmp/datrail-guardian-openclaw-payload.json
```

NemoClaw:

```bash
python3 rail-guardian/tools/agent-environment-scanner/scan_agent_environment.py \
  --mode docker \
  --container nemoclaw-monitoring-nemoclaw-1 \
  --skills-file examples/nemoclaw-monitoring/output/nemoclaw-skills.json \
  --output /tmp/datrail-guardian-nemoclaw-payload.json
```

The scanner accepts either:

| `--skills-file` format | Behavior |
| --- | --- |
| `SkillInput[]` | Merges the list into the generated registration payload. |
| `RegisterAgentRequest` object | Reads the object's `skills` field and merges it into the generated registration payload. |

MCP skills from `.mcp.json`, `/workdir/.mcp.json`, or `~/.mcp.json` are also
merged when present.

## Register With Rail Center

OpenClaw:

```bash
python3 rail-guardian/tools/agent-environment-scanner/scan_agent_environment.py \
  --mode docker \
  --container openclaw-monitoring-openclaw-1 \
  --skills-file examples/openclaw-monitoring/output/openclaw-skills.json \
  --register \
  --center-url http://localhost:23001 \
  --registration-output /tmp/datrail-guardian-registration.json
```

NemoClaw:

```bash
python3 rail-guardian/tools/agent-environment-scanner/scan_agent_environment.py \
  --mode docker \
  --container nemoclaw-monitoring-nemoclaw-1 \
  --skills-file examples/nemoclaw-monitoring/output/nemoclaw-skills.json \
  --register \
  --center-url http://localhost:23001 \
  --registration-output /tmp/datrail-guardian-registration.json
```

Use `RAIL_CENTER_URL` instead of `--center-url` when running as a service:

```bash
RAIL_CENTER_URL=http://localhost:23001 \
python3 rail-guardian/tools/agent-environment-scanner/scan_agent_environment.py \
  --register
```

By default, registration state is stored at:

```text
.datrail/rail-guardian/registration.json
```

Stored registration state contains:

```json
{
  "registered_at": "2026-05-01T00:57:02.758286+00:00",
  "center_url": "http://localhost:23001",
  "registration_url": "http://localhost:23001/v1/agents/register",
  "status": 201,
  "agent_id": "6854eb04-6a2f-4b99-83a7-db8d65cae4ea",
  "sandbox_id": "d02c5690a0453a0c",
  "environment_fingerprint": "8195b2b146d076f4",
  "token": "base64-x-rail-token",
  "request_summary": {
    "type": "personal",
    "owner": "linuxdev8883@example.com",
    "skills_count": 13
  },
  "response": {}
}
```

Use `--output-register-response` to print the stored state to stdout as well as
writing it to disk.

## Verify Registration

Read the local state file:

```bash
python3 - <<'PY'
import json
state = json.load(open('/tmp/datrail-guardian-registration.json'))
print(state['agent_id'])
print(state['sandbox_id'])
print(state['status'])
print(len(state['token']))
PY
```

Query Rail Center:

```bash
AGENT_ID="$(python3 - <<'PY'
import json
print(json.load(open('/tmp/datrail-guardian-registration.json'))['agent_id'])
PY
)"

curl -fsS "http://localhost:23001/v1/agents/$AGENT_ID" | python3 -m json.tool
curl -fsS "http://localhost:23001/v1/agents?limit=5" | python3 -m json.tool
```

Decode the returned token:

```bash
python3 - <<'PY'
import base64, json
state = json.load(open('/tmp/datrail-guardian-registration.json'))
print(json.dumps(json.loads(base64.b64decode(state['token']).decode()), indent=2))
PY
```

## Runtime Interaction Forwarding

RailMon emits Rail Center-compatible runtime events when started with
`--output-format runtime-interaction`:

```bash
python3 collector/collector.py \
  --mode http \
  --output-format runtime-interaction \
  --output examples/openclaw-monitoring/output/openclaw-runtime-interactions.jsonl
```

Each line contains `interaction_id`, `agent_id`, `x_rail_header`, request
method/path/destination, response status, `latency_ms`, and raw RailMon
metadata. `agent_id` is decoded from the captured `x-rail` header when present.

RailCollector forwards the JSONL stream to Rail Center:

```bash
python3 rail-guardian/rail-collector/rail_collector.py \
  --input examples/openclaw-monitoring/output/openclaw-runtime-interactions.jsonl \
  --follow \
  --center-url http://localhost:23001
```

The collector spools every event under
`.datrail/rail-guardian/rail-collector/pending/` before POSTing to Rail Center,
then deletes or moves the file after a 2xx response. This lets the process
survive temporary Rail Center outages without dropping captured interactions.

Verify ingestion:

```bash
curl -fsS "http://localhost:23001/v1/interactions?limit=10" | python3 -m json.tool
```

## Verified Run

The flow was tested against the real Rail Center API and real OpenClaw/NemoClaw
containers.

OpenClaw result:

| Check | Result |
| --- | --- |
| Rail Center API | `http://localhost:23001/docs` returned 200 |
| Migration | Alembic `upgrade head` completed from host checkout |
| Skills scan | `examples/openclaw-monitoring/output/openclaw-skills.json` contained 13 skills |
| Registration POST | `POST /v1/agents/register` returned HTTP 201 |
| Stored state | `/tmp/datrail-guardian-registration.json` contained UUID + token |
| Rail Center DB read | `GET /v1/agents/{id}` returned `sandbox_type=openclaw` and 13 skills |

NemoClaw skills scan result:

| Check | Result |
| --- | --- |
| Skills scan | `examples/nemoclaw-monitoring/output/nemoclaw-skills.json` contained 72 skills |

## Verified Runtime Forwarding

The RuntimeInteraction flow was tested against the real Rail Center API, real
OpenClaw and NemoClaw containers, RailMon eBPF capture, and RailCollector.

OpenClaw runtime result:

| Check | Result |
| --- | --- |
| Managed agent container | `openclaw-monitoring-openclaw-1` using Node.js 24 |
| RailMon command | `collector.py --mode http --output-format runtime-interaction` in the `datrail-agent-monitor` image |
| Trigger | OpenClaw container Node sent HTTPS `POST /v1/chat/completions` with `x-rail` |
| Capture output | `examples/openclaw-monitoring/output/openclaw-runtime-interactions.jsonl` contained 1 RuntimeInteraction |
| Header extraction | `agent_id=6854eb04-6a2f-4b99-83a7-db8d65cae4ea`, `x_rail_header` present |
| Timing | `latency_ms=0.755244` from RailMon request/response timestamps |
| RailCollector POST | `POST /v1/interactions` returned HTTP 201 |
| Idempotency replay | Reposting the same `interaction_id` returned HTTP 200 and Rail Center total stayed 1 |

NemoClaw runtime result:

| Check | Result |
| --- | --- |
| Managed agent container | `nemoclaw-monitoring-nemoclaw-1` using Node.js 22 |
| RailMon command | `collector.py --mode http --output-format runtime-interaction` in the `datrail-agent-monitor` image |
| Trigger | NemoClaw container Node sent HTTPS `POST /v1/chat/completions` with `x-rail` |
| Capture output | `examples/nemoclaw-monitoring/output/nemoclaw-runtime-interactions.jsonl` contained 1 RuntimeInteraction |
| Header extraction | `agent_id=c3eddd33-74e4-4af8-9eb7-9a7f5fbc1371`, `x_rail_header` present |
| Timing | `latency_ms=1.079157` from RailMon request/response timestamps |
| RailCollector POST | `POST /v1/interactions` returned HTTP 201 |
| Rail Center DB read | `GET /v1/interactions?agent_id=c3eddd33-74e4-4af8-9eb7-9a7f5fbc1371` returned total 1 |

The test used a local HTTPS OpenAI-compatible endpoint only as the LLM
destination; the monitored clients were the real OpenClaw and NemoClaw
containers, and the captured TLS plaintext came from RailMon eBPF hooks.

## Error Handling

Rail Guardian exits with code `2` for user-correctable registration errors.

Examples:

```text
agent-environment-scanner: --center-url or RAIL_CENTER_URL is required with --register
agent-environment-scanner: rail-center registration failed: <urlopen error [Errno 111] Connection refused>
agent-environment-scanner: rail-center registration failed: HTTP 500: Internal Server Error
```

If Rail Center returns HTTP 500 with `relation "agents" does not exist`, the API
is reachable but migrations have not been applied.

## Constraints

Rail Guardian only reports the discovered environment and skill inventory. It
does not prove that a skill is safe, does not perform static analysis of skill
implementation files, and does not capture interactions. Use `collector/` for
interaction capture.

Rail Center currently treats `system_info` and `user_info` as free-form JSON.
Rail Guardian fills stable keys, but Rail Center does not enforce a nested
schema for those fields yet.
