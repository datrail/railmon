# RC-74: RailMon To Runtime Monitor Integration

RC-74 / 4.9 connects RailMon's standard RuntimeInteraction output from RC-58
to Rail Center's Runtime Monitor ingestion endpoint:

```text
POST /v1/interactions
```

The integration was originally implemented in `datrail-agent-monitor` by
running RailCollector beside RailMon. After the repository split, RailMon owns
capture and JSONL output while RailCollector lives in `railscan`.

## Status

Implemented across the standalone `railmon` and `railscan` repositories.

Code:

| File | Responsibility |
| --- | --- |
| `collector/runtime_interaction.py` | Converts captured RailMon HTTP interactions into Rail Center RuntimeInteraction events. |
| `collector/collector.py` | Adds `--output-format runtime-interaction` and writes RuntimeInteraction JSONL. |
| `rail-guardian/rail-collector/rail_collector.py` | Reads RuntimeInteraction JSONL, durably spools events, and POSTs them to Rail Center `/v1/interactions`. |
| `rail-guardian/entrypoint.sh` | Starts RailMon and RailCollector together in the monitor sidecar/all-in-one container when `RAIL_CENTER_URL` is set. |

Related docs:

| Ticket | Document |
| --- | --- |
| RC-58 / 3.12 | `docs/rc-58-railmon-runtimeinteraction-output.md` |
| RC-75 / 4.10 | `docs/rc-75-railcollector-forwarding.md` |
| Unified runtime runbook | `docs/rail-center-runtime-integration.md` |

## Runtime Flow

```text
OpenClaw or NemoClaw agent
  sends HTTPS request to an OpenAI-compatible LLM endpoint

RailMon
  captures plaintext request/response through eBPF
  emits one RuntimeInteraction JSON object per line

RailCollector
  follows the RailMon JSONL file
  writes each valid event to local pending spool
  POSTs each event to Rail Center /v1/interactions

Rail Center Runtime Monitor
  validates and stores the RuntimeInteraction row
  exposes it through GET /v1/interactions
```

## RuntimeInteraction Payload

RailMon emits the RuntimeInteraction shape accepted by Rail Center:

```json
{
  "interaction_id": "railmon-...",
  "agent_id": "uuid-or-null",
  "x_rail_header": "base64-token-or-null",
  "timestamp": "2026-05-01T01:28:34.574764+00:00",
  "request": {
    "method": "POST",
    "path": "/v1/chat/completions",
    "destination": "host.docker.internal:8443"
  },
  "response": {
    "status": 200
  },
  "latency_ms": 95.27,
  "capture_source": "railmon",
  "raw": {}
}
```

Required field mapping:

| RuntimeInteraction field | Source |
| --- | --- |
| `interaction_id` | Stable RailMon-generated id. |
| `agent_id` | Decoded from captured `x-rail` header when present. |
| `x_rail_header` | Captured request `x-rail` header value when present. |
| `timestamp` | RailMon request timestamp. |
| `request.method` | Parsed HTTP request method. |
| `request.path` | Parsed HTTP request path. |
| `request.destination` | Request host, authority, or absolute URI host. |
| `response.status` | Parsed HTTP response status. |
| `latency_ms` | Response timestamp minus request timestamp in milliseconds. |

## Run With Rail Center

Start Rail Center from the `rail-center` repository with the runtime ingestion
API available:

```bash
cd $RAIL_WORKSPACE_HOME/rail-center/api
docker compose up -d --build db api
PYTHONPATH=src .venv/bin/alembic -c migrations/alembic.ini upgrade head
curl -fsS http://localhost:23001/health
```

Run RailMon in RuntimeInteraction mode:

```bash
cd $RAIL_WORKSPACE_HOME/datrail-agent-monitor
python3 collector/collector.py \
  --mode http \
  --sslsniff /usr/local/bin/sslsniff \
  --output-format runtime-interaction \
  --output output/runtime-interactions.jsonl
```

Run RailCollector against that output file:

```bash
RAIL_CENTER_URL=http://localhost:23001 \
python3 rail-guardian/rail-collector/rail_collector.py \
  --input output/runtime-interactions.jsonl \
  --follow \
  --center-url http://localhost:23001
```

Verify Rail Center ingestion:

```bash
curl -fsS "http://localhost:23001/v1/interactions?limit=10" | python3 -m json.tool
```

## Run As Monitor Sidecar

The sidecar/all-in-one container starts RailMon and RailCollector together. Set
`RAIL_CENTER_URL` to enable forwarding:

```bash
cd $RAIL_WORKSPACE_HOME/datrail-agent-monitor/examples/openclaw-monitoring
RAIL_CENTER_URL=http://localhost:23001 \
OPENAI_BASE_URL=https://host.docker.internal:8443/v1 \
OPENAI_API_KEY=sk-local \
NODE_TLS_REJECT_UNAUTHORIZED=0 \
docker compose up -d openclaw monitor
```

The same pattern applies to `examples/nemoclaw-monitoring`.

Runtime files:

| File | Purpose |
| --- | --- |
| `output/openclaw-runtime-interactions.jsonl` | RailMon RuntimeInteraction JSONL output. |
| `output/railmon.log` | RailMon capture logs. |
| `output/rail-collector.log` | RailCollector forwarding logs. |
| `.datrail/rail-guardian/rail-collector/pending/` | Durable pending spool for not-yet-delivered events. |

## End-To-End Verification

The integration was tested with real local services:

| Component | Runtime used |
| --- | --- |
| Rail Center | Local Docker Compose API and Postgres. |
| Agent | Real OpenClaw container. |
| LLM endpoint | Local `llama.cpp` OpenAI-compatible HTTPS server. |
| Capture | RailMon eBPF capture from the monitor container. |
| Forwarding | RailCollector POST to Rail Center `/v1/interactions`. |

Observed result:

| Check | Result |
| --- | --- |
| Agent traffic | OpenClaw sent real `POST /v1/chat/completions` requests to `host.docker.internal:8443`. |
| RailMon output | RuntimeInteraction JSONL contained captured request, response, destination, status, and latency. |
| RailCollector forwarding | RailCollector logged `forwarded ... status=201`. |
| Rail Center readback | `GET /v1/interactions?limit=20` returned the forwarded records. |
| Timing | Captured records included measured `latency_ms` values such as `95.27`. |
| Data loss | Delivered events were removed from pending spool after HTTP 201. |

The real OpenClaw plus `llama.cpp` run produced both successful and failed LLM
responses because the local TinyLlama context was intentionally small for a
lightweight test environment. This does not affect RC-74: both response classes
were captured by RailMon, forwarded by RailCollector, and stored by Rail Center.

## x-rail Limitation

RC-74 does not inject `x-rail`. It only preserves and forwards `x-rail` when
the managed agent or proxy sends it.

Current behavior:

| Case | Result |
| --- | --- |
| Request contains valid `x-rail` | RailMon sets `agent_id` and `x_rail_header`; Rail Center can query by agent id. |
| Request has no `x-rail` | RailMon still emits the event; RailCollector still forwards it; Rail Center stores it with `agent_id: null`. |

Managed OpenClaw/NemoClaw `x-rail` injection remains a separate managed-client
or MCP proxy task. It is not required for the RC-74 transport path to work, but
it is required if the demo must show interactions grouped under a registered
agent id.
