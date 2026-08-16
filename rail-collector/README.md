# RailCollector

RailCollector forwards RailMon runtime interaction events to Rail Center.

It reads JSONL produced by:

```bash
python3 collector/collector.py \
  --mode http \
  --output-format runtime-interaction \
  --output /var/log/agent-monitor/runtime-interactions.jsonl
```

and POSTs every event to:

```text
POST /v1/interactions
```

## Event Contract

RailCollector expects each JSONL line to match the Rail Center
`RuntimeInteractionInput` payload:

```json
{
  "interaction_id": "railmon-...",
  "agent_id": "uuid-or-null",
  "x_rail_header": "base64-token-or-null",
  "timestamp": "2026-05-01T01:00:00+00:00",
  "request": {
    "method": "POST",
    "path": "/v1/chat/completions",
    "destination": "api.openai.com"
  },
  "response": {
    "status": 200
  },
  "latency_ms": 128.4,
  "capture_source": "railmon",
  "raw": {}
}
```

RailMon derives `agent_id` from the captured `x-rail` header when that header is
present. If a managed client does not inject `x-rail`, RailCollector still
forwards the event with `agent_id=null` and stores the captured header as
`x_rail_header=null`.

## Durable Forwarding

RailCollector spools every valid event to disk before sending it to Rail Center:

```text
.datrail/rail-guardian/rail-collector/pending/
```

After Rail Center returns HTTP 2xx, the pending file is deleted. Use
`--keep-sent` to move delivered files to:

```text
.datrail/rail-guardian/rail-collector/sent/
```

This avoids data loss when Rail Center is temporarily unreachable. Re-run with
`--drain-only` to resend pending files without reading a new RailMon input file.

## Run With Rail Center

Start Rail Center and apply migrations from the `rail-center/api` checkout:

`$RAIL_WORKSPACE_HOME` is where `dev-toolkits/dev-setup.sh` clones the repositories as flat siblings; it defaults to `~/workspace`.

```bash
cd $RAIL_WORKSPACE_HOME/rail-center/api
docker compose up -d db api
PYTHONPATH=src uv run --python 3.13 alembic -c migrations/alembic.ini upgrade head
```

Then run RailMon and RailCollector from the `datrail-agent-monitor` checkout.

OpenClaw:

```bash
cd $RAIL_WORKSPACE_HOME/datrail-agent-monitor
mkdir -p examples/openclaw-monitoring/output

sudo python3 collector/collector.py \
  --mode http \
  --sslsniff /usr/local/bin/sslsniff \
  --output-format runtime-interaction \
  --output examples/openclaw-monitoring/output/openclaw-runtime-interactions.jsonl

python3 rail-collector/rail_collector.py \
  --input examples/openclaw-monitoring/output/openclaw-runtime-interactions.jsonl \
  --follow \
  --center-url http://localhost:23001
```

NemoClaw:

```bash
cd $RAIL_WORKSPACE_HOME/datrail-agent-monitor
mkdir -p examples/nemoclaw-monitoring/output

sudo python3 collector/collector.py \
  --mode http \
  --sslsniff /usr/local/bin/sslsniff \
  --output-format runtime-interaction \
  --output examples/nemoclaw-monitoring/output/nemoclaw-runtime-interactions.jsonl

python3 rail-collector/rail_collector.py \
  --input examples/nemoclaw-monitoring/output/nemoclaw-runtime-interactions.jsonl \
  --follow \
  --center-url http://localhost:23001
```

For Docker sidecars, set RailMon's command to include
`--output-format runtime-interaction`, mount the output directory into a
RailCollector process, and point RailCollector at the host or service URL for
Rail Center:

```bash
RAIL_CENTER_URL=http://host.docker.internal:23001 \
python3 rail-collector/rail_collector.py \
  --input /var/log/agent-monitor/runtime-interactions.jsonl \
  --follow
```

## Verify

Check that Rail Center ingested events:

```bash
curl -fsS "http://localhost:23001/v1/interactions?limit=10" | python3 -m json.tool
```

If the managed agent injected `x-rail`, verify:

```bash
curl -fsS "http://localhost:23001/v1/interactions?limit=10" \
  | python3 -c 'import json,sys; data=json.load(sys.stdin); print([(i["agent_id"], bool(i["x_rail_header"])) for i in data["interactions"]])'
```

## Verified Real Runs

This tool was tested with real OpenClaw and NemoClaw containers, RailMon eBPF
capture, and the local Rail Center API.

OpenClaw:

```text
RailMon captured: POST /v1/chat/completions -> 200
JSONL file: examples/openclaw-monitoring/output/openclaw-runtime-interactions.jsonl
RailCollector: POST /v1/interactions -> HTTP 201
Rail Center query: total=1, x_rail_header present, latency_ms=0.755244
Replay same interaction_id: HTTP 200, total remained 1
```

NemoClaw:

```text
RailMon captured: POST /v1/chat/completions -> 200
JSONL file: examples/nemoclaw-monitoring/output/nemoclaw-runtime-interactions.jsonl
RailCollector: POST /v1/interactions -> HTTP 201
Rail Center query: total=1, x_rail_header present, latency_ms=1.079157
```
