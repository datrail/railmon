# RC-58: RailMon RuntimeInteraction Output Format

RC-58 defines the standard output format that RailMon emits for Rail Center.
The output must match the `RuntimeInteractionInput` payload accepted by Rail
Center `POST /v1/interactions`.

This document only covers RailMon formatting. RailCollector forwarding is
covered by `rail-guardian/rail-collector/README.md` and RC-43.

## Status

Implemented in `datrail-agent-monitor`.

Code:

| File | Responsibility |
| --- | --- |
| `collector/collector.py` | Adds `--output-format runtime-interaction` and writes RuntimeInteraction JSONL. |
| `collector/runtime_interaction.py` | Converts RailMon parsed HTTP interactions into Rail Center RuntimeInteraction events. |

## Command

Run RailMon in RuntimeInteraction output mode:

```bash
python3 collector/collector.py \
  --mode http \
  --sslsniff /usr/local/bin/sslsniff \
  --output-format runtime-interaction \
  --output runtime-interactions.jsonl
```

`runtime-interactions.jsonl` contains one JSON object per captured HTTP
request/response pair.

The default output format remains `legacy-http` to preserve existing RailMon
behavior:

```bash
python3 collector/collector.py --mode http --output captured.jsonl
```

## RuntimeInteraction JSON

RailMon emits this shape:

```json
{
  "interaction_id": "railmon-0cf69dfedd549e73a79559612e234447fab17101",
  "agent_id": "6854eb04-6a2f-4b99-83a7-db8d65cae4ea",
  "x_rail_header": "base64-x-rail-token",
  "timestamp": "2026-05-01T01:28:34.574764+00:00",
  "request": {
    "method": "POST",
    "path": "/v1/chat/completions",
    "destination": "api.openai.com"
  },
  "response": {
    "status": 200
  },
  "latency_ms": 0.755244,
  "capture_source": "railmon",
  "raw": {}
}
```

Required contract fields for Rail Center:

| Field | Type | Source |
| --- | --- | --- |
| `interaction_id` | string | Stable RailMon-generated id based on session, timing, process, request, and response metadata. |
| `agent_id` | UUID string or null | Decoded from the captured `x-rail` request header. |
| `x_rail_header` | string or null | Captured `x-rail` request header value. |
| `timestamp` | ISO-8601 string | RailMon request timestamp. |
| `request.method` | string | Parsed HTTP request method. |
| `request.path` | string | Parsed HTTP request path. |
| `request.destination` | string | Request `Host` header, `:authority` header, or absolute URI host. |
| `response.status` | integer or null | Parsed HTTP response status code. |
| `latency_ms` | number or null | Response timestamp minus request timestamp, in milliseconds. |

Additional fields:

| Field | Purpose |
| --- | --- |
| `capture_source` | Always `railmon` for RailMon-emitted events. |
| `raw` | Original RailMon parsed interaction plus session metadata for debugging and auditability. |

## x-rail Header Handling

Rail Center registration returns an `x-rail` token. Managed agents, proxies, or
callers should send it as:

```http
x-rail: <base64-json-token>
```

RailMon reads the captured request headers and decodes the token as URL-safe
base64 JSON. If the token contains `agent_id`, RailMon normalizes it as a UUID
string and sets:

```json
{
  "agent_id": "uuid",
  "x_rail_header": "<original header value>"
}
```

If `x-rail` is missing or invalid, RailMon still emits the interaction:

```json
{
  "agent_id": null,
  "x_rail_header": null
}
```

This preserves runtime visibility but Rail Center cannot associate the
interaction with a registered agent unless another component supplies the
identity.

## Timing

RailMon computes `latency_ms` from the eBPF event timestamps:

```text
latency_ms = (response_timestamp_ns - request_timestamp_ns) / 1_000_000
```

If either timestamp is missing or invalid, `latency_ms` is null.

## Destination Resolution

RailMon resolves `request.destination` in this order:

1. Absolute request URI host, when the HTTP request line contains an absolute URI.
2. Request `Host` header.
3. Request `:authority` header.
4. `unknown`.

Examples:

| Request input | Destination |
| --- | --- |
| `POST https://api.openai.com/v1/chat/completions HTTP/1.1` | `api.openai.com` |
| `POST /v1/chat/completions HTTP/1.1` with `Host: api.openai.com` | `api.openai.com` |
| Missing host information | `unknown` |

## Rail Center Compatibility

The emitted JSON matches Rail Center `RuntimeInteractionInput`:

```text
POST /v1/interactions
```

RailMon itself only writes JSONL. Posting to Rail Center is handled by
RailCollector in RC-43.

## Verified Output

The RuntimeInteraction output format was tested with real RailMon eBPF capture
against real OpenClaw and NemoClaw containers.

OpenClaw output check:

| Check | Result |
| --- | --- |
| Captured request | `POST /v1/chat/completions` |
| `agent_id` | `6854eb04-6a2f-4b99-83a7-db8d65cae4ea` |
| `x_rail_header` | Present |
| `request.destination` | `mock-api:8443` |
| `response.status` | `200` |
| `latency_ms` | `0.755244` |

NemoClaw output check:

| Check | Result |
| --- | --- |
| Captured request | `POST /v1/chat/completions` |
| `agent_id` | `c3eddd33-74e4-4af8-9eb7-9a7f5fbc1371` |
| `x_rail_header` | Present |
| `request.destination` | `host.docker.internal:8443` |
| `response.status` | `200` |
| `latency_ms` | `1.079157` |

The LLM destination in the verification run was a local HTTPS
OpenAI-compatible endpoint to avoid requiring real provider keys. The monitored
OpenClaw/NemoClaw containers and RailMon eBPF capture were real.
