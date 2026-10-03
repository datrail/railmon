# railmon forward

`railmon forward` sends the RuntimeInteraction JSONL that the collector writes
(`--output-format runtime-interaction`) on to Rail Center's
`POST /v1/interactions`, in batches. It is standard-library Python and needs no
eBPF privilege.

```bash
docker run --rm -v "$PWD/out:/out" -e RAIL_CENTER_URL=http://rail-center:23001 \
  railmon forward --input /out/runtime-interactions.jsonl --follow
```

From a checkout, the same command is `python3 tools/forward/forward.py …`.
`--center-url` overrides `RAIL_CENTER_URL`; the credential it presents is the
one `RAIL_AUTH_MODE` names, as described in the [top-level README](../../README.md).

## Input

Each line is one event. An event needs `interaction_id`, `timestamp`, a
`request` object with `method`, `path` and `destination`, and a `response`
object; a line that does not parse or lacks those is skipped with a message
on stderr. `--input -` (the default) reads stdin; `--follow` keeps reading a
file as the collector appends to it.

## What Rail Center receives

Rail Center's `/v1/interactions` takes one capture run's interactions in an
`InteractionBatchRequest` envelope, each item an `HttpInteractionPayload`:

```json
{
  "session_id": "<raw.railmon_session_id>",
  "agent": "railmon",
  "capture_start": "<raw.railmon_capture_start>",
  "interactions": [
    {
      "timestamp": "2026-05-01T01:00:00+00:00",
      "pid": 4021, "tid": 4033,
      "request": {"method": "POST", "path": "/v1/chat/completions", "headers": {}, "body": {}},
      "response": {"status_code": 200, "headers": {}, "body": {}, "is_sse": false},
      "latency_ms": 128.4,
      "request_size": 512, "response_size": 4096,
      "idempotency_key": "railmon-..."
    }
  ]
}
```

Each item is built from the event's `raw` interaction, the same object the
collector's own `--webhook` sends, so the captured headers (`x-rail`
included) reach Rail Center's agent matching. `idempotency_key` is the
event's `interaction_id`. A keyed event's `runtime_identity_version`,
`agent_ref` and `attribution` ride along, except that a null `method` or
`reason` is left out, as Rail Center's published schema requires. A path
longer than 2048 characters or a session id longer than 64 is trimmed to
what Rail Center stores.

Events are grouped by capture session, in batches of at most `--batch-size`
(default 100, at most 1000) and 16 MiB of JSON. Each flush sends everything
pending, and a flush happens every `--flush-count` events (default 1) or
`--flush-interval` seconds, so with `--follow` raise `--flush-count` to get
bigger batches. Rail Center answers 202 with `recorded`, `duplicates` and
`conflicts` counts, which the forwarder logs.

A batch refused with 413 or 422, or failing with a 5xx, is halved and each
half retried, so one bad item does not hold the rest back. An item refused
on its own (413/422) moves to `<spool>/rejected/`; one that gets a 5xx on its
own stays pending, since the error may pass.
[`tests/fixtures/rail-center/`](../../tests/fixtures/rail-center/) holds a
vendored copy of Rail Center's schema for this body and a fixture checked
against it.

## Durable spool

Every valid event is written to `<spool>/pending/` before it is sent, and the
file is deleted once Rail Center answers 2xx (`--keep-sent` moves it to
`<spool>/sent/` instead). An event that fails stays pending and is retried at
every later flush and on the next start; `--drain-only` resends what is
pending without reading new input. Replaying the same `interaction_id` is safe: Rail Center treats it as
the same interaction.

The spool defaults to `.rail/railmon/forward/` (relative to the working
directory; `--spool-dir` sets it). It used to be
`.datrail/rail-guardian/rail-collector/`, from when this forwarder was
RailScan's `rail-collector`: where that directory exists and the new one does
not, it is still used, with a deprecation note on stderr, so events pending
from before an upgrade are delivered rather than stranded.

## Old names

`railmon rail-collector` and `rail-collector/rail_collector.py` still work as
deprecated aliases for `railmon forward` and `tools/forward/forward.py`.
