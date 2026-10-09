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
what Rail Center stores, and an integer (pid, tid, sizes, status code) outside
its 32-bit columns is left out, as is a `capture_start` that is not a real
date-time.

Events are grouped by capture session, in batches of at most `--batch-size`
(default 100, at most 1000) and 16 MiB of JSON. Each flush sends everything
pending, and a flush happens every `--flush-count` events (default 1), or
on the first event queued at least `--flush-interval` seconds after the last
flush (the interval is checked when an event arrives, not on a timer), so
with `--follow` raise `--flush-count` to get bigger batches, knowing that
events then wait for the next one to arrive. Rail Center answers 202 with `recorded`, `duplicates` and
`conflicts` counts, which the forwarder logs.

A batch refused with 413 or 422 is halved and each half retried, so one bad
item does not hold the rest back; an item refused on its own moves to
`<spool>/rejected/`. A 5xx is not split: the whole batch stays pending and is
retried at the next flush, since a server error may pass.
[`tests/fixtures/rail-center/`](../../tests/fixtures/rail-center/) holds a
vendored copy of Rail Center's schema for this body and a fixture checked
against it.

## Durable spool

Every valid event is written to `<spool>/pending/` before it is sent, and the
file is deleted once Rail Center answers 2xx (`--keep-sent` moves it to
`<spool>/sent/` instead). An event that fails for a reason that may pass
(unreachable, a redirect, a 5xx) stays pending and is retried at every later
flush and on the next start; one Rail Center refuses outright (413/422, on its
own) moves to `<spool>/rejected/`. `--drain-only` resends what is pending
without reading new input. Replaying an event is safe: its `interaction_id`
is the item's `idempotency_key`, so Rail Center records it once.

The spool defaults to `.rail/railmon/forward/` (relative to the working
directory; `--spool-dir` sets it). It used to be
`.datrail/rail-guardian/rail-collector/`, from when this forwarder was
RailScan's `rail-collector`: where that directory exists and the new one does
not, it is still used, with a deprecation note on stderr, so events pending
from before an upgrade are delivered rather than stranded.

## Old names

`railmon rail-collector` and `rail-collector/rail_collector.py` still work as
deprecated aliases for `railmon forward` and `tools/forward/forward.py`.
