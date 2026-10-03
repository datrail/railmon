# railmon forward

`railmon forward` sends the RuntimeInteraction JSONL that the collector writes
(`--output-format runtime-interaction`) on to Rail Center's
`POST /v1/interactions`, one event per request. It is standard-library Python
and needs no eBPF privilege.

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
