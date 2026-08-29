# Contributing to RailMon

RailMon is the runtime-interaction collector in
[DatRail](https://github.com/datrail). It spawns AgentSight, pairs the HTTP it
reconstructs into interactions, attributes each one to an agent from its
`x-rail` ticket, and forwards them.

Where RailScan sees an agent's static setup, RailMon sees what it actually did.

## What is ours and what is upstream's

Read this before proposing a change, because it decides where a fix belongs.

The hard part — reconstructing HTTP from raw SSL reads and writes, SSE
reassembly, gzip, chunked transfer-encoding, truncation, credential redaction —
is **AgentSight's**, consumed as the `agentsight-capture` library. RailMon used
to carry its own 786-line implementation of that; keeping a second copy in step
with upstream was all cost.

What is ours: **pairing** (a FIFO per `(pid, tid)`), **attribution** (reading
the `x-rail` ticket), the **Rail Center schema**, and **delivery**.

A parsing bug most likely belongs upstream. Say so in the issue and we will
help route it.

## The one thing that will get a change declined

**A credential must not reach the output.** The chain redacts header values and
`HTTPParser` is constructed with `disable_raw_data()` so the original wire text
never travels; `message_body` drops `raw_data`, `body_hex` and `data_hex` — though only on the
paired path, since `--mode raw` serialises the event directly, which is why the
redactor is an analyzer in the chain rather than a step in pairing. Both were once wrong at the same time, and the tests
could not see it because they fed the pairing stage synthetic data.

If you touch the analyzer chain, verify against a probe that emits a real bearer
token and check the token appears nowhere in the output — in **both** `--mode
http` and `--mode raw`.

## Development

```bash
make test          # cargo fmt --check, clippy -D warnings, and the unit tests
make fetch-agentsight   # only needed to run outside the container
```

## Testing the seam, not just the parts

Every defect this collector has shipped lived at the boundary between our code
and the library, where no unit test reached:

- the probe emits an **envelope** with sslsniff fields nested under `data`;
  feeding it to a parser expecting them flat produced a collector that ran
  happily and captured nothing;
- `timestamp_ns` is `bpf_ktime_get_ns()` — nanoseconds since **boot**. Dropping
  the conversion dated every interaction to 1970, and latency still looked
  correct because the offset cancels in a subtraction.

So: drive the real binary against a fake probe emitting real envelopes, and
assert against an external oracle — the host's actual uptime, the consumer's
actual schema — not against what the code currently does.

## Sending a change

- One coherent change per pull request; the message says *why*.
- Branch from `master`, **sign off your commits** (`git commit -s`,
  [DCO](https://developercertificate.org/)), no CLA.
- CI runs `make test` and builds the image (amd64 on a pull request; both
  architectures on a release tag). Both jobs must pass.

## Reporting a vulnerability

Not here — see [SECURITY.md](SECURITY.md).
