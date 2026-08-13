# RailMon

RailMon captures decrypted TLS traffic from AI-agent processes, pairs HTTP
requests with their responses, attributes each interaction to an agent, and
emits JSON Lines or Rail Center `RuntimeInteraction` events.

Where RailScan sees an agent's static setup, RailMon sees what it actually did.

## What is ours and what is AgentSight's

The hard part of reading agent traffic — reconstructing HTTP from raw SSL reads
and writes, reassembling SSE streams, gzip, chunked transfer-encoding,
truncation, and stripping `Authorization` before anything leaves the process —
is [AgentSight](https://github.com/eunomia-bpf/agentsight)'s, consumed as the
`agentsight-capture` library rather than reimplemented here. RailMon used to
carry its own 786-line HTTP/SSE parser; keeping a second implementation of that
in step with upstream was the whole cost and none of the value.

What remains RailMon's own is the part AgentSight has no opinion about:

| | |
| --- | --- |
| **Pairing** | a FIFO per `(pid, tid)`, so concurrent threads do not steal each other's responses and latency is measured against the right request |
| **Attribution** | reads the `x-rail` ticket and resolves an `agent_id`, so an interaction can be tied to a registered agent |
| **Rail Center schema** | `RuntimeInteraction`, including the content-hashed `interaction_id` |
| **Delivery** | JSONL file and/or batched webhook |

The dependency is a caret requirement and the image downloads the AgentSight
binary unpinned, both deliberate: we track upstream rather than freeze it.

## Build

```bash
make build           # cargo build --release
make fetch-agentsight   # only to run outside the container
```

## Run

Capture requires root or equivalent eBPF capabilities:

```bash
sudo railmon --mode http --output captured.jsonl
```

The default `legacy-http` format is the one Rail Center ingests: `POST
/v1/interactions` accepts `HttpInteractionPayload`, and RailMon sends it inside
the `InteractionBatchRequest` envelope the endpoint requires.

There is also `--output-format runtime-interaction`, which emits the shape
`docs/rc-58` describes:

```bash
sudo railmon \
  --mode http \
  --output-format runtime-interaction \
  --output runtime-interactions.jsonl
```

**It has no consumer today.** Rail Center exposes no RuntimeInteraction
endpoint, and posting this shape to `/v1/interactions` returns 202 while
storing a row with no headers — so `agent_id` is never resolved from `x-rail`
and the interaction is attributed to nobody. Use it for a local file if you
want the richer shape; do not point it at a webhook until the control-plane
side is settled.

`railmon --help` has the full surface. The flags are unchanged from the Python
implementation, so existing compose files and run scripts keep working.

## Docker

```bash
docker build -t railmon .
docker run --rm --privileged --pid=host -v /sys:/sys:ro railmon \
  --mode http --binary-path /proc/1/exe
```

The exact PID namespace, target binary path, and mounts depend on the monitored
agent deployment. Reference deployment configuration belongs in
`agent-hardening`, not in this component repository.

Images are published to `ghcr.io/datrail/railmon` on a release tag, by CI —
`git tag v0.1.0 && git push origin v0.1.0`.

## Validation

```bash
make test    # cargo fmt --check, clippy -D warnings, cargo test
```

`interaction_id` is a content hash, so the test suite pins it against the value
the Python implementation produced. If that assertion ever fails, ids already
stored in Rail Center have stopped correlating with newly captured ones.

## License

MIT; see [LICENSE](LICENSE).
