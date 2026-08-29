# RailMon

RailMon is DatRail's agent-observability component. One image, four jobs:

| command | what it does |
| --- | --- |
| `collect` *(default)* | capture decrypted TLS traffic, pair requests with responses, attribute each to an agent, emit JSONL or Rail Center events |
| `scan` | inventory an agent's host, model configuration, skills and MCP tools into a local feature file |
| `skills` | inventory OpenClaw / NemoClaw `SKILL.md` files |
| `forward` | send captured interactions on to Rail Center |

`collect` sees what an agent actually did; `scan` sees how it was set up.

The scanner and the forwarder moved here from `datrail/railscan` under DR-84 so
a deployment pulls one container instead of two. RailScan's command names are
still accepted as aliases, and `railmon --mode http …` — the collector invoked
with a flag first, as the previous image expected — still means what it did.

## Quick start

One command from a clean checkout. No cloud, no account, no Rail Center — and
nothing to point it at: `railmon demo` scans this container itself for the
inventory half, and taps a small local, offline HTTPS exchange it starts
itself for the capture half, so there is something to show without a real
agent running yet. See "Platforms" below for what this needs from the host.

```bash
git clone https://github.com/datrail/railmon.git
cd railmon
make demo
```

`make demo` builds the image and runs it once, privileged and with the host's
PID namespace — the same requirements `collect` always has, because the demo
capture goes through the same eBPF tap real traffic would. It writes into
`./out/`:

```bash
docker run --rm --privileged --pid=host -v $(pwd)/out:/out railmon demo
```

**You should see** `railmon demo` print three steps and then a summary line
naming how many interactions it captured (at least one; the demo pair makes
three requests, so a slow first attach can still show as non-empty). In
`./out/`:

- `features.json` — a non-empty inventory of this container: its `environment`,
  declared `skills`, and identity. Re-running `make demo` replaces this file
  rather than growing it (the scanner truncates on write), so a second run
  never duplicates the inventory.
- `capture.jsonl` — a non-empty capture with at least one interaction: host
  `127.0.0.1:8443`, method `POST`, path `/v1/demo` or `/v1/demo/other`, status
  `200`. Unlike `features.json`, this one **appends** — the collector's output
  file is a log, so a second `make demo` adds another run's interactions
  rather than replacing them. That is expected, not a bug: it is real captured
  traffic, and re-running does not duplicate an existing line, it captures a
  new one.

If `capture.jsonl` comes up empty, the demo prints the collector's own log —
see "Troubleshooting the demo" below before assuming something is broken.

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
| **Delivery** | JSONL file and/or batched webhook; payloads split at 16 MiB after JSON escaping and at RailDash's structure bound |

The dependency is a caret requirement and the image downloads the AgentSight
binary unpinned, both deliberate: we track upstream rather than freeze it.

## Build

```bash
make build           # cargo build --release
make fetch-agentsight   # only to run outside the container
```

## Run

Capture requires root or equivalent eBPF capabilities:

The four commands are dispatched by the image's entrypoint, so they are how you
drive the **container**:

```bash
docker run --rm --privileged --pid=host railmon collect --mode http
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  railmon scan --mode docker --container openclaw-1
docker run --rm railmon                       # lists the four commands
```

Built from source you get the collector binary alone — `cargo build` produces
`target/release/railmon`, which takes the collector's flags and knows nothing
about `scan` or `skills`:

```bash
sudo ./target/release/railmon --mode http --output captured.jsonl
```

The scanner and forwarder are plain Python and run directly:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py --mode self
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

`railmon help` lists the four commands; `railmon --help` shows the collector's
flags, which are unchanged from the Python implementation, so existing compose
files and run scripts keep working.

## Docker

```bash
docker build -t railmon .
docker run --rm --privileged --pid=host -v /sys:/sys:ro railmon \
  --mode http --binary-path /proc/1/exe
```

The exact PID namespace, target binary path, and mounts depend on the monitored
agent deployment. Reference deployment configuration belongs in
`agent-hardening`, not in this component repository.

## Platforms

`collect` (and therefore `demo`) needs a Linux kernel with BTF/CO-RE and runs
privileged — that is AgentSight's requirement, not a RailMon choice, and it
does not relax for a local run.

- **Linux** — works natively, provided the kernel ships BTF (`/sys/kernel/btf/vmlinux`
  exists; most distributions from the last few years have this on by default).
- **WSL2 (Windows)** — this is a real Linux kernel, so it works the same as
  Linux. WSL1 does not: it has no Linux kernel for eBPF to attach to.
- **macOS** — Docker Desktop runs containers inside a Linux VM, so `collect`
  attaches inside that VM, not on the Mac. It sees the VM's own processes.
  Traffic from a process running directly on macOS, outside the VM, is not
  visible to it — only agents already running inside a container are.
- **Architecture** — the image's collector is built for whatever platform
  builds it, but AgentSight itself ships an **x86_64 release binary only**
  (see the Dockerfile). On arm64 (Apple Silicon, arm64 Linux) the image builds
  and `scan`/`skills`/`forward` all work — only `collect` and `demo` have
  nothing to run and fail with a clear "probe not found" error rather than a
  silent no-op.

`scan --mode self`, `scan --mode docker`, `skills`, and `forward` have none of
these requirements — they read the filesystem, environment, or a Docker
socket, and run unprivileged, anywhere Python does.

## Troubleshooting the demo

`railmon demo` is new orchestration (`tools/local-demo/`) wired through eBPF,
which is inherently the least predictable part of this repository to get
right without a machine that can actually run it. If `./out/capture.jsonl`
comes up empty:

- **`.collector.log` inside `./out/`** (printed automatically on failure) is
  the first thing to read — it is the collector's own stderr, and "probe not
  found" or a probe attach error will say so directly.
- **Nothing captured, no error** — the three demo requests may have finished
  before the eBPF probe finished attaching. `run_local_demo.sh` already waits
  for the collector's own "agentsight at …" log line plus one extra second
  before generating traffic; if that is still not enough on a particular
  machine, raise the `sleep 1` after that wait (search for it in
  `tools/local-demo/run_local_demo.sh`) to `sleep 2` or `3`.
- **"probe not found"** — see "Platforms" above; this means no AgentSight
  binary shipped for this architecture.
- **Everything else works but `collect`/`demo` refuses to start** — check the
  container actually got `--privileged --pid=host`; `make demo` passes both,
  but a hand-rolled `docker run` that drops either will fail the same way
  `collect` always has.

## Environment

[`.env.example`](.env.example) is the complete inventory of environment
variables RailMon uses for its own configuration and the well-known agent
settings its scanner recognizes. Every value is blank: copy only the settings
the deployment owns into `.env`, which Git ignores. RailMon does not load the
file implicitly; export selected values for a source run or pass it explicitly
with `docker run --env-file .env`.

Ambient process identity such as `HOME`, `USER` and `LOGNAME` is intentionally
not repeated there. The scanner records those as observations of its subject;
they are not RailMon configuration. Likewise, `RAIL_SANDBOX_NAME` is not an
environment input: set `scan --sandbox-name` or the `rail.sandbox_name`
container label so an unconfigured agent can still be discovered honestly.

Images are published to `ghcr.io/datrail/railmon` on a release tag, by CI —
`git tag v0.1.0 && git push origin v0.1.0`.

## Validation

```bash
make test          # everything below
make test-rust     # cargo fmt --check, clippy -D warnings, cargo test
make test-python   # py_compile, each subcommand's --help, the scanner's 80 tests
```

`interaction_id` is a content hash, so the test suite pins it against the value
the Python implementation produced. If that assertion ever fails, ids already
stored in Rail Center have stopped correlating with newly captured ones.

`make test-python` compiles and lint-checks `tools/local-demo/` along with
everything else, but `make demo` itself is not part of `make test` — it needs
a privileged, `--pid=host` container on a BTF-capable kernel, which CI does
not provide. Treat a green `make test` and a successful `make demo` as two
separate signals.

## License

MIT; see [LICENSE](LICENSE).
