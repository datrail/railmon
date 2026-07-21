# RailMon

RailMon captures decrypted TLS traffic from AI-agent processes with
`ebpf-tls-tap`, parses HTTP request/response pairs, redacts common credential
headers, and emits JSON Lines or Rail Center `RuntimeInteraction` events.

## Dependency model

`ebpf-tls-tap` is pinned as a git submodule. At runtime its `sslsniff` binary is
a RailMon subprocess. Clone recursively so the eBPF source and its nested
`libbpf`/`bpftool` dependencies are present:

```bash
git clone --recursive https://github.com/railxia/railmon.git
cd railmon
make build-ebpf
```

This commit pin is the initial reproducible integration contract. Publishing
signed multi-architecture eBPF release artifacts can replace it later without
folding the two repositories back together.

## Run

Capture to a local file (root or equivalent eBPF capabilities are required):

```bash
sudo python3 collector/collector.py \
  --mode http \
  --output captured.jsonl
```

Emit Rail Center's runtime interaction format:

```bash
sudo python3 collector/collector.py \
  --mode http \
  --output-format runtime-interaction \
  --output runtime-interactions.jsonl
```

Use `--sslsniff /path/to/sslsniff` or `SSLSNIFF_PATH` to override the pinned
binary. See `python3 collector/collector.py --help` and [docs/](docs/) for the
full capture and output contract.

## Docker

```bash
git submodule update --init --recursive
docker build -t railmon .
docker run --rm --privileged --pid=host -v /sys:/sys:ro railmon \
  --mode http --binary-path /proc/1/exe
```

The exact PID namespace, target binary path, and mounts depend on the monitored
agent deployment. Reference deployment configuration belongs in
`agent-hardening`, not in this component repository.

## Validation

```bash
make test
```

## License

RailMon's Python code is MIT; see [LICENSE](LICENSE). The eBPF submodule has
additional file-level license terms documented in its own repository.
