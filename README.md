# RailMon

RailMon captures decrypted TLS traffic from AI-agent processes using
[AgentSight](https://github.com/eunomia-bpf/agentsight), parses HTTP
request/response pairs, redacts common credential headers, and emits JSON Lines
or Rail Center `RuntimeInteraction` events.

## Dependency model

RailMon downloads a pinned **AgentSight** release binary (`bin/agentsight`) and
runs `agentsight debug ssl` as a subprocess. No eBPF source tree or git submodule
is required.

```bash
git clone https://github.com/datrail/railmon.git
cd railmon
make fetch-agentsight
```

Override the pin with `AGENTSIGHT_VERSION=vX.Y.Z make fetch-agentsight`, or point
`AGENTSIGHT_PATH` / `--agentsight` at an existing binary.

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

Use `--agentsight /path/to/agentsight` or `AGENTSIGHT_PATH` to override the
downloaded binary. See `python3 collector/collector.py --help` and [docs/](docs/)
for the full capture and output contract.

## Docker

```bash
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

RailMon's Python code is MIT; see [LICENSE](LICENSE). AgentSight is a separate
upstream project with its own license terms.
