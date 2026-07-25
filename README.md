# RailMon

RailMon captures decrypted TLS traffic from AI-agent processes using
[AgentSight](https://github.com/eunomia-bpf/agentsight), parses HTTP
request/response pairs, redacts common credential headers, and emits JSON Lines
or Rail Center `RuntimeInteraction` events.

## Dependency model

Download the [AgentSight](https://github.com/eunomia-bpf/agentsight) binary:

```bash
mkdir -p bin
curl -fsSL -o bin/agentsight \
  https://github.com/eunomia-bpf/agentsight/releases/latest/download/agentsight
chmod +x bin/agentsight
# or: make fetch-agentsight
```

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

See `python3 collector/collector.py --help` and [docs/](docs/) for the full
capture and output contract.

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
