# RailMon

RailMon captures decrypted TLS traffic from AI-agent processes, parses HTTP
request/response pairs, redacts common credential headers, and emits JSON Lines
or Rail Center `RuntimeInteraction` events.

## Build

```bash
make fetch-agentsight
```

## Run

Capture requires root or equivalent eBPF capabilities:

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

MIT; see [LICENSE](LICENSE).

Using [AgentSight](https://github.com/eunomia-bpf/agentsight).
