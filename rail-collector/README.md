# rail-collector (deprecated path)

The forwarder that lived here is now `railmon forward`, with its source in
[`tools/forward/`](../tools/forward/). `rail_collector.py` in this directory is
a symlink to `tools/forward/forward.py`, kept so existing scripts and
deployments that call the old path keep working; new ones should use
`railmon forward` or the new path. The old README is kept, as a historical
record, at [docs/archive/rail-collector-README.md](../docs/archive/rail-collector-README.md).
