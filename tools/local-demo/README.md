# tools/local-demo

Backs `railmon demo`, the local quickstart added for [DR-48](https://railxia.atlassian.net/browse/DR-48)
(BDL-F4 — RailMon deployable locally on its own). Nothing here is used by
`collect`, `scan`, `skills`, or `forward` outside of this one command.

RailDash's local quickstart could ship a static capture file to read on first
run. RailMon has no equivalent: `collect` taps *live* traffic, so a clean
checkout has nothing to show until some agent is running under it. This
directory gives it one, self-contained and offline:

- `demo_server.py` — a stdlib HTTPS server on `127.0.0.1:8443` that answers a
  fixed JSON response.
- `demo_client.py` — issues a few HTTPS requests to it, certificate
  verification off (the server's cert is a fresh, throwaway self-signed one
  every run — see `run_local_demo.sh`).
- `run_local_demo.sh` — the orchestrator `railmon demo` execs: self-scan for
  the inventory, then start the server, start the collector tapping
  `--comm python3`, run the client, stop the collector, and report what it
  wrote.

`--comm python3` is host-wide within the container's PID namespace — it is
not scoped to just these two processes, because the collector's `--pid` flag
only accepts one PID and the demo has two. In the few seconds the demo runs,
this is a reasonable trade for simplicity; it is not a pattern to copy for a
real deployment, which should filter by the actual agent's identity.
