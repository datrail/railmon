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

**This is why three requests produce six interactions.** Both ends of each
exchange are `python3` — `demo_server.py` and `demo_client.py` — so the tap
records each request twice, once as the client wrote it and once as the
server read it. The two rows carry different `pid`s and share a timestamp to
the millisecond. That is two honest observations of one exchange, not a
duplicate: a real deployment filtering on the agent's own identity would see
each exchange once. Worth knowing before reading `capture.jsonl`, and worth
not mistaking for a double-write bug.

## DR-81's two extra knobs

`railmon demo` alone (DR-48) never sets these, and a bare `make demo` behaves
exactly as before. DR-81's compose bundle (owned by
[`datrail/raildash`](https://github.com/datrail/raildash), not this repo) sets
both so the same demo run wires both of RailDash's ingestion paths at once
instead of just the file:

- `RAILMON_SESSION_ID` — passed to the collector as `--session-id`. Unset,
  the collector generates a random one per run (`main.rs`).
- `RAILMON_WEBHOOK_URL` — passed to the collector as `--webhook`. Unset, the
  collector only writes the file, same as today.

Both matter together, not separately: RailMon's legacy-http JSONL lines carry
no `session_id` field of their own (only the `RuntimeInteraction` output
format embeds one, and that format has no consumer — see the main README's
"Run" section), and RailDash's dedup index is `(session_id, interaction_id)`,
not `interaction_id` alone. So the bundle's file-import step (`raildash load
... --session-id <same value>`) has to be told the session id explicitly — it
can't recover it from the file. Passing `RAILMON_SESSION_ID` here is what
gives the bundle a value to pass to both sides. Set only
`RAILMON_WEBHOOK_URL` without also fixing the session id and the two paths
land in different sessions and are never recognized as the same interaction —
see RailDash's README for the full "why both paths don't double-count"
explanation.
