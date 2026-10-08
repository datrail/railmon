# Running RailMon against several agents in one sandbox

This is the operator's page for `--target-manifest`: how to write the
manifest, what RailMon reports while it runs, how to diagnose a target that is
not being captured, and how to go back to single-agent mode. The scanner's
side — per-agent scans, keyed artifacts, delivery — is in
[the scanner README](../tools/scan/README.md#multi-agent-target-manifest).

## Writing the manifest

The manifest is YAML or JSON in the shape of
[`schemas/target-manifest-v1.schema.json`](../schemas/target-manifest-v1.schema.json).
The collector parses it with its own checks rather than the schema file;
unknown fields are rejected everywhere.

```yaml
manifest_version: 1
sandbox:
  host_id: build-host-7          # must match the scanner's --host-id
  sandbox_name: agents-prod      # must match the scanner's --sandbox-name
  access:
    kind: docker
    container: agents-prod
agents:
  - agent_key: planner           # [a-z0-9][a-z0-9._-]{0,63}, unique, not "default"
    display_name: Planner
    discovery:
      pid_file: /run/agents/planner.pid     # exactly one of pid_file / cgroup
    scan:
      config_roots: [/srv/planner]          # without it the scanner neither scans nor registers this agent
    capture:
      binary_path: /usr/local/bin/node      # overrides --binary-path for this tap
  - agent_key: executor
    discovery:
      cgroup: /sys/fs/cgroup/agents/executor
```

What the collector checks beyond the schema, and what a violation looks like:

- **One process per locator.** A `pid_file` holds exactly one PID; a
  `cgroup`'s `cgroup.procs` must list exactly one (`names no process` /
  `names N processes; multi-process attribution is not supported yet`).
- **One uid, one session per agent.** Each agent runs under its own uid, not
  the supervisor's, and leads its own process session (start it with
  `setsid`). Two agents sharing a uid, a session or a process are all marked
  ambiguous — a shared uid or session is not an attribution boundary. Neither
  gets a tap of its own or evidence; each process session they resolved to is
  tapped once instead, and its rows are `ambiguous` with no agent. Two agents
  may run the same binary; each gets its own tap filtered by its session.
- **Locators are re-read only while some target is down.** Every 5 s, while
  at least one declared target has no tap, RailMon re-resolves every locator.
  A running target whose locator now collides with another's is tapped as
  ambiguous; one whose locator names another process moves its tap there. One
  whose locator names nothing keeps its tap while its pinned process lives,
  unless another target now claims that process. While every target runs, a
  rewritten locator is not noticed until one of them stops.
- **Trusted control paths.** The manifest, each locator and every directory
  above them up to `/`, and each registration state file must be absolute, not
  a symlink, owned by root or the supervisor, not group/other-writable, and
  carry no POSIX ACL. A locator an agent's own uid could rewrite is refused
  (`control path … is owned by monitored uid N`).
- **`scan.config_roots` for a registered agent.** The scanner skips the
  agent-scoped scan and registration of an available agent that declares none
  (`executor` above), so its ticket claims are never corroborated.
- `sandbox.access` is validated but not yet used by the collector; the scanner
  still reaches the container through its own `--mode docker --container`.

Check a manifest without capturing anything. The `railmon collect` commands
on this page run inside the RailMon container image, where `railmon` is the
entrypoint; there is no `railmon collect` command on the host. A native build
runs the collector binary directly, as root, with the same flags (no
`collect`):

```bash
# in the container image
docker run --rm --privileged --pid host -v /etc/railmon:/etc/railmon:ro \
  railmon collect --target-manifest /etc/railmon/targets.yaml --print-resolved-targets
# native build, on the host
sudo ./target/release/railmon --target-manifest /etc/railmon/targets.yaml --print-resolved-targets
```

It prints one JSON array with an object per agent — `status` is `available`,
`not_found` or `ambiguous`, with the `reason` — and exits. The scanner runs this same command
to decide which agents to scan, so it is also the first thing to run when the
scanner skips an agent.

## Running it

Keyed capture needs `--output-format runtime-interaction` and the default
`--mode http`, and cannot be combined with `--pid`, `--uid` or `--comm`:

```bash
railmon collect \
  --target-manifest /etc/railmon/targets.yaml \
  --registration-state /var/lib/railmon/registration.json \
  --output-format runtime-interaction \
  --output /var/lib/railmon/interactions.jsonl
```

`--registration-state` is optional. Give it the same **absolute** path the
scanner writes with `--registration-output` (the scanner's default is
relative, so set it explicitly); the collector reads `<path>.<agent_key>`
every 5 s and uses it to judge unsigned `x-rail` tickets. Without it every
row is attributed by process target alone.

All agents' rows go to the one `--output` file, interleaved; separate them by
`attribution.target_id`, which every row carries (`agent_ref` is null on a
conflict row). `--webhook` works too, but Rail Center's `/v1/interactions`
stores this row shape unattributed for now, and the collector warns so. The
file is created with
the process umask, so tighten the umask or the directory if other local users
should not read captured traffic.

## What it reports

There are no metrics endpoints or per-target counters; everything is a log
line on stderr (`RUST_LOG`, default `info`) or a field in the output.

| Log line | Meaning |
| --- | --- |
| `validated N keyed targets for <host>/<sandbox>` | manifest accepted |
| `N of M keyed target(s) have a registered agent_id for ticket-claim resolution` | registration state picked up (logged on change) |
| `N interaction(s) forwarded` | total rows written, all targets, at exit |
| `N webhook batch(es) failed to deliver` | at exit, only when non-zero |

Per row, the output carries `agent_ref` (host, sandbox, `agent_key`) and
`attribution`:

| `attribution.state` | `method` / `reason` | When |
| --- | --- | --- |
| `attributed` | `process_target` | captured from the agent's own tap; no usable ticket claim |
| `attributed` | `process_target_with_ticket_claim` | the ticket names this target's own registered `agent_id` |
| `conflict` | reason `TICKET_CLAIM_CONFLICT` | the ticket names a sibling's `agent_id`; `agent_ref` and `agent_id` are cleared and the claim is kept in `raw.railmon_attribution_audit` |
| `ambiguous` | reason `MULTIPLE_TARGETS` | captured on a process session more than one target claims; `agent_ref`, `agent_id` and `target_id` are null, and `raw.railmon_attribution_audit` lists the `candidate_targets` and the discovery reason. `process` is the claimed process |

Rows flushed because their target stopped mid-request, or because a request
waited longer than `--pending-timeout` (600 s by default) for its response,
carry `raw.incomplete: true`. Conflict and unattributed totals are not logged;
count them from the file, e.g.
`jq -r .attribution.state interactions.jsonl | sort | uniq -c`.

## Diagnosing a target that is not captured

| Log line | What to check |
| --- | --- |
| `target '<k>' not found: <reason>` | the PID file or cgroup, the process being alive, the control-path rules above, the process running as the supervisor's uid, or not leading its own session |
| `target '<k>' is ambiguous: <reason>` | two agents sharing a uid, session or process |
| `targets <k>, <k> sharing session <s> collide (…); capturing that session as ambiguous …` | that session's traffic goes to the unattributed queue until the collision clears |
| `target '<k>' now collides with another target (…)` | a running target was claimed by another; its own tap stops and its session is tapped as ambiguous |
| `targets <k>, <k> sharing session <s> collide but the shared tap failed to start: …` | the probe for that session (AgentSight path; with colliding targets naming different `binary_path`s the collector-wide `--binary-path` is used); retried every 5 s |
| `session <s> is now claimed by targets <k>, <k>, …` | the set of targets claiming an already shared session changed; its tap keeps running and later rows' audit lists the new set |
| `target '<k>' locator now names another process; moving its tap there` | its PID file or cgroup was rewritten while it ran |
| `target '<k>' locator no longer names its running process, which another target now claims; stopping its tap` | its locator was removed and another target's names its process; that target gets the tap |
| `a process in shared session <s> exited or its PID was reused; stopping its ambiguous tap` | the colliding process restarted; discovery re-runs within 5 s |
| `shared ambiguous tap on session <s> ended (…); will retry discovery` | the probe for that shared session stopped |
| `session <s> no longer collides as it did; stopping its shared ambiguous tap` | the collision cleared or changed; a target that now resolves alone gets its own tap back |
| `target '<k>' resolved but its tap failed to start: …` | the probe for that agent (AgentSight path, `binary_path`); retried with the others |
| `no declared agent resolved to a capturable process` (fatal, exit 1) | nothing in the manifest resolved to a process at startup, not even an ambiguous one; run `--print-resolved-targets` |
| `target '<k>' exited or its PID was reused; stopping its tap …` | expected on agent restart; pending requests are written as incomplete |
| `target '<k>' tap ended (…); … will retry discovery` | the probe for that one agent stopped |
| `N request(s) got no response within …s and were forwarded as incomplete` / `N response(s) matched no request` | the probe reports threads, not connections; a reply streamed while another HTTP connection on the agent's thread is active (typical of Node agents) can be lost ([#70](https://github.com/datrail/railmon/issues/70)) |
| `target '<k>' resolved again; tap restarted` | recovery, retried every 5 s under the same `agent_key` |
| `every declared target is currently down; capture is idle …` | RailMon keeps running and retrying; it does not exit |
| `capture analyzer panicked on captured traffic (…); stopping this tap` | an analyzer panicked on captured traffic (since agentsight-capture 1.0.34 a malformed HPACK block no longer does); only that tap stops and restarts |
| `ignoring registration state for ticket-claim resolution: <path>: <error>` | the state file fails the control-path rules, has no UUID `agent_id`, or names a different host/sandbox than the manifest |
| `keyed capture requires …` / `… cannot be combined with --target-manifest` | a flag combination keyed mode refuses (exit 1) |

One target failing never stops the others. SIGINT and SIGTERM (`docker stop`)
both flush and stop cleanly; with `--webhook` the final flush can take up to
10 s against a slow receiver, so give the container a longer stop grace
period (`docker stop -t 30`, compose `stop_grace_period`). Exit codes: 0 on a
stop signal, 1 on a
startup or I/O error (message on stderr as `Error: …`), 2 on a command-line
usage error.

## Rolling back to single-agent mode

Drop `--target-manifest` (and `--registration-state` /
`--print-resolved-targets`, which require it) from the collector, along with
`--output-format runtime-interaction` if the consumer expects the default
`legacy-http` rows; unset `--target-manifest` / `RAIL_TARGET_MANIFEST` for the
scanner. Both return to their previous behaviour unchanged: collector rows
carry no `agent_ref` or `attribution` and read `agent_id` from the ticket as
before, and `--pid`/`--uid`/`--comm` work again.

The keyed files the scanner wrote (`….<agent_key>` next to the registration,
feature and evidence-bundle outputs) are left on disk; delete them if the
agents should not be recognised on a later switch back. They can never be
mistaken for the un-keyed files, since `default` is not a valid key.
