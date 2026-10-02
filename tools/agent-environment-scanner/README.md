# Agent Environment Scanner

Scans a running agent environment and emits JSON compatible with rail-center's
`POST /v1/agents/register` request body.

This tool is meant to run before registration. It does not capture traffic and
does not require eBPF privileges. It reads container metadata, safe environment
metadata, system/runtime information, owner identity, and optional MCP config.

## Output Schema

The output matches `RegisterAgentRequest` in rail-center:

```json
{
  "type": "personal",
  "owner": "user-or-team",
  "host_id": "vm-7f3c",
  "sandbox_name": "openclaw-1",
  "environment": {
    "sandbox_type": "openclaw",
    "llm_provider": "local",
    "llm_model": "tinyllama",
    "system_info": {},
    "user_info": {}
  },
  "skills": []
}
```

`host_id` and `sandbox_name` are optional; they are omitted when the scanner has
nothing it can stand behind. See [Agent identity](#agent-identity).

The scanner uses secret-bearing environment variables to infer the provider, but
it only records environment variable names. API key values are not written into
the payload. The container's entrypoint is recorded as `system_info.process
.proc1_cmdline` with credential-bearing arguments — `--api-key=…`, `--token …`,
an inline `API_KEY=…` — stripped, since an entrypoint routinely carries one.

Every file the scanner writes — the payload under `--output`, the registration
state, and the feature file — is created `0600`.

## Registration Flow

RC-41 flow is supported directly:

```text
collect environment data + skills data
  -> POST /v1/agents/register        (optional)
  -> store the returned agent id     (the response token is discarded)
  -> write the feature file          (always, and last, so it records the outcome)
```

Run the skills scanner first if the agent uses OpenClaw/NemoClaw `SKILL.md`
files:

```bash
tools/skills-scanner/run-openclaw.sh
```

Then register the agent with Rail Center:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --mode docker \
  --container openclaw-monitoring-openclaw-1 \
  --skills-file examples/openclaw-monitoring/output/openclaw-skills.json \
  --register \
  --center-url http://localhost:23001
```

Rail Center must be running with database migrations applied before this POST.

The scanner accepts either a raw `SkillInput[]` JSON file or a full
`RegisterAgentRequest` JSON object with a `skills` field. It merges those skills
with any MCP skills discovered from `.mcp.json`.

By default, Rail Center's response is stored at:

```text
.datrail/rail-guardian/registration.json
```

The stored file contains:

```json
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "sandbox_id": "a1b2c3d4e5f6",
  "host_id": "vm-7f3c",
  "sandbox_name": "openclaw-1",
  "environment_fingerprint": "f6e5d4c3b2a1"
}
```

**No ticket is stored.** Rail Center's response carries a `token`, and the
scanner discards it: it is a placeholder minted with a null posture, because
posture is scored asynchronously after the response returns. Storing or
forwarding it would pin the fleet to a posture that was never computed. The
proxy fetches its own ticket; the scanner is the registrar, and a registrar
holds no credentials.

Override the state file with:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --register \
  --center-url http://localhost:23001 \
  --registration-output /var/lib/datrail/rail-guardian-registration.json
```

Use `RAIL_CENTER_URL` instead of `--center-url` when running as a service.
The `DATRAIL_*` names it used to accept were removed in DR-74 — there is no
fallback, so a deployment still setting an old name gets no value at all rather
than a silently ignored one.
Rail Center unreachable errors, invalid payload responses, and invalid response
bodies are reported as scanner errors with exit code `2`.

## Feature file

The feature file is the scanner's primary output and needs no control plane. It
is written to `.rail/railscan/features.json` (override with `--feature-output`
or `RAIL_FEATURE_OUTPUT`; skip with `--no-feature-file`) and covers dimensions
1–5 at inventory depth:

| Section | Contents |
|---|---|
| `host_and_identity` | `sandbox_type`, `host_class`, `host_id` (+ source), `sandbox_name` (+ source), image, container id, owner |
| `secrets_hygiene` | env key *names*, plus one entry per secret-looking variable with its `secret_type` and `secret_class` (`plaintext` / `reference` / `mount`) |
| `model_and_egress` | provider, model, `base_url` and whether it is `canonical`, `local` or an `unknown_proxy` |
| | URLs are recorded with userinfo, query strings, fragments and key-shaped path segments redacted — gateways routinely carry the key in the URL. A path segment is key-shaped if it is 20 characters or longer, or matches a known vendor key format (`sk-…`, `ghp_…`, `xoxb-…`, `AKIA…`, …) at any length |
| `tool_and_mcp_reach` | MCP inventory: name, the command's executable (not its arguments, which carry tokens), redacted url, transport |
| `skills` | name, description, destination endpoints, source type. A skills file is operator-written free text, so strings matching a known vendor key format are stripped from all three before they are recorded or POSTed. The formats carry their length and character shape, not just a prefix, so a skill called `asian-markets` keeps its name |
| `observed_reach` | only with `--observed-file`: hosts actually reached, with counts, errors and a redacted path; the tool *names* used; the models seen; and `undeclared_destinations` |
| `observed_listeners` | only with `--listen-file`: sockets the agent opened to accept inbound traffic — protocol, bound address, port (or `ephemeral`) and process name — plus counts of lost, unlisted and malformed events; and `peers`, who connected in (see [Ingress peers](#ingress-peers)) |

Metadata only — never a secret value. That is what makes the file safe to
persist and hand to a scorer. It is written `0600`: the inventory names an
agent's tools, endpoints and which of its secrets sit in plaintext, which is a
map worth reading for anyone who wants to attack that agent.

`registration_status` reports what happened, not what was asked for: with
`--register` it stays `registration_failed` until the POST actually succeeds.

The feature file is written even when a registration or an `--output` write
fails, and failing to write it is itself an exit code `2` — it is the primary
artifact, not a side effect. A registration error is never replaced by a
feature-file error: both are printed, the registration one last, since that is
the one the operator has to act on.

`secret_class` distinguishes `mount` from `reference` by asking the filesystem
the value refers to: in `--mode docker` that is the scanned container's, so a
secret mounted into the container is not reported as a dangling pointer.

## Evidence bundle

The evidence bundle is the scanner's second output and the security-profile
brain's input. Where the feature file is the operator's inventory, the bundle
is the scorer's: every attribute carries one of the six closed status values
(`ANSWERED`, `ABSENT`, `TEMPLATED`, `PARTIAL`, `BLIND`, `FAILED`), a tier
(`declared` / `interrogated` / `observed`) and, for what it did not answer, a
reason from the closed reason-code set — so a consumer can judge every field
instead of guessing what an empty one means. Honesty over completeness: an
attribute this pack cannot collect is emitted `BLIND` with the reason why,
never an empty `ANSWERED` that reads as "none exists".

It is written to `.rail/railscan/evidence-bundle.json` (override with
`--evidence-bundle-output` or `RAIL_EVIDENCE_BUNDLE_OUTPUT`; skip with
`--no-evidence-bundle`), like the feature file it is created `0600`, and it
rides the same guarantee: the bundle is written from the same `finally`, so it
lands even when the registration fails. A write failure is reported without
changing the exit code — the feature file owns that.

The envelope names the container the bundle was collected from with
`host_id` and `sandbox_name` — the pair the scan registers the container
under (`RAIL_HOST_ID`, and the `rail.sandbox_name` label or the container
name when there isn't one). Rail Center files the bundle under that
registered agent, so the bundle lines up with the interactions Rail Center
already matches from the x-rail ticket. The `agent_id` the registration
returns is not in the envelope: the control plane looks the pair up, which
keeps the builder decoupled from the scan job's output.

Attributes that are *absent* from the bundle rather than absent *on the
agent* carry `method`: where the pack looked. The `deployment` attribute
retains the closed set of non-empty deployment fields the scanner can read:
`RAIL_DEPLOYMENT` plus `RAIL_NAMESPACE` from the scanned subject environment,
and the Compose project/service pair from container labels. Consumers use a
complete environment pair first, then a complete Compose pair; a half-pair is
evidence of an incomplete operator setting, not a deployment key. This makes
the Kubernetes path work through the downward API even though pod labels do
not reach Docker `Config.Labels`. With none of those fields set, the attribute
is `ABSENT`; arbitrary labels and image names are never grouping signals.

`credential_inventory` uses the profiler's closed credential classes:
`secret_plaintext`, `secret_ref`, and `mount`. Empty secret-shaped environment
variables are omitted because they contain no credential. Values are never
collected or written to the bundle.

## RailDash delivery

A user should never have to run a CLI command to get an evidence bundle into
RailDash (standing decision: ASP must not depend on the CLI). `--raildash-url`
POSTs the bundle's exact bytes — the same bytes `--evidence-bundle-output`
would write — straight to a RailDash instance:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --raildash-url http://localhost:8000
```

This POSTs to `<raildash-url>/v1/evidence-bundles`, which RailDash dedupes by
the content digest of the bytes it receives. Use `RAIL_RAILDASH_URL` instead
of `--raildash-url` when running as a service.

It is independent of `--register`/`--center-url`: name either URL, both, or
neither in one invocation, and each target is attempted and reported on its
own — a failed `--register` does not skip the RailDash delivery, and vice
versa. It is also independent of `--no-evidence-bundle`: the bundle is built
for delivery even when the local file write is skipped.

`--agent-key` (or `RAIL_AGENT_KEY`) is forwarded as the request's
`?agent_key=` query parameter, for RailDash to resolve identity when the
bundle carries no deployment pair — the same key `raildash asp load
--agent-key` takes today. (This is a best guess at DR-120's exact contract,
made before that route's PR existed; if DR-120 lands with `agent_key` as a
header instead, this is the one place to change.)

RailDash is expected to run localhost-only, so no auth header is sent by
default. `--auth-mode`/`RAIL_AUTH_MODE` (see [Authentication](#authentication))
applies to this target too, for the rare deployment that fronts RailDash with
its own auth.

A non-2xx response, an unreachable RailDash, or an evidence bundle that fails
its own contract are all reported as scanner errors with exit code `2` —
mirroring `--register`'s existing failure handling — without stopping the
rest of the scan: the feature file, the local evidence bundle (if
`--evidence-bundle-output` was also requested), and any `--register` attempt
still happen.

## Observed reach (optional)

The other dimensions describe what an agent is *configured* to reach.
`--observed-file` adds what it *actually* reached, from an
[AgentSight](https://github.com/eunomia-bpf/agentsight) snapshot:

```bash
sudo agentsight record -- claude          # or: agentsight report --local  (no sudo)
agentsight report export -o snapshot.json
python3 .../scan_agent_environment.py --observed-file snapshot.json
```

AgentSight has already done the parsing and the aggregation, so the scanner only
classifies, redacts and diffs — it grows no parser of its own. The payoff is
`undeclared_destinations`: hosts the agent reached that nothing in its
configuration declared.

It reads `network_targets`, `tool_calls[].tool_name`, `token_summary[].group`
and the summary counts, and deliberately nothing else. `tool_calls` also carries
`input`/`output` and `process_nodes` carries full `argv` — conversation and
command-line *contents*, not metadata — which must never reach a file that is
persisted and handed to a scorer.

## Observed listeners (optional)

The other direction of reach: a socket the agent opened to *accept* traffic is
a service nobody declared, the shape a covert channel takes.
`--listen-file` (or `RAIL_LISTEN_FILE`) reads the JSON lines that
[`listensnoop`](https://github.com/datrail/ebpf-tls-tap#listening-sockets)
appends. The RailMon image ships it as `railmon listen`; the
[top-level README](../../README.md#listening-sockets) has the two-container
deployment. Run it in the agent's PID namespace, so that only this sandbox's
sockets carry a PID. Without the image, build it from ebpf-tls-tap
(`make build-bpf`) and enter the namespace yourself:

```bash
agent=$(docker inspect -f '{{.State.Pid}}' my-agent)
sudo nsenter -t "$agent" -p -- ./bpf/listensnoop >> listen.jsonl &
python3 .../scan_agent_environment.py --listen-file listen.jsonl
```

The scanner re-reads the whole file on every scan, so the list covers
everything since listensnoop started. It becomes the `observed_listeners`
attribute, and it is built so that it only changes when the agent starts
listening somewhere new:

- each entry is `{protocol, addr, port, process}`, with no counts or PIDs;
- a port the kernel chose (listensnoop's `ephemeral`: a bind to port 0, a
  `listen()` on an unbound socket, an autobind) is `ephemeral`, not a number
  that differs on every run. A port the caller asked for stays a number in
  any range, so a covert listener on one is a new entry;
- an event with `pid` 0 came from outside listensnoop's PID namespace. It is
  counted (`outside_namespace`) but not listed;
- the PARTIAL note names the kind of gap, never a count, so a growing lost
  count is not drift on every scan. The counts are in the feature file.

The events are per PID namespace, which is the sandbox, so in a multi-agent
bundle `observed_listeners` is sandbox-scoped, not per agent.

Keep the file where the agent cannot write. An agent that can truncate it, or
edit it, can hide its own listener, and deleting it fails the scan. The
two-container deployment keeps it on a volume the agent does not mount; the
nsenter recipe writes it on the host. Lines of 4096 characters or more are
skipped as malformed.

`ephemeral` needs a listensnoop from DR-125 on. With an older one, only an
autobind is known to be kernel-chosen, so a bind to port 0 shows its real
port, which changes when the agent restarts. That causes churn, but it never
hides a listener.

No configuration declares a listener, so every one is undeclared. Drift is
RailDash's comparison against the locked baseline: a new entry is a change to
`observed_listeners`. The attribute is:

- ANSWERED with the list;
- ABSENT when nothing listened;
- PARTIAL when the list may be missing a listener. A gap never reads as
  "none". There are two reasons:
  - `NO_SOURCE_ACCESS` covers three cases: listensnoop restarted (a second
    `start` record), its heartbeat is more than three intervals old, or it
    never attached (no `start` record);
  - `SIZE_CAP_EXCEEDED`: it reported lost events, or more than 256 distinct
    listeners were seen;
- BLIND without a file.

The attribute is new in rule pack 2. RailDash shows a baseline locked under
pack 1 as `CONTRACT_MISMATCH`, not as drift, until a pack-2 ASP is locked.
`tests/listen_drift_acceptance.py` runs the whole path against a real RailDash
in CI.

### Ingress peers

The same file carries listensnoop's `peer` events (ebpf-tls-tap from DR-144
on): each remote address a process accepted a TCP connection from, once per
listener. They become the `observed_ingress_peers` attribute, the "Ingress
request" dimension of the first ASP requirements, whose threshold is an
approved list of addresses or "internal only":

- each entry is `{protocol, addr, port, process, peer, scope}`. The first four
  are the listener's, written as in `observed_listeners`, and a repeat of a
  peer is the same entry, so the value only changes when a new peer
  connects;
- `scope` is `loopback`, `link-local`, `private` (RFC 1918 or IPv6 ULA),
  `public` (globally routable) or `other` (CGNAT, documentation, reserved);
- an IPv4 client of a dual-stack listener is its IPv4 address.

The attribute is:

- ANSWERED with the list, or ABSENT when nothing connected in;
- PARTIAL for the same probe gaps as `observed_listeners` (restart, stale
  heartbeat, never attached, lost events), or past 256 distinct peers. A
  listener that the whole internet can reach meets new peers all the time,
  and that is what the cap says;
- BLIND without a file, or when the probe's newest `start` record lacks
  `"peers": true`. That probe predates peer events, and "it didn't look" must
  not read as "nobody connected".

Only TCP peers are seen, and only once accepted. Behind NAT or a proxy, a
peer is the last hop: a client of a Docker published port arrives as the
bridge gateway when the userland proxy carries it. The attribute is
sandbox-scoped, like `observed_listeners`, and new in rule pack 3: RailDash
shows a baseline locked under pack 2 as `CONTRACT_MISMATCH` until a pack-3
ASP is locked. The drift acceptance test covers it too.

## Agent identity

| Field | Where it comes from |
|---|---|
| `host_id` | `RAIL_HOST_ID` (or `--host-id`), the same value every Rail component on the host reads. The scanner's own environment is read before the scanned container's, so a container cannot relabel the host it runs on; `host_id_source` distinguishes `flag`, `env` and `container_env`. **No fallback is invented** — an id this scanner made up would disagree with the proxy and the collector, so an unset variable is reported as unset. |
| `sandbox_name` | the `rail.sandbox_name` container label, else the container name, else the hostname. **Never an environment variable**: an agent nobody onboarded carries no Rail configuration, and those are exactly the ones worth discovering. |
| `host_class` | DMI vendor/product — `gce_vm`, `ec2_vm`, `azure_vm`, `virtual_machine`, `bare_metal`, `container`, or `unknown` when the DMI is unreadable. |

Both identity fields are optional on Rail Center's side and bounded to its
storage width (64 and 255), so the scanner truncates rather than letting a long
value surface as a server error.

## Multi-agent target manifest (DR-109 M2)

`--target-manifest` (or `RAIL_TARGET_MANIFEST`) names the same
`target-manifest-v1` YAML the collector reads with its own `--target-manifest`
flag. When given, a collection is no longer just the one sandbox-wide scan
above — it becomes that same sandbox-wide scan **plus** one agent-scoped scan
and registration per manifest agent the collector currently resolves as
`available`, each scoped to that agent's `scan.config_roots` and carrying its
`agent_key` into the registration payload, the RailDash delivery, and the
local `--feature-output`/`--registration-output`/`--evidence-bundle-output`
paths (each suffixed `.<agent_key>` so a keyed scan never overwrites the
sandbox-wide scan's, or another key's, artifact). A declared agent the
collector reports as `not_found` or `ambiguous` is logged and skipped, not
treated as a failure — the same "never drop a declared agent's siblings over
one bad target" rule the collector's own multi-target capture follows. An
`available` target with no declared `scan.config_roots` is logged and
skipped too: there is nothing agent-specific to scope the scan to, and
running it anyway would just re-collect the sandbox-wide scan's own default
paths and register that duplicate, un-scoped data under the agent's key as
if it had been observed specifically for it.

Process resolution — liveness, ownership, and cross-target collision
detection — has exactly one implementation, in the collector's `identity.rs`.
This scanner shells out to it (`<collector> --target-manifest <path>
--print-resolved-targets`, resolved via `RAILMON_BIN`, defaulting to
`/usr/local/bin/railmon-collector` the same way `entrypoint.sh` does) rather
than reimplementing that resolution in Python, where it could silently
diverge from it.

`--interval`/`RAIL_SCAN_INTERVAL_IN_SECONDS` applies the same way: each tick
re-runs the full collection (sandbox scan plus every currently-available
keyed scan), not just the sandbox-wide half.

The keyed registration state is also what the collector's multi-target
capture reads to judge an unsigned `x-rail` ticket (DR-109 M3). Start the
collector with `--registration-state` set to the same absolute path passed
here as `--registration-output`; it re-reads each `<path>.<agent_key>` every
few seconds. A ticket claiming the capturing target's own registered
`agent_id` is recorded as corroboration (`process_target_with_ticket_claim`),
one claiming a sibling's is a `conflict` with `agent_ref` and `agent_id`
cleared, and any other claim is ignored — the process target alone decides.
Without the flag every row is attributed by process target alone. The
collector only trusts a state file whose `host_id` and `sandbox_name` equal
the manifest's `sandbox` values, so pass the scanner `--host-id` and
`--sandbox-name` (or `RAIL_HOST_ID`/the `rail.sandbox_name` label) matching
the manifest; a mismatched file is logged and ignored.

## Authentication

`RAIL_AUTH_MODE` (or `--auth-mode`) selects the credential presented when
registering, mirroring Rail Center's `RAIL_AUTH_MODES_ACCEPTED`:

- `none` (default) — sends nothing; accepted while the control plane still
  lists `none`. A token set beside it is refused as a likely misconfiguration.
- `bearer` — sends `RAIL_AUTH_TOKEN`, or the contents of
  `RAIL_AUTH_TOKEN_FILE`, as `Authorization: Bearer …`. The file is read on
  every pass, so with `--interval` a rotated secret takes effect without a
  restart. Setting both is refused; neither form wins.
- `gcp` — mints an identity token for `RAIL_AUTH_AUDIENCE` (Rail Center's
  `SERVICE_TOKEN_AUDIENCE`) from the workload's metadata server
  (`GCE_METADATA_HOST` overrides the address), held only in memory until
  shortly before it expires. Nothing is stored or rotated by hand.

With `--register`, a credential that cannot be produced fails that
registration like any other delivery failure (non-zero exit; the feature file
and `--raildash-url` delivery still happen); nothing is ever sent anonymously
instead. The
registration request does not follow redirects, so the credential cannot be
carried to another host. These are the same variables, read the same way, as
the collector's `--webhook` and `railmon forward`.

## Local Machine Scan

From the repository root:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py
```

Write the payload to a file:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --output output/registration-payload.json
```

Use explicit values when the model or provider cannot be inferred:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --sandbox-type bare_metal \
  --llm-provider anthropic \
  --llm-model claude-sonnet-4-20250514
```

## OpenClaw Integration

Start the real OpenClaw example container:

```bash
cd examples/openclaw-monitoring
mkdir -p openclaw-data output
docker compose up -d openclaw
```

Run the scanner against the running OpenClaw container:

```bash
cd ../..
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --mode docker \
  --container openclaw-monitoring-openclaw-1 \
  --output examples/openclaw-monitoring/output/registration-payload.json
```

If Compose uses a different container name, get it with:

```bash
docker compose -f examples/openclaw-monitoring/docker-compose.yml ps openclaw
```

Expected detection for the bundled OpenClaw compose file:

| Field | Expected value |
| --- | --- |
| `environment.sandbox_type` | `openclaw` |
| `environment.llm_provider` | `local` |
| `environment.llm_model` | `unknown` unless a model is configured or a capture file is provided |

To infer model from an actual monitor capture:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --mode docker \
  --container openclaw-monitoring-openclaw-1 \
  --capture-file examples/openclaw-monitoring/output/openclaw-capture.jsonl
```

## NemoClaw Integration

Start the real NemoClaw example container:

```bash
cd examples/nemoclaw-monitoring
mkdir -p nemoclaw-data output
docker compose up -d nemoclaw
```

Run the scanner against the running NemoClaw container:

```bash
cd ../..
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --mode docker \
  --container nemoclaw-monitoring-nemoclaw-1 \
  --output examples/nemoclaw-monitoring/output/registration-payload.json
```

If Compose uses a different container name, get it with:

```bash
docker compose -f examples/nemoclaw-monitoring/docker-compose.yml ps nemoclaw
```

Expected detection for the bundled NemoClaw compose file:

| Field | Expected value |
| --- | --- |
| `environment.sandbox_type` | `nemo_claw` |
| `environment.llm_provider` | `local` |
| `environment.llm_model` | `unknown` unless a model is configured or a capture file is provided |

To infer model from an actual monitor capture:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --mode docker \
  --container nemoclaw-monitoring-nemoclaw-1 \
  --capture-file examples/nemoclaw-monitoring/output/nemoclaw-capture.jsonl
```

## MCP Skills

The scanner looks for MCP config in:

```text
.mcp.json
/workdir/.mcp.json
~/.mcp.json
```

Each `mcpServers` entry becomes a registration `SkillInput` with
`source_type: "mcp_config"`. Pass custom paths with:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --mcp-config /path/to/.mcp.json
```

An estate that declares its MCP server via environment variables instead of a
config file (confirmed for one GCP estate behind DR-123, e.g.
`compose.agent-zone.yml`: one server per agent) is still discovered — no flag
needed. If both `AGENT_MCP_NAME` and `AGENT_MCP_URL` are set, that server is
added to the inventory and skills list the same way a `.mcp.json` entry would
be, merged with any file-derived servers (a file entry with the same name
wins). Only this one name/URL pair is read; there is no env-var equivalent of
a multi-server `mcpServers` block.

Merge external skills from the skills scanner:

```bash
python3 tools/agent-environment-scanner/scan_agent_environment.py \
  --skills-file examples/openclaw-monitoring/output/openclaw-skills.json
```

## Validate Against rail-center

From the `rail-center` repository, validate a generated payload with the current
Pydantic schema:

```bash
uv run --python 3.13 --with pydantic --with typing-extensions python -c '
import json, sys
sys.path.insert(0, "api/src")
from registry.schemas import RegisterAgentRequest
RegisterAgentRequest.model_validate(json.load(open("../datrail-agent-monitor/output/registration-payload.json")))
print("valid")
'
```
