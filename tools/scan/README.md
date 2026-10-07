# Agent Environment Scanner

Scans a running agent environment and emits JSON compatible with rail-center's
`POST /v1/agents/register` request body.

This tool is meant to run before registration. It does not capture traffic and
does not require eBPF privileges. It reads container metadata, safe environment
metadata, system/runtime information, owner identity, and optional MCP config.

Every example below assumes the host id is set (`RAIL_HOST_ID`, or
`--host-id`). Without one the evidence bundle fails its contract and the scan
exits `2`; pass `--no-evidence-bundle` to scan without a bundle.

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

The registration flow is supported directly:

```text
collect environment data + skills data
  -> POST /v1/agents/register        (optional)
  -> store the returned agent id     (the response token is discarded)
  -> write the feature file          (always, and last, so it records the outcome)
```

Run the skills scanner first if the agent uses OpenClaw/NemoClaw `SKILL.md`
files:

```bash
tools/skills/run-openclaw.sh
```

Then register the agent with Rail Center:

```bash
python3 tools/scan/scan_agent_environment.py \
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
.rail/railmon/registration.json
```

(RailScan wrote it to `.datrail/rail-guardian/registration.json`. Where that
directory exists and `.rail/railmon/registration.json` does not, the scanner
keeps using the old location and prints a deprecation note; the feature file
and evidence bundle below follow the same rule for `.rail/railscan/`. Move the
files, or set the path explicitly, to finish the move.)

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
python3 tools/scan/scan_agent_environment.py \
  --register \
  --center-url http://localhost:23001 \
  --registration-output /var/lib/railmon/registration.json
```

Use `RAIL_CENTER_URL` instead of `--center-url` when running as a service.
The `DATRAIL_*` names it used to accept have been removed — there is no
fallback, so a deployment still setting an old name gets no value at all rather
than a silently ignored one.
Rail Center unreachable errors, invalid payload responses, and invalid response
bodies are reported as scanner errors with exit code `2`.

## Feature file

The feature file is the scanner's primary output and needs no control plane. It
is written to `.rail/railmon/features.json` (override with `--feature-output`
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
| `observed_file_access` | only with `--files-file`: the files the sandbox opened, as `files` (path and read/write/exec/layer), plus counts of lost, unlisted, unnamed and malformed events, and `collapsed`, the distinct randomly named temp files folded into listed entries (a lower bound past 16,384) (see [Observed file access](#observed-file-access-optional)) |

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

It is written to `.rail/railmon/evidence-bundle.json` (override with
`--evidence-bundle-output` or `RAIL_EVIDENCE_BUNDLE_OUTPUT`; skip with
`--no-evidence-bundle`), like the feature file it is created `0600`, and it
rides the same guarantee: the bundle is written from the same `finally`, so it
lands even when the registration fails. A write failure is reported without
changing the exit code — the feature file owns that. A bundle that fails its
own contract (for example, no `host_id` because `RAIL_HOST_ID` is unset) is
not written and fails the scan with exit code `2`; `--no-evidence-bundle`
skips building it.

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
RailDash, where it becomes an Agent Security Profile (ASP). `--raildash-url`
POSTs the bundle's exact bytes — the same bytes `--evidence-bundle-output`
would write — straight to a RailDash instance:

```bash
python3 tools/scan/scan_agent_environment.py \
  --raildash-url http://localhost:8000
```

This POSTs to `<raildash-url>/v1/evidence-bundles`, which RailDash dedupes by
the content digest of the bytes it receives. Use `RAIL_RAILDASH_URL` instead
of `--raildash-url` when running as a service.

With `--interval`, a scan whose bundle is unchanged since the same process's
previous scan (everything but `bundle_id` and `collected_at` equal) reuses
that previous bundle whole, so the file and the POST carry the same bytes as
last time and RailDash answers `duplicate` instead of storing a new ASP every
interval. It is still re-sent rather than skipped, so a RailDash that was
reset, or that pruned the row, gets it back. A content-derived `bundle_id`
alone would not do this: `collected_at` would still differ, and RailDash
refuses a known `bundle_id` with different bytes.

It is independent of `--register`/`--center-url`: name either URL, both, or
neither in one invocation, and each target is attempted and reported on its
own — a failed `--register` does not skip the RailDash delivery, and vice
versa. It is also independent of `--no-evidence-bundle`: the bundle is built
for delivery even when the local file write is skipped.

`--agent-key` (or `RAIL_AGENT_KEY`) is forwarded as the request's
`?agent_key=` query parameter, for RailDash to resolve identity when the
bundle carries no deployment pair — the same key `raildash asp load
--agent-key` takes. RailDash's `POST /v1/evidence-bundles` reads it from that
query parameter.

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

`RAIL_OBSERVED_FILE` works in place of the flag, like `RAIL_LISTEN_FILE` for
`--listen-file`.

AgentSight has already done the parsing and the aggregation, so the scanner only
classifies, redacts and diffs — it grows no parser of its own. The payoff is
`undeclared_destinations`: hosts the agent reached that nothing in its
configuration declared.

Without a snapshot, `observed_destinations`, `undeclared_destinations` and
`tool_names` are `BLIND` / `NOT_COLLECTED_BY_PACK`: nobody watched, which is
not the same as an agent that sends nowhere. A snapshot with no traffic did
look: `observed_destinations` is then an `ANSWERED` empty list, and
`tool_names` and `undeclared_destinations` are `ABSENT` with nothing to list.
`observed_destinations` used to be `ABSENT` without a snapshot too; rule
pack 6 corrected it, so RailDash shows a baseline locked under pack 5 as
`CONTRACT_MISMATCH`, not as drift, until a pack-6 ASP is locked.

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
- a record with `"snapshot": true` is a socket that was already listening
  when `railmon listen` attached, read from the agent's socket table. It is
  listed like the probe's own records, so a socket both report is usually
  one entry. Its port is a number, since the socket table does not say
  whether the kernel chose it, so a port the probe saw as `ephemeral` shows
  twice if it is still open at a reattach (already PARTIAL). Its process is
  the main thread's name, so a socket bound in a thread named apart shows
  twice too;
- the PARTIAL note names the kind of gap, never a count, so a growing lost
  count is not drift on every scan. The counts are in the feature file.

The events are per PID namespace, which is the sandbox, so in a multi-agent
bundle `observed_listeners` is sandbox-scoped, not per agent.

Keep the file where the agent cannot write. An agent that can truncate it, or
edit it, can hide its own listener, and deleting it fails the scan. The
two-container deployment keeps it on a volume the agent does not mount; the
nsenter recipe writes it on the host. Lines of 4096 characters or more are
skipped as malformed.

`ephemeral` needs a listensnoop recent enough to report it. With an older one, only an
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

The same file carries listensnoop's `peer` events (from ebpf-tls-tap versions
that report them): each remote address a process accepted a TCP connection from, once per
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

## Observed file access (optional)

What the sandbox actually read, wrote and ran, as the kernel saw it.
`--files-file` (or `RAIL_FILES_FILE`) reads the JSON lines that
[`filesnoop`](https://github.com/datrail/ebpf-tls-tap#file-opens) appends:
one line the first time a process opens a regular file for a kind of access.
The RailMon image ships it as `railmon files`; the
[top-level README](../../README.md#opened-files) has the deployment, which is
the listener one. Without the image, build it from ebpf-tls-tap and run it
in the agent's PID namespace with `-n`, as for listensnoop above.

It becomes the `observed_file_access` attribute, at tier `observed` and
authored by nobody. It is evidence of what happened, kept apart from what a
configuration declares and from the file access a tool call asked for. Like
the listeners, it only changes when a file is opened in a new way:

- each entry is `{path, read, write, exec, layer}`, one per path. `read`,
  `write` and `exec` are the union of every way it was opened, so a file
  first read and later written is one entry whose `write` turns true;
- `path` is the path the process saw, with every non-printable character
  (control characters, and invisible ones such as U+200B) replaced by `?`;
  two paths that differ only there are one entry. A path that is not UTF-8 is the one filesnoop printed (U+FFFD for
  each bad byte);
- `layer` is filesnoop's flag for an open overlayfs made in a layer beneath,
  for an overlay mounted from a user namespace. Its path is relative to the
  layer (kernel 6.8 on) or the overlay's (before), and it is a separate
  entry either way. A container root a rootful runtime mounted has none; a
  rootless runtime's containers do, for their first opens;
- there are no PIDs, counts or process names. A thread's name is chosen by
  the agent (Python names its threads `Thread-8 (reader)`), so it would
  churn;
- an event with `pid` 0 came from outside filesnoop's PID namespace. It is
  counted (`outside_namespace`) but not listed;
- the list is capped at 512 entries and at 256 KiB as rendered (a path of
  non-ASCII characters is written as `\uXXXX` escapes, so the agent could
  otherwise push the bundle past RailDash's 1 MiB bound). Past either,
  reads are left out first, so every write and exec is kept while there is
  room, and an entry too large to fit is skipped rather than everything
  after it. While each class below stays within its budget, the choice
  depends only on the set of files, not on the order they were opened. A stdlib-only Python opens about 150 files on start,
  and an agent with its packages more, so a busy agent does reach the cap;
- while reading, up to 16,384 read-only paths and 16,384 written or run ones
  are tracked, each class on its own, so a flood of reads cannot crowd out a
  write;
- a path longer than 1024 characters, or one filesnoop could not resolve,
  is counted as `unnamed`, not listed;
- randomly named temp files are folded, so a name that differs on every
  run is not a new path on every scan (see
  [Randomly named temp files](#randomly-named-temp-files) below);
- the PARTIAL note names the kind of gap, never a count. A written or run
  file that was left out or unnamed has its own words in the note, so a
  baseline already PARTIAL for too many reads still drifts when a write goes
  missing. The counts are in the feature file.

The attribute is:

- ANSWERED with the list;
- ABSENT when no regular file was opened;
- PARTIAL when the list may be missing a file:
  - `NO_SOURCE_ACCESS`: filesnoop restarted, its heartbeat is stale, or it
    never attached, exactly as for `observed_listeners`;
  - `SIZE_CAP_EXCEEDED`: it reported lost events, the list hit its cap, or
    a path was unnamed;
- BLIND without a file.

### Randomly named temp files

An agent's `tempfile.mkstemp()`, `mktemp` or editor writes a file under a
name that is random each run. Kept as filesnoop reports it, that would be a
newly written path, and drift, on every scan. So the scanner folds those
names, and only those, at the source:

- only a file in or below `/tmp`, `/var/tmp` or `/dev/shm`, or directly in
  the scanned environment's `$TMPDIR` (the container's in `--mode docker`,
  the scanner's own in `--mode self`). The agent can set `$TMPDIR`, so it
  counts only when it is an absolute path of at most 256 printable
  characters (a trailing `/` is dropped) with no empty, `.` or `..` part,
  whose last part names a temp dir (`tmp`, `temp`, `tmpdir` or `tempdir`, in
  any case, with or without a leading `.`), and which is not the
  environment's `$HOME` or in or below `/bin`, `/boot`, `/dev`, `/etc`,
  `/lib`, `/lib32`, `/lib64`, `/libexec`, `/libx32`, `/proc`, `/sbin`, `/sys`
  or `/usr`. So `/home/a/.tmp` counts, and `/home/a`, `~/.ssh` or a workdir
  never do;
- only when the file's own name matches one of these, in full. The first
  that matches, and may apply where the file is, wins:

  | Pattern | Made by | Example | Folded path |
  | --- | --- | --- | --- |
  | `.<name>.sw` + one of `a`-`p` | Vim's swap file | `/tmp/.notes.txt.swo` | `/tmp/.notes.txt.sw*` |
  | 8 of `[a-z0-9_]`, nothing else; only directly in a temp dir, never below one | Python's `tempfile`, which writes and at once removes one such file the first time a process uses it, to check it can write there | `/tmp/0vuw8his` | `/tmp/*` |
  | `tmp` + 8 of `[a-z0-9_]`, then an optional `.ext` | Python's `tempfile` (`mkstemp`, `NamedTemporaryFile`, ...) with its default prefix | `/tmp/tmpk3j_9xq2.json` | `/tmp/tmp*.json` |
  | a prefix ending in `.` `-` or `_` (or just `tmp`), then 6 to 12 of `[A-Za-z0-9]` holding at least one digit or capital, then an optional `.ext` | `mkstemp(3)`/`mkstemps(3)`'s `XXXXXX`, `mktemp(1)`'s `tmp.XXXXXXXXXX`, Go's `os.CreateTemp` with a pattern like `run-*` | `/tmp/tmp.h4Gq0ZtR2b` | `/tmp/tmp.*` |

  `.ext` is a dot and 1 to 8 letters or digits;
- each match becomes the entry whose path is its directory, unchanged, and
  the name with `*` in place of the random part. There is one entry per
  (directory, pattern, layer), and its `read`, `write` and `exec` are the
  union of every file folded into it, as for any path.

A name that matches none of these is never folded. A new fixed name in a
temp dir (`/tmp/exfil.tar`, `/tmp/build-output`) is its own entry and drift,
and so is a random name outside one (`/workspace/tmpk3j_9xq2`). A template is
drift the first time it appears too, so a baseline only accepts the random
names it has seen the kind of: the same directory, prefix and extension.

What folding gives up: any name that matches a pattern folds, whether a
program drew it at random or the agent chose it. `/tmp/*` is in the baseline
of nearly every agent that runs Python, from `tempfile`'s check file, so a
later write to an 8-character name such as `/tmp/backupdb` or `/tmp/keys_out`
is aligned, and so is `/tmp/tmpEXFIL1` once `/tmp/tmp*` is in. An agent that
knows the rule can name a file to fit a template it already has. Running a
folded file is still drift when its entry was never run before, since the
flags are the union. That is the trade made for not reporting drift on every
scan.

Only the file's name is folded, not a directory's: a file with a fixed name
inside a fresh `mkdtemp()` directory (`/tmp/tmpk3j_9xq2/out.json`) is still a
new path each run. A 6-character `mkstemp(3)` name that happens to be all
lower-case letters (about 1 in 180) is not folded either.

When an entry in the list holds a folded file, the note says "randomly named
temp files are folded into one path per directory and name pattern, with * for
the random part", so a templated path never passes for a file of that name.
The feature file's `collapsed` counts the distinct paths folded into listed
entries; past 16,384 it is a lower bound, with at least 1 per listed template.
Folding is new in rule pack 5: RailDash shows a baseline locked under pack 4 as
`CONTRACT_MISMATCH`, not as drift, until a pack-5 ASP is locked.

### Schema and limits

The published v1 schema holds an ANSWERED or PARTIAL value to that shape
(`$defs.file_access_value` in `schemas/evidence-bundle-v1.schema.json`): five
fields, all required, a path of 1 to 1024 characters, at most 512 entries.
`verify_bundle` walks that schema, and adds the bound no schema keyword
states: at most 256 KiB of compact JSON. The v2 schema has no per-attribute
shapes, so `verify_bundle_v2` holds the sandbox-scoped value to the same def
in code.

Not covered, because filesnoop does not see it: files already open when it
attached, reads and writes through a descriptor opened earlier or passed in,
`truncate(2)`, `rename` and `unlink`, directories and devices. The events are
per PID namespace, so in a multi-agent bundle the attribute is
sandbox-scoped. Keep the file where the agent cannot write, as for
listensnoop's, and remember that paths can be sensitive.

The attribute is new in rule pack 4. RailDash shows a baseline locked under
pack 3 as `CONTRACT_MISMATCH`, not as drift, until a pack-4 ASP is locked.
`tests/files_drift_acceptance.py` runs the path against a real RailDash in
CI. A newly written path, or a write to a file that was only read, is drift
on this attribute alone. A second run that writes temp files under new
random names (made by Python's `tempfile` and `mktemp`) stays aligned, and a
new fixed name in `/tmp` is drift.

## Agent identity

| Field | Where it comes from |
|---|---|
| `host_id` | `RAIL_HOST_ID` (or `--host-id`), the same value every Rail component on the host reads. The scanner's own environment is read before the scanned container's, so a container cannot relabel the host it runs on; `host_id_source` distinguishes `flag`, `env` and `container_env`. **No fallback is invented** — an id this scanner made up would disagree with the proxy and the collector, so an unset variable is reported as unset. |
| `sandbox_name` | the `rail.sandbox_name` container label, else the container name, else the hostname. **Never an environment variable**: an agent nobody onboarded carries no Rail configuration, and those are exactly the ones worth discovering. |
| `host_class` | DMI vendor/product — `gce_vm`, `ec2_vm`, `azure_vm`, `virtual_machine`, `bare_metal`, `container`, or `unknown` when the DMI is unreadable. |

Both identity fields are optional on Rail Center's side and bounded to its
storage width (64 and 255), so the scanner truncates rather than letting a long
value surface as a server error.

## Multi-agent target manifest

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

The collection is delivered as one evidence-bundle v2 document, and RailDash
locks it as a baseline like a v1 bundle. Every declared agent stays in it:
one whose process has gone is still listed, now as `not_found`. Against the
baseline, that is drift on that agent alone (`AGENT_CHANGED`, then its
attributes and sources), with siblings and the sandbox scope unchanged.
`tests/multi_agent_drift_acceptance.py` runs that path in the image against
a real RailDash in CI.

The v2 schema also publishes an optional `window` member on an attribute
(DR-169), for a list that holds only what the observation window saw: an
item a quieter window did not see is not a removal. `ignore` names the item
keys that count traffic (`observed_destinations`' `count` and
`error_count`), and `union` the boolean keys that are true if it happened at
any point in the window (`observed_file_access`' `read`, `write` and
`exec`). Status is unchanged by it. The lists it applies to are one table,
`WINDOW_LISTS` in `compose_evidence_bundle_v2.py`: `tool_names`,
`observed_destinations`, `undeclared_destinations`, `observed_listeners`,
`observed_ingress_peers` and `observed_file_access`. The scanner emits it
on each of them whose status reports a window (`ANSWERED`, `PARTIAL` or
`ABSENT`), never on `BLIND` or `FAILED`. Rail Center's ingest
(`/v1/evidence-bundles`) rejects an attribute member it does not know, so
delivering to a Rail Center that predates the member fails.

The keyed registration state is also what the collector's multi-target
capture reads to judge an unsigned `x-rail` ticket. Start the
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
export RAIL_HOST_ID=my-host
python3 tools/scan/scan_agent_environment.py
```

Write the payload to a file:

```bash
python3 tools/scan/scan_agent_environment.py \
  --output output/registration-payload.json
```

Use explicit values when the model or provider cannot be inferred:

```bash
python3 tools/scan/scan_agent_environment.py \
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
python3 tools/scan/scan_agent_environment.py \
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
python3 tools/scan/scan_agent_environment.py \
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
python3 tools/scan/scan_agent_environment.py \
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
python3 tools/scan/scan_agent_environment.py \
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
python3 tools/scan/scan_agent_environment.py \
  --mcp-config /path/to/.mcp.json
```

An estate that declares its MCP server via environment variables instead of a
config file (as some Compose deployments do, one server per agent) is still
discovered — no flag
needed. If both `AGENT_MCP_NAME` and `AGENT_MCP_URL` are set, that server is
added to the inventory and skills list the same way a `.mcp.json` entry would
be, merged with any file-derived servers (a file entry with the same name
wins). Only this one name/URL pair is read; there is no env-var equivalent of
a multi-server `mcpServers` block.

Merge external skills from the skills scanner:

```bash
python3 tools/scan/scan_agent_environment.py \
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
RegisterAgentRequest.model_validate(json.load(open("/path/to/registration-payload.json")))
print("valid")
'
```
