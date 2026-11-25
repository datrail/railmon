# Changelog

Notable changes to RailMon, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Releases are the
`v0.1.0-mN` milestone tags; each date is the tagged commit's date.

A line marked **Rule pack N** bumps `rule_pack_version`
(`RULE_PACK_VERSION` in `tools/scan/evidence_bundle.py`). After a bump, a
baseline locked on the previous pack reads `CONTRACT_MISMATCH` until it is
re-locked.

Each PR adds its line under `## Unreleased`.

## Unreleased

### Added

- gke-scan's cluster reader and its full configuration (RC-550). `railmon gke-scan` now takes `--namespaces` (`RAIL_NAMESPACES`, required: the enrolled namespaces, or `*`), `--label-selector`, `--interval`, `--registry-access`, `--layer-budget`, `--probe-external`, `--data-guardrail-url`, `--sidecar-interval` and `--register-without-sidecar`, each with its variable and default; a missing or unparsable value exits 2 naming it. `KubeClient` lists and watches, retrying 429 and 5xx with backoff. The reader (`tools/scan/gke/central_service/cluster_reader.py`) lists and watches the enrolled namespaces' agent pods, MCP server pods, Services, NetworkPolicies, PersistentVolumeClaims and Namespaces, re-watching when a watch ends and listing again on 410 Gone and every interval, and reports each change with the workloads it affects. A read gke-scan's role refuses (403) is logged and retried each interval while the rest carry on, and a kind that lists but whose watch keeps failing backs off up to a minute. The intake's pod check answers from the watched copy, never waiting on the reader's API reads, and reads the API for a pod the copy doesn't have with the token's UID. The chart passes `RAIL_NAMESPACES` and `RAIL_SIDECAR_INTERVAL_SECONDS`; the list and watch permissions come with RC-557, and until then the reader logs each refused read once and the intake reads the API as before. No change to any bundle.
- gke-scan's pod-spec fields and the rest of its workload resolver (RC-551), in `tools/scan/gke/central_service/pod_fields.py`: the agent container (the `rail.datrail.io/scan-agent-container` annotation the webhook also reads, else the first container that is neither the scan sidecar nor rail-proxy, with a note when there was a choice), the pod's revision, whether it has a sidecar, `agent_type` from the `rail.datrail.io/agent-type` label for a workload with no sidecar, and `image_digest`, `mounts`, `permissions`, `declared_ports`, `services_exposing_agent` and `sandbox_network_policy` over one revision's Ready pods, built with evidence_bundle's helpers. A revision whose pods run different digests is PARTIAL listing them; a NetworkPolicy's podSelector is evaluated with every matchExpressions operator, and one that can't be evaluated makes the field PARTIAL naming the policy. Tested on research phase 15's pods from gke-test, gke-auto and gke-sandbox, with their env values left out, against central_v3.py's output. Nothing sends these yet: gke-scan's bundle comes with RC-555. No change to any bundle.
- The v1 schema accepts gke-scan's fields (RC-552): `egress_containment` gains a Kubernetes shape, told apart from Docker's by `network_mode`, and the enforcer `kubernetes_network_policy`, and `declared_ports` and `services_exposing_agent` get published value shapes (`$defs.declared_ports_value`, `$defs.services_exposing_agent_value`), which v2 checks in code. `egress_containment.classify_kubernetes` gives a pod's level from the NetworkPolicies that select it and whether anetd or calico-node enforces them (`central_service/enforcement.py`, once per interval: a DaemonSet counts only with every scheduled pod Ready, and is unknown otherwise): `host_network`, `open` (no restricting policy, an allow-all one, no enforcement, or some ports open to any address, a `/0` ipBlock however it's written), or `allow_list_enforced`; PARTIAL at `open` when enforcement couldn't be checked for a policy that would otherwise restrict egress, or a selector couldn't be evaluated. The schema walker checks `maximum`. Additive: every existing bundle still passes, and the scanner's own output doesn't change, so no rule pack bump.

### Changed

- **Rule pack 18:** the webhook gives the sidecar every volume an agent's files are on (RC-549). The `rail.datrail.io/scan-config-path` annotation takes several comma-separated paths (`/data/openclaw,/root/.openclaw`, `/root/.claude,/workspace`), and the chart's `sidecar.configPath` may be a list: each is its own `--config-path`, the agent's volume mounts holding any of them are mounted read-only once each, and a warning names the path it is about. One path behaves as before. An OpenClaw agent with `openclaw.json` apart from its state, or a Claude Code agent with its project on its own volume, no longer reads the other volume's fields `BLIND`.
- **Rule pack 18:** `framework_identity` in pod mode reads Python's or Node's version from the interpreter the agent's process runs when no `PYTHON_VERSION` or `NODE_VERSION` says it (RC-549): a venv's `pyvenv.cfg` beside the interpreter the command line starts, else a version in the executable's path (a standalone build's `python-3.14.9+.../bin/python3.14`), else `python3.14`'s own name. Read, never run; a variable still wins. An image that ships its own interpreter (Hermes) gets it `ANSWERED` rather than `BLIND`.

### Fixed

- **Rule pack 18:** pod mode reads the files of an agent image whose layers report their own device (RC-549): on GKE image streaming (Autopilot's default for Artifact Registry images) and under gVisor (GKE Sandbox), a file from a lower layer reports that layer's `st_dev`, and RC-509's guard took it for another filesystem, so Claude Code's `harness_identity` read `BLIND` and OpenClaw's version was missing from `framework_identity`. A file or link whose `st_dev` differs is now the root's when the agent's `/proc/<pid>/mountinfo` lists no mount at its path; directories must still share the root's `st_dev`, and volumes, single-file mounts (`subPath`, `/etc/hosts`) and the pod's `/proc` are still refused. Without a readable mountinfo the guard compares `st_dev` alone, as before.

## [v0.1.0-m19] - 2026-11-22

**Rule pack 17** (was 16 since v0.1.0-m18). A baseline locked on pack 16 reads `CONTRACT_MISMATCH` until it is re-locked.

### Added

- **Rule pack 17:** `mcp_servers_observed`, in pod mode (RC-545): the MCP servers the agent called and which of their tools, `[{"name", "tools_called": [tool, ...]}]`, from the tool names the harness profile reads for `tool_names`: names only, and a floor, not a count, so an agent that keeps calling the same tools reads the same on every scan. A call is a server's when its name matches the profile's pattern (OpenClaw's `<server>__<tool>`, Claude Code's `mcp__<server>__<tool>`) with a server `mcp_servers_declared` names; Claude Code's `mcp__` prefix is only for MCP tools, so a server no config declares counts too, under the name Claude Code spells (a plugin's server is `plugin_<plugin>_<server>`), and the note lists it. No endpoint: a transcript names the tool, not the address called. Built-in tools are left out. Transcripts with no MCP call give `ABSENT`, as `tool_names` does with no tool calls; some left unread give `PARTIAL` as `tool_names` does; none readable gives `BLIND` with `NO_SOURCE_ACCESS` in place of the AgentSight placeholder; a harness without a profile gives `BLIND` with `UNKNOWN_HARNESS`. Self and docker scans are unchanged.
- The scan-sidecar image and the `railmon-gke` chart (RC-518). `Dockerfile.scan-sidecar` builds a slim image with Python and `tools/scan` only (no collector, AgentSight, Docker CLI, OpenShell, curl, openssl or pip) that runs as any UID with a read-only root filesystem and no capabilities; CI builds and tests it on amd64 and arm64, and a release tag pushes it to Artifact Registry. Its entrypoint offers `scan`, `gke-scan` and `scan-webhook`. `railmon scan-webhook`, a mutating admission webhook, adds the sidecar to pods labeled `rail.datrail.io/scan=true` in enrolled namespaces (failurePolicy Ignore; it always allows the pod), as a native sidecar, with the agent's config volume read-only at the same path, the downward API, a projected token (audience `gke-scan`, 3600 seconds), `shareProcessNamespace`, the agent's UID and GID, and `RAIL_SANDBOX_TYPE` `gvisor` when the pod's `runtimeClassName` is `gvisor`, else `kubernetes`. Beside a root agent the sidecar gets the agent container's own capabilities, since Linux won't let a process with fewer read a root agent's environment or root; beside any other it has none. What the webhook had to guess is kept on the pod in `rail.datrail.io/scan-sidecar-warnings`. `--collect-system-prompt` (`RAIL_COLLECT_SYSTEM_PROMPT`, the chart's `sidecar.collectSystemPrompt`) puts the system prompt files' text in `system_prompt_text` in pod mode; it is off by default, as before. The chart (`deploy/helm/railmon-gke`) holds the one sidecar spec, the webhook, gke-scan with its RBAC, the CA both trust (kept across upgrades, or given as `tls.ca` for `helm template` and Argo CD; gke-scan and the webhook load a renewed certificate without a restart), and the NetworkPolicies: agent pods may reach only gke-scan and DNS (kube-dns and `169.254.20.10/32`), and gke-scan accepts only labeled pods and reaches only Rail Center, the Kubernetes API, DNS, the metadata server and the spec targets; `networkPolicy.agentEgress.extraEgress` adds the agent's own destinations. The Artifact Registry push is skipped, with a warning, until `SCAN_SIDECAR_IMAGE` is set. Bundles are unchanged unless `--collect-system-prompt` is given.
- `railmon gke-scan`, the central GKE service (one per cluster in `rail-system`), starting with the sidecar intake: `POST /v1/agents/register` over HTTPS takes a scan sidecar's bundle, checks its projected token with a TokenReview (audience `gke-scan`), then that the bundle is v1, at most 4 MB, filed under this cluster's `host_id`, the token's namespace and pod UID, and the pod's own workload, with each owner it names read from the API and checked (UID, selector, up to the Deployment, Rollout or CronJob), from a pod that still exists labeled `rail.datrail.io/scan=true`, with one bundle per pod at a time and no `?agent_key=` (which would let a pod file its bundle under another agent's key), and relays the same bytes to Rail Center with `X-Rail-Source: sidecar` and `X-Rail-Pod-UID` under gke-scan's own credential. A bundle that fails a check is refused with 401, 403, 409, 411, 413 or 422 and never relayed. Rail Center's answer passes back as is, except that 401, 403, 5xx or no answer becomes 503 for the sidecar to retry. Bundles are unchanged (RC-515).

### Changed

- **Rule pack 17:** `tool_names` reads every transcript it can (RC-530). OpenClaw's profile reads the events OpenClaw 2026.10.8 compresses into `event_zstd` (any event of 1 KB or more, with `event_json` NULL), with the standard library's `compression.zstd` (Python 3.14+; the image and CI run 3.15), names only as before: one event may decompress to at most 4 MB and a database's events to 64 MB within its 5-second deadline, and a frame that doesn't decompress, passes the cap or can't be read on an older Python counts as unparsed (`PARTIAL`, `PARSE_FAILED`) while the rest still count. The shared reader and Claude Code's profile read the newest transcripts first when there are more than `TRANSCRIPT_MAX_FILES` (50), by modification time, and report `tool_names` `PARTIAL` with `SIZE_CAP_EXCEEDED` and how many were read, where they were `ANSWERED` from an arbitrary 50 before; with transcripts left unread, none found is an empty floor, not `ABSENT`. An OpenClaw 2026.10.8 agent's names in `event_zstd` now count, so its `tool_names` can move from `PARTIAL` (`PARSE_FAILED`) to `ANSWERED`. An OpenClaw 2026.9.2 agent, and a Claude Code or generic-reader agent with 50 transcripts or fewer, read as before. A baseline locked on pack 16 reads `CONTRACT_MISMATCH` until it is re-locked.
- Pod mode's code moved from `tools/scan/gke/` to `tools/scan/gke/sidecar/`, beside gke-scan's in `tools/scan/gke/central_service/`. Behavior and bundles are unchanged (RC-515).

## [v0.1.0-m18] - 2026-11-19

**Rule pack 16** (was 15 since v0.1.0-m17). A baseline locked on pack 14 or 15 reads `CONTRACT_MISMATCH` until it is re-locked.

### Added

- Pod mode's reporter retries safely: a post to gke-scan that gets 429, a 5xx or no answer is retried 5 seconds later, doubling with ±20% jitter up to 5 minutes and never sooner than a `Retry-After` gke-scan passes on, in the background of an `--interval` sidecar. Only the latest bundle waits: a newer scan's bundle takes its place and its time. 401, 403, 409, 413, 422 and any other answer are final for that bundle and not resent. The post's timeout is 30 seconds. `--center-ca-file` (`RAIL_CENTER_CA_FILE`) trusts a PEM CA, such as the chart's for gke-scan, beside the system store for the `--center-url` host only; the MCP and spec probes, RailDash and the metadata server keep the system store. Self and docker scans make one attempt as before. Bundles are unchanged. ([#153](https://github.com/datrail/railmon/pull/153))
- `asp_redaction`, RailMon's URL redaction rule in the `asp_spelling` package, so Rail Center's capture plan and the proxy match on the redacted path with the rule RailMon applies instead of re-implementing it. Bundles are unchanged ([#140](https://github.com/datrail/railmon/pull/140)).
- **Rule pack 16:** OpenClaw's harness profile, the first to ship: in pod mode an OpenClaw agent's `harness_identity`, `model_name`, `llm_provider`, `inference_endpoint`, `mcp_servers_declared`, `tool_allow_deny`, `approval_policy`, `tool_names`, `system_prompt_present` and `skills_inventory` are read from its own files (`openclaw.json`, its package, its state and transcript databases, its workspace), in the folder OpenClaw itself picks for `--profile`, `--dev`, `OPENCLAW_HOME` or `OPENCLAW_STATE_DIR`. Self and docker scans are unchanged ([#141](https://github.com/datrail/railmon/pull/141)).
- Claude Code's harness profile, in the same rule pack 16 as OpenClaw's: in pod mode a Claude Code agent's harness fields are read from its managed, project, local and user settings (in Claude Code's own precedence, `managed-settings.d` drop-ins first), `~/.claude.json`, its project's `.mcp.json`, its npm package or native install, its transcripts and its `CLAUDE.md` and skills, wherever `CLAUDE_CONFIG_DIR` and the agent's working directory put them. A project's allow rules are reported as ignored until its workspace is trusted, as Claude Code ignores them. Pod mode now reads the agent's working directory (`/proc/<pid>/cwd`), to find files only. Self and docker scans are unchanged ([#144](https://github.com/datrail/railmon/pull/144)).
- **Rule pack 16:** `tool_schemas`, every MCP tool's input schema and annotations with key-shaped strings redacted (`record_tool_schema`, `redact_json`), capped at 8 KiB a tool and 256 KiB in all. A server that needs a credential is `BLIND` or `PARTIAL` with `PRIVATE_STORE`; an oversized schema is `PARTIAL` with `SIZE_CAP_EXCEEDED`. In pod mode the MCP probe drops the agent's MCP headers, so the sidecar sends no credential ([#143](https://github.com/datrail/railmon/pull/143)).
- **Rule pack 16:** `tool_schemas` keeps one entry per server and source: a server named in both `./.mcp.json` and `~/.mcp.json` is two copies, each with its own tools, and none are merged. Each entry says where it was read from (`source`, now the config's path with `HOME` as `~`, and `source_kind`: `file`, `environment` or `harness_profile`). Each tool carries its server's `description` and `schema_sha256`, which RailDash's captured-traffic hash matches when nothing was redacted. A description cut for size is marked with `description_omitted`. `skills_inventory` is unchanged ([#150](https://github.com/datrail/railmon/pull/150)).
- **Rule pack 16:** `http_operations`, in pod mode: each MCP server's origin is asked, without credentials, for `/openapi.json`, `/v3/api-docs`, `/swagger.json` and `/api-docs`, then the same under the path the MCP server is mounted at (http and https only, same-origin redirects only, up to 4 MB; a server whose URL carries a credential is not a destination), and each spec operation's method, path, operationId and content types are kept. A destination that answers 401 or 403 is `BLIND` or `PARTIAL` with `PRIVATE_STORE`; a spec over 4 MB is `PARTIAL` with `SIZE_CAP_EXCEEDED`. Pod mode now runs its MCP and spec probes 4 at a time and gives the scan 60 seconds: a probe still out then is reported `BLIND` for that server alone (`deadline_exceeded`), and the rest of the bundle is still built. Self and docker scans report `http_operations` `BLIND`, `NOT_COLLECTED_BY_PACK`, and probe as before. `tool_schemas` and `skills_inventory` also redact a credential by its name, not only by a vendor key's shape (a `password`, `pwd`, `api_key`, `authorization` or `cookie` property's defaults, examples, const and enum; any value under such a key in sample data), a URL's credential whatever its scheme or port, and an HTTP auth scheme's (`Bearer …`, `Basic …`); and an MCP response is bounded by JSON elements as well as bytes ([#151](https://github.com/datrail/railmon/pull/151)).
- In pod mode `tool_schemas` and `skills_inventory` probe the MCP servers the agent's harness profile declares: OpenClaw's `openclaw.json`, and Claude Code's user, project and local scopes, or `managed-mcp.json` alone when it exists. Each server is asked once, without credentials: a URL carrying one isn't asked, and the server is `auth_refused`. `tool_schemas` is `BLIND`, not `ABSENT`, when the profile couldn't read the MCP config (RC-531) ([#143](https://github.com/datrail/railmon/pull/143)).
- A generic reader for any other harness, in the same rule pack 16: in pod mode an agent no harness profile matches gets `mcp_servers_declared`, `model_name`, `llm_provider`, `inference_endpoint`, `tool_allow_deny`, `approval_policy` and `system_prompt_present` from what any harness may use (`.mcp.json`, `AGENTS.md`, `*_MODEL` and `*_BASE_URL` variables, and model-like and permission-named keys in the top-level `*.json` under `--config-path`). Every harness field it can't fill is `BLIND` with `UNKNOWN_HARNESS` instead of `ABSENT`, and `tool_schemas` is `BLIND`, not `ABSENT`, when there is no MCP config. Self and docker scans are unchanged ([#147](https://github.com/datrail/railmon/pull/147)).
- Pod mode's watcher: with `--interval`, the sidecar hashes the sources the agent's harness profile names every 10 seconds (transcripts by file list only) and scans once nothing has changed for 5 seconds, or 60 seconds after a change that never settles, one scan at a time with one more queued for a change during it; the interval still rescans. One poll reads at most 64 MiB and 5,000 files in all, and the transcript file lists have 5,000 of their own. An OpenClaw agent's first scan waits for `openclaw.json` and `agents/main/`, up to 300 seconds, then scans with what is missing `BLIND`; any other harness is scanned as soon as its process is found. SIGTERM abandons a scan in progress, writing and sending nothing for it, and gives a bundle in flight 5 seconds. Each scan writes the time to a health file (`RAIL_HEALTH_FILE`, default `/tmp/railmon-health.json`), and `railmon scan --health-check`, for the exec liveness probe, fails when it is older than two intervals, or, before the first scan, once the startup waits (for the agent, then RailDash) and two intervals are over. Bundles are unchanged ([#152](https://github.com/datrail/railmon/pull/152)).

### Changed

- **Rule pack 16:** `railmon scan --mode docker` runs nothing in the agent's container, so it needs no write access to Docker: inspect is the only Docker call (a read-only Docker API proxy is enough). What `docker exec` printed is read from inspect and from the container's own files through `/proc/<pid>/root`, which needs `pid: host` and `cap_add: [SYS_PTRACE]` on the scan's container. Runtime versions come from build stamps and the image's `NODE_VERSION`/`PYTHON_VERSION` instead of `--version`, so a Python without `PYTHON_VERSION` is no longer listed, the scan's own `sh`/`id`/`env` no longer appear in `observed_file_access`, and `system_info.uname` names the image's machine (from the ELF header of the container's own `/bin/sh`), as `uname -m` in an emulated container did ([#142](https://github.com/datrail/railmon/pull/142)).
- **Rule pack 16:** the runtimes read from an agent's files, in docker and pod mode, include Claude Code (its npm package, or the native installer's `versions/<version>` file the `claude` on PATH links to), as `<version> (Claude Code)`. A pod-mode scan of a Claude Code agent gains `claude` in `framework_identity`, and `system_info.runtime` names it ([#142](https://github.com/datrail/railmon/pull/142)).
- **Rule pack 16:** in `observed_listeners` and `observed_ingress_peers`, when `railmon listen` follows a container (`RAIL_LISTEN_CONTAINER`, as the stack runs it), a listener or peer from AgentSight's process probe is named for its process (its main thread's name, as the snapshot of already-open sockets is), not for the thread that bound or accepted it. An agent whose runtime names its threads (Python from 3.14, the JVM) no longer reports a peer accepted on a worker as `Thread-1 (serve`; one whose threads share the process's name is unchanged ([#149](https://github.com/datrail/railmon/pull/149)).
- Dependency updates: zstd 0.14.4, with upstream's memory-safety fixes ([#146](https://github.com/datrail/railmon/pull/146)).
- The image and CI run Python 3.15 (was 3.13) ([#149](https://github.com/datrail/railmon/pull/149)).
- An `--interval` scan that delivers to RailDash waits up to 120 s for RailDash to answer before its first scan, so after a reboot, when both start together, the log says RailDash isn't up yet instead of reporting a failed delivery. Bundles are unchanged ([#148](https://github.com/datrail/railmon/pull/148)).
- OpenClaw's harness profile also matches a process named `openclaw-gateway`, as OpenClaw 2026.9.2's gateway names itself in `/proc/<pid>/cmdline`. Before, a running OpenClaw gateway matched no profile in pod mode and was read by the generic reader ([#152](https://github.com/datrail/railmon/pull/152)).

## [v0.1.0-m17] - 2026-11-16

**Rule pack 15** (was 14 since v0.1.0-m15). A baseline locked on pack 14 reads `CONTRACT_MISMATCH` until it is re-locked.

### Added

- `railmon scan --mode pod` runs the scanner as a sidecar in a Kubernetes pod and names the agent from the downward API ([#122](https://github.com/datrail/railmon/pull/122)).
- Pod mode reads the agent's own process, found again after a restart, instead of the sidecar's ([#123](https://github.com/datrail/railmon/pull/123)).
- `asp_spelling`, a standard-library package holding the one ASP value spelling RailDash and Rail Center both read ([#118](https://github.com/datrail/railmon/pull/118)).
- `asp_normalize`, one normalization from an evidence bundle (v1 or v2) to each agent's attributes ([#119](https://github.com/datrail/railmon/pull/119)).
- `asp_normalize.unreached_server`, so a comparison of `skills_inventory` items skips the placeholder for an MCP server RailMon could not reach instead of reading an outage as a new tool. Normalized maps are unchanged ([#138](https://github.com/datrail/railmon/pull/138)).
- One harness reader (`tools/scan/gke/harness/`) reads any agent harness's fields from a profile per harness ([#124](https://github.com/datrail/railmon/pull/124)).
- **Rule pack 15:** each MCP skill says whether its server was reached (`reachability`), why a tool's input schema was left out (`schema_omitted`) and when `tools/list` was cut short (`tools_truncated`); the v1 schema closes these values ([#126](https://github.com/datrail/railmon/pull/126)).

### Changed

- **Rule pack 15:** a `[redacted]` path segment only ever comes from redaction: `[` and `]` in a kept path segment are percent-encoded, so a consumer can rely on the marker ([#129](https://github.com/datrail/railmon/pull/129)).
- Each sensor names the capability, tracefs mount or Docker access it is missing, instead of pointing at the kernel or the agent's libssl ([#137](https://github.com/datrail/railmon/pull/137)).
- Dependency updates: base64 0.23, brotli 9.1, brotli-decompressor 6.3, sha2 0.11, zstd 0.14 and the cargo group ([#131](https://github.com/datrail/railmon/pull/131) – [#136](https://github.com/datrail/railmon/pull/136)).
- **Rule pack 15:** `tools/list` follows `nextCursor` for up to 20 pages and 200 tools, and a malformed MCP response marks that server unreachable instead of aborting the scan ([#126](https://github.com/datrail/railmon/pull/126)).
- A tag's GitHub Release notes open with the annotated tag's message ([#121](https://github.com/datrail/railmon/pull/121)).
- The Dockerfile's comment on the OpenShell CLI no longer says CI installs the same release ([#120](https://github.com/datrail/railmon/pull/120)).

## [v0.1.0-m16] - 2026-11-03

Rule pack 14 (unchanged).

### Changed

- The container release workflow creates the tag's GitHub Release ([#117](https://github.com/datrail/railmon/pull/117)).

### Security

- rustls 0.23.46, for four advisories ([#116](https://github.com/datrail/railmon/pull/116)).

## [v0.1.0-m15] - 2026-10-29

### Added

- `egress_containment` carries an OpenShell sandbox's allow-list, read from OpenShell by `railmon openshell` ([#115](https://github.com/datrail/railmon/pull/115)).

### Changed

- **Rule pack 14.** A crowded group of written files is listed as `<dir>/*.<ext>`, so a write isn't lost to the list cap; OpenShell placeholders are classified as references ([#113](https://github.com/datrail/railmon/pull/113)).
- Skills name their MCP server and say whether they are a tool or a server; a probed tool keeps its `inputSchema` and annotations ([#114](https://github.com/datrail/railmon/pull/114)).
- A keyed target's tap follows its uid and process tree, not one session ([#111](https://github.com/datrail/railmon/pull/111)).
- CONTRIBUTING documents the required `rail-review` status ([#112](https://github.com/datrail/railmon/pull/112)).

## [v0.1.0-m14] - 2026-10-27

### Fixed

- `railmon collect` follows the container's process tree, not one session, so a real OpenClaw agent's calls are captured ([#110](https://github.com/datrail/railmon/pull/110)).

## [v0.1.0-m13] - 2026-10-24

### Fixed

- An agent switched to a new target starts on a fresh listen and files file ([#109](https://github.com/datrail/railmon/pull/109)).

## [v0.1.0-m12] - 2026-10-24

### Fixed

- A streamed reply whose connection closed between chunks is recorded and paired with its request ([#108](https://github.com/datrail/railmon/pull/108)).

## [v0.1.0-m11] - 2026-10-24

### Changed

- The image's OpenShell CLI is 0.1.5 ([#107](https://github.com/datrail/railmon/pull/107)).

### Fixed

- An OpenShell L7 denial's port comes from its URL's scheme ([#107](https://github.com/datrail/railmon/pull/107)).

## [v0.1.0-m10] - 2026-10-24

### Added

- `railmon openshell` posts an OpenShell sandbox's policy and its supervisor's denials to RailDash ([#106](https://github.com/datrail/railmon/pull/106)).

## [v0.1.0-m9] - 2026-10-24

### Added

- Follow an OpenShell sandbox by name, `openshell:<sandbox>` ([#105](https://github.com/datrail/railmon/pull/105)).

## [v0.1.0-m8] - 2026-10-24

Rule pack 13 (unchanged).

### Changed

- `railmon collect` pairs a reply with its request by AgentSight 1.0.35's `http_exchange_id` ([#104](https://github.com/datrail/railmon/pull/104)).

### Fixed

- RailDash's local token is passed as `--token=…` ([#103](https://github.com/datrail/railmon/pull/103)).

## [v0.1.0-m7] - 2026-10-23

### Changed

- **Rule pack 13.** `listen` and `files` run AgentSight v1.0.35's process probe by default; RailMon no longer carries its own eBPF probes ([#102](https://github.com/datrail/railmon/pull/102)).

## [v0.1.0-m6] - 2026-10-23

### Added

- AgentSight's process probe can feed the listen and files lines, opt-in ([#99](https://github.com/datrail/railmon/pull/99)).
- The demo agent declares its MCP server; the demo client opens a GET stream and ends its session ([#101](https://github.com/datrail/railmon/pull/101)).

### Changed

- **Rule pack 12.** The user is read from the image's `Config.User`, MCP allow lists are recorded, credential names are narrowed, and JSON is parsed strictly ([#98](https://github.com/datrail/railmon/pull/98)).
- A target manifest without agent keys fails closed with `MULTI_AGENT_KEY_REQUIRED` instead of sending an unkeyed v1 bundle ([#100](https://github.com/datrail/railmon/pull/100)).

## [v0.1.0-m5] - 2026-10-20

### Changed

- The release builds each architecture natively, without QEMU ([#92](https://github.com/datrail/railmon/pull/92)).
- The docs name Rail Center's register route, not its removed evidence-bundles route ([#95](https://github.com/datrail/railmon/pull/95)).
- The scan README says Rail Center's register answer carries no ticket ([#96](https://github.com/datrail/railmon/pull/96)).

### Fixed

- A compressed HTTP/1 reply is decoded before the parser reads it as text ([#94](https://github.com/datrail/railmon/pull/94)).

## [v0.1.0-m4] - 2026-10-13

### Added

- Emit ASP v1 deployment identity keys ([#19](https://github.com/datrail/railmon/pull/19)).
- Capture multiple agents without collapsing their identities ([#21](https://github.com/datrail/railmon/pull/21)).
- Probe each MCP server's `tools/list` instead of synthesizing one skill ([#22](https://github.com/datrail/railmon/pull/22)).
- Deliver evidence bundles to RailDash and scan on an interval ([#24](https://github.com/datrail/railmon/pull/24)).
- Send `X-RailDash-Token` with evidence-bundle delivery ([#25](https://github.com/datrail/railmon/pull/25)).
- Discover MCP servers declared through environment variables ([#26](https://github.com/datrail/railmon/pull/26)).
- Publish the evidence bundle v2 schema with its own fixtures ([#27](https://github.com/datrail/railmon/pull/27)).
- Run agent-scoped scanning and registration once per agent key ([#30](https://github.com/datrail/railmon/pull/30)).
- Emit and validate evidence bundle v2 ([#31](https://github.com/datrail/railmon/pull/31)).
- Resolve non-delegated cgroup locators to a process incarnation ([#33](https://github.com/datrail/railmon/pull/33)).
- Capture, log and expose `RAIL_AGENT_KEY` as a diagnostic hint ([#34](https://github.com/datrail/railmon/pull/34)).
- Restart a target's tap safely across process exit and PID reuse ([#35](https://github.com/datrail/railmon/pull/35)).
- Judge an unsigned x-rail ticket against the process target ([#36](https://github.com/datrail/railmon/pull/36)).
- The image ships the v2 bundle schema ([#38](https://github.com/datrail/railmon/pull/38)).
- Document multi-agent manifest authoring, reporting, diagnosis and rollback ([#39](https://github.com/datrail/railmon/pull/39)).
- Scanner registration takes a token file and the `gcp` mode ([#48](https://github.com/datrail/railmon/pull/48)).
- **Rule pack 2.** Listening sockets fold into observed reach as a drift signal ([#49](https://github.com/datrail/railmon/pull/49)).
- The image ships listensnoop as `railmon listen` ([#50](https://github.com/datrail/railmon/pull/50)).
- **Rule pack 3.** Accepted peers fold into the bundle as `observed_ingress_peers` ([#51](https://github.com/datrail/railmon/pull/51)).
- **Rule pack 4.** filesnoop's file opens fold into the bundle as `observed_file_access` ([#58](https://github.com/datrail/railmon/pull/58)).
- The v1 schema publishes `observed_file_access`'s value shape ([#59](https://github.com/datrail/railmon/pull/59)).
- Evidence bundle v2 attributes may carry an optional `window` member ([#64](https://github.com/datrail/railmon/pull/64)), and the six window-bounded lists emit it ([#65](https://github.com/datrail/railmon/pull/65)).
- Record the sockets the agent was already listening on when listen attached ([#67](https://github.com/datrail/railmon/pull/67)).
- `railmon collect` follows a container: its TLS library, its process session and its restarts ([#72](https://github.com/datrail/railmon/pull/72)).
- **Rule pack 8.** The evidence bundle carries every field the registration payload does ([#74](https://github.com/datrail/railmon/pull/74)).
- **Rule pack 9.** The bundle carries dynamic agent data, and the schema publishes which attributes are dynamic ([#76](https://github.com/datrail/railmon/pull/76)).
- Send Rail Center the evidence bundle on `/v1/agents/register` ([#79](https://github.com/datrail/railmon/pull/79)).
- Send RailDash's write token with every capture, and a heartbeat while a tap is attached ([#82](https://github.com/datrail/railmon/pull/82)).
- The demo agent has an MCP server, reads through it, and can upload on demand ([#85](https://github.com/datrail/railmon/pull/85)).
- `demo_mcp_call.py --big N` measures the capture past its 1 MiB bound ([#86](https://github.com/datrail/railmon/pull/86)).
- Capture an agent in an OpenShell sandbox: the collector finds it, and runc's per-exec procfs paths fold ([#87](https://github.com/datrail/railmon/pull/87)).
- **Rule pack 11.** The bundle says whether the agent's egress is contained (`egress_containment`) ([#88](https://github.com/datrail/railmon/pull/88)).
- The arm64 image installs AgentSight's aarch64 build ([#90](https://github.com/datrail/railmon/pull/90)).

### Changed

- Align the evidence source schema ([#20](https://github.com/datrail/railmon/pull/20)).
- One canonical evidence-bundle schema, walked rather than re-coded by hand ([#23](https://github.com/datrail/railmon/pull/23)).
- RailScan-era names move to RailMon's; the old ones keep working ([#53](https://github.com/datrail/railmon/pull/53)).
- `railmon forward` sends interactions in Rail Center's batch envelope ([#56](https://github.com/datrail/railmon/pull/56)).
- Take agentsight-capture 1.0.34, which drops hpack 0.3 for loona-hpack ([#62](https://github.com/datrail/railmon/pull/62)).
- The image pins the AgentSight release it downloads and checks its SHA-256 ([#83](https://github.com/datrail/railmon/pull/83)).
- **Rule pack 5.** Randomly named temp files fold in observed file access ([#60](https://github.com/datrail/railmon/pull/60)).
- **Rule pack 6.** `observed_destinations` reads `BLIND` when no AgentSight snapshot was given ([#61](https://github.com/datrail/railmon/pull/61)).
- **Rule pack 7.** `observed_file_access` folds `/proc/<pid>` paths to `/proc/*/` ([#69](https://github.com/datrail/railmon/pull/69)).
- Each distinct file open is appended once, so an always-on `files.jsonl` stays bounded ([#68](https://github.com/datrail/railmon/pull/68)).
- **Rule pack 10.** Python bytecode-cache writes fold into `<dir>/__pycache__/*.pyc` ([#84](https://github.com/datrail/railmon/pull/84)).
- `RAIL_AUTH_MODE` applies to the collector's webhook and `railmon forward` ([#47](https://github.com/datrail/railmon/pull/47)).
- The skills scanner does not register with Rail Center ([#80](https://github.com/datrail/railmon/pull/80)).
- Point a new user at datrail-project first ([#66](https://github.com/datrail/railmon/pull/66)); the README's opening says what RailMon does today ([#91](https://github.com/datrail/railmon/pull/91)).
- Correct the public docs and drop internal references ([#55](https://github.com/datrail/railmon/pull/55)); fix documentation drift and remove duplicate code, no behaviour change ([#77](https://github.com/datrail/railmon/pull/77)); the scan README states where the bundle goes ([#73](https://github.com/datrail/railmon/pull/73)).
- CI and releases run on `ubuntu-26.04` by name ([#46](https://github.com/datrail/railmon/pull/46)); workflow actions move to their Node 24 majors ([#63](https://github.com/datrail/railmon/pull/63)).
- CI runs the RailMon and RailDash images together ([#44](https://github.com/datrail/railmon/pull/44)), with acceptance against the built image: fail-closed and single-agent cases ([#41](https://github.com/datrail/railmon/pull/41)), stricter fail-closed evidence checks ([#42](https://github.com/datrail/railmon/pull/42)) and stale PID reuse ([#43](https://github.com/datrail/railmon/pull/43)); an end-to-end check that RailDash locks a multi-agent baseline and reports a stopped agent as drift on that agent ([#52](https://github.com/datrail/railmon/pull/52)); tests for target-manifest validation and ownership ([#28](https://github.com/datrail/railmon/pull/28)) and for owner-only keyed artifacts that keep no ticket ([#32](https://github.com/datrail/railmon/pull/32)).

### Fixed

- One bad target no longer aborts a whole multi-agent run ([#29](https://github.com/datrail/railmon/pull/29)).
- An analyzer panic on captured traffic is contained to its own tap ([#37](https://github.com/datrail/railmon/pull/37)).
- Shut down cleanly on SIGTERM, not only SIGINT ([#40](https://github.com/datrail/railmon/pull/40)).
- A colliding process is captured as ambiguous instead of left untapped ([#45](https://github.com/datrail/railmon/pull/45)).
- A scan fails on an invalid bundle, config is documented, and interval scans no longer pile up ASPs ([#54](https://github.com/datrail/railmon/pull/54)).
- The interval PID-reuse test replaces only the scanner's sleep ([#57](https://github.com/datrail/railmon/pull/57)).
- A request whose response never pairs is forwarded as incomplete, with a count ([#71](https://github.com/datrail/railmon/pull/71)).
- A Node agent's reads on other connections stay out of a streamed reply ([#75](https://github.com/datrail/railmon/pull/75)).
- Run as a script, the scanner catches the `ScannerError` its helpers raise ([#78](https://github.com/datrail/railmon/pull/78)).
- `egress_containment`'s `via` and `network_mode` are strings or null ([#89](https://github.com/datrail/railmon/pull/89)).

### Security

- rustls 0.23.45, for a TLS 1.3 handshake advisory ([#81](https://github.com/datrail/railmon/pull/81)).

## [v0.1.0-m3] - 2026-09-15

### Added

- **Rule pack 1.** Emit the v1 evidence bundle the published schema accepts; `rule_pack_version` starts at 1 ([#17](https://github.com/datrail/railmon/pull/17)).

### Changed

- Evidence credential classes align with the schema ([#18](https://github.com/datrail/railmon/pull/18)).

## [v0.1.0-m2] - 2026-09-01

The initial public release, commit `45c58a8`. The work merged before it
(PRs #2 to #16) is squashed into that one commit.

Note: the `v0.1.0` tag points at the same commit `45c58a8`. It is a stray
tag, not a release; the milestone is `v0.1.0-m2`.

[v0.1.0-m19]: https://github.com/datrail/railmon/compare/v0.1.0-m18...v0.1.0-m19
[v0.1.0-m18]: https://github.com/datrail/railmon/compare/v0.1.0-m17...v0.1.0-m18
[v0.1.0-m17]: https://github.com/datrail/railmon/compare/v0.1.0-m16...v0.1.0-m17
[v0.1.0-m16]: https://github.com/datrail/railmon/compare/v0.1.0-m15...v0.1.0-m16
[v0.1.0-m15]: https://github.com/datrail/railmon/compare/v0.1.0-m14...v0.1.0-m15
[v0.1.0-m14]: https://github.com/datrail/railmon/compare/v0.1.0-m13...v0.1.0-m14
[v0.1.0-m13]: https://github.com/datrail/railmon/compare/v0.1.0-m12...v0.1.0-m13
[v0.1.0-m12]: https://github.com/datrail/railmon/compare/v0.1.0-m11...v0.1.0-m12
[v0.1.0-m11]: https://github.com/datrail/railmon/compare/v0.1.0-m10...v0.1.0-m11
[v0.1.0-m10]: https://github.com/datrail/railmon/compare/v0.1.0-m9...v0.1.0-m10
[v0.1.0-m9]: https://github.com/datrail/railmon/compare/v0.1.0-m8...v0.1.0-m9
[v0.1.0-m8]: https://github.com/datrail/railmon/compare/v0.1.0-m7...v0.1.0-m8
[v0.1.0-m7]: https://github.com/datrail/railmon/compare/v0.1.0-m6...v0.1.0-m7
[v0.1.0-m6]: https://github.com/datrail/railmon/compare/v0.1.0-m5...v0.1.0-m6
[v0.1.0-m5]: https://github.com/datrail/railmon/compare/v0.1.0-m4...v0.1.0-m5
[v0.1.0-m4]: https://github.com/datrail/railmon/compare/v0.1.0-m3...v0.1.0-m4
[v0.1.0-m3]: https://github.com/datrail/railmon/compare/v0.1.0-m2...v0.1.0-m3
[v0.1.0-m2]: https://github.com/datrail/railmon/releases/tag/v0.1.0-m2
