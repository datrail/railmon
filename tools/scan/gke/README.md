# Pod mode

`railmon scan --mode pod` runs the scanner as a sidecar in a Kubernetes pod
(RC-504). The code is [`pod_mode.py`](pod_mode.py); `scan_agent_environment.py`
and `evidence_bundle.py` call into it only in pod mode. The sidecar
learns which pod it is in from the downward API, which the kubelet writes; the
agent process can't write these values. (The labels file follows the pod's
labels, so something allowed to patch the pod could change them; the pod's
own service account has no such permission in the sidecar design.)

| Source | Used for |
|---|---|
| `POD_NAME`, `POD_NAMESPACE`, with the labels file | `sandbox_name` as `namespace/workload`, and the `deployment` attribute (`RAIL_NAMESPACE`, `RAIL_DEPLOYMENT`) |
| `POD_UID`, `NODE_NAME` (with `POD_NAME`) | the `agent_instance` attribute, `{"pod": {"name", "uid", "node"}}` |
| `labels` in `RAIL_POD_INFO_DIR` (default `/etc/podinfo`) | the workload name, from the labels the pod's controller stamps on it: a StatefulSet's pod name is kept; a Deployment's pod name loses its `pod-template-hash` and suffix, and an Argo Rollout's its `rollouts-pod-template-hash`; a DaemonSet's pod (`controller-revision-hash` without the StatefulSet label) loses its five-character suffix; a Job's pod takes its job name, less a CronJob's run number (eight digits in the range of minutes since 1970 a CronJob uses, so a date or Unix seconds stays); any other pod keeps its own name (a bare ReplicaSet's pod carries no label that tells it from a bare pod). Kubernetes cuts a generated pod name's base to 58 characters, so a Deployment over 46 characters or a DaemonSet over 56 can't be read back exactly; then no workload is derived and the scan logs that `--sandbox-name` is needed (the webhook sets it from the pod's owner). The file is read up to 64,000 bytes; a longer one is cut at a whole line and logged, and if no workload label came before the cut, no workload is derived |
| `RAIL_OWNER` (or `--owner`) | the `owner` attribute; the manifest maps it from the pod's owner label |

`host_id` still comes only from `--host-id` or `RAIL_HOST_ID`: the cluster's
name is not in the downward API. A restarted pod keeps its `sandbox_name` and
`deployment` and gets a new `agent_instance`.

The name and labels are the pod's creator's choice, not the cluster's: only
the namespace and UID are. So someone allowed to create pods in a namespace
could name a pod to claim another workload's `sandbox_name` there. The agent
process can't, and gke-scan, which relays the sidecar's bundle, is where the
claim gets checked: against the token's namespace and pod UID and the pod's
real owner from the Kubernetes API (task 15 of the sidecar design).

What pod mode refuses to guess:

- **No agent key, no bundle.** Without a `host_id`, or without a
  `sandbox_name` (from the downward API or `--sandbox-name`), the scan exits
  `2` and writes and sends nothing, since a bundle filed under a guessed key
  would be an agent that gke-scan's bundle for the same pod never matches.
  That includes a pod with no labels file: without `pod-template-hash` a
  Deployment's pod name can't be told from a bare pod's, and using it whole
  would file a new agent on every restart. (A labels file that is present but
  empty is a pod with no labels, which keeps its own name.)
- **No owner fallback.** The git and login-user fallbacks are off; they would
  name the sidecar image's user. Without `RAIL_OWNER`, `owner` is `BLIND` with
  `NO_SOURCE_ACCESS`, as are `agent_instance` and `deployment` without the
  downward API. The scan still runs if it has its key, and logs which downward
  API variables or labels file were missing (names only).
- **`sandbox_type`** is `kubernetes` unless `--sandbox-type` or
  `RAIL_SANDBOX_TYPE` says more (for example `gvisor`).

```bash
python3 tools/scan/scan_agent_environment.py --mode pod \
  --config-path /root/.openclaw \
  --host-id gke-test \
  --register --center-url https://gke-scan.rail-system.svc
```

## Reporting to gke-scan (RC-513)

With `--register`, pod mode posts each bundle to gke-scan through
`gke/reporter.py`, with a 30-second timeout (gke-scan's own post to Rail
Center takes up to 15).

| gke-scan answers | The sidecar |
| --- | --- |
| 2xx, accepted or `duplicate` | Done |
| 429, 503 or another 5xx, or no answer (refused, timed out, TLS failure) | Retries 5 s later, doubling with ±20% jitter up to 5 minutes, never sooner than `Retry-After` (read up to an hour) |
| 401, 403, 409, 413, 422, or anything else | Logs it and drops the bundle; the next scan sends its own |
| Nothing, because the token file can't be read | Sends nothing, never anonymously, and drops the bundle |

The first attempt is the scan's own, so its log line says what gke-scan
answered. Retries run on one background thread, only with `--interval`; a
single scan makes its one attempt. At most one bundle waits: a scan that
finishes during the backoff replaces it and goes at its scheduled time, so
Rail Center gets the newest view and gke-scan's backoff still holds. A retry
that gets through stores the registration state as the scan would have.

gke-scan serves a certificate from the chart's own CA. `--center-ca-file`
(or `RAIL_CENTER_CA_FILE`) names that CA as a PEM file, and the post to
`--center-url` trusts it beside the system store. Only that post does: the
MCP and spec probes, RailDash and the metadata server keep the system store.
The file is read on every post, so a rotated CA is picked up without a
restart; one that can't be read fails the post before anything is sent.

```bash
python3 tools/scan/scan_agent_environment.py --mode pod --interval 3600 \
  --register --center-url https://gke-scan.rail-system.svc \
  --center-ca-file /etc/rail/gke-scan-ca.crt
```

## The agent's own process (RC-509)

With `shareProcessNamespace: true`, the sidecar reads the agent's own process
instead of its own ([`agent_process.py`](agent_process.py)). On every scan,
`find_agent_process` looks under `/proc` for processes whose root filesystem
isn't the sidecar's, leaves out the pause process, prefers one whose root
holds the agent's config (`--config-path`), and otherwise takes the
lowest-numbered. A restarted agent comes back under a new pid and is found
again on the next scan.

From `/proc/<pid>` it reads:

| Source | Field |
|---|---|
| `environ` | `credential_inventory` and `system_info`'s `environment_keys` (names only, never values), `egress_proxy_declared` (the proxy variables, credentials removed), and model, provider and MCP detection |
| `status` and the agent's own `/etc/passwd` | `user_info`: the uid, gid and user name the agent runs as |
| `cmdline` | the command line, kept for the harness markers |
| `root/…/openclaw/dist/build-info.json`, `NODE_VERSION`, `PYTHON_VERSION` | `framework_identity` and `system_info.runtimes`, read rather than run: nothing is executed in the agent's container |
| `root/etc/os-release` | `system_info.os_release` |
| `cgroup` | `system_info.container.id` (none when the cgroup namespace hides it) |

Files under the agent's root are read one path component at a time inside
that root: links resolve there, `..` stops at it, no step crosses into another
filesystem (the agent's `/proc` is the sidecar's too), and only a regular file
is opened, without blocking.

The scan logs a warning when its choice of process was uncertain: no
candidate's root holds the config, or processes in more than one other
container could be read (counted by root, so the agent's own child processes
don't count). An agent that runs code in its own container can still start a
decoy beside itself; its fields are `authored_by: subject` for that reason.

Pod mode needs `--config-path` (the webhook sets it): the agent's config
folder on the config volume. It has no default, because the sidecar's own
`$HOME` or cwd says nothing about the agent. Without `--mcp-config`, it reads
`.mcp.json` in each `--config-path` folder, never the sidecar's own cwd or
`$HOME`.

The scan's own settings (`RAIL_OWNER`, `RAIL_DEPLOYMENT`, `RAIL_NAMESPACE`,
`RAIL_HOST_ID`, `RAIL_SANDBOX_TYPE`) are still read from the sidecar's
environment, which the webhook sets, so an agent can't choose the owner,
deployment or key it is filed under.

When no agent process can be read (no shared process namespace, a different
UID, or the agent restarting mid-scan), `credential_inventory`, `user_info`,
`framework_identity`, `egress_proxy_declared` and `system_info` are `BLIND`
with `NO_SOURCE_ACCESS`, and the scan logs why. The sidecar's own process is
never reported in the agent's place.

## Rescans, shutdown and health (RC-523)

With `--interval` (or `RAIL_SCAN_INTERVAL_IN_SECONDS`; the sidecar design's
hourly rescan is 3600), pod mode runs [`watcher.py`](watcher.py) in place of
the plain interval loop:

- **What it hashes, every 10 seconds.** The sources the agent's harness
  profile names (its config `sources`, workspace `prompt_files` and `skills`,
  and `watch.content`) by content, and its transcripts (`watch.list`) by file
  list only, so a new session triggers a scan and a longer one doesn't. Every
  harness also has `.mcp.json` in each `--config-path` and each
  `--mcp-config`; an agent no profile matches has what the generic reader
  reads (`.mcp.json`, `AGENTS.md` and the top-level `*.json` under
  `--config-path`). The agent's command line, environment and working
  directory are hashed too, so a restart with a new environment is a change.

  | Harness | By content | By file list |
  |---|---|---|
  | OpenClaw | `openclaw.json` and the other top-level `*.json` in its folder, `state/openclaw.sqlite` and its `-wal`, `skills/`, `workspace/skills/`, the workspace prompt files | `agents/` |
  | Claude Code | managed, project, local and user settings, `~/.claude.json`, its `CLAUDE.md` files, `.claude/skills/` | `~/.claude/projects/` |
  | Any other | `.mcp.json`, `AGENTS.md`, top-level `*.json` under `--config-path` | |

  OpenClaw's `openclaw.json.bak*` and `openclaw.json.last-good`, which it
  writes beside `openclaw.json` on each change, don't match `*.json`.
- **What a poll may read.** One budget for the whole poll, never per path:
  64 MiB of file content and 5,000 files and folders, 8 deep. Config comes
  first and the agent's own skill folders last, so a folder the agent stuffs
  (links in it are followed inside its root) spends only what is left; what
  doesn't fit is left to the interval scan, and the log says so once. The
  file lists, which read no content, have their own 5,000 files and folders,
  so a full budget can't hide a new agent or session.
- **When it scans.** After a change, once nothing has changed for 5
  seconds, so a config written in several steps is scanned once, but never
  more than 60 seconds after the change was first seen: files that never
  stop changing (a busy agent, or one rewriting a watched file on purpose)
  get a scan at most about once a minute, and can't put one off for good.
  The same content rewritten changes no hash. The interval still rescans,
  whether or not a change is pending. One scan runs at a time: what changes
  during a scan is seen on the next poll and gives exactly one more scan.
- **Waiting at start.** OpenClaw's gateway creates `agents/main/` 70 to 100
  seconds after it starts, and a scan before that reports `agent_count` 0, so
  for OpenClaw the first scan waits until `openclaw.json` (or
  `$OPENCLAW_CONFIG_PATH`) and `agents/main/` exist, for up to 300 seconds;
  after that it scans anyway and what is missing is `BLIND`. Any other
  harness is scanned as soon as its process is found. With no agent process
  at all, it waits up to 300 seconds for one, then scans. The profile says
  what to wait for (`watch.wait_for`, see [the harness README](harness/README.md)).
  With a RailDash URL, the first scan then also waits up to 120 seconds for
  RailDash to answer (DR-316), as any interval scan does.
- **Shutdown.** On SIGTERM a scan in progress is abandoned, and nothing is
  written or sent for it. A bundle being written or sent gets up to 5
  seconds to finish; the sidecar exits well inside the pod's 30-second
  default grace period.
- **Health.** After each scan and delivery, the time and interval are
  written to `RAIL_HEALTH_FILE` (default `/tmp/railmon-health.json`, in the
  sidecar's writable emptyDir). `railmon scan --health-check` exits 1 when
  the last scan is older than two intervals, or there is no health file, for
  the exec liveness probe. At start it writes when the first scan is due at
  the latest: the longest wait for the agent (300 seconds), then the wait
  for RailDash if there is one (about 130 seconds), then two intervals. The
  check passes until then, so a slow start isn't restarted, and fails after,
  so a start that is stuck is:

  ```yaml
  livenessProbe:
    exec:
      command: ["railmon", "scan", "--health-check"]
    periodSeconds: 60
  ```
- **Logs.** One line per event on stderr (`watcher: change in
  $OPENCLAW_DIR/openclaw.json`, `watcher: scan: interval`), with paths as the
  profile writes them: no environment value, secret or token.

Without an interval, a pod-mode scan runs once, as before, without waiting.

## The agent's harness fields (RC-510)

The harness fields (`harness_identity`, `model_name`, `llm_provider`,
`inference_endpoint`, `mcp_servers_declared`, `tool_allow_deny`,
`approval_policy`, `tool_names`, `system_prompt_present`,
`system_prompt_text`, `skills_inventory`) are read by the shared harness
reader, [`harness/reader.py`](harness/README.md), from the profile whose
markers match the agent's command line or environment. That reader is not
specific to pods; `harness/harness_sources.py` is pod mode's side of it:

- A path under a `--config-path` is read from the config volume, with the
  volume as the root: a link the agent planted there can't leave it.
- Any other path is read through the agent's root, with the same guards as
  the agent's other files (links resolve inside it, no step crosses into
  another filesystem, only regular files, without blocking).
- `~` and `$VAR` in a profile's paths, and the markers, come from the agent's
  process, and `$AGENT_CWD` from its working directory (`/proc/<pid>/cwd`).
  Environment values and the working directory are used to find files only.

Pod mode replaces a harness field only with a value a matching profile
found. OpenClaw's profile (RC-516) and Claude Code's (RC-526) ship. For an
agent no profile matches, the generic reader (`harness/generic.py`, RC-520)
reads what any harness may use (`.mcp.json`, `AGENTS.md`, `*_MODEL` and
`*_BASE_URL` variables, and model-like and permission-named keys in the
top-level `*.json` under `--config-path`); its values are merged as a
profile's are, and every harness field it can't fill is `BLIND` with
`UNKNOWN_HARNESS` where the bundle would only have said "not found", with
`tool_schemas` `BLIND`, not `ABSENT`, when there is no MCP config.

## HTTP operations (RC-512)

The code is [`spec_probe.py`](spec_probe.py) (the prober and the bundle
attribute) and [`probe_pool.py`](probe_pool.py) (the pool and the deadline).
Like the other modules here they import nothing of railmon's: the scanner
hands itself over with `register`, and what every scan mode shares stays in
`scan_agent_environment.py` (the MCP probe and its memory bounds, and the
redaction `tool_schemas` and `skills_inventory` use).

The sidecar asks each HTTP destination for its public API spec, for the
bundle's `http_operations`. The destinations are the origins
(`scheme://host:port`) of the MCP servers the MCP probe asks
([`../README.md`](../README.md#tool-schemas)), the harness profile's included, so OpenClaw's and Claude Code's servers are
covered; the model endpoint is not one. Each is sent `GET /openapi.json`,
`/v3/api-docs`, `/swagger.json` and `/api-docs`, in that order, with no
credentials, 5 seconds a path, until one serves an OpenAPI 3 or Swagger 2 JSON
document. When the origin serves none, the same four paths are asked under
the path its MCP servers are mounted at (`/finretail/v3/api-docs` for a server
at `/finretail/mcp`), up to two mount paths a destination, and `spec_path`
says where the spec was found. A server whose URL carries a credential is
neither a destination nor a mount path, as the MCP probe doesn't ask it
either: it is usually a tenant of a shared service, whose origin's spec
wouldn't describe what the agent calls. Only `http` and `https` are asked,
and a redirect is followed only to the same origin, so a config entry can
never make the sidecar read a `file://` URL or ask another host. The prober
follows a redirect itself, at most 3 times, from its `Location` header alone,
so a redirect's body is never read. At most 4 MB of a spec is read
(`OPENAPI_MAX_BYTES`), and the whole request, redirects included, has its
5 seconds.

`http_operations` holds one entry per destination: its `destination`, its own
`status` (and `reason` and `note` when it isn't `ANSWERED`), and for a spec
found its `spec_path`, `spec_version` and `operations`. Each operation keeps
its `method`, `path`, `operationId`, and the `request_content_types` and
`response_content_types` the spec declares, every string through
`redact_text`; nothing else of the spec (parameters, schemas, examples) is
kept. A destination keeps at most 1,000 operations, and the whole value at
most 128 KiB as the bundle writes it; past either, `operations_truncated`.
With `skills_inventory`'s and `tool_schemas`' 256 KiB and
`observed_file_access`'s 256 KiB (only with a files snapshot), that leaves
128 KiB of a pod-mode bundle's 1 MiB for every other attribute, and a test
fails if the budgets grow past it. The caps are to be revisited with the
overhead benchmark (RC-525).

| Status, reason | When |
| --- | --- |
| `ANSWERED` | some destination served a spec, and every other answered without one |
| `PARTIAL` / `BLIND`, `PRIVATE_STORE` | a destination answered 401 or 403 and served no spec: it isn't public |
| `PARTIAL` / `BLIND`, `NO_SOURCE_ACCESS` | a destination didn't answer, answered 5xx, or was still unanswered at the scan's deadline (`deadline_exceeded`) |
| `PARTIAL`, `SIZE_CAP_EXCEEDED` | a spec past 4 MB or 500,000 JSON elements (the operations in the part read are kept), or past the operation caps |
| `BLIND`, `NOT_COLLECTED_BY_PACK` | a self or docker scan: only the sidecar probes specs |
| `BLIND`, `tool_schemas`' reason | no MCP server found at all, and `tool_schemas` is `BLIND` or `FAILED` with no server: the servers the destinations come from weren't established (a profile that couldn't read the MCP config, or a harness no profile matches with none) |
| `ABSENT` | no HTTP destination (no MCP server, or only command servers and URLs carrying a credential, none with an origin to ask), or none serves a spec |

### The probe pool and the scan deadline

The sidecar's MCP and spec probes run 4 at a time (`PROBE_POOL_WORKERS`),
3 seconds an MCP call and 5 seconds a spec path, and the whole scan gets 60
seconds from its start (`SCAN_DEADLINE_SECONDS`). A probe that hasn't answered
by then is reported for its server alone: its `tool_schemas` entry is
`unreachable` with `deadline_exceeded`, its `http_operations` entry `BLIND`,
`NO_SOURCE_ACCESS` with `deadline_exceeded`, and the rest of the bundle is
built and sent as usual. A late probe isn't waited for: it ends on its own
per-call timeout, in the background. Self and docker scans probe one server
after another, with no deadline, as before.
