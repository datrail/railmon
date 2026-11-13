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
  process. Environment values are used to find files only.

Pod mode replaces a harness field only when a profile matches. No profile
ships yet (OpenClaw's is task 4, Claude Code's task 5, the generic reader for
any other harness task 6), so until then the bundle's own values stand.
