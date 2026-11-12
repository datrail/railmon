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
  --host-id gke-test \
  --register --center-url https://gke-scan.rail-system.svc
```
