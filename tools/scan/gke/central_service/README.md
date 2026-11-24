# gke-scan, the central service

`railmon gke-scan` is the central GKE service: one per cluster, a single
replica in the `rail-system` namespace. It reads what the cluster declares
about each agent pod through the Kubernetes API, and it relays each scan
sidecar's bundle to Rail Center. The sidecar is in [`../sidecar/`](../sidecar/README.md).

So far it is the sidecar intake (RC-515) and the cluster reader (RC-550),
which keeps a watched copy of the enrolled namespaces. The cluster field
collectors and its own bundle per workload come in the later tasks of the
gke-scan design, in this same process.

| File | What it does |
|---|---|
| [`gke_scan.py`](gke_scan.py) | The entry point: configuration, the relay to Rail Center, SIGTERM |
| [`intake.py`](intake.py) | The intake's HTTPS server and its checks |
| [`kube.py`](kube.py) | TokenReview, get, list and watch, with gke-scan's own service account |
| [`cluster_reader.py`](cluster_reader.py) | The watched copy of the enrolled namespaces, and the workloads each change affects |
| [`workload.py`](workload.py) | A pod's `namespace/workload`, with each owner checked through the API |

It shares the scanner's `auth_headers` (`RAIL_AUTH_MODE`), `registration_url`
and register opener, which refuses redirects, through
`tools/scan/scan_agent_environment.py`. It shares nothing else with the
sidecar. Like the scanner, it uses only the Python standard library.

## Sidecar intake (RC-515)

The sidecar posts each bundle to `POST /v1/agents/register` on gke-scan's
ClusterIP Service, over HTTPS with the chart's certificate. That's the same
path as Rail Center's, so the sidecar's reporter only needs a different
`--center-url`. It authenticates with its projected service account token
(audience `gke-scan`) as a bearer token.

Before anything is relayed, gke-scan checks, in order:

| Check | Refused with |
|---|---|
| A bearer token, which a TokenReview accepts for audience `gke-scan` (signature, audience and expiry) | 401 |
| The token is a service account's, bound to a pod (a projected token carries the pod's name and UID) | 403 |
| A `Content-Length` of at most 4 MB, checked before the body is read | 411, 413 |
| A JSON object with `bundle_version` 1 | 422 |
| `host_id` is this cluster's name (`--cluster-name`) | 403 |
| The namespace in `sandbox_name` (`namespace/workload`) is the token's | 403 |
| The pod UID in `agent_instance` is the token's | 403 |
| The token's pod still exists with that UID and is labeled `rail.datrail.io/scan=true` | 403 |
| The whole `sandbox_name` is the pod's own `namespace/workload`, with each owner it names checked through the API ([below](#the-workload)) | 403 |
| The post names no `?agent_key=` | 422 |
| No other bundle from the same pod is being relayed | 409 |

A bundle that fails any check is refused and never relayed. If the
Kubernetes API can't answer a check, the answer is 503, which the sidecar
retries.

A bundle that passes goes to Rail Center's `/v1/agents/register` unchanged,
byte for byte, with `X-Rail-Source: sidecar` and `X-Rail-Pod-UID`, under
gke-scan's own credential (`RAIL_AUTH_MODE=gcp`: its Google identity through
Workload Identity). gke-scan doesn't parse it beyond the checks, merge,
change or retry it.

No `?agent_key=` is ever relayed. A v1 bundle names no key of its own, and
Rail Center files one under the `?agent_key=` it comes with, so passing a
key on would let a pod with a valid token file its bundle under another
agent's key, in any namespace, past every check above. Without one, Rail
Center files the bundle under its `host_id` and `sandbox_name`, both of which
gke-scan checks. A sidecar run with `--agent-key` or `RAIL_AGENT_KEY` gets
422, final, rather than having its key dropped without a word.

### The workload

A pod's name, labels and `ownerReferences` are all written by whoever
creates it, and the API server doesn't check that an owner exists. So
gke-scan takes none of them as given. It reads each owner the pod names from
the API, which must be a kind it checks, exist with the UID the pod names,
and select the pod with its label selector, and so on up the chain. Then the
bundle's `sandbox_name` must be the workload that gives (403 if not):

| The pod's controller | Its workload, as the sidecar keys it |
|---|---|
| A ReplicaSet controlled by a Deployment or Argo Rollout | The Deployment or Rollout |
| A ReplicaSet with no controller | The pod itself |
| A StatefulSet | The pod itself, `<statefulset>-<ordinal>`: each replica is its own agent |
| A DaemonSet | The DaemonSet |
| A Job named `<cronjob>-<run>`, controlled by a CronJob that lists it in `status.active` | The CronJob |
| A Job with no controller | The Job |
| None | The pod itself |
| Anything else (another controller kind, an owner that doesn't exist, has another UID or doesn't select the pod, more than one controller) | Refused |

Whatever the key, no other workload may be keyed the same way: a
Deployment, DaemonSet, Job, CronJob or Rollout of that name, or a StatefulSet
whose pod would have it. A key two workloads share is refused for both,
since it would file one's bundle as the other's. The one exception is Argo's
migration from a Deployment: a Rollout whose `spec.workloadRef` names a
Deployment of the same name is one workload with it, so the pods of both are
filed under that name. If the API can't be read
for any of this, the answer is 503.

This stops a pod claiming a workload by its name, by a label, by an owner
that doesn't exist or doesn't select it, by a Job made up under someone
else's CronJob (only the CronJob's controller writes `status.active`), or by
a workload of its own given someone else's name. The exception is an Argo
Rollout whose `workloadRef` names a Deployment of the same name: it counts as
that Deployment, by design, so someone who may create Rollouts can file as it.

**The trust boundary is pod creation.** Anyone who may create pods in an
enrolled namespace can make one that copies a real replica's owner reference
(its ReplicaSet's UID is on every sibling pod) and its labels. To Kubernetes
that pod is one of the workload's replicas until the ReplicaSet controller
removes it, and its termination grace period (30 seconds by default) is long
enough for its sidecar to post. gke-scan can't tell it from any other
replica, and no check can. Anyone who may create or change workloads
(Kubernetes' `edit` role) can do the same more lastingly. So give pod
creation in enrolled namespaces only to those you'd trust to report as any
workload there.

Pods of controller kinds gke-scan can't check (Argo Workflows, OpenShift's
DeploymentConfig, other operators) are refused. So is a bare Job named like
a CronJob's run (`<name>-<8 digits>`), which the sidecar keys as `<name>`, and
a CronJob's run in the moment before the CronJob lists it as active; the
sidecar's next scan sends again.

| Rail Center answers | The sidecar gets |
|---|---|
| 2xx, 409, 413, 422, 429 or any other 4xx | The same status and body, with any `Retry-After` |
| 401 or 403 (gke-scan's credential refused) | 503 |
| 5xx | 503, with any `Retry-After` |
| No answer (refused, timed out), or gke-scan couldn't get its credential | 503 |

None of the 503s is the sidecar's to fix. Its reporter retries them with its
own backoff ([RC-513](../sidecar/README.md#reporting-to-gke-scan-rc-513)).

The pod check answers from the cluster reader's watched copy when the copy
has the token's pod with the token's UID, and reads the pod from the
Kubernetes API otherwise: a pod created since the last watch event, a
namespace not listed yet, or one whose pods gke-scan may not list. The owners
up the chain are still read from the API on each post.

Each post is one log line on stderr: the pod, the outcome and the status.
The token is never logged.

## Cluster reader (RC-550)

gke-scan keeps a copy, in memory, of what it reads in each enrolled namespace
(or across every namespace, for `--namespaces '*'`):

| Kind | Kept |
|---|---|
| Pods | Agent pods (those `--label-selector` matches) and MCP server pods (labeled `rail.datrail.io/mcp-server=true` or annotated `rail.datrail.io/source`). Others are dropped. |
| Services, NetworkPolicies, PersistentVolumeClaims | All of them |
| Namespaces | The enrolled ones |

Each kind in each namespace is listed, then watched from the list's
resourceVersion with bookmarks. The API server ends each watch after 5
minutes, and gke-scan watches again from the last resourceVersion it saw. A
410 Gone lists again, and so does every `--interval`: listing again compares
the list with the copy, so a change missed between watches is still
reported. Pods are listed without a label selector, since a selector can't
match an MCP server's annotation; the selector is applied in gke-scan.
`managedFields` aren't kept.

A list or a watch that gets 429 or 5xx is tried again up to 4 times, after
1, 2 and 4 seconds or the answer's `Retry-After`. Any other error is logged
and tried again after 1 second, doubling up to a minute. A 403 is logged once
and tried again each interval; the namespace's other kinds and the other
namespaces carry on. The backoff and the 403's log line start over only once
a watch has run to its end, so a kind that lists but can't be watched still
backs off rather than listing again every second.

Each change is reported with the workloads it affects, keyed `namespace/workload`
as the intake checks it ([below](#the-workload)):

| A change to | Affects |
|---|---|
| An agent pod | Its workload |
| A Service | Every workload in its namespace, and those whose pods name it in a URL env value |
| A NetworkPolicy, or the Namespace | Every workload in its namespace |
| A PersistentVolumeClaim | The workloads whose pods mount it |
| An MCP server pod | The workloads whose pods name, in a URL env value, a Service that selects it |

Only literal env values are read for URLs, never Secrets or ConfigMaps. A
Service's bare name counts only for pods in its own namespace; elsewhere it
must be `<name>.<namespace>`, `.svc` or `.svc.cluster.local`. A pod's workload
is read from the API once per pod UID and owner references; when its owners
can't be read, it's tried again on the pod's next change. Those reads happen
before the copy is locked, and a change's workloads come from what was read,
so a slow API server never holds up the intake's pod check. Nothing consumes the
changes yet: the bundle builder and scheduler ([RC-555](https://railxia.atlassian.net/browse/RC-555)) will.

## Running it

```sh
railmon gke-scan \
  --cluster-name gke-test \
  --center-url https://rail-center.example.com \
  --tls-cert-file /etc/rail/intake/tls.crt \
  --tls-key-file /etc/rail/intake/tls.key
```

With `RAIL_AUTH_MODE=gcp` and `RAIL_AUTH_AUDIENCE` set to Rail Center's URL.

| Flag | Environment variable | Default |
|---|---|---|
| `--cluster-name` | `RAIL_CLUSTER_NAME` | required: the `host_id` the cluster's sidecars report under |
| `--center-url` | `RAIL_CENTER_URL` | required |
| `--tls-cert-file`, `--tls-key-file` | `RAIL_INTAKE_TLS_CERT_FILE`, `RAIL_INTAKE_TLS_KEY_FILE` | required: the intake's certificate from the chart's CA, loaded again when its Secret changes ([`tls_reload.py`](../tls_reload.py)) |
| `--listen` | `RAIL_INTAKE_LISTEN` | `0.0.0.0:8443` |
| `--audience` | `RAIL_INTAKE_AUDIENCE` | `gke-scan` |
| `--kube-api-url`, `--kube-token-file`, `--kube-ca-file` | | the in-cluster API and gke-scan's service account, where Kubernetes mounts them |
| `--namespaces` | `RAIL_NAMESPACES` | required: the enrolled namespaces, comma-separated, or `*` for every namespace |
| `--label-selector` | `RAIL_LABEL_SELECTOR` | `rail.datrail.io/scan=true`: the agent pods |
| `--interval` | `RAIL_INTERVAL_SECONDS` | `3600`: seconds between full lists (and, with RC-555, resends) |
| `--registry-access`, `--no-registry-access` | `RAIL_REGISTRY_ACCESS` | yes: read images from their registry (RC-553) |
| `--layer-budget` | `RAIL_LAYER_BUDGET` | `2Gi`: bytes of image layers read per image, plain or with `K`, `M`, `G`, `Ki`, `Mi`, `Gi` (RC-553) |
| `--probe-external`, `--no-probe-external` | `RAIL_PROBE_EXTERNAL` | no: fetch API specs from hosts outside the cluster (RC-554) |
| `--data-guardrail-url` | `RAIL_DATA_GUARDRAIL_URL` | none: Rail Center's `/data-guardrail` route; nothing is sent there without it |
| `--sidecar-interval` | `RAIL_SIDECAR_INTERVAL_SECONDS` | `3600`: the sidecars' scan interval; a sidecar's report is current for two (RC-555) |
| `--register-without-sidecar`, `--no-register-without-sidecar` | `RAIL_REGISTER_WITHOUT_SIDECAR` | no: send a cluster-only bundle for a labeled workload with no sidecar (RC-555) |

A flag wins over its variable, and a variable over the default. A true or
false variable takes `true`, `false`, `yes`, `no`, `on`, `off`, `1` or `0`. A
missing required value, or one that doesn't parse, exits 2 and names it.
Only the reader's settings are used so far; the rest are read now for the
tasks named. SIGTERM stops taking posts, gives relays in flight up to 10
seconds, and exits 0.

gke-scan needs `create` on `tokenreviews` (the `system:auth-delegator`
ClusterRole), and `get` in enrolled namespaces on pods, and on the controllers
it checks a pod's owners against:

| API group | Resources |
|---|---|
| `""` (core) | `pods` |
| `apps` | `replicasets`, `deployments`, `statefulsets`, `daemonsets` |
| `batch` | `jobs`, `cronjobs` |
| `argoproj.io` | `rollouts` |

Grant the `rollouts` rule even where Argo isn't installed. The API server
checks permission before it looks for the resource, so without the rule
every read is refused (403) rather than not found (404), and every
sidecar's post is answered 503 until it's granted. The log line names the
read that was refused. The [`railmon-gke` chart](../../../../deploy/helm/railmon-gke/README.md)
grants exactly this, and runs gke-scan with its Service and NetworkPolicy (RC-518).

The cluster reader also needs `list` and `watch`, in each enrolled namespace,
on `pods`, `services`, `persistentvolumeclaims` and
`networkpolicies.networking.k8s.io`, and on the enrolled `namespaces` (cluster
scope, by name); for `*`, on all of them cluster-wide. The chart grants these
with RC-557. Until then the reader logs each refused read once, keeps trying
each interval, and the intake's pod check reads the API as before.

## Tests

`tests-python/test_gke_scan_intake.py` runs the intake on loopback with a
mocked TokenReview and pod read, and relays through the real relay to a fake
Rail Center. It covers every check, every Rail Center answer, one bundle per
pod at a time, HTTPS with a test certificate, and `KubeClient` against a fake
Kubernetes API.

`tests-python/test_gke_scan_reader.py` covers the configuration (a missing or
bad value exits 2 naming it; variables over defaults, flags over variables),
`KubeClient`'s list, watch and backoff, and the cluster reader against a fake
Kubernetes API with list and watch: a watch that ends is watched again from
its last resourceVersion, 410 and the interval list again, a 403 in one
namespace leaves the others readable, each kind's change names the right
workloads, and the intake's pod check answers from the copy.
