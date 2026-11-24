# railmon-gke

RailMon's scanner on a GKE cluster (RC-518): one release per cluster, in
`rail-system`.

| Part | What it does |
|---|---|
| gke-scan | Takes each sidecar's bundle, checks the pod that sent it, and relays it to Rail Center ([`central_service/`](../../../tools/scan/gke/central_service/README.md)) |
| The admission webhook | Adds the scan sidecar to pods labeled `rail.datrail.io/scan=true` in enrolled namespaces ([`webhook/`](../../../tools/scan/gke/webhook/README.md)) |
| The sidecar spec | The one definition of the sidecar, in the `rail-scan-sidecar-spec` ConfigMap, which the webhook reads |
| A CA | Signs gke-scan's and the webhook's certificates; each enrolled namespace gets its certificate in the `rail-scan-ca` ConfigMap, which the sidecar trusts gke-scan with |
| NetworkPolicies | Agent pods reach only gke-scan and DNS; gke-scan accepts only labeled pods |

All three containers run the scan-sidecar image (`Dockerfile.scan-sidecar`):
Python and `tools/scan`, read-only root filesystem, no capabilities.

## Install

```sh
helm install railmon-gke deploy/helm/railmon-gke -n rail-system --create-namespace \
  --set clusterName=gke-test \
  --set gkeScan.centerUrl=https://rail-center.example.com \
  --set gkeScan.gcpServiceAccount=gke-scan@PROJECT.iam.gserviceaccount.com \
  --set 'enrolledNamespaces={gke-test}' \
  --set 'networkPolicy.railCenterCidrs={203.0.113.10/32}' \
  --set "networkPolicy.kubeApiCidrs={$(kubectl get endpoints kubernetes -n default -o jsonpath='{.subsets[0].addresses[0].ip}')/32}" \
  --set image.digest=sha256:...
```

Then label an agent's pod template `rail.datrail.io/scan: "true"`. New pods
get the sidecar; running pods get it when they restart.

gke-scan's Kubernetes service account must be bound to its Google service
account through Workload Identity (`roles/iam.workloadIdentityUser`), and that
account must be one Rail Center accepts.

[`ci/test-values.yaml`](ci/test-values.yaml) is a complete example; CI lints
and renders the chart with it.

## Telling the webhook about the agent

The webhook fills in what changes from pod to pod. Most pods need nothing
more than the label; these annotations cover the rest:

| Annotation | Default | What for |
|---|---|---|
| `rail.datrail.io/scan-config-path` | `sidecar.configPath` (`/root/.openclaw`; a list for several) | The agent's config home, or several comma-separated paths (`/data/openclaw,/root/.openclaw`, `/root/.claude,/workspace`) for an agent whose files sit on several volumes. Each goes to the sidecar as its own `--config-path`, and the agent's volume mounts that hold any of them are mounted read-only in the sidecar at the same paths, once each. A path that isn't on a volume can't be read, and the webhook warns for that path |
| `rail.datrail.io/scan-agent-container` | The pod's first container | Which container is the agent |
| `rail.datrail.io/scan-run-as-user`, `-run-as-group` | The agent container's, then the pod's `securityContext` | The agent's UID and GID, when the pod spec doesn't say (an image that sets its own `USER`). The sidecar must run as the agent's UID and GID to read its process |
| `rail.datrail.io/owner` (a label) | none | The `owner` the agent is filed under, through the downward API |

When the agent's UID can't be found anywhere, the sidecar runs as the image's
UID 65532 rather than guessing root, and its process fields are `BLIND`.
`sidecar.runAsUser` and `sidecar.runAsGroup` set a cluster-wide fallback (0
for a cluster whose agents' images all run as root).

What the webhook had to guess (a GID taken from the UID, no UID at all, a
config that isn't on a volume) is in its log, in the admission warnings, and
on the pod itself, since a Deployment's warnings only reach the ReplicaSet
controller:

```sh
kubectl get pod <pod> -o jsonpath='{.metadata.annotations.rail\.datrail\.io/scan-sidecar-warnings}'
```

### Capabilities

The sidecar drops every capability, except beside a root agent. Linux lets a
process read another's environment and root filesystem (what the sidecar
reads through the shared process namespace) only if its permitted
capabilities include all of the other's, or it has `SYS_PTRACE`, even at the
same UID. A root agent keeps the runtime's default set, so a sidecar with none
can't read it. For a root agent the webhook gives the sidecar exactly the
agent container's `capabilities` (the runtime default when it sets none):
what reading it needs, and never a capability the agent lacks, which also
keeps the pod within whatever Autopilot already admitted for the agent. A
non-root agent has no permitted capabilities, so its sidecar needs none. CI's
container test checks all three cases (`tests/scan_sidecar_acceptance.py`).
GKE Sandbox (gVisor) implements this check itself; phases 15 and 17 of the
GKE test read a root agent there.

`sidecar.collectSystemPrompt: true` puts the text of the agent's system prompt
files in the bundle (`system_prompt_text`, each file bounded in size). It is
off by default: then only which files exist is reported.

The sidecar goes in as a native sidecar (an init container with
`restartPolicy: Always`, Kubernetes 1.29+), so a Job's or CronJob's pod still
completes, and it stops after the agent. `sidecar.nativeSidecar: false` adds
it as a second regular container instead.

## Without the webhook

The webhook and a hand-written manifest use the same spec, so they can't drift
apart. Copy it from the cluster:

```sh
kubectl get configmap rail-scan-sidecar-spec -n rail-system -o jsonpath='{.data.sidecar\.json}'
```

and add to the pod template: `container` (as an init container with
`restartPolicy: Always`) and `volumes`, then the per-pod parts the webhook
would: `--config-path <the agent's config home>` at the end of `args`, the
agent's config volume mount with `readOnly: true`, `runAsUser`, `runAsGroup`
and `runAsNonRoot` set to the agent's (`runAsNonRoot: true` when it has no
UID), `RAIL_SANDBOX_TYPE` (`gvisor` on GKE Sandbox, else `kubernetes`), and
`shareProcessNamespace: true` on the pod.
The namespace must be in `enrolledNamespaces`, for the CA ConfigMap and
gke-scan's checks.

## NetworkPolicies

**Agent pods** (`networkPolicy.agentEgress`): in each enrolled namespace,
pods labeled `rail.datrail.io/scan=true` may reach gke-scan's pods on its port
and DNS: the kube-dns pods, and NodeLocal DNSCache at `169.254.20.10/32`
(allowing only the kube-dns pods blocks DNS on a cluster that runs it). The
sidecar shares the agent's network, so it never needs Rail Center's address,
and neither does the agent.

A NetworkPolicy that selects a pod for egress denies it every destination no
policy allows. So once this is installed, a labeled agent reaches its MCP
servers, its model endpoint and anything else only through policies of its
own. That's the design (the agent's pod has no path out of the cluster but
what the customer allows), but it is a change for a namespace that had no
egress policy before, and the install's notes say so. Allow the agent's own
destinations in `networkPolicy.agentEgress.extraEgress` (added to this same
policy) or in the namespace's own policies; NetworkPolicies add up.
`networkPolicy.agentEgress.enabled: false` leaves egress to the customer's own
policies, which must then allow gke-scan and DNS.

**rail-system** (`networkPolicy.railSystem`):

- gke-scan accepts only labeled pods in enrolled namespaces, on its port, and
  reaches only Rail Center (`railCenterCidrs`, on 443; through Cloud NAT on
  private nodes), the Kubernetes API (`kubeApiCidrs`), DNS, the metadata
  server for its Google ID token (`169.254.169.254:80`, and
  `169.254.169.252:988` on Dataplane V2), and `specTargets`.
- The webhook is the one other ingress: the API server calls it from
  addresses no selector can name, so its port is open to any source. It has
  no egress.

A NetworkPolicy can't match a hostname, so Rail Center and the API server are
given as addresses.

## GKE notes

- **Private Standard clusters.** The control plane reaches nodes only on 443
  and 10250 unless a firewall rule allows more. Add one for `webhook.port`
  (9443) from the control plane's range, or set `webhook.port: 10250`.
  Otherwise every pod starts without a sidecar (failurePolicy Ignore).
- **Autopilot** allows everything here: no privilege, host namespaces or
  added capabilities, and `shareProcessNamespace` is allowed. The sidecar's
  resources are explicit, since Autopilot gives a container with none 500m
  CPU and 2Gi.
- **GKE Sandbox**: pods with `runtimeClassName: gvisor` get
  `RAIL_SANDBOX_TYPE=gvisor`.

## The image

A release tag (`vX.Y.Z`) builds the scan-sidecar image for amd64 and arm64 and
pushes it to Artifact Registry under the same version tags, with no key:
GitHub Actions signs in as a Google service account through Workload Identity
Federation. It needs three repository variables; until `SCAN_SIDECAR_IMAGE` is
set, the push is skipped with a warning and the rest of the release goes on.

| Variable | Example |
|---|---|
| `SCAN_SIDECAR_IMAGE` | `us-docker.pkg.dev/datrail/railmon/scan-sidecar` |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | `projects/123456789/locations/global/workloadIdentityPools/github/providers/datrail` |
| `GCP_ARTIFACT_PUSHER` | a service account with `roles/artifactregistry.writer` on the repository, and `roles/iam.workloadIdentityUser` for the provider's principal for `datrail/railmon` |

The run's summary gives the digest; pin it as `image.digest`.

## The CA

The chart makes a CA on install and keeps it in the `rail-scan-ca` Secret,
which outlives an uninstall (`helm.sh/resource-policy: keep`). Upgrades read
it back and sign new certificates for gke-scan and the webhook with it, so
sidecars keep trusting gke-scan and the API server keeps trusting the
webhook. gke-scan and the webhook load their certificate again when its
Secret changes, so a renewed one needs no restart.

`helm template`, Argo CD and anything else that renders without reading the
cluster can't read the CA back, so they would make a new one on every render.
For those, give the chart a CA of your own in `tls.ca`, and every render signs
with it:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=railmon-gke-ca \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
  -keyout ca.key -out ca.crt
helm template railmon-gke deploy/helm/railmon-gke -n rail-system -f my-values.yaml \
  --set-file tls.ca.cert=ca.crt --set-file tls.ca.key=ca.key
```

Keep `ca.key` where your other secrets are (a secrets plugin for Argo CD, say),
not in a values file in git.
