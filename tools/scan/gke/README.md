# GKE

RailMon's scanner on GKE comes in three parts:

| Part | Runs | Code |
|---|---|---|
| The scan sidecar: `railmon scan --mode pod` | A container in each agent pod | [`sidecar/`](sidecar/README.md) |
| gke-scan, the central service: `railmon gke-scan` | One per cluster, in `rail-system` | [`central_service/`](central_service/README.md) |
| The admission webhook that adds the sidecar: `railmon scan-webhook` | In `rail-system` | [`webhook/`](webhook/README.md) |

The sidecar reads what only the pod can see and posts its bundle to gke-scan.
gke-scan checks the pod that sent it and relays the same bytes to Rail Center.
It will also send the cluster's own view of each workload as a second bundle.

The sidecar and gke-scan share the scanner's bundle builder, verifier and
reporter code in `tools/scan/`, and nothing else. Neither imports the other,
and the webhook imports neither.

All three run from the slim scan-sidecar image (`Dockerfile.scan-sidecar`),
and the [`railmon-gke` chart](../../../deploy/helm/railmon-gke/README.md)
deploys them with the NetworkPolicies that keep agent pods inside the cluster
(RC-518).
