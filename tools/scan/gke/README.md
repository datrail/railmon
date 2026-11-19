# GKE

RailMon's scanner on GKE comes in two parts:

| Part | Runs | Code |
|---|---|---|
| The scan sidecar: `railmon scan --mode pod` | A container in each agent pod | [`sidecar/`](sidecar/README.md) |
| gke-scan, the central service: `railmon gke-scan` | One per cluster, in `rail-system` | [`central_service/`](central_service/README.md) |

The sidecar reads what only the pod can see and posts its bundle to gke-scan.
gke-scan checks the pod that sent it and relays the same bytes to Rail Center.
It will also send the cluster's own view of each workload as a second bundle.

The two share the scanner's bundle builder, verifier and reporter code in
`tools/scan/`, and nothing else. Neither imports the other.
