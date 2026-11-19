# The scan-sidecar webhook

`railmon scan-webhook` is a mutating admission webhook (RC-518). For each pod
created with `rail.datrail.io/scan=true` in an enrolled namespace, it answers
with a JSON patch that adds the scan sidecar ([`../sidecar/`](../sidecar/README.md)).
The chart ([`deploy/helm/railmon-gke`](../../../../deploy/helm/railmon-gke/README.md))
runs it and registers it.

| File | What it does |
|---|---|
| [`patch.py`](patch.py) | `sidecar_patch(pod, spec)`: the whole decision, with no I/O |
| [`scan_webhook.py`](scan_webhook.py) | The HTTPS server: `POST /mutate` (AdmissionReview v1) and `GET /healthz` |

It reads the sidecar spec the chart renders (`sidecar.json`) and fills in, per
pod: the agent's config mounts and `--config-path`, the agent's UID and GID,
its capabilities when it runs as root (none otherwise; the chart's README says
why), `RAIL_SANDBOX_TYPE` (`gvisor` for `runtimeClassName: gvisor`, else
`kubernetes`) and `shareProcessNamespace: true`. A pod that already has the
sidecar, by hand or from an earlier pass, gets no patch. Nor does a pod with
`hostPID: true`, with a warning: Kubernetes refuses `shareProcessNamespace`
beside it, so the patch would stop the pod.

It always allows the pod. A patch it can't build is logged and the pod starts
without a sidecar, as it does with the webhook down (`failurePolicy: Ignore`).
What it had to guess (a GID taken from the UID, no UID at all, a config that
isn't on a volume) is logged, returned as admission warnings, and kept on the
pod in the `rail.datrail.io/scan-sidecar-warnings` annotation.

It calls nothing and holds no credential. Like the scanner and gke-scan, it
uses only the Python standard library.

```sh
railmon scan-webhook \
  --sidecar-spec /etc/rail/sidecar/sidecar.json \
  --tls-cert-file /etc/rail/tls/tls.crt --tls-key-file /etc/rail/tls/tls.key
```

| Flag | Environment variable | Default |
|---|---|---|
| `--sidecar-spec` | `RAIL_SCAN_SIDECAR_SPEC` | required |
| `--tls-cert-file`, `--tls-key-file` | `RAIL_WEBHOOK_TLS_CERT_FILE`, `RAIL_WEBHOOK_TLS_KEY_FILE` | required; loaded again when its Secret changes ([`tls_reload.py`](../tls_reload.py)) |
| `--listen` | `RAIL_WEBHOOK_LISTEN` | `0.0.0.0:9443` |

## Tests

`tests-python/test_scan_webhook.py`: the patch for a plain pod, a gVisor pod
and a pod that already has the sidecar (the ticket's criteria), the config
mounts, the UID and GID, failing open, and the server over HTTPS. CI runs it
again against the sidecar spec the chart renders (`RAILMON_SIDECAR_SPEC`).
