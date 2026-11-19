#!/bin/sh
# The scan-sidecar image's entrypoint (RC-518), installed as /usr/local/bin/railmon.
#
# The image carries only tools/scan, so only the commands that live there:
# the main image's entrypoint.sh would hand the rest (collect, listen, files,
# forward, ...) to programs this image doesn't have. The names are the main
# image's, so `railmon scan --health-check` is the same liveness probe in both.
set -eu

root="${RAILMON_ROOT:-/opt/railmon}"

command_name="${1:-help}"
[ "$#" -gt 0 ] && shift

case "$command_name" in
    scan)
        exec python3 "$root/tools/scan/scan_agent_environment.py" "$@"
        ;;
    gke-scan)
        exec python3 "$root/tools/scan/gke/central_service/gke_scan.py" "$@"
        ;;
    scan-webhook)
        exec python3 "$root/tools/scan/gke/webhook/scan_webhook.py" "$@"
        ;;
    help|-h|--help)
        cat <<'EOF'
Usage: railmon COMMAND [ARGS...]

The scan-sidecar image. Commands:
  scan          the scanner; in a pod, `scan --mode pod` (the scan sidecar)
  gke-scan      the central GKE service: relays scan sidecars' bundles
  scan-webhook  the admission webhook that adds the scan sidecar to labeled pods

The collector, listen, files, forward, skills and openshell are in the main
railmon image, not this one.
EOF
        ;;
    *)
        echo "railmon (scan-sidecar image): unknown command '$command_name'; try 'railmon help'" >&2
        exit 64
        ;;
esac
