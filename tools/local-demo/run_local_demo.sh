#!/bin/sh
# `railmon demo` — DR-48's local quickstart, from one container.
#
# Produces both halves of what BDL-F4 asks a clean checkout to show:
#   - a non-empty inventory (self-scan of this container — always available,
#     needs no target)
#   - a non-empty capture (a real, local, offline HTTPS exchange between
#     demo_server.py and demo_client.py, tapped by the collector like any
#     other agent traffic)
#
# Requires the same privileges `collect` always has: --privileged --pid=host,
# a Linux kernel with BTF/CO-RE, and (per the Dockerfile) an x86_64 host —
# AgentSight ships no other architecture. See README.md's "Platforms" section.
set -eu

root="${RAILMON_ROOT:-/opt/railmon}"
collector="${RAILMON_BIN:-/usr/local/bin/railmon-collector}"
out_dir="${RAILMON_DEMO_OUT:-/out}"
mkdir -p "$out_dir"

echo "railmon demo: 1/3 self-scan -> $out_dir/features.json"
python3 "$root/tools/agent-environment-scanner/scan_agent_environment.py" \
    --mode self --output "$out_dir/features.json" >/dev/null
# store_json (scan_agent_environment.py) opens with O_TRUNC, so re-running
# this replaces features.json rather than growing it — running the demo
# twice does not duplicate the inventory.

echo "railmon demo: 2/3 starting the local HTTPS demo pair"
cert_dir=$(mktemp -d)
cleanup() {
    [ -n "${server_pid:-}" ] && kill "$server_pid" 2>/dev/null || true
    rm -rf "$cert_dir"
}
trap cleanup EXIT INT TERM

openssl req -x509 -newkey rsa:2048 -keyout "$cert_dir/key.pem" -out "$cert_dir/cert.pem" \
    -days 1 -nodes -subj "/CN=127.0.0.1" >/dev/null 2>&1

python3 "$root/tools/local-demo/demo_server.py" "$cert_dir/cert.pem" "$cert_dir/key.pem" &
server_pid=$!

# Poll for the port rather than a blind sleep — a fixed delay is either
# wasted time on a warm cache or a race against a cold one. No `nc` in the
# image (one fewer apt package to justify), so the probe is a one-line
# Python socket connect — consistent with the demo pair themselves.
tries=0
until python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.2); sys.exit(0 if s.connect_ex(('127.0.0.1', 8443)) == 0 else 1)" 2>/dev/null; do
    tries=$((tries + 1))
    if [ "$tries" -ge 50 ]; then
        echo "railmon demo: demo server never came up on 127.0.0.1:8443" >&2
        exit 1
    fi
    sleep 0.1
done

echo "railmon demo: 3/3 capturing -> $out_dir/capture.jsonl"
"$collector" --output "$out_dir/capture.jsonl" --comm python3 \
    >"$out_dir/.collector.log" 2>&1 &
collector_pid=$!

# The probe (AgentSight) attaches asynchronously after the collector starts;
# give it a moment before generating traffic, or the first request or two can
# race the attach and go untapped. Same reasoning as the server wait above:
# poll the collector's own log for the line that means it is actually
# attached, with a generous timeout as a fallback rather than a guessed sleep.
tries=0
until grep -q "agentsight at" "$out_dir/.collector.log" 2>/dev/null || [ "$tries" -ge 100 ]; do
    tries=$((tries + 1))
    sleep 0.1
done
sleep 1

python3 "$root/tools/local-demo/demo_client.py"

# flush_interval defaults to 2s; give the collector a full cycle to write
# before asking it to stop.
sleep 3
kill -INT "$collector_pid" 2>/dev/null || true
wait "$collector_pid" 2>/dev/null || true

if [ -s "$out_dir/capture.jsonl" ]; then
    lines=$(wc -l <"$out_dir/capture.jsonl")
    echo "railmon demo: done — $out_dir/features.json and $out_dir/capture.jsonl ($lines interaction(s))"
else
    echo "railmon demo: capture.jsonl is empty or missing — see $out_dir/.collector.log" >&2
    cat "$out_dir/.collector.log" >&2 2>/dev/null || true
    exit 1
fi
