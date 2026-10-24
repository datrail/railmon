#!/bin/sh
# One container, four jobs (DR-84 / RM-F7).
#
# RailMon now carries the scanner and the forwarder that used to live in
# railscan, so a stack pulls one image instead of two. This dispatches to
# whichever of them was asked for.
#
# Backwards compatibility matters here in two directions:
#
#   * RailMon's image previously ran the collector directly as its entrypoint,
#     so `docker run railmon --mode http …` must keep working. Anything that
#     starts with a dash, and the empty invocation, go to the collector.
#   * RailScan's image used long command names (`agent-environment-scanner`,
#     `skills-scanner`, `rail-collector`). Those are kept as deprecated
#     aliases so a compose file that switches image does not also have to
#     rewrite its command, and so are the old script paths under
#     $RAILMON_ROOT (symlinks to tools/scan, tools/skills, tools/forward).
set -eu

root="${RAILMON_ROOT:-/opt/railmon}"
collector="${RAILMON_BIN:-/usr/local/bin/railmon-collector}"

# No arguments, or the first one is a flag: this is the collector being invoked
# the way it always was.
if [ "$#" -eq 0 ]; then
    exec "$collector"
fi
case "$1" in
    -*)
        exec "$collector" "$@"
        ;;
esac

command_name="$1"
shift

case "$command_name" in
    collect)
        # With RAIL_COLLECT_CONTAINER set, a supervisor finds that container's
        # TLS library and process session, runs the collector scoped to
        # them, and re-attaches after the agent restarts (DR-187).
        if [ -n "${RAIL_COLLECT_CONTAINER:-}" ]; then
            exec python3 "$root/tools/collect/follow_container_tls.py" \
                --collector "$collector" "$RAIL_COLLECT_CONTAINER" "$@"
        fi
        exec "$collector" "$@"
        ;;
    scan|agent-environment-scanner)
        exec python3 "$root/tools/scan/scan_agent_environment.py" "$@"
        ;;
    skills|skills-scanner)
        exec python3 "$root/tools/skills/skill_scanner.py" "$@"
        ;;
    forward|rail-collector)
        exec python3 "$root/tools/forward/forward.py" "$@"
        ;;
    listen)
        # One JSON line per socket the agent opens to accept inbound traffic
        # (listensnoop's lines), appended to RAIL_LISTEN_FILE for `scan
        # --listen-file` (DR-143), or to stdout when that is unset. Needs
        # eBPF privilege. The probe is AgentSight's process probe (DR-170),
        # --pidns-of the agent so other namespaces' sockets stay out of the
        # file, its events written in listensnoop's lines by
        # tools/listen/agentsight_adapter.py; --heartbeat lets the scan see a
        # probe that stopped (RAIL_LISTEN_HEARTBEAT).
        #
        # With RAIL_LISTEN_CONTAINER (and --pid host plus the Docker
        # socket), a supervisor outside the agent's reach keeps the probe
        # attached to that container's PID namespace across agent restarts
        # and kills, and records the sockets the agent was already listening
        # on at each attach (DR-182). Without it, the probe follows this
        # container's own namespace (e.g. `--pid container:<agent>`).
        #
        # RAIL_LISTEN_SOURCE=listensnoop runs an operator's own listensnoop
        # (ebpf-tls-tap) instead, from LISTENSNOOP_PATH: the image no longer
        # ships it.
        heartbeat="${RAIL_LISTEN_HEARTBEAT:-60}"
        case "${RAIL_LISTEN_SOURCE:-agentsight}" in
            agentsight)
                if [ -n "${RAIL_LISTEN_CONTAINER:-}" ]; then
                    exec python3 "$root/tools/listen/follow_container.py" --source agentsight \
                        --heartbeat "$heartbeat" --snapshot-listeners "$RAIL_LISTEN_CONTAINER" "$@"
                fi
                if [ -n "${RAIL_LISTEN_FILE:-}" ]; then
                    exec python3 "$root/tools/listen/agentsight_adapter.py" --mode listen \
                        --heartbeat "$heartbeat" "$@" >> "$RAIL_LISTEN_FILE"
                fi
                exec python3 "$root/tools/listen/agentsight_adapter.py" --mode listen \
                    --heartbeat "$heartbeat" "$@"
                ;;
            listensnoop)
                listensnoop="${LISTENSNOOP_PATH:-}"
                if [ -z "$listensnoop" ]; then
                    echo "railmon listen: RAIL_LISTEN_SOURCE=listensnoop needs LISTENSNOOP_PATH (the image does not ship it)" >&2
                    exit 64
                fi
                ;;
            *)
                echo "railmon listen: RAIL_LISTEN_SOURCE must be agentsight or listensnoop" >&2
                exit 64
                ;;
        esac
        if [ -n "${RAIL_LISTEN_CONTAINER:-}" ]; then
            exec python3 "$root/tools/listen/follow_container.py" --source probe --probe "$listensnoop" \
                --snapshot-listeners "$RAIL_LISTEN_CONTAINER" -n -H "$heartbeat" "$@"
        fi
        if [ -n "${RAIL_LISTEN_FILE:-}" ]; then
            exec "$listensnoop" -n -H "$heartbeat" "$@" >> "$RAIL_LISTEN_FILE"
        fi
        exec "$listensnoop" -n -H "$heartbeat" "$@"
        ;;
    files)
        # One JSON line the first time a process opens a regular file for a
        # kind of access (read, write, exec), in filesnoop's lines (DR-152),
        # appended to RAIL_FILES_FILE for `scan --files-file` (DR-154), or to
        # stdout when that is unset. The same shape as `listen`: the same
        # AgentSight probe and adapter, eBPF privilege, RAIL_FILES_HEARTBEAT,
        # and with RAIL_FILES_CONTAINER the same supervisor, following that
        # container's PID namespace; it appends each distinct open once
        # (DR-185), so an always-on file stays bounded.
        # RAIL_FILES_SOURCE=filesnoop runs an operator's own filesnoop from
        # FILESNOOP_PATH instead.
        heartbeat="${RAIL_FILES_HEARTBEAT:-60}"
        case "${RAIL_FILES_SOURCE:-agentsight}" in
            agentsight)
                if [ -n "${RAIL_FILES_CONTAINER:-}" ]; then
                    exec python3 "$root/tools/listen/follow_container.py" --source agentsight \
                        --command files --output "${RAIL_FILES_FILE:-}" --distinct-opens \
                        --heartbeat "$heartbeat" "$RAIL_FILES_CONTAINER" "$@"
                fi
                if [ -n "${RAIL_FILES_FILE:-}" ]; then
                    exec python3 "$root/tools/listen/agentsight_adapter.py" --mode files \
                        --heartbeat "$heartbeat" "$@" >> "$RAIL_FILES_FILE"
                fi
                exec python3 "$root/tools/listen/agentsight_adapter.py" --mode files \
                    --heartbeat "$heartbeat" "$@"
                ;;
            filesnoop)
                filesnoop="${FILESNOOP_PATH:-}"
                if [ -z "$filesnoop" ]; then
                    echo "railmon files: RAIL_FILES_SOURCE=filesnoop needs FILESNOOP_PATH (the image does not ship it)" >&2
                    exit 64
                fi
                ;;
            *)
                echo "railmon files: RAIL_FILES_SOURCE must be agentsight or filesnoop" >&2
                exit 64
                ;;
        esac
        if [ -n "${RAIL_FILES_CONTAINER:-}" ]; then
            exec python3 "$root/tools/listen/follow_container.py" --source probe \
                --command files --probe "$filesnoop" --output "${RAIL_FILES_FILE:-}" --distinct-opens \
                "$RAIL_FILES_CONTAINER" -n -H "$heartbeat" "$@"
        fi
        if [ -n "${RAIL_FILES_FILE:-}" ]; then
            exec "$filesnoop" -n -H "$heartbeat" "$@" >> "$RAIL_FILES_FILE"
        fi
        exec "$filesnoop" -n -H "$heartbeat" "$@"
        ;;
    openshell)
        # DR-249: the opt-in collector that posts an OpenShell sandbox's
        # policy and the denials its supervisor logged to RailDash.
        exec python3 "$root/tools/openshell/collector.py" "$@"
        ;;
    demo)
        # BDL-F4's local quickstart: self-scan plus a real, offline, local
        # capture, from this one container. See tools/local-demo/README.md.
        exec sh "$root/tools/local-demo/run_local_demo.sh" "$@"
        ;;
    help|-h|--help)
        cat <<'EOF'
Usage: railmon COMMAND [ARGS...]
       railmon [COLLECTOR FLAGS...]

Commands:
  collect    capture agent traffic and forward interactions   (default)
  scan       inspect and optionally register an agent
  skills     inventory OpenClaw/NemoClaw SKILL.md files
  forward    send captured interactions on to Rail Center
  listen     report sockets the agent opens to accept traffic (AgentSight)
  files      report files the agent opens to read, write or run (AgentSight)
  openshell  post an OpenShell sandbox's policy and denials to RailDash (opt-in)
  demo       self-scan + a local offline capture, for a clean-checkout first run

Called with no command, or with a flag first, RailMon runs the collector —
so `railmon --mode http --output x.jsonl` still means what it used to.

RailScan's command names (agent-environment-scanner, skills-scanner,
rail-collector) are still accepted as aliases, but are deprecated: use
scan, skills and forward.
EOF
        ;;
    python|python3|sh|/bin/sh)
        exec "$command_name" "$@"
        ;;
    *)
        exec "$command_name" "$@"
        ;;
esac
