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
#     `skills-scanner`, `rail-collector`). Those are kept as aliases so a
#     compose file that switches image does not also have to rewrite its
#     command.
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
        exec "$collector" "$@"
        ;;
    scan|agent-environment-scanner)
        exec python3 "$root/tools/agent-environment-scanner/scan_agent_environment.py" "$@"
        ;;
    skills|skills-scanner)
        exec python3 "$root/tools/skills-scanner/skill_scanner.py" "$@"
        ;;
    forward|rail-collector)
        exec python3 "$root/rail-collector/rail_collector.py" "$@"
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

Called with no command, or with a flag first, RailMon runs the collector —
so `railmon --mode http --output x.jsonl` still means what it used to.

RailScan's command names (agent-environment-scanner, skills-scanner,
rail-collector) are accepted as aliases.
EOF
        ;;
    python|python3|sh|/bin/sh)
        exec "$command_name" "$@"
        ;;
    *)
        exec "$command_name" "$@"
        ;;
esac
