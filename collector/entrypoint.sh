#!/bin/sh
set -eu

exec python3 /opt/railmon/collector.py "$@"
