#!/bin/sh
set -eu
DATA="${CONTROL_DATA:-/data}"
mkdir -p "$DATA"
if [ ! -f "$DATA/control.db" ] && [ -n "${CONTROL_PASSWORD:-}" ]; then
  cyberswarm control init --data "$DATA" --user "${CONTROL_USER:-dono}" || true
fi
exec cyberswarm control serve --data "$DATA" --host 0.0.0.0 --port "${PORT:-8770}" --allow-lan --secure-cookie
