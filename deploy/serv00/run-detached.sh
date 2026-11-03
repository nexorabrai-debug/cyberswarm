#!/usr/bin/env bash
# Arranque em background sem screen (útil no cron).
set -euo pipefail
HOME_DIR="${HOME:-/usr/home/$USER}"
LOG="$HOME_DIR/cs-control.log"
nohup "$HOME_DIR/cyberswarm/deploy/serv00/start.sh" >>"$LOG" 2>&1 &
echo "pid $! — log $LOG"
