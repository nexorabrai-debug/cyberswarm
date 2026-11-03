#!/usr/bin/env bash
# Mantém Control+workers vivos (processo único). Bind 127.0.0.1 + proxy HTTPS do Serv00.
set -euo pipefail
LOGIN="${USER:?}"
HOME_DIR="${HOME:-/usr/home/$LOGIN}"
APP="$HOME_DIR/cyberswarm"
DATA="$HOME_DIR/cs-control"
VENV="$HOME_DIR/.virtualenvs/cs"
PORT_FILE="$HOME_DIR/cs-port.txt"
LOG="$HOME_DIR/cs-control.log"

# Porta reservada: echo 12345 > ~/cs-port.txt  (DevilWEB → Port reservation)
PORT="$(cat "$PORT_FILE" 2>/dev/null || echo "${CONTROL_PORT:-}")"
[[ -n "$PORT" ]] || { echo "Reserve uma porta TCP no painel e grave em $PORT_FILE"; exit 1; }

# shellcheck disable=SC1091
source "$VENV/bin/activate"
cd "$APP"
export CONTROL_DATA="$DATA"
export CONTROL_SECURE_COOKIE=1
export CONTROL_ALLOW_LAN=0
export PYTHONUNBUFFERED=1

# Reinício em loop — se o processo cair, volta. Não expõe shell/admin.
while true; do
  echo "$(date -Is) start port=$PORT" >>"$LOG"
  cyberswarm control serve --data "$DATA" --host 127.0.0.1 --port "$PORT" --secure-cookie \
    >>"$LOG" 2>&1 || true
  echo "$(date -Is) exit; sleep 3" >>"$LOG"
  sleep 3
done
