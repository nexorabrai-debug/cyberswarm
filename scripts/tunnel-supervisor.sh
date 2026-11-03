#!/usr/bin/env bash
# Sobe túnel HTTPS gratuito apontando SÓ para Control em 127.0.0.1:8770.
# Preferência: cloudflared quick → localtunnel. Reinicia se cair.
set -euo pipefail
PORT="${CONTROL_PORT:-8770}"
LOG="${TUNNEL_LOG:-/tmp/cs-tunnel.log}"
URL_FILE="${TUNNEL_URL_FILE:-/tmp/cs-tunnel.url}"
echo "supervisor start $(date -Iseconds)" | tee -a "$LOG"
while true; do
  if command -v cloudflared >/dev/null 2>&1; then
    echo "try cloudflared" | tee -a "$LOG"
    cloudflared tunnel --url "http://127.0.0.1:${PORT}" --protocol http2 --no-autoupdate 2>&1 | tee -a "$LOG" | while read -r line; do
      if echo "$line" | grep -Eo 'https://[a-zA-Z0-9.-]+\.trycloudflare\.com' >/tmp/cs-url.partial; then
        cp /tmp/cs-url.partial "$URL_FILE"
        echo "URL $(cat "$URL_FILE")" | tee -a "$LOG"
      fi
    done || true
  elif command -v npx >/dev/null 2>&1; then
    echo "try localtunnel" | tee -a "$LOG"
    npx --yes localtunnel --port "$PORT" 2>&1 | tee -a "$LOG" | while read -r line; do
      if echo "$line" | grep -Eo 'https://[a-zA-Z0-9.-]+\.loca\.lt' >/tmp/cs-url.partial; then
        cp /tmp/cs-url.partial "$URL_FILE"
        echo "URL $(cat "$URL_FILE")" | tee -a "$LOG"
      fi
    done || true
  else
    echo "instale cloudflared ou node/npx" | tee -a "$LOG"; sleep 60; continue
  fi
  echo "tunnel exited; retry in 5s" | tee -a "$LOG"; sleep 5
done
