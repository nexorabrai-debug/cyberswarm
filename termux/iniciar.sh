#!/data/data/com.termux/files/usr/bin/bash
# Liga o CyberSwarm SOMENTE em 127.0.0.1 (nunca na rede). Não edite host/LAN aqui.
set -e
. "$HOME/.cyberswarm_env"
unset CONTROL_ALLOW_LAN CONTROL_HOST HOST
export CONTROL_DATA="$HOME/cyberswarm-data" PORT=8770 CONTROL_USER=dono CONTROL_PASSWORD CYBERSWARM_SECRET
export CONTROL_SECURE_COOKIE=0 PYTHONUNBUFFERED=1
export PYTHONPATH="$HOME/cyberswarm" TMPDIR="${TMPDIR:-$PREFIX/tmp}"
mkdir -p "$CONTROL_DATA" "$TMPDIR"
cd "$HOME/cyberswarm"
if [ ! -f "$CONTROL_DATA/control.db" ]; then
  python -m cyberswarm control init --data "$CONTROL_DATA" --user dono
fi
command -v termux-wake-lock >/dev/null && termux-wake-lock || true
echo "CyberSwarm rodando. Abra no Chrome: http://127.0.0.1:8770  (Ctrl+C para parar)"
exec python -m cyberswarm control serve --data "$CONTROL_DATA" --host 127.0.0.1 --port 8770
