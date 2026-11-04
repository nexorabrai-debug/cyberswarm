#!/data/data/com.termux/files/usr/bin/bash
# CyberSwarm no Termux (Galaxy A32) — grátis, roda só no próprio celular.
set -e
REPO="https://github.com/nexorabrai-debug/cyberswarm.git"
DIR="$HOME/cyberswarm"; ENVF="$HOME/.cyberswarm_env"; DATA="$HOME/cyberswarm-data"
echo "== Atualizando pacotes =="
yes | pkg update -y || true
pkg install -y python git
PYV=$(python -c 'import sys;print("%d%02d"%sys.version_info[:2])')
[ "$PYV" -ge 310 ] || { echo "Python muito antigo ($PYV). Precisa 3.10+."; exit 1; }
if [ -d "$DIR/.git" ]; then echo "== Atualizando CyberSwarm =="; git -C "$DIR" pull --ff-only
else echo "== Baixando CyberSwarm =="; git clone --depth 1 "$REPO" "$DIR"; fi
mkdir -p "$DATA"
if [ ! -f "$ENVF" ]; then
  echo; echo "Escolha a senha do usuário 'dono' (mínimo 10 caracteres)."
  echo "Deixe em branco e aperte Enter para gerar uma automática."
  PW=""
  if { : < /dev/tty; } 2>/dev/null; then read -r -s -p "Senha: " PW < /dev/tty || true; echo; fi
  if [ -z "$PW" ] || [ ${#PW} -lt 10 ]; then
    [ -n "$PW" ] && echo "Senha curta demais; vou gerar uma."
    PW=$(python -c 'import secrets;print(secrets.token_urlsafe(12))')
    echo; echo "=========================================="
    echo " SUA SENHA (anote agora, aparece só 1 vez):"
    echo "   usuário: dono"; echo "   senha:   $PW"
    echo "=========================================="; echo
  fi
  umask 077
  printf 'CONTROL_PASSWORD=%q\n' "$PW" > "$ENVF"; chmod 600 "$ENVF"
  unset PW
fi
cat > "$HOME/iniciar.sh" <<'EOS'
#!/data/data/com.termux/files/usr/bin/bash
set -e
. "$HOME/.cyberswarm_env"
export CONTROL_DATA="$HOME/cyberswarm-data" PORT=8770 CONTROL_USER=dono CONTROL_PASSWORD
export CONTROL_SECURE_COOKIE=0 CONTROL_ALLOW_LAN=0 PYTHONUNBUFFERED=1
export PYTHONPATH="$HOME/cyberswarm" TMPDIR="${TMPDIR:-$PREFIX/tmp}"
mkdir -p "$CONTROL_DATA" "$TMPDIR"
cd "$HOME/cyberswarm"
if [ ! -f "$CONTROL_DATA/control.db" ]; then
  python -m cyberswarm control init --data "$CONTROL_DATA" --user dono
fi
command -v termux-wake-lock >/dev/null && termux-wake-lock || true
echo "CyberSwarm rodando. Abra no Chrome: http://127.0.0.1:8770  (Ctrl+C para parar)"
exec python -m cyberswarm control serve --data "$CONTROL_DATA" --host 127.0.0.1 --port "$PORT"
EOS
chmod 700 "$HOME/iniciar.sh"
echo; echo "Pronto! Agora rode:  bash ~/iniciar.sh"
echo "Depois abra no Chrome: http://127.0.0.1:8770"
