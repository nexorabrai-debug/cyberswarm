#!/data/data/com.termux/files/usr/bin/bash
# CyberSwarm 2.1.1 no Termux (Android ARM64). Roda só no próprio celular (127.0.0.1).
# Uso (versão FIXA): curl -fsSL https://raw.githubusercontent.com/nexorabrai-debug/cyberswarm/<SHA>/termux/instalar.sh | bash -s <SHA>
# O código é baixado exatamente no commit <SHA> e conferido com `git rev-parse HEAD`.
set -euo pipefail
REPO="https://github.com/nexorabrai-debug/cyberswarm.git"
TAG="v2.1.1"
WANT="${1:-${CS_SHA:-}}"
DIR="$HOME/cyberswarm"; ENVF="$HOME/.cyberswarm_env"; DATA="$HOME/cyberswarm-data"
PFX="${PREFIX:-/data/data/com.termux/files/usr}"

echo "== 1/5 Pacotes do Termux =="
yes | pkg update -y || true
# python (inclui ssl, sqlite3, pip) | git | openssl-tool (certificado local) | libsqlite | ca-certificates (TLS)
# python-cryptography (verificação TLS / chaves) | python-pillow (dependência do PDF, já compilada)
pkg install -y python git openssl openssl-tool libsqlite ca-certificates python-cryptography python-pillow
PYV=$(python -c 'import sys;print("%d%02d"%sys.version_info[:2])')
[ "$PYV" -ge 310 ] || { echo "Python muito antigo ($PYV). Precisa 3.10+."; exit 1; }

echo "== 2/5 Biblioteca de PDF =="
pip install --disable-pip-version-check --no-input -q "fpdf2>=2.7,<3" || echo "AVISO: fpdf2 não instalou; o PDF vai cair para HTML."

echo "== 3/5 Código do CyberSwarm (versão fixa) =="
[ -d "$DIR/.git" ] || git init -q "$DIR"
git -C "$DIR" remote remove origin 2>/dev/null || true
git -C "$DIR" remote add origin "$REPO"
if [ -n "$WANT" ]; then
  git -C "$DIR" fetch -q --depth 1 origin "$WANT"
else
  echo "AVISO: nenhum commit informado; usando a tag $TAG."
  git -C "$DIR" fetch -q --depth 1 origin "refs/tags/$TAG:refs/tags/$TAG"; WANT=$(git -C "$DIR" rev-parse "$TAG^{commit}")
fi
git -C "$DIR" -c advice.detachedHead=false checkout -q -f FETCH_HEAD 2>/dev/null || git -C "$DIR" checkout -q -f "$WANT"
GOT=$(git -C "$DIR" rev-parse HEAD)
if [ "$GOT" != "$WANT" ]; then echo "ERRO: commit baixado ($GOT) diferente do esperado ($WANT). Parei."; exit 1; fi
echo "Commit conferido: $GOT"

echo "== 4/5 Senha e chave local =="
mkdir -p "$DATA"; umask 077
if [ ! -f "$ENVF" ]; then
  echo "Escolha a senha do usuário 'dono' (mínimo 10 caracteres)."
  echo "Deixe em branco e aperte Enter para gerar uma automática."
  PW=""
  if { : < /dev/tty; } 2>/dev/null; then read -r -s -p "Senha: " PW < /dev/tty || true; echo; fi
  if [ -z "$PW" ] || [ ${#PW} -lt 10 ]; then
    [ -n "$PW" ] && echo "Senha curta demais; vou gerar uma."
    PW=$(python -c 'import secrets;print(secrets.token_urlsafe(12))')
    echo "=========================================="
    echo " SUA SENHA (anote agora, aparece só 1 vez):"
    echo "   usuário: dono"; echo "   senha:   $PW"
    echo "=========================================="
  fi
  printf 'CONTROL_PASSWORD=%q\n' "$PW" > "$ENVF"; unset PW
fi
grep -q '^CYBERSWARM_SECRET=' "$ENVF" || printf 'CYBERSWARM_SECRET=%s\n' "$(python -c 'import secrets;print(secrets.token_urlsafe(32))')" >> "$ENVF"
chmod 600 "$ENVF"

echo "== 5/5 Scripts =="
cp "$DIR/termux/iniciar.sh" "$HOME/iniciar.sh"
cp "$DIR/termux/cyberswarm-backup.sh" "$HOME/cyberswarm-backup.sh"
cp "$DIR/termux/cyberswarm-restore.sh" "$HOME/cyberswarm-restore.sh"
chmod 700 "$HOME/iniciar.sh" "$HOME/cyberswarm-backup.sh" "$HOME/cyberswarm-restore.sh"
python - <<'PY' || true
import importlib
for m, what in [("ssl","TLS"),("sqlite3","banco"),("cryptography","TLS/chaves"),("fpdf","PDF")]:
    try: importlib.import_module(m); print(f"  ok   {m:13s} ({what})")
    except Exception as e: print(f"  FALTA {m:12s} ({what}): {e}")
PY
echo; echo "Pronto! CyberSwarm 2.1.1 ($GOT)"
echo "Ligar:   bash ~/iniciar.sh     e abra no Chrome: http://127.0.0.1:8770"
echo "Backup:  bash ~/cyberswarm-backup.sh    Restaurar: bash ~/cyberswarm-restore.sh ARQUIVO"
