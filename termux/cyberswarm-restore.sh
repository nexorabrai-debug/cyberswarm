#!/data/data/com.termux/files/usr/bin/bash
# Restaura um backup. Desligue o CyberSwarm antes (Ctrl+C no iniciar.sh).
# Uso: bash ~/cyberswarm-restore.sh ARQUIVO.tar.gz
set -euo pipefail
F="${1:?Informe o arquivo .tar.gz do backup}"
DATA="${CONTROL_DATA:-$HOME/cyberswarm-data}"; ENVF="$HOME/.cyberswarm_env"
[ -f "$F" ] || { echo "Arquivo não encontrado: $F"; exit 1; }
if pgrep -f "cyberswarm control serve .*--port 8770" >/dev/null 2>&1; then echo "Desligue o CyberSwarm primeiro (Ctrl+C)."; exit 1; fi
STG=$(mktemp -d "${TMPDIR:-$PREFIX/tmp}/csrs.XXXXXX"); trap 'rm -rf "$STG"' EXIT
tar -xzf "$F" -C "$STG"
[ -d "$STG/data" ] || { echo "Backup inválido (sem pasta data)."; exit 1; }
python - "$STG/data" <<'PY'
import os, sqlite3, sys
for r, _, fs in os.walk(sys.argv[1]):
    for f in fs:
        if f.endswith(".db"):
            assert sqlite3.connect(os.path.join(r, f)).execute("PRAGMA integrity_check").fetchone()[0] == "ok", f
PY
if [ -d "$DATA" ]; then OLD="$DATA.antes-restore-$(date +%Y%m%d-%H%M%S)"; mv "$DATA" "$OLD"; echo "Dados atuais guardados em: $OLD"; fi
mv "$STG/data" "$DATA"
if [ -f "$STG/cyberswarm_env" ]; then
  [ -f "$ENVF" ] && cp "$ENVF" "$ENVF.antes-restore"
  install -m 600 "$STG/cyberswarm_env" "$ENVF"; echo "Senha/chave restauradas do backup."
else echo "Backup sem senha/chave: mantida a senha atual (~/.cyberswarm_env)."; fi
echo "Restaurado. Ligue de novo: bash ~/iniciar.sh"
