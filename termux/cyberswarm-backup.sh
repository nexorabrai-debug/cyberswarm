#!/data/data/com.termux/files/usr/bin/bash
# Backup consistente dos dados do CyberSwarm (pode rodar com o servidor ligado).
# Padrão: salva em ~/cyberswarm-backups (privado do Termux), COM a senha/chave (~/.cyberswarm_env).
# --compartilhar: salva em ~/storage/shared/CyberSwarm-backups (pasta do celular) SEM a senha/chave.
set -euo pipefail
DATA="${CONTROL_DATA:-$HOME/cyberswarm-data}"; ENVF="$HOME/.cyberswarm_env"
OUT="$HOME/cyberswarm-backups"; WITH_ENV=1
if [ "${1:-}" = "--compartilhar" ]; then
  [ -d "$HOME/storage/shared" ] || termux-setup-storage || true
  [ -d "$HOME/storage/shared" ] || { echo "Sem acesso ao armazenamento. Rode termux-setup-storage e permita."; exit 1; }
  OUT="$HOME/storage/shared/CyberSwarm-backups"; WITH_ENV=0
fi
[ -d "$DATA" ] || { echo "Pasta de dados não existe: $DATA"; exit 1; }
mkdir -p "$OUT"; umask 077
STG=$(mktemp -d "${TMPDIR:-$PREFIX/tmp}/csbk.XXXXXX"); trap 'rm -rf "$STG"' EXIT
python - "$DATA" "$STG/data" <<'PY'
import os, shutil, sqlite3, sys
src, dst = sys.argv[1], sys.argv[2]
for root, dirs, files in os.walk(src):
    rel = os.path.relpath(root, src); os.makedirs(os.path.join(dst, rel), exist_ok=True)
    for f in files:
        s, d = os.path.join(root, f), os.path.join(dst, rel, f)
        if f.endswith(("-wal", "-shm", "-journal")): continue
        if f.endswith(".db"):
            a = sqlite3.connect(f"file:{s}?mode=ro", uri=True); b = sqlite3.connect(d)
            a.backup(b); b.close(); a.close()
            assert sqlite3.connect(d).execute("PRAGMA integrity_check").fetchone()[0] == "ok", d
        else: shutil.copy2(s, d)
PY
[ "$WITH_ENV" = 1 ] && [ -f "$ENVF" ] && cp "$ENVF" "$STG/cyberswarm_env"
F="$OUT/cyberswarm-$(date +%Y%m%d-%H%M%S).tar.gz"
tar -czf "$F" -C "$STG" .
echo "Backup salvo: $F ($(du -h "$F" | cut -f1))"
[ "$WITH_ENV" = 0 ] && echo "Obs.: este backup NÃO tem a senha. Guarde a senha anotada."
