#!/usr/bin/env bash
# Corre no SSH do Serv00. NÃO cria conta — assume LOGIN já existe.
set -euo pipefail
LOGIN="${USER:?}"
HOME_DIR="${HOME:-/usr/home/$LOGIN}"
APP="$HOME_DIR/cyberswarm"
DATA="$HOME_DIR/cs-control"
PY="${PYTHON_BIN:-python3.12}"

mkdir -p "$HOME_DIR/.virtualenvs" "$DATA"
# Binexec deve estar ligado no painel (DevilWEB → Additional services)
if [[ ! -d "$HOME_DIR/.virtualenvs/cs" ]]; then
  virtualenv -p "$(command -v "$PY" || command -v python3)" "$HOME_DIR/.virtualenvs/cs"
fi
# shellcheck disable=SC1091
source "$HOME_DIR/.virtualenvs/cs/bin/activate"
cd "$APP"
pip install -U pip
pip install -e .

if [[ ! -f "$DATA/control.db" ]]; then
  echo "Criando owner (senha via CONTROL_PASSWORD ou prompt)…"
  CONTROL_PASSWORD="${CONTROL_PASSWORD:?defina CONTROL_PASSWORD (>=10 chars)}" \
    cyberswarm control init --data "$DATA" --user "${CONTROL_USER:-dono}"
fi
echo "OK. Dados em $DATA. Depois: ./deploy/serv00/start.sh"
