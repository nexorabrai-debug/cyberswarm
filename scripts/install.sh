#!/bin/sh
set -e
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/pip" install -U pip
"$ROOT/.venv/bin/pip" install -e "$ROOT"
echo "OK. Ative: . $ROOT/.venv/bin/activate"
echo "Depois: cyberswarm control init --data \$HOME/cs-control"
