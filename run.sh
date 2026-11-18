#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

PY=${PYTHON:-python3}
command -v "$PY" >/dev/null || { echo "[!] Python 3.10+ is required"; exit 1; }

if [ ! -x .venv/bin/python ]; then
    echo "[*] Creating virtual environment..."
    "$PY" -m venv .venv
fi

echo "[*] Installing / updating dependencies..."
.venv/bin/python -m pip install --disable-pip-version-check -q -r requirements.txt

if [ ! -f .env ]; then
    cp .env.example .env
    echo "[*] Created .env - add your free API keys there to unlock more sources."
fi

exec .venv/bin/python -m tiscan "$@"
