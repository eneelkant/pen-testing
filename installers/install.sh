#!/usr/bin/env bash
# Base installer for pen-testing-platform (+ optional MCP profile).
# Does not silently install Docker or change system Python.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PROFILE="${1:-base}"  # base | mcp | dev
ASSUME_YES="${PEN_ASSUME_YES:-0}"

echo "== pen-testing install ($PROFILE) =="
echo "OS=$(uname -s) ARCH=$(uname -m) ROOT=$ROOT"

confirm() {
  local prompt="$1"
  if [[ "$ASSUME_YES" == "1" ]]; then return 0; fi
  read -r -p "$prompt [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]]
}

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required (3.10+)."
  exit 1
fi

PY_VER="$(python3 -c 'import sys; print("%d.%d"%sys.version_info[:2])')"
python3 - <<'PY'
import sys
maj, min_ = sys.version_info[:2]
if (maj, min_) < (3, 10):
    raise SystemExit(f"Python >=3.10 required; found {sys.version}")
print(f"Python OK: {sys.version.split()[0]}")
PY

if [[ ! -d .venv ]]; then
  if confirm "Create isolated venv at .venv?"; then
    if ! python3 -m venv .venv; then
      echo "ERROR: python3 -m venv failed. Install python3-venv, then retry."
      exit 1
    fi
  else
    echo "Aborted: isolated venv required for reproducible installs."
    exit 1
  fi
fi

# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install -U pip
case "$PROFILE" in
  base) pip install -e . -c requirements/base.txt ;;
  mcp)  pip install -e ".[mcp]" -r requirements/mcp.txt ;;
  dev)  pip install -e ".[dev]" -r requirements/dev.txt ;;
  *) echo "Unknown profile: $PROFILE (use base|mcp|dev)"; exit 2 ;;
esac

if [[ ! -f .env && -f .env.example ]]; then
  if confirm "Create .env from .env.example?"; then
    cp .env.example .env
  fi
fi

if ! command -v docker >/dev/null 2>&1; then
  echo
  echo "Docker is NOT installed. Shannon workers require Docker."
  echo "Install manually: https://docs.docker.com/get-docker/"
  echo "This installer will not install Docker without explicit operator action."
fi

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
python -m core.cli doctor || true
python - <<'PY'
from mcp_server import service
print("MCP service import OK")
r = service.run_local_diagnostics()
print("diagnostics_ok=", r.get("ok"))
PY

echo
echo "Install complete."
echo "Activate: source .venv/bin/activate"
echo "MCP stdio: pen-testing-mcp"
echo "Client setup: python installers/configure_cursor.py --print-only"
