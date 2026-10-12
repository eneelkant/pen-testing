#!/usr/bin/env bash
# Interactive-friendly setup. Does not silently install host packages.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== pen-testing setup =="
echo "Repository: $ROOT"
echo
echo "This script will:"
echo "  1) Detect OS/arch and prerequisites"
echo "  2) Optionally create a Python virtualenv for the orchestrator"
echo "  3) Optionally create an isolated venv for briar-pentest"
echo "  4) Copy .env.example to .env if missing"
echo "  5) Run doctor diagnostics"
echo
echo "It will NOT install Docker or change host packages without confirmation."
echo

OS="$(uname -s 2>/dev/null || echo unknown)"
ARCH="$(uname -m 2>/dev/null || echo unknown)"
echo "Detected OS=$OS ARCH=$ARCH"

need_confirm() {
  local prompt="$1"
  if [[ "${PEN_ASSUME_YES:-}" == "1" ]]; then
    return 0
  fi
  read -r -p "$prompt [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]]
}

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required."
  exit 1
fi

if [[ ! -f .env && -f .env.example ]]; then
  if need_confirm "Create .env from .env.example?"; then
    cp .env.example .env
    echo "Created .env (fill in provider keys only when needed)."
  fi
fi

if [[ ! -d .venv ]]; then
  if need_confirm "Create orchestrator venv at .venv and install this project?"; then
    if python3 -m venv .venv; then
      # shellcheck disable=SC1091
      source .venv/bin/activate
      pip install -U pip
      pip install -e ".[dev]"
    else
      echo "WARN: python3 -m venv failed (python3-venv may be missing)."
      echo "Install python3-venv via your package manager, or use: pip install --user -e .[dev]"
    fi
  fi
else
  echo "Orchestrator venv .venv already exists."
fi

if [[ ! -d .venv-briar ]]; then
  if need_confirm "Create isolated Briar venv at .venv-briar (briar-pentest==0.4.62)?"; then
    if python3 -m venv .venv-briar; then
      .venv-briar/bin/pip install -U pip
      .venv-briar/bin/pip install 'briar-pentest==0.4.62'
      echo "Briar installed. Set PEN_BRIAR_PYTHON=$ROOT/.venv-briar/bin/python"
    else
      echo "WARN: could not create .venv-briar"
    fi
  fi
fi

if ! command -v docker >/dev/null 2>&1; then
  echo
  echo "Docker is NOT installed."
  echo "Install via official docs, then re-run ./scripts/doctor.sh:"
  echo "  https://docs.docker.com/get-docker/"
else
  echo "Docker binary found: $(command -v docker)"
fi

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
python3 -m core.cli doctor || true
echo
echo "Setup finished. Next:"
echo "  1) Review scopes/registry.yaml and authorize targets"
echo "  2) Configure AI provider env vars only if needed (.env)"
echo "  3) make smoke   # local smoke test without external attacks"
