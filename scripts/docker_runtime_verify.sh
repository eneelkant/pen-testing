#!/usr/bin/env bash
# Docker Engine + Compose runtime verification for CI and local hosts.
# Uses only local fixtures / doctor / unit smoke — no external active scans.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if ! command -v docker >/dev/null 2>&1; then
    return 0
  fi
  log "== cleanup: compose down (workers + fixtures) =="
  docker compose --profile workers --profile fixtures down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "== verify Docker Engine =="
command -v docker >/dev/null 2>&1 || die "docker executable not found. Install from https://docs.docker.com/get-docker/"
docker version
docker info >/dev/null

log "== verify Docker Compose plugin =="
docker compose version

log "== docker compose config -q =="
docker compose config -q

log "== build required project images (orchestrator + briar worker) =="
# Default profile builds orchestrator; workers profile builds briar.
docker compose --progress=plain build
docker compose --profile workers --progress=plain build briar

log "== orchestrator smoke (compose service: orchestrator) =="
# Documented check: docker compose run --rm orchestrator
# Default command is `python -m core.cli doctor` (harmless diagnostics).
docker compose run --rm --no-deps orchestrator

log "== host smoke script (no external targets) =="
bash scripts/smoke.sh

log "Docker runtime verification passed."
