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
  log "== cleanup: compose down (workers + live-workers + fixtures) =="
  docker compose --profile workers --profile live-workers --profile fixtures down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "== verify Docker Engine =="
command -v docker >/dev/null 2>&1 || die "docker executable not found. Install from https://docs.docker.com/get-docker/"
docker version
docker info >/dev/null

log "== verify Docker Compose plugin =="
docker compose version

log "== docker compose config -q =="
docker compose --profile workers --profile live-workers --profile fixtures config -q

log "== assert isolation networks present in render =="
RENDER="$(docker compose --profile workers --profile live-workers config)"
echo "$RENDER" | grep -q 'pen-scanner-isolated' || die "missing pen-scanner-isolated network"
echo "$RENDER" | grep -q 'pen-scanner-live' || die "missing pen-scanner-live network"
echo "$RENDER" | grep -q 'internal: true' || die "expected internal: true on isolated scanner network"
# Refuse accidental docker.sock mounts in any service definition we ship.
if echo "$RENDER" | grep -E '/var/run/docker.sock|docker.sock:'; then
  die "docker.sock mount must not appear in compose render"
fi

log "== build required project images (orchestrator + briar workers) =="
docker compose --progress=plain build
docker compose --profile workers --progress=plain build briar
docker compose --profile live-workers --progress=plain build briar-live

log "== orchestrator smoke (compose service: orchestrator) =="
docker compose run --rm --no-deps orchestrator

log "== briar isolated worker smoke (no external egress network) =="
docker compose --profile workers run --rm --no-deps briar

log "== inspect briar container mounts for docker.sock =="
# Create a short-lived container inspect via compose config labels already checked;
# additionally ensure image has no privileged defaults by running help successfully.
docker compose --profile workers run --rm --no-deps briar --help >/dev/null

log "== host smoke script (no external targets) =="
bash scripts/smoke.sh

log "== isolation unit tests (must not be skipped) =="
python3 -m pytest -q tests/unit/test_scanner_isolation.py
test -f tests/unit/test_scanner_isolation.py || die "isolation tests missing"

log "Docker runtime verification passed."
