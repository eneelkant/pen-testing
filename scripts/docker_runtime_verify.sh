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
docker compose --profile workers run --rm --no-deps briar --help >/dev/null

log "== runtime connectivity: isolated network must not reach external IP =="
# Create the isolated network by instantiating the briar service, then probe it.
docker compose --profile workers create briar >/dev/null
ISO_NET="$(docker network ls --format '{{.Name}}' | grep -E 'pen-scanner-isolated$' | head -n1 || true)"
test -n "$ISO_NET" || die "could not locate pen-scanner-isolated docker network"
# Probe uses the same Python base image already pulled for builds; no third-party scan.
# Expect connection failure (egress blocked by internal:true).
set +e
PROBE_OUT="$(docker run --rm --network "$ISO_NET" python:3.12-slim-bookworm \
  python -c 'import socket,sys
try:
    socket.create_connection(("1.1.1.1", 443), timeout=3)
    print("UNEXPECTED_CONNECT")
    sys.exit(0)
except OSError as exc:
    print("ISOLATED_BLOCKED", type(exc).__name__)
    sys.exit(1)
' 2>&1)"
PROBE_RC=$?
set -e
echo "$PROBE_OUT"
# Success for isolation means the connect failed (non-zero) and did not print UNEXPECTED_CONNECT.
echo "$PROBE_OUT" | grep -q 'UNEXPECTED_CONNECT' && die "isolated network unexpectedly reached 1.1.1.1:443"
test "$PROBE_RC" -ne 0 || die "isolated network probe unexpectedly succeeded"
echo "$PROBE_OUT" | grep -q 'ISOLATED_BLOCKED' || die "isolated probe did not report ISOLATED_BLOCKED"

log "== runtime connectivity: control network can reach local fixture =="
docker compose --profile fixtures --profile live-workers up -d fixture-headers
# Wait briefly for fixture readiness
ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if docker compose --profile fixtures exec -T fixture-headers python -c 'import socket; s=socket.create_connection(("127.0.0.1",8080),2); s.close()' 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
test "$ready" -eq 1 || die "fixture-headers did not become ready"
CTRL_NET="$(docker network ls --format '{{.Name}}' | grep -E 'pen-control$' | head -n1 || true)"
test -n "$CTRL_NET" || die "could not locate pen-control docker network"
CTRL_OUT="$(docker run --rm --network "$CTRL_NET" python:3.12-slim-bookworm \
  python -c 'import socket,sys
s=socket.create_connection(("fixture-headers",8080), timeout=5)
s.close()
print("CONTROL_REACHES_FIXTURE")
')"
echo "$CTRL_OUT"
echo "$CTRL_OUT" | grep -q 'CONTROL_REACHES_FIXTURE' || die "control network could not reach fixture-headers"

log "== runtime: actual briar worker container is on pen-scanner-isolated =="
# Capture the container id of a short-lived briar worker and inspect its networks.
ISO_CID="$(docker compose --profile workers run -d --no-deps --entrypoint sleep briar 30)"
test -n "$ISO_CID" || die "failed to start briar worker container for inspect"
ISO_NETWORKS="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$ISO_CID")"
echo "BRIAR_ISOLATED_NETWORKS=$ISO_NETWORKS"
echo "$ISO_NETWORKS" | grep -Eq 'pen-scanner-isolated' || {
  docker rm -f "$ISO_CID" >/dev/null 2>&1 || true
  die "briar worker not attached to pen-scanner-isolated"
}
echo "$ISO_NETWORKS" | grep -Eq 'pen-scanner-live|pen-control' && {
  docker rm -f "$ISO_CID" >/dev/null 2>&1 || true
  die "briar isolated worker unexpectedly attached to control/live network"
}
# Probe FROM the real briar worker network namespace (not an unrelated container).
set +e
WORKER_PROBE="$(docker exec "$ISO_CID" python -c 'import socket,sys
try:
    socket.create_connection(("1.1.1.1", 443), timeout=3)
    print("UNEXPECTED_CONNECT")
    sys.exit(0)
except OSError as exc:
    print("BRIAR_WORKER_ISOLATED_BLOCKED", type(exc).__name__)
    sys.exit(1)
' 2>&1)"
WORKER_RC=$?
set -e
echo "$WORKER_PROBE"
docker rm -f "$ISO_CID" >/dev/null 2>&1 || true
echo "$WORKER_PROBE" | grep -q 'UNEXPECTED_CONNECT' && die "briar worker reached 1.1.1.1:443"
test "$WORKER_RC" -ne 0 || die "briar worker egress probe unexpectedly succeeded"
echo "$WORKER_PROBE" | grep -q 'BRIAR_WORKER_ISOLATED_BLOCKED' || die "missing BRIAR_WORKER_ISOLATED_BLOCKED"

log "== runtime: briar-live worker can reach authorized fixture on pen-scanner-live =="
LIVE_NET="$(docker network ls --format '{{.Name}}' | grep -E 'pen-scanner-live$' | head -n1 || true)"
test -n "$LIVE_NET" || die "could not locate pen-scanner-live docker network"
LIVE_CID="$(docker compose --profile live-workers run -d --no-deps --entrypoint sleep briar-live 30)"
test -n "$LIVE_CID" || die "failed to start briar-live worker for inspect"
LIVE_NETWORKS="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$LIVE_CID")"
echo "BRIAR_LIVE_NETWORKS=$LIVE_NETWORKS"
echo "$LIVE_NETWORKS" | grep -Eq 'pen-scanner-live' || {
  docker rm -f "$LIVE_CID" >/dev/null 2>&1 || true
  die "briar-live worker not attached to pen-scanner-live"
}
LIVE_FIX="$(docker exec "$LIVE_CID" python -c 'import socket
s=socket.create_connection(("fixture-headers",8080), timeout=5)
s.close()
print("BRIAR_LIVE_REACHES_FIXTURE")
' 2>&1)"
echo "$LIVE_FIX"
echo "$LIVE_FIX" | grep -q 'BRIAR_LIVE_REACHES_FIXTURE' || {
  docker rm -f "$LIVE_CID" >/dev/null 2>&1 || true
  die "briar-live worker could not reach fixture-headers"
}
# Private/link-local style destinations must still be blocked by policy at launch;
# at the network layer, prove the live worker is NOT on the isolated-only network.
echo "$LIVE_NETWORKS" | grep -Eq 'pen-scanner-isolated' && {
  docker rm -f "$LIVE_CID" >/dev/null 2>&1 || true
  die "briar-live unexpectedly also on pen-scanner-isolated"
}
docker rm -f "$LIVE_CID" >/dev/null 2>&1 || true

log "== runtime: adapter dry-run plans compose argv (worker path) =="
export PEN_COMPOSE_DIR="$ROOT"
export PEN_BRIAR_EXEC=compose
python3 - <<'PY'
from pathlib import Path
from core.config import PlatformConfig
from core.scope import AuthorizationRecord, ScopeEngine
from integrations.base import AdapterRequest
from integrations.briar import BriarAdapter

url = "http://fixture-headers:8080/"
scope = ScopeEngine([
    AuthorizationRecord(
        program_name="t",
        program_url="https://example.invalid",
        target_id="t",
        asset_type="url",
        scope_source="test",
        policy_reference="t",
        allowed_assets=[url],
        allowed_test_categories=["active", "passive", "dast"],
        environment="local",
    )
])
cfg = PlatformConfig(reports_dir=Path("reports/out"))
adapter = BriarAdapter(cfg, scope)
result = adapter.run(AdapterRequest(target=url, mode="quick", dry_run=True))
assert result.status == "skipped", result
cmd = result.artifacts.get("planned_command", "")
assert "docker compose" in cmd, cmd
assert "briar-live" in cmd, cmd
assert "pen-scanner" not in cmd  # network is via compose service attachment
print("ADAPTER_PLANS_COMPOSE_BRIAR_LIVE")
print(cmd)
PY

log "== host smoke script (no external targets) =="
bash scripts/smoke.sh

log "== isolation unit tests (must not be skipped) =="
python3 -m pytest -q tests/unit/test_scanner_isolation.py
test -f tests/unit/test_scanner_isolation.py || die "isolation tests missing"

log "Docker runtime verification passed."
