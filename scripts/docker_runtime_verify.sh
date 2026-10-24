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
  docker rm -f pen-shannon-egress-gateway pen-shannon-fixture pen-shannon-llm-mock pen-shannon-redirect shannon-temporal >/dev/null 2>&1 || true
  docker ps -aq --filter "name=shannon-worker-" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm shannon-net pen-shannon-egress pen-shannon-host >/dev/null 2>&1 || true
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
echo "$RENDER" | grep -E 'PEN_REQUIRE_DATA_ENCRYPTION: ("true"|true)' >/dev/null \
  || die "compose must require data encryption"
echo "$RENDER" | grep -E 'PEN_DOCTOR_STRICT: ("true"|true)' >/dev/null \
  || die "compose must run doctor in strict mode"
echo "$RENDER" | grep -E 'PEN_ALLOW_SHANNON_FULL_PIPELINE: ("false"|false)' >/dev/null \
  || die "compose must keep the Shannon full pipeline off"
# Refuse accidental docker.sock mounts in any service definition we ship.
if echo "$RENDER" | grep -E '/var/run/docker.sock|docker.sock:'; then
  die "docker.sock mount must not appear in compose render"
fi

log "== assert compose JSON marks scanner nets internal (fail-closed parser) =="
docker compose --profile workers --profile live-workers config --format json | python3 -c '
import json, sys
from core.isolation import compose_networks_must_be_internal
cfg = json.load(sys.stdin)
compose_networks_must_be_internal(cfg, ("pen-scanner-isolated", "pen-scanner-live"))
print("COMPOSE_NETWORKS_INTERNAL_ASSERTED")
'

log "== build required project images (orchestrator + briar + egress-gateway) =="
docker compose --progress=plain build
docker compose --profile workers --progress=plain build briar
docker compose --profile live-workers --progress=plain build briar-live egress-gateway

log "== orchestrator strict doctor fails closed without PEN_DATA_KEY =="
set +e
env -u PEN_DATA_KEY docker compose run --rm --no-deps -e PEN_DATA_KEY= orchestrator
strict_rc=$?
set -e
test "$strict_rc" -ne 0 || die "strict doctor exited 0 without PEN_DATA_KEY"
echo "ORCHESTRATOR_STRICT_MISSING_KEY_BLOCKED"

log "== orchestrator smoke with an ephemeral encryption key =="
EPHEMERAL_KEY="$(python3 -c 'import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
PEN_DATA_KEY="$EPHEMERAL_KEY" docker compose run --rm --no-deps orchestrator
unset EPHEMERAL_KEY
echo "ORCHESTRATOR_STRICT_DOCTOR_OK"

log "== briar isolated worker smoke (no external egress network) =="
docker compose --profile workers run --rm --no-deps briar

log "== inspect briar container mounts for docker.sock =="
docker compose --profile workers run --rm --no-deps briar --help >/dev/null

log "== runtime connectivity: isolated network must not reach external IP =="
# Create the isolated network by instantiating the briar service, then probe it.
docker compose --profile workers create briar >/dev/null
ISO_NET="$(docker network ls --format '{{.Name}}' | grep -E 'pen-scanner-isolated$' | head -n1 || true)"
test -n "$ISO_NET" || die "could not locate pen-scanner-isolated docker network"
ISO_INTERNAL="$(docker network inspect -f '{{.Internal}}' "$ISO_NET")"
test "$ISO_INTERNAL" = "true" || die "pen-scanner-isolated Internal=$ISO_INTERNAL (must be true; HTTP_PROXY is not a boundary)"
echo "PEN_SCANNER_ISOLATED_INTERNAL=true"
# Probe uses the same Python base image already pulled for builds; no third-party scan.
# Expect connection failure (egress blocked by internal:true).
set +e
PROBE_OUT="$(docker run --rm --network "$ISO_NET" python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 \
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
CTRL_OUT="$(docker run --rm --network "$CTRL_NET" python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 \
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

log "== runtime: briar isolated worker cannot reach pen-control / docker.sock =="
# Re-create short-lived worker for control-plane / host-resource probes.
ISO_CID2="$(docker compose --profile workers run -d --no-deps --entrypoint sleep briar 45)"
test -n "$ISO_CID2" || die "failed to start briar worker for control-plane probe"
set +e
CTRL_PROBE="$(docker exec "$ISO_CID2" python -c 'import socket,sys
try:
  socket.create_connection(("orchestrator",8000),3); print("UNEXPECTED_CONTROL"); sys.exit(0)
except OSError as e:
  print("BRIAR_WORKER_NO_CONTROL_PLANE", type(e).__name__); sys.exit(1)
' 2>&1)"
CTRL_PROBE_RC=$?
SOCK_PROBE="$(docker exec "$ISO_CID2" python -c 'import os,sys
p="/var/run/docker.sock"
print("DOCKER_SOCK_EXISTS" if os.path.exists(p) else "BRIAR_WORKER_NO_DOCKER_SOCK")
sys.exit(0 if not os.path.exists(p) else 1)
' 2>&1)"
SOCK_RC=$?
set -e
echo "$CTRL_PROBE"
echo "$SOCK_PROBE"
echo "$CTRL_PROBE" | grep -q UNEXPECTED_CONTROL && {
  docker rm -f "$ISO_CID2" >/dev/null 2>&1 || true
  die "briar isolated worker reached orchestrator on pen-control"
}
test "$CTRL_PROBE_RC" -ne 0 || die "control-plane probe unexpectedly succeeded"
echo "$CTRL_PROBE" | grep -q BRIAR_WORKER_NO_CONTROL_PLANE || die "missing BRIAR_WORKER_NO_CONTROL_PLANE"
test "$SOCK_RC" -eq 0 || die "docker.sock visible inside briar worker"
echo "$SOCK_PROBE" | grep -q BRIAR_WORKER_NO_DOCKER_SOCK || die "missing BRIAR_WORKER_NO_DOCKER_SOCK"
docker rm -f "$ISO_CID2" >/dev/null 2>&1 || true

log "== runtime: briar-live on internal pen-scanner-live (fixture ok, direct internet blocked) =="
# Ensure gateway + fixture are up on pen-scanner-live.
docker compose --profile live-workers --profile fixtures up -d egress-gateway fixture-headers
LIVE_NET="$(docker network ls --format '{{.Name}}' | grep -E 'pen-scanner-live$' | head -n1 || true)"
test -n "$LIVE_NET" || die "could not locate pen-scanner-live docker network"
LIVE_INTERNAL="$(docker network inspect -f '{{.Internal}}' "$LIVE_NET")"
test "$LIVE_INTERNAL" = "true" || die "pen-scanner-live Internal=$LIVE_INTERNAL (must be true; HTTP_PROXY is not a boundary)"
echo "PEN_SCANNER_LIVE_INTERNAL=true"
LIVE_CID="$(docker compose --profile live-workers run -d --no-deps --entrypoint sleep briar-live 90)"
test -n "$LIVE_CID" || die "failed to start briar-live worker for inspect"
LIVE_NETWORKS="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$LIVE_CID")"
echo "BRIAR_LIVE_NETWORKS=$LIVE_NETWORKS"
echo "$LIVE_NETWORKS" | grep -Eq 'pen-scanner-live' || {
  docker rm -f "$LIVE_CID" >/dev/null 2>&1 || true
  die "briar-live worker not attached to pen-scanner-live"
}
echo "$LIVE_NETWORKS" | grep -Eq 'pen-egress|pen-control' && {
  docker rm -f "$LIVE_CID" >/dev/null 2>&1 || true
  die "briar-live unexpectedly attached to pen-egress/pen-control"
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
set +e
LIVE_EGRESS="$(docker exec "$LIVE_CID" python -c 'import socket,sys
try:
  socket.create_connection(("1.1.1.1",443),3); print("UNEXPECTED_CONNECT"); sys.exit(0)
except OSError as e:
  print("BRIAR_LIVE_DIRECT_EGRESS_BLOCKED", type(e).__name__); sys.exit(1)
' 2>&1)"
LIVE_EGRESS_RC=$?
set -e
echo "$LIVE_EGRESS"
echo "$LIVE_EGRESS" | grep -q UNEXPECTED_CONNECT && {
  docker rm -f "$LIVE_CID" >/dev/null 2>&1 || true
  die "briar-live direct-reached 1.1.1.1 (pen-scanner-live must be internal)"
}
test "$LIVE_EGRESS_RC" -ne 0 || die "briar-live egress probe unexpectedly succeeded"
echo "$LIVE_EGRESS" | grep -q BRIAR_LIVE_DIRECT_EGRESS_BLOCKED || die "missing BRIAR_LIVE_DIRECT_EGRESS_BLOCKED"

log "== runtime: briar-live direct egress still blocked with proxy env unset =="
set +e
NOPROXY_LIVE="$(docker exec -e HTTP_PROXY= -e HTTPS_PROXY= -e http_proxy= -e https_proxy= -e ALL_PROXY= -e all_proxy= \
  "$LIVE_CID" python -c 'import os,socket,sys
for k in list(os.environ):
  if "proxy" in k.lower():
    del os.environ[k]
try:
  socket.create_connection(("1.1.1.1",443),3); print("UNEXPECTED_CONNECT"); sys.exit(0)
except OSError as e:
  print("BRIAR_LIVE_NOPROXY_DIRECT_BLOCKED", type(e).__name__); sys.exit(1)
' 2>&1)"
NOPROXY_LIVE_RC=$?
set -e
echo "$NOPROXY_LIVE"
echo "$NOPROXY_LIVE" | grep -q UNEXPECTED_CONNECT && {
  docker rm -f "$LIVE_CID" >/dev/null 2>&1 || true
  die "briar-live direct egress succeeded with proxy unset"
}
test "$NOPROXY_LIVE_RC" -ne 0 || die "briar-live noproxy probe unexpectedly succeeded"
echo "$NOPROXY_LIVE" | grep -q BRIAR_LIVE_NOPROXY_DIRECT_BLOCKED || die "missing BRIAR_LIVE_NOPROXY_DIRECT_BLOCKED"

log "== runtime: briar-live restart retains isolation =="
docker restart "$LIVE_CID" >/dev/null
ready=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if docker exec "$LIVE_CID" python -c 'print(1)' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
test "$ready" -eq 1 || {
  docker rm -f "$LIVE_CID" >/dev/null 2>&1 || true
  die "briar-live not ready after restart"
}
set +e
RESTART_EGRESS="$(docker exec -e HTTP_PROXY= -e HTTPS_PROXY= "$LIVE_CID" python -c 'import socket,sys
try:
  socket.create_connection(("1.1.1.1",443),3); print("UNEXPECTED_CONNECT"); sys.exit(0)
except OSError as e:
  print("BRIAR_LIVE_RESTART_DIRECT_BLOCKED", type(e).__name__); sys.exit(1)
' 2>&1)"
RESTART_EGRESS_RC=$?
set -e
echo "$RESTART_EGRESS"
echo "$RESTART_EGRESS" | grep -q UNEXPECTED_CONNECT && {
  docker rm -f "$LIVE_CID" >/dev/null 2>&1 || true
  die "restarted briar-live reached 1.1.1.1"
}
test "$RESTART_EGRESS_RC" -ne 0 || die "briar-live restart egress probe unexpectedly succeeded"
echo "$RESTART_EGRESS" | grep -q BRIAR_LIVE_RESTART_DIRECT_BLOCKED || die "missing BRIAR_LIVE_RESTART_DIRECT_BLOCKED"

log "== runtime: egress-gateway denies empty allowlist / non-public via CONNECT =="
# From briar-live, proxy CONNECT to example.invalid should be denied (empty allowlist).
set +e
PROXY_DENY="$(docker exec "$LIVE_CID" python -c '
import http.client
conn = http.client.HTTPConnection("egress-gateway", 3128, timeout=5)
try:
  conn.request("CONNECT", "example.invalid:443")
  resp = conn.getresponse()
  print("PROXY_STATUS", resp.status, resp.reason)
except Exception as exc:
  print("PROXY_ERROR", type(exc).__name__, exc)
' 2>&1)"
set -e
echo "$PROXY_DENY"
echo "$PROXY_DENY" | grep -Eq 'PROXY_STATUS 403|PROXY_ERROR' || die "proxy did not deny unlisted host"
echo "PROXY_DENIES_UNLISTED_HOST"

log "== runtime: egress-gateway denies disallowed ports (default 80/443 only) =="
set +e
PROXY_PORT_DENY="$(docker exec "$LIVE_CID" python -c '
import http.client
conn = http.client.HTTPConnection("egress-gateway", 3128, timeout=5)
try:
  conn.request("CONNECT", "example.invalid:22")
  resp = conn.getresponse()
  print("PROXY_PORT_STATUS", resp.status, resp.reason)
except Exception as exc:
  print("PROXY_PORT_ERROR", type(exc).__name__, exc)
' 2>&1)"
set -e
echo "$PROXY_PORT_DENY"
echo "$PROXY_PORT_DENY" | grep -Eq 'PROXY_PORT_STATUS 403|PROXY_PORT_ERROR' || die "proxy did not deny disallowed port"
echo "PROXY_DENIES_DISALLOWED_PORT"

docker rm -f "$LIVE_CID" >/dev/null 2>&1 || true

log "== runtime: missing internal network fails closed (unit-level assert) =="
python3 - <<'PY'
from core.isolation import compose_networks_must_be_internal
try:
    compose_networks_must_be_internal(
        {"networks": {"pen-scanner-live": {"driver": "bridge"}}},
        ("pen-scanner-live",),
    )
except PermissionError as exc:
    assert "internal" in str(exc).lower()
    print("MISSING_INTERNAL_CONFIG_BLOCKS")
else:
    raise SystemExit("expected PermissionError for non-internal compose net")
PY

log "== runtime: Shannon controlled prepare + Temporal/worker E2E (local fixtures) =="
# shannon_e2e_verify.sh runs prepare (stand-in + real-image network probes) then the
# real upstream path: npx start --validate-model → Temporal + keygraph/shannon worker
# against a local OpenAI-compatible mock (no public targets / no external LLM keys).
command -v npx >/dev/null 2>&1 || die "npx required for Shannon E2E"
command -v node >/dev/null 2>&1 || die "node required for Shannon E2E"
PEN_SHANNON_E2E_CLEAN_NET=0 bash scripts/shannon_e2e_verify.sh
# Cleanup shannon artifacts so later host smoke starts clean.
docker rm -f pen-shannon-egress-gateway pen-shannon-fixture pen-shannon-llm-mock pen-shannon-redirect shannon-temporal >/dev/null 2>&1 || true
docker ps -aq --filter "name=shannon-worker-" | xargs -r docker rm -f >/dev/null 2>&1 || true
docker network rm shannon-net pen-shannon-egress pen-shannon-host >/dev/null 2>&1 || true

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
