#!/usr/bin/env bash
# Controlled Shannon Temporal + real worker E2E (local fixtures only).
#
# Exercises the REAL upstream path:
#   npx @keygraph/shannon start --validate-model
#   → Temporal (shannon-temporal on shannon-net)
#   → keygraph/shannon worker container on shannon-net
#   → local OpenAI-compatible mock (no third-party LLM / no public targets)
#
# Distinguishes:
#   SHANNON_E2E_*          = full Temporal/worker path markers
#   SHANNON_NET_*          = stand-in / prepare probes (not full E2E)
#   SHANNON_REAL_WORKER_*  = real-image network probes without Temporal
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

NET_NAME="${PEN_SHANNON_NET_NAME:-shannon-net}"
FIXTURE_NAME="${PEN_SHANNON_FIXTURE_NAME:-pen-shannon-fixture}"
LLM_NAME="${PEN_SHANNON_LLM_MOCK_NAME:-pen-shannon-llm-mock}"
REDIR_NAME="${PEN_SHANNON_REDIRECT_NAME:-pen-shannon-redirect}"
SHANNON_IMAGE="${PEN_SHANNON_WORKER_IMAGE:-keygraph/shannon:3.4.0@sha256:4e726ed8f3a0b10e2a1dbb41185a526f20ea6fccc98740ca553e3c00c2a6bd0e}"
SHANNON_PKG="${PEN_SHANNON_PACKAGE:-@keygraph/shannon@3.4.0}"
E2E_TIMEOUT="${PEN_SHANNON_E2E_TIMEOUT:-420}"

cleanup() {
  log "== shannon e2e cleanup =="
  docker rm -f "$FIXTURE_NAME" "$LLM_NAME" "$REDIR_NAME" >/dev/null 2>&1 || true
  # Do not remove shannon-net here when called from docker_runtime_verify (shared cleanup).
  if [[ "${PEN_SHANNON_E2E_CLEAN_NET:-0}" == "1" ]]; then
    docker rm -f pen-shannon-egress-gateway shannon-temporal >/dev/null 2>&1 || true
    docker ps -aq --filter "name=shannon-worker-" | xargs -r docker rm -f >/dev/null 2>&1 || true
    docker network rm shannon-net pen-shannon-egress pen-shannon-host >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || die "docker required"
command -v npx >/dev/null 2>&1 || die "npx required"
command -v node >/dev/null 2>&1 || die "node required"
docker info >/dev/null || die "docker daemon not usable"

log "== prepare controlled shannon-net (Internal=true + gateway) =="
bash scripts/shannon_net_prepare.sh

INTERNAL="$(docker network inspect -f '{{.Internal}}' "$NET_NAME")"
test "$INTERNAL" = "true" || die "shannon-net Internal=$INTERNAL (must be true)"

log "== stage docker wrap shim (named docker) =="
WRAP_BIN="$ROOT/scripts/.shannon-docker-bin"
mkdir -p "$WRAP_BIN"
ln -sfn "$ROOT/scripts/shannon-docker-wrap" "$WRAP_BIN/docker"
test -x "$WRAP_BIN/docker" || test -L "$WRAP_BIN/docker" || die "docker wrap shim missing"
# Resolve the real docker binary before prepending the wrap shim to PATH.
PEN_REAL_DOCKER=""
while IFS= read -r candidate; do
  [[ -n "$candidate" && -x "$candidate" && "$candidate" != "$WRAP_BIN/docker" ]] || continue
  # Skip if the candidate resolves to our wrap script.
  resolved="$(readlink -f "$candidate" 2>/dev/null || echo "$candidate")"
  wrap_resolved="$(readlink -f "$WRAP_BIN/docker" 2>/dev/null || echo "$WRAP_BIN/docker")"
  [[ "$resolved" == "$wrap_resolved" ]] && continue
  PEN_REAL_DOCKER="$candidate"
  break
done < <(type -aP docker 2>/dev/null || true)
if [[ -z "$PEN_REAL_DOCKER" ]]; then
  for candidate in /usr/bin/docker /usr/local/bin/docker; do
    if [[ -x "$candidate" ]]; then
      PEN_REAL_DOCKER="$candidate"
      break
    fi
  done
fi
test -n "$PEN_REAL_DOCKER" || die "could not locate real docker for PEN_REAL_DOCKER"
export PEN_REAL_DOCKER
export PATH="$WRAP_BIN:$PATH"
# Prove wrap shim is first on PATH and runnable.
command -v docker | grep -q '.shannon-docker-bin/docker' || die "wrap docker not first on PATH"
WRAP_PROBE="$(docker run --help 2>&1 | head -n1 || true)"
test -n "$WRAP_PROBE" || die "wrap docker shim failed"
echo "SHANNON_E2E_DOCKER_WRAP_ACTIVE real=$PEN_REAL_DOCKER"

log "== start on-net authorized fixture + redirect + LLM mock =="
docker rm -f "$FIXTURE_NAME" "$LLM_NAME" "$REDIR_NAME" >/dev/null 2>&1 || true
docker run -d --name "$FIXTURE_NAME" --network "$NET_NAME" --network-alias fixture-shannon \
  -v "$ROOT/tests/fixtures/headers_server.py:/app/headers_server.py:ro" \
  --read-only --tmpfs /tmp \
  python:3.12.15-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d \
  python /app/headers_server.py 8080 >/dev/null
docker run -d --name "$REDIR_NAME" --network "$NET_NAME" --network-alias shannon-redirect \
  -v "$ROOT/tests/fixtures/redirect_server.py:/app/redirect_server.py:ro" \
  --read-only --tmpfs /tmp \
  python:3.12.15-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d \
  python /app/redirect_server.py 8081 >/dev/null
docker run -d --name "$LLM_NAME" --network "$NET_NAME" --network-alias shannon-llm-mock \
  -v "$ROOT/tests/fixtures/llm_mock_server.py:/app/llm_mock_server.py:ro" \
  --read-only --tmpfs /tmp \
  python:3.12.15-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d \
  python /app/llm_mock_server.py 8080 >/dev/null

ready=0
for _ in $(seq 1 30); do
  if docker exec "$FIXTURE_NAME" python -c 'import socket;s=socket.create_connection(("127.0.0.1",8080),2);s.close()' \
    && docker exec "$LLM_NAME" python -c 'import socket;s=socket.create_connection(("127.0.0.1",8080),2);s.close()' \
    && docker exec "$REDIR_NAME" python -c 'import socket;s=socket.create_connection(("127.0.0.1",8081),2);s.close()'; then
    ready=1
    break
  fi
  sleep 1
done
test "$ready" -eq 1 || die "shannon on-net fixtures not ready"

FIXTURE_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$FIXTURE_NAME")"
test -n "$FIXTURE_IP" || die "fixture IP missing"
TARGET_URL="http://${FIXTURE_IP}:8080/"
echo "SHANNON_E2E_FIXTURE_TARGET $TARGET_URL"

log "== prove fixture reachable / prohibited unreachable from shannon-net (pre-assessment) =="
docker run --rm --network "$NET_NAME" python:3.12.15-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d \
  python -c "import socket;s=socket.create_connection(('$FIXTURE_IP',8080),5);s.close();print('SHANNON_E2E_FIXTURE_REACHABLE')"
docker run --rm --network "$NET_NAME" python:3.12.15-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d \
  python -c "import socket;s=socket.create_connection(('shannon-llm-mock',8080),5);s.close();print('SHANNON_E2E_LLM_MOCK_REACHABLE')"
set +e
PROHIBITED="$(docker run --rm --network "$NET_NAME" \
  -e HTTP_PROXY= -e HTTPS_PROXY= -e http_proxy= -e https_proxy= \
  python:3.12.15-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d \
  python -c 'import os,socket,sys
for k in list(os.environ):
  if "proxy" in k.lower(): del os.environ[k]
try:
  socket.create_connection(("1.1.1.1",443),3); print("UNEXPECTED_CONNECT"); sys.exit(0)
except OSError as e:
  print("SHANNON_E2E_PROHIBITED_BLOCKED", type(e).__name__); sys.exit(1)
' 2>&1)"
PROHIBITED_RC=$?
set -e
echo "$PROHIBITED"
echo "$PROHIBITED" | grep -q UNEXPECTED_CONNECT && die "prohibited destination reachable with proxy unset"
test "$PROHIBITED_RC" -ne 0 || die "prohibited probe unexpectedly succeeded"
echo "$PROHIBITED" | grep -q SHANNON_E2E_PROHIBITED_BLOCKED || die "missing SHANNON_E2E_PROHIBITED_BLOCKED"

log "== prove redirect-to-prohibited cannot complete from shannon-net =="
set +e
REDIR_PROBE="$(docker run --rm --network "$NET_NAME" python:3.12.15-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d \
  python -c '
import http.client, socket, sys
conn = http.client.HTTPConnection("shannon-redirect", 8081, timeout=5)
conn.request("GET", "/")
resp = conn.getresponse()
loc = resp.getheader("Location") or ""
print("SHANNON_E2E_REDIRECT_LOCATION", loc)
if "1.1.1.1" not in loc:
    print("UNEXPECTED_REDIRECT_TARGET"); sys.exit(2)
try:
    socket.create_connection(("1.1.1.1", 80), 3)
    print("UNEXPECTED_CONNECT"); sys.exit(0)
except OSError as e:
    print("SHANNON_E2E_REDIRECT_FOLLOW_BLOCKED", type(e).__name__); sys.exit(1)
' 2>&1)"
REDIR_RC=$?
set -e
echo "$REDIR_PROBE"
echo "$REDIR_PROBE" | grep -q SHANNON_E2E_REDIRECT_LOCATION || die "redirect fixture did not respond"
echo "$REDIR_PROBE" | grep -q UNEXPECTED_CONNECT && die "redirect follow reached 1.1.1.1"
test "$REDIR_RC" -ne 0 || die "redirect follow unexpectedly succeeded"
echo "$REDIR_PROBE" | grep -q SHANNON_E2E_REDIRECT_FOLLOW_BLOCKED || die "missing SHANNON_E2E_REDIRECT_FOLLOW_BLOCKED"

log "== prove DNS to external name fails closed on internal net =="
set +e
DNS_PROBE="$(docker run --rm --network "$NET_NAME" python:3.12.15-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d \
  python -c '
import socket,sys
try:
  socket.getaddrinfo("example.invalid", 443)
  # Even if embedded DNS returns something, connect must fail for public IPs.
  socket.create_connection(("1.0.0.1",443),3)
  print("UNEXPECTED_CONNECT"); sys.exit(0)
except OSError as e:
  print("SHANNON_E2E_DNS_OR_CONNECT_BLOCKED", type(e).__name__); sys.exit(1)
' 2>&1)"
DNS_RC=$?
set -e
echo "$DNS_PROBE"
echo "$DNS_PROBE" | grep -q UNEXPECTED_CONNECT && die "external DNS/connect succeeded on internal net"
test "$DNS_RC" -ne 0 || die "dns probe unexpectedly succeeded"
echo "$DNS_PROBE" | grep -q SHANNON_E2E_DNS_OR_CONNECT_BLOCKED || die "missing SHANNON_E2E_DNS_OR_CONNECT_BLOCKED"

log "== fail-closed: missing internal network blocks live adapter path =="
python3 - <<'PY'
from core.isolation import compose_networks_must_be_internal
try:
    compose_networks_must_be_internal({"networks": {"shannon-net": {"driver": "bridge"}}}, ("shannon-net",))
except PermissionError:
    print("SHANNON_E2E_MISSING_INTERNAL_CONFIG_BLOCKS")
else:
    raise SystemExit("expected PermissionError")
PY

log "== run REAL Shannon Temporal + worker --validate-model against local mock =="
REPO_DIR="$ROOT/tests/fixtures/shannon_repo"
mkdir -p "$REPO_DIR"
echo "# shannon e2e fixture repo" > "$REPO_DIR/README.md"
OUT_DIR="$ROOT/reports/shannon-e2e-$$"
mkdir -p "$OUT_DIR"

# Scope authorizes the on-net fixture IP literal (launch gate). Network isolation
# remains the worker boundary; we do NOT disable egress dual-gate.
export PEN_ALLOW_SHANNON_LIVE=1
unset PEN_ALLOW_SHANNON_UNCONTAINED_NET || true
export PEN_REQUIRE_EGRESS_POLICY=true
unset PEN_ALLOW_EGRESS_DISABLE || true
export PEN_REQUIRE_SCOPE=true
unset PEN_ALLOW_SCOPE_DISABLE || true
# Custom pi catalogue entry (tests/fixtures/shannon_models.json) — not a cloud provider.
export SHANNON_AI_MODEL="shannon-mock:gpt-test"
export SHANNON_AI_API_KEY="test-fixture-key-not-a-secret"
unset SHANNON_AI_BASE_URL || true
unset OPENAI_API_KEY || true
unset ANTHROPIC_API_KEY || true
export PEN_SHANNON_NO_PROXY="egress-gateway,shannon-temporal,fixture-shannon,shannon-llm-mock,shannon-redirect,${FIXTURE_IP},localhost,127.0.0.1,::1"
MODELS_CONFIG="$ROOT/tests/fixtures/shannon_models.json"
test -f "$MODELS_CONFIG" || die "missing $MODELS_CONFIG"

# Adapter stages its own wrap shim and must see the real engine docker via
# PEN_REAL_DOCKER / PATH resolution — keep WRAP_BIN on PATH but pin real binary.
export PATH="$WRAP_BIN:$PATH"
export PEN_REAL_DOCKER

set +e
TARGET_URL="$TARGET_URL" REPO_DIR="$REPO_DIR" OUT_DIR="$OUT_DIR" E2E_TIMEOUT="$E2E_TIMEOUT" \
MODELS_CONFIG="$MODELS_CONFIG" PEN_REAL_DOCKER="$PEN_REAL_DOCKER" \
python3 - <<'PY'
import os
import sys
from pathlib import Path

from core.config import PlatformConfig
from core.scope import AuthorizationRecord, ScopeEngine
from integrations.base import AdapterRequest
from integrations.shannon import ShannonAdapter

target = os.environ["TARGET_URL"]
repo = Path(os.environ["REPO_DIR"])
out = Path(os.environ["OUT_DIR"])
timeout = int(os.environ["E2E_TIMEOUT"])
models_config = os.environ["MODELS_CONFIG"]
scope = ScopeEngine([
    AuthorizationRecord(
        program_name="shannon-e2e",
        program_url="https://example.invalid",
        target_id="fixture",
        asset_type="url",
        scope_source="test",
        policy_reference="shannon-e2e",
        allowed_assets=[target],
        allowed_test_categories=["active", "passive", "dast"],
        environment="local",
    )
])
cfg = PlatformConfig(reports_dir=out)
adapter = ShannonAdapter(cfg, scope)
result = adapter.run(
    AdapterRequest(
        target=target,
        repo_path=str(repo),
        output_dir=str(out),
        dry_run=False,
        timeout_seconds=timeout,
        extra={
            "validate_model": True,
            "models_config": models_config,
            # Retain worker briefly for diagnostics when validation fails.
            "keep_container": True,
        },
    )
)
print("SHANNON_E2E_ADAPTER_STATUS", result.status)
print("SHANNON_E2E_NETWORK_MODE", (result.metadata or {}).get("network_mode"))
if (result.metadata or {}).get("network_mode") != "controlled":
    print("SHANNON_E2E_UNEXPECTED_NETWORK_MODE")
    sys.exit(2)
if result.error:
    print("SHANNON_E2E_ADAPTER_ERROR", (result.error or "")[:1200])
combined = "\n".join([*(result.logs or []), result.error or "", result.status or ""])
for line in (result.logs or []):
    if line:
        print(line[-2500:])
validation_completed = (
    "Validation COMPLETED" in combined
    and "Status:      completed" in combined
    and "Preflight (LLM credentials, target URL) — OK" in combined
)
reconnect_error = "Could not read the scan outcome from Temporal" in combined
if validation_completed:
    print("SHANNON_E2E_VALIDATION_COMPLETED")
if reconnect_error:
    # Dual-home Temporal should prevent this; do NOT treat as success.
    print("SHANNON_E2E_TEMPORAL_HOST_RECONNECT_FAILURE")
# Require a clean CLI success. Validation strings alone are insufficient.
ok = result.status == "succeeded" and not reconnect_error
sys.exit(0 if ok else 1)
PY
ADAPTER_RC=$?
set -e

# Collect Temporal / worker evidence regardless of adapter exit.
TEMPORAL_STATE="$(docker inspect -f '{{.State.Status}}' shannon-temporal 2>/dev/null || echo missing)"
echo "SHANNON_E2E_TEMPORAL_STATE $TEMPORAL_STATE"
WORKER_IDS="$(docker ps -aq --filter name=shannon-worker- || true)"
echo "SHANNON_E2E_WORKER_CONTAINERS ${WORKER_IDS:-none}"

# Regression: host Temporal gRPC must remain reachable after the run (dual-home proof).
log "== temporal host endpoint readiness (post-run regression) =="
bash scripts/shannon_temporal_host_ready.sh
echo "SHANNON_E2E_TEMPORAL_HOST_READY_AFTER"

# Worker must be on shannon-net only — never pen-shannon-host / pen-shannon-egress.
if [[ -n "${WORKER_IDS}" && "${WORKER_IDS}" != "none" ]]; then
  for wid in $WORKER_IDS; do
    WNETS="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$wid" 2>/dev/null || true)"
    echo "SHANNON_E2E_WORKER_NETWORKS id=$wid nets=$WNETS"
    echo "$WNETS" | grep -Eq 'shannon-net' || die "worker $wid not on shannon-net"
    echo "$WNETS" | grep -Eq 'pen-shannon-host|pen-shannon-egress|pen-control' && \
      die "worker $wid attached to prohibited network"
  done
  echo "SHANNON_E2E_WORKER_NET_ISOLATED"
fi

# Mock LLM must have served at least one completion (real Temporal path used the mock).
MOCK_LOGS="$(docker logs "$LLM_NAME" 2>&1 || true)"
echo "$MOCK_LOGS" | grep -q 'POST /v1/chat/completions' || die "LLM mock received no chat completions"
echo "SHANNON_E2E_LLM_MOCK_SERVED"

if [[ "$ADAPTER_RC" -ne 0 ]]; then
  echo "SHANNON_E2E_LLM_MOCK_LOGS_BEGIN"
  echo "$MOCK_LOGS" | tail -n 80 || true
  echo "SHANNON_E2E_LLM_MOCK_LOGS_END"
  echo "SHANNON_E2E_TEMPORAL_LOGS_BEGIN"
  docker logs shannon-temporal 2>&1 | tail -n 40 || true
  echo "SHANNON_E2E_TEMPORAL_LOGS_END"
fi

if [[ "$TEMPORAL_STATE" == "running" ]]; then
  echo "SHANNON_E2E_TEMPORAL_RUNNING"
else
  die "shannon-temporal not running after validate-model (state=$TEMPORAL_STATE)"
fi

# During/after assessment: probe from a real Shannon worker image on shannon-net.
log "== post-path isolation on real Shannon worker image (proxy unset) =="
set +e
REAL_POST="$(docker run --rm --network "$NET_NAME" --entrypoint node \
  -e HTTP_PROXY= -e HTTPS_PROXY= -e http_proxy= -e https_proxy= \
  "$SHANNON_IMAGE" -e '
const net = require("net");
const s = net.connect({host:"1.1.1.1", port:443, timeout:3000}, () => {
  console.log("UNEXPECTED_CONNECT"); process.exit(0);
});
s.on("error", (e) => { console.log("SHANNON_E2E_REAL_WORKER_PROHIBITED_BLOCKED", e.code || e.message); process.exit(1); });
setTimeout(() => { console.log("SHANNON_E2E_REAL_WORKER_PROHIBITED_BLOCKED", "TIMEOUT"); process.exit(1); }, 3500);
' 2>&1)"
REAL_POST_RC=$?
set -e
echo "$REAL_POST"
echo "$REAL_POST" | grep -q UNEXPECTED_CONNECT && die "real worker reached prohibited destination"
test "$REAL_POST_RC" -ne 0 || die "real worker prohibited probe unexpectedly succeeded"
echo "$REAL_POST" | grep -q SHANNON_E2E_REAL_WORKER_PROHIBITED_BLOCKED || die "missing SHANNON_E2E_REAL_WORKER_PROHIBITED_BLOCKED"

log "== restart retention on real Shannon worker keep-alive =="
REAL_CID="$(docker run -d --network "$NET_NAME" --entrypoint node "$SHANNON_IMAGE" -e 'setInterval(()=>{},1e3); setTimeout(()=>process.exit(0),90000)')"
docker restart "$REAL_CID" >/dev/null
ready=0
for _ in $(seq 1 15); do
  if docker exec "$REAL_CID" node -e 'process.exit(0)' >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
test "$ready" -eq 1 || die "restarted real worker not ready"
set +e
RESTART_PROBE="$(docker exec -e HTTP_PROXY= -e HTTPS_PROXY= "$REAL_CID" node -e '
const net = require("net");
const s = net.connect({host:"1.1.1.1", port:443, timeout:3000}, () => {
  console.log("UNEXPECTED_CONNECT"); process.exit(0);
});
s.on("error", (e) => { console.log("SHANNON_E2E_RESTART_PROHIBITED_BLOCKED", e.code || e.message); process.exit(1); });
setTimeout(() => { console.log("SHANNON_E2E_RESTART_PROHIBITED_BLOCKED", "TIMEOUT"); process.exit(1); }, 3500);
' 2>&1)"
RESTART_RC=$?
set -e
echo "$RESTART_PROBE"
docker rm -f "$REAL_CID" >/dev/null 2>&1 || true
echo "$RESTART_PROBE" | grep -q UNEXPECTED_CONNECT && die "restarted worker reached prohibited destination"
test "$RESTART_RC" -ne 0 || die "restart probe unexpectedly succeeded"
echo "$RESTART_PROBE" | grep -q SHANNON_E2E_RESTART_PROHIBITED_BLOCKED || die "missing SHANNON_E2E_RESTART_PROHIBITED_BLOCKED"

# Fixture still reachable after assessment activity.
docker run --rm --network "$NET_NAME" python:3.12.15-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d \
  python -c "import socket;s=socket.create_connection(('$FIXTURE_IP',8080),5);s.close();print('SHANNON_E2E_FIXTURE_STILL_REACHABLE')"

if [[ "$ADAPTER_RC" -ne 0 ]]; then
  die "Shannon adapter --validate-model E2E failed (rc=$ADAPTER_RC). See $OUT_DIR"
fi
echo "SHANNON_E2E_VALIDATE_MODEL_SUCCEEDED"
echo "SHANNON_E2E_PACKAGE $SHANNON_PKG"
echo "SHANNON_E2E_WORKER_IMAGE $SHANNON_IMAGE"
echo "SHANNON_E2E_PATH temporal+worker+validate-model+local-llm-mock"
log "Shannon controlled E2E verification passed."
