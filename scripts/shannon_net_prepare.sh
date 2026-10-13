#!/usr/bin/env bash
# Prepare a platform-managed shannon-net (internal) + egress gateway for controlled Shannon runs.
# Shannon's CLI hardcodes --network shannon-net; we pre-create that name as internal.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker required"
docker info >/dev/null || die "docker daemon not usable"

NET_NAME="${PEN_SHANNON_NET_NAME:-shannon-net}"
GW_NAME="${PEN_SHANNON_GATEWAY_NAME:-pen-shannon-egress-gateway}"
EGRESS_NET="${PEN_SHANNON_EGRESS_NET:-pen-shannon-egress}"

if docker network inspect "$NET_NAME" >/dev/null 2>&1; then
  INTERNAL="$(docker network inspect -f '{{.Internal}}' "$NET_NAME")"
  MANAGED="$(docker network inspect -f '{{index .Labels "pen.managed"}}' "$NET_NAME" 2>/dev/null || true)"
  if [[ "$INTERNAL" != "true" ]]; then
    die "network $NET_NAME exists but is not internal (Internal=$INTERNAL). Refusing uncontrolled shannon-net. Set PEN_ALLOW_SHANNON_UNCONTAINED_NET=1 to bypass controlled mode, or remove the network."
  fi
  if [[ "$MANAGED" != "1" ]]; then
    log "WARN: $NET_NAME is internal but missing pen.managed=1 label; continuing"
  fi
else
  log "== create internal $NET_NAME =="
  docker network create --internal --label pen.managed=1 --label pen.role=shannon-workers "$NET_NAME"
fi

if ! docker network inspect "$EGRESS_NET" >/dev/null 2>&1; then
  log "== create egress $EGRESS_NET =="
  docker network create --label pen.managed=1 --label pen.role=shannon-egress "$EGRESS_NET"
fi

log "== build egress gateway image =="
docker build -t pen-testing-egress-gateway:local -f docker/egress-gateway/Dockerfile .

if docker ps -a --format '{{.Names}}' | grep -qx "$GW_NAME"; then
  docker rm -f "$GW_NAME" >/dev/null 2>&1 || true
fi

ALLOW="${PEN_PROXY_ALLOW_HOSTS:-}"
log "== start egress gateway on $NET_NAME + $EGRESS_NET =="
docker run -d --name "$GW_NAME" \
  --label pen.managed=1 \
  --network "$NET_NAME" \
  --network-alias egress-gateway \
  -e PEN_PROXY_ALLOW_HOSTS="$ALLOW" \
  -e PEN_PROXY_PORT=3128 \
  --read-only --tmpfs /tmp \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  pen-testing-egress-gateway:local >/dev/null

docker network connect "$EGRESS_NET" "$GW_NAME" 2>/dev/null || true

# Prove worker-equivalent isolation on shannon-net.
log "== prove shannon-net worker stand-in cannot reach 1.1.1.1 =="
set +e
PROBE="$(docker run --rm --network "$NET_NAME" python:3.12-slim-bookworm \
  python -c 'import socket,sys
try:
  socket.create_connection(("1.1.1.1",443),3); print("UNEXPECTED_CONNECT"); sys.exit(0)
except OSError as e:
  print("SHANNON_NET_ISOLATED_BLOCKED", type(e).__name__); sys.exit(1)
' 2>&1)"
RC=$?
set -e
echo "$PROBE"
echo "$PROBE" | grep -q UNEXPECTED_CONNECT && die "shannon-net reached 1.1.1.1"
test "$RC" -ne 0 || die "shannon-net probe unexpectedly succeeded"
echo "$PROBE" | grep -q SHANNON_NET_ISOLATED_BLOCKED || die "missing SHANNON_NET_ISOLATED_BLOCKED"

log "== prove shannon-net stand-in can reach egress-gateway =="
docker run --rm --network "$NET_NAME" python:3.12-slim-bookworm \
  python -c 'import socket; s=socket.create_connection(("egress-gateway",3128),5); s.close(); print("SHANNON_NET_REACHES_GATEWAY")'

log "== prove direct egress blocked with proxy env explicitly unset =="
set +e
NOPROXY_PROBE="$(docker run --rm --network "$NET_NAME" \
  -e HTTP_PROXY= -e HTTPS_PROXY= -e http_proxy= -e https_proxy= -e ALL_PROXY= -e all_proxy= \
  python:3.12-slim-bookworm \
  python -c 'import os,socket,sys
for k in list(os.environ):
  if "proxy" in k.lower():
    del os.environ[k]
try:
  socket.create_connection(("1.1.1.1",443),3); print("UNEXPECTED_CONNECT"); sys.exit(0)
except OSError as e:
  print("SHANNON_NET_NOPROXY_DIRECT_BLOCKED", type(e).__name__); sys.exit(1)
' 2>&1)"
NOPROXY_RC=$?
set -e
echo "$NOPROXY_PROBE"
echo "$NOPROXY_PROBE" | grep -q UNEXPECTED_CONNECT && die "shannon-net direct egress succeeded with proxy unset"
test "$NOPROXY_RC" -ne 0 || die "noproxy probe unexpectedly succeeded"
echo "$NOPROXY_PROBE" | grep -q SHANNON_NET_NOPROXY_DIRECT_BLOCKED || die "missing SHANNON_NET_NOPROXY_DIRECT_BLOCKED"

log "== prove real Shannon worker image on shannon-net (if pullable) =="
SHANNON_IMAGE="${PEN_SHANNON_WORKER_IMAGE:-keygraph/shannon:3.4.0}"
if docker pull "$SHANNON_IMAGE" >/tmp/shannon-pull.log 2>&1; then
  set +e
  REAL_PROBE="$(docker run --rm --network "$NET_NAME" --entrypoint node \
    -e HTTP_PROXY= -e HTTPS_PROXY= -e http_proxy= -e https_proxy= \
    "$SHANNON_IMAGE" -e '
const net = require("net");
const s = net.connect({host:"1.1.1.1", port:443, timeout:3000}, () => {
  console.log("UNEXPECTED_CONNECT");
  process.exit(0);
});
s.on("error", (e) => {
  console.log("SHANNON_REAL_WORKER_DIRECT_BLOCKED", e.code || e.message);
  process.exit(1);
});
setTimeout(() => { console.log("SHANNON_REAL_WORKER_DIRECT_BLOCKED", "TIMEOUT"); process.exit(1); }, 3500);
' 2>&1)"
  REAL_RC=$?
  set -e
  echo "$REAL_PROBE"
  echo "$REAL_PROBE" | grep -q UNEXPECTED_CONNECT && die "real Shannon worker reached 1.1.1.1"
  test "$REAL_RC" -ne 0 || die "real Shannon worker egress probe unexpectedly succeeded"
  echo "$REAL_PROBE" | grep -q SHANNON_REAL_WORKER_DIRECT_BLOCKED || die "missing SHANNON_REAL_WORKER_DIRECT_BLOCKED"

  log "== prove real Shannon worker restart retains isolation =="
  # Keep-alive via node (image may lack GNU sleep as ENTRYPOINT).
  REAL_CID="$(docker run -d --network "$NET_NAME" --entrypoint node "$SHANNON_IMAGE" -e 'setInterval(()=>{},1e3); setTimeout(()=>process.exit(0),60000)')"
  test -n "$REAL_CID" || die "failed to start real Shannon worker keep-alive"
  docker restart "$REAL_CID" >/dev/null
  # Wait for node to be ready after restart.
  ready=0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if docker exec "$REAL_CID" node -e 'process.exit(0)' >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  test "$ready" -eq 1 || die "restarted Shannon worker not ready"
  set +e
  REAL_RESTART="$(docker exec -e HTTP_PROXY= -e HTTPS_PROXY= -e http_proxy= -e https_proxy= "$REAL_CID" node -e '
const net = require("net");
const s = net.connect({host:"1.1.1.1", port:443, timeout:3000}, () => {
  console.log("UNEXPECTED_CONNECT");
  process.exit(0);
});
s.on("error", (e) => {
  console.log("SHANNON_REAL_WORKER_RESTART_BLOCKED", e.code || e.message);
  process.exit(1);
});
setTimeout(() => { console.log("SHANNON_REAL_WORKER_RESTART_BLOCKED", "TIMEOUT"); process.exit(1); }, 3500);
' 2>&1)"
  REAL_RESTART_RC=$?
  set -e
  echo "$REAL_RESTART"
  docker rm -f "$REAL_CID" >/dev/null 2>&1 || true
  echo "$REAL_RESTART" | grep -q UNEXPECTED_CONNECT && die "restarted Shannon worker reached 1.1.1.1"
  test "$REAL_RESTART_RC" -ne 0 || die "restart probe unexpectedly succeeded"
  echo "$REAL_RESTART" | grep -q SHANNON_REAL_WORKER_RESTART_BLOCKED || die "missing SHANNON_REAL_WORKER_RESTART_BLOCKED"
else
  die "unable to pull $SHANNON_IMAGE for real-worker isolation proof (see /tmp/shannon-pull.log)"
fi

log "Shannon controlled network prepared."
echo "SHANNON_CONTROLLED_NET_READY name=$NET_NAME gateway=$GW_NAME"
