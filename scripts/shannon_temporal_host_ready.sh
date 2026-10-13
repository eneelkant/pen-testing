#!/usr/bin/env bash
# Bounded readiness probe for host → Temporal gRPC (127.0.0.1:7233).
# Used by Shannon E2E to detect dual-home / port-publish regressions.
set -euo pipefail

HOST="${PEN_SHANNON_TEMPORAL_HOST:-127.0.0.1}"
PORT="${PEN_SHANNON_TEMPORAL_PORT:-7233}"
ATTEMPTS="${PEN_SHANNON_TEMPORAL_READY_ATTEMPTS:-30}"
SLEEP_SECS="${PEN_SHANNON_TEMPORAL_READY_SLEEP:-1}"

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

for i in $(seq 1 "$ATTEMPTS"); do
  if python3 - "$HOST" "$PORT" <<'PY'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    s = socket.create_connection((host, port), timeout=2)
    s.close()
    sys.exit(0)
except OSError:
    sys.exit(1)
PY
  then
    log "SHANNON_TEMPORAL_HOST_READY ${HOST}:${PORT} attempt=${i}"
    exit 0
  fi
  sleep "$SLEEP_SECS"
done

die "Temporal host endpoint ${HOST}:${PORT} not ready after ${ATTEMPTS} attempts"
