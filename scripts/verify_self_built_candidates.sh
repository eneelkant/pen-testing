#!/usr/bin/env bash
# Builds candidate images from digest-pinned upstream bases, captures raw Trivy
# evidence, and runs Shannon against the repository's local test fixtures.
# This script never changes production pins or publishes images.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REQUIRE_CLEAN=0
if [[ "${1:-}" == "--require-clean" ]]; then
  REQUIRE_CLEAN=1
fi

SHA="${GITHUB_SHA:-local}"
TAG="$(printf '%s' "$SHA" | cut -c1-12 | tr '[:upper:]' '[:lower:]')"
SHANNON_IMAGE="local/shannon-worker-candidate:$TAG"
TRIVY_CANDIDATE_IMAGE="local/trivy-scanner-candidate:$TAG"
mkdir -p candidate-reports "$HOME/.cache/trivy"
# Preserve a file so CI can upload diagnostics even when the first build fails.
printf '%s\n' "candidate build started for $SHA" > candidate-reports/build-status.txt

log() { printf '%s\n' "$*"; }

log "== build candidate images for linux/amd64 =="
if ! docker build --pull --platform linux/amd64 \
  --file docker/candidates/shannon/Dockerfile \
  --tag "$SHANNON_IMAGE" 2>&1 | tee candidate-reports/shannon-build.log; then
  printf '%s\n' "Shannon candidate build failed; see shannon-build.log. No pin changed." >> candidate-reports/build-status.txt
  exit 1
fi
if ! docker build --pull --platform linux/amd64 \
  --file docker/candidates/trivy/Dockerfile \
  --tag "$TRIVY_CANDIDATE_IMAGE" 2>&1 | tee candidate-reports/trivy-build.log; then
  printf '%s\n' "Trivy candidate build failed; see trivy-build.log. No pin changed." >> candidate-reports/build-status.txt
  exit 1
fi

log "== assert constrained packages are present in Shannon candidate =="
docker run --rm --platform linux/amd64 --entrypoint /bin/sh "$SHANNON_IMAGE" -ec \
  'apk info -v nodejs-22; apk info -v curl; apk info -v libcurl-openssl4'

log "== assert constrained libcurl is present in Trivy candidate =="
docker run --rm --platform linux/amd64 --entrypoint /bin/sh "$TRIVY_CANDIDATE_IMAGE" -ec \
  'apk info -v libcurl'

log "== verify Trivy candidate entrypoint starts =="
docker run --rm --platform linux/amd64 "$TRIVY_CANDIDATE_IMAGE" --version

log "== use the existing digest-pinned Trivy scanner for raw candidate scans =="
TRIVY_SCANNER="$(python -c 'from core.supply_chain.images import TRIVY_IMAGE; print(TRIVY_IMAGE)')"
docker pull --platform linux/amd64 "$TRIVY_SCANNER"

scan_candidate() {
  local image_ref="$1"
  local name="$2"
  local require_clean="$3"
  local report="candidate-reports/$name-local.json"
  local summary="candidate-reports/$name-summary.json"

  docker run --rm --platform linux/amd64 \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$ROOT:/work" -v "$HOME/.cache/trivy:/root/.cache/trivy" \
    -w /work "$TRIVY_SCANNER" image --scanners vuln --format json \
    --output "/work/$report" --no-progress "$image_ref"

  local args=(--image-ref "$image_ref" --report "$report" --summary "$summary" --output-name "${name}_acceptable")
  if [[ "$require_clean" == "1" ]]; then
    args+=(--require-clean)
  fi
  python scripts/verify_image_candidate.py "${args[@]}"
}

log "== scan Shannon candidate =="
scan_candidate "$SHANNON_IMAGE" shannon "$REQUIRE_CLEAN"

log "== scan Trivy candidate =="
scan_candidate "$TRIVY_CANDIDATE_IMAGE" trivy "$REQUIRE_CLEAN"

log "== validate Shannon end-to-end against local fixtures and mock model =="
# This invokes the existing Temporal + real-worker --validate-model path. It
# does not contact public targets or use an external model provider.
PEN_SHANNON_WORKER_IMAGE="$SHANNON_IMAGE" \
PEN_SHANNON_E2E_CLEAN_NET=1 \
bash scripts/shannon_e2e_verify.sh

log "Candidate build and local runtime evidence collected."
