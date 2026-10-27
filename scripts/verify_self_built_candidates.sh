#!/usr/bin/env bash
# Builds the self-built image candidates from digest-pinned upstream bases,
# checks their package requirements inside the built images, captures raw
# Trivy evidence with a vulnerability-database probe, verifies it with
# scripts/verify_image_candidate.py, and runs Shannon's controlled Temporal +
# worker --validate-model test against the *candidate* image.
#
# Never changes production pins and never publishes images.
#
#   bash scripts/verify_self_built_candidates.sh [--require-clean]
#
# Without --require-clean a verified-but-failing candidate is evidence, not an
# error. NOT_VERIFIED evidence always fails. Acceptance outputs are written to
# $GITHUB_OUTPUT only after every step below has succeeded.
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
# The Shannon 3.4.0 CLI (npx mode) always runs the worker image keygraph/shannon:3.4.0
# by tag and uses a local image with that tag when present. To runtime-test the
# candidate, that tag is pointed at the candidate for the duration of the E2E and
# restored afterwards; the E2E then asserts the worker containers used the
# candidate's image ID.
SHANNON_CLI_WORKER_TAG="keygraph/shannon:3.4.0"
REPORTS="candidate-reports"
TRIVY_CACHE="${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}"
mkdir -p "$REPORTS" "$TRIVY_CACHE"
# Preserve a file so CI can upload diagnostics even when the first build fails.
printf '%s\n' "candidate build started for $SHA" > "$REPORTS/build-status.txt"

log() { printf '%s\n' "$*"; }
status() { printf '%s\n' "$*" | tee -a "$REPORTS/build-status.txt"; }

PREVIOUS_WORKER_TAG_ID=""
restore_worker_tag() {
  if [[ -n "${RETAGGED:-}" ]]; then
    if [[ -n "$PREVIOUS_WORKER_TAG_ID" ]]; then
      docker tag "$PREVIOUS_WORKER_TAG_ID" "$SHANNON_CLI_WORKER_TAG" >/dev/null 2>&1 || true
    else
      docker image rm "$SHANNON_CLI_WORKER_TAG" >/dev/null 2>&1 || true
    fi
  fi
}
trap restore_worker_tag EXIT

build_candidate() {
  local name="$1" dockerfile="$2" tag="$3"
  log "== build $name candidate for linux/amd64 =="
  # The build context is docker/candidates (not the repository root) so no
  # repository files can leak into the image.
  if ! docker build --pull --platform linux/amd64 \
      --file "$dockerfile" --tag "$tag" docker/candidates 2>&1 | tee "$REPORTS/$name-build.log"; then
    status "$name candidate build failed; see $name-build.log. No pin changed."
    exit 1
  fi
  docker image inspect --format '{{.Id}}' "$tag" > "$REPORTS/$name-image-id.txt"
  status "$name candidate built: $tag $(cat "$REPORTS/$name-image-id.txt")"
}

# Writes <name>-packages.tsv: package, required minimum, installed version, state.
# Versions come from the image's own /lib/apk/db/installed and are compared with
# apk's own comparator, so apk version semantics are authoritative.
check_packages() {
  local name="$1" image="$2"
  local requirements
  requirements="$(python - "$name" <<'PY'
import json, sys
spec = json.load(open("docker/candidates/requirements.json"))["candidates"][sys.argv[1]]["packages"]
for package, item in sorted(spec.items()):
    print(f"{package} {item['minimum']}")
PY
)"
  log "== $name: required package versions inside the built image =="
  printf '%s\n' "$requirements" | docker run -i --rm --platform linux/amd64 --user 0 --entrypoint /bin/sh "$image" -c '
set -eu
db=/lib/apk/db/installed
test -r "$db"
while read -r name min; do
  [ -n "$name" ] || continue
  v=$(awk -v n="$name" "/^P:/{p=substr(\$0,3)} /^V:/{if(p==n){print substr(\$0,3); exit}}" "$db")
  if [ -z "$v" ]; then printf "%s\t%s\t-\tmissing\n" "$name" "$min"; continue; fi
  c=$(apk version -t "$v" "$min")
  case "$c" in ">"|"=") s=satisfied;; "<") s=unsatisfied;; *) s=unknown;; esac
  printf "%s\t%s\t%s\t%s\n" "$name" "$min" "$v" "$s"
done' > "$REPORTS/$name-packages.tsv"
  cat "$REPORTS/$name-packages.tsv"
  docker run --rm --platform linux/amd64 --user 0 --entrypoint /bin/cat "$image" /lib/apk/db/installed \
    > "$REPORTS/$name-apk-installed.txt"
}

TRIVY_SCANNER="$(python -c 'from core.supply_chain.images import TRIVY_IMAGE; print(TRIVY_IMAGE)')"

# scan_and_verify <name> <image-ref> <image-src: docker|remote> [image-id]
scan_and_verify() {
  local name="$1" image_ref="$2" source="$3" image_id="${4:-}"
  local report="$REPORTS/$name-scan.json" probe="$REPORTS/$name-trivy-version.json"
  local summary="$REPORTS/$name-summary.json" rc
  log "== scan $name ($image_ref, source $source) with the pinned scanner =="
  set +e
  docker run --rm --platform linux/amd64 \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$ROOT/$REPORTS:/reports" -v "$TRIVY_CACHE:/root/.cache/trivy" \
    "$TRIVY_SCANNER" image --scanners vuln --format json --quiet \
    --image-src "$source" --platform linux/amd64 \
    --output "/reports/$name-scan.json" "$image_ref"
  rc=$?
  set -e
  # Database probe with the same cache, immediately after the scan.
  docker run --rm --platform linux/amd64 -v "$TRIVY_CACHE:/root/.cache/trivy" \
    "$TRIVY_SCANNER" version --format json > "$probe" || true
  local args=(--candidate "$name" --image-ref "$image_ref" --report "$report" --db-probe "$probe"
              --trivy-exit-code "$rc" --package-check "$REPORTS/$name-packages.tsv" --summary "$summary")
  if [[ -n "$image_id" ]]; then
    args+=(--image-id "$image_id")
  fi
  if [[ "$REQUIRE_CLEAN" == "1" ]]; then
    args+=(--require-clean)
  fi
  python scripts/verify_image_candidate.py "${args[@]}"
}

build_candidate shannon docker/candidates/shannon/Dockerfile "$SHANNON_IMAGE"
build_candidate trivy docker/candidates/trivy/Dockerfile "$TRIVY_CANDIDATE_IMAGE"
SHANNON_ID="$(cat "$REPORTS/shannon-image-id.txt")"
TRIVY_ID="$(cat "$REPORTS/trivy-image-id.txt")"

check_packages shannon "$SHANNON_IMAGE"
check_packages trivy "$TRIVY_CANDIDATE_IMAGE"

log "== Trivy candidate: binary, database download, and scanning still work =="
docker run --rm --platform linux/amd64 "$TRIVY_CANDIDATE_IMAGE" --version | tee "$REPORTS/trivy-candidate-version.txt"
docker run --rm --platform linux/amd64 -v "$TRIVY_CACHE:/root/.cache/trivy" \
  "$TRIVY_CANDIDATE_IMAGE" rootfs --scanners vuln --format json --quiet --output /tmp/self.json / \
  && status "trivy candidate scanned its own rootfs successfully"
docker run --rm --platform linux/amd64 --entrypoint /bin/sh "$TRIVY_CANDIDATE_IMAGE" -ec \
  'git --version; ldd /usr/libexec/git-core/git-remote-http | grep -E "libcurl|not found"' \
  | tee "$REPORTS/trivy-candidate-git.txt"
if grep -q "not found" "$REPORTS/trivy-candidate-git.txt"; then
  status "trivy candidate git helper has unresolved libraries"
  exit 1
fi

docker pull --platform linux/amd64 "$TRIVY_SCANNER" >/dev/null
scan_and_verify shannon "$SHANNON_IMAGE" docker "$SHANNON_ID"
scan_and_verify trivy "$TRIVY_CANDIDATE_IMAGE" docker "$TRIVY_ID"

log "== Shannon controlled E2E with the CANDIDATE worker image =="
PREVIOUS_WORKER_TAG_ID="$(docker image inspect --format '{{.Id}}' "$SHANNON_CLI_WORKER_TAG" 2>/dev/null || true)"
RETAGGED=1
docker tag "$SHANNON_IMAGE" "$SHANNON_CLI_WORKER_TAG"
# Local fixtures and a mock model only; no public targets or model providers.
PEN_SHANNON_WORKER_IMAGE="$SHANNON_IMAGE" \
PEN_SHANNON_EXPECT_WORKER_IMAGE_ID="$SHANNON_ID" \
PEN_SHANNON_E2E_CLEAN_NET=1 \
bash scripts/shannon_e2e_verify.sh 2>&1 | tee "$REPORTS/shannon-e2e.log"
grep -q "SHANNON_E2E_WORKER_IMAGE_ID_VERIFIED $SHANNON_ID" "$REPORTS/shannon-e2e.log"
restore_worker_tag
RETAGGED=""
status "shannon candidate passed the controlled --validate-model E2E (worker image $SHANNON_ID)"

# Only now, after every check above has run without error, publish outputs.
SHANNON_OK="$(python -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["acceptable"] is True).lower())' "$REPORTS/shannon-summary.json")"
TRIVY_OK="$(python -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["acceptable"] is True).lower())' "$REPORTS/trivy-summary.json")"
status "shannon acceptable=$SHANNON_OK trivy acceptable=$TRIVY_OK"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "shannon_acceptable=$SHANNON_OK"
    echo "trivy_acceptable=$TRIVY_OK"
  } >> "$GITHUB_OUTPUT"
fi
log "Candidate build and runtime evidence collected."
