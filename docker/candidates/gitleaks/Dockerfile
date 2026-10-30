# Candidate only. Tests the upstream Gitleaks v8.30.1 image (immutable
# multi-platform index digest) plus additive OS package updates.
# It must not replace the production pin unless fresh digest-bound Trivy
# evidence, the package requirements, image regression gate, and the
# Gitleaks runtime smoke test all pass.
FROM zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f

LABEL org.opencontainers.image.title="Gitleaks patched candidate" \
      org.opencontainers.image.description="Test candidate; not a production pin"

# Upstream release: zricethezav/gitleaks v8.30.1 (released 2026-03-21).
#   - 9 minor versions ahead of the production pin (v8.21.2 -> v8.30.1).
#   - Upstream release notes not yet inspected for security content; this PR
#     stages v8.30.1 as a VERIFICATION CANDIDATE. CI must prove that the
#     v8.30.1 image, when scanned with the production-pinned Trivy scanner
#     (v0.76.0) against the current vulnerability DB, resolves the inherited
#     Go-module findings (stdlib, golang.org/x/sys, golang.org/x/text,
#     golang.org/x/crypto) AND the OS-package findings (openssh, git, musl,
#     libexpat). If any finding remains, the candidate is unacceptable and
#     the production pin stays at v8.21.2.
#
# Package provenance:
# - The base image (zricethezav/gitleaks:v8.30.1) is Alpine-based with the
#   standard Alpine main/community repositories already configured and trusted.
# - The base image's default USER is non-root; apk needs root to write its
#   log/cache. Switch to root for the apk layer; the candidate inherits the
#   base image's runtime USER for the entrypoint.
# - Following the Shannon candidate pattern: the version constraint is OMITTED
#   from `apk add` for packages whose fixed versions may not be available in
#   the base image's pinned apk repos. apk installs whatever's newest
#   signed-and-available; if that's older than the minimum recorded in
#   docker/candidates/requirements.json, scripts/verify_self_built_candidates.sh
#   ::check_packages flags the candidate as `unsatisfied` and the candidate is
#   marked unacceptable. The minimum in requirements.json is the single source
#   of truth; the candidate is never relabeled acceptable based on a successful
#   apk exit alone.
USER root
RUN apk add --no-cache --upgrade \
      openssh-client-common \
      openssh-client-default \
      openssh-keygen \
      git \
      musl \
      musl-utils \
      libexpat
