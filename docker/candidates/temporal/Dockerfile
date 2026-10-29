# Candidate only. Tests the upstream Temporal v1.9.1 image (immutable
# multi-platform index digest) plus additive OS package updates.
# It must not replace the production pin unless fresh digest-bound Trivy
# evidence, the package requirements, image regression gate, and the
# Temporal runtime smoke test all pass.
FROM temporalio/temporal:1.9.1@sha256:ad4c82c97bd12b417d1ea942610dbcd511afb250c4d5ed26c694009533df447e

LABEL org.opencontainers.image.title="Temporal patched candidate" \
      org.opencontainers.image.description="Test candidate; not a production pin"

# Upstream release: temporalio/temporal v1.9.1 (released 2026-09-14).
#   - Two minor version jumps from the production pin (1.7.0 -> 1.8.x -> 1.9.1).
#   - Upstream release notes not yet inspected for security content; this PR
#     stages v1.9.1 as a VERIFICATION CANDIDATE. CI must prove that the v1.9.1
#     image, when scanned with the production-pinned Trivy scanner (v0.76.0)
#     against the current vulnerability DB, resolves the inherited Go-module
#     findings (gomarkdown/markdown, stdlib, golang.org/x/net, golang.org/x/sys,
#     golang.org/x/crypto, apache/thrift) AND the OS-package findings (musl,
#     libcrypto3, libssl3). If any finding remains, the candidate is
#     unacceptable and the production pin stays at 1.7.0.
#
# Package provenance:
# - The base image (temporalio/temporal:1.9.1) is Alpine-based with the standard
#   Alpine main/community repositories already configured and trusted.
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
      musl \
      musl-utils \
      libcrypto3 \
      libssl3
