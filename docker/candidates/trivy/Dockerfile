# Candidate only. Tests the upstream Trivy v0.76.1 security release image
# (immutable multi-platform index digest) plus additive OS package updates.
# It must not replace the production pin unless fresh digest-bound Trivy
# evidence, the package requirements, image regression gate, and the
# candidate-verification workflow all pass.
FROM aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c

LABEL org.opencontainers.image.title="Trivy patched candidate" \
      org.opencontainers.image.description="Test candidate; not a production pin"

# Upstream release notes (https://github.com/aquasecurity/trivy/releases/tag/v0.76.1):
#   v0.76.1 (2026-10-21) is an explicit SECURITY UPDATE:
#     - Mitigates the eMudhra intermediate CA key compromise
#       (https://blog.cloudflare.com/emudhra-certificate-compromise/).
#     - Official binaries are built with Go 1.27.3, which includes the
#       certificate distrust mitigation tracked as CVE-2026-111943.
#     - Official container images include an updated Alpine CA trust store
#       that rejects the affected certificate chains.
#   Upstream explicitly recommends upgrading to v0.76.1 and redeploying
#   container images to apply these updates.
#
# This PR stages v0.76.1 as a VERIFICATION CANDIDATE. It is NOT auto-merged.
# CI must prove that the v0.76.1 image, when scanned with the production-pinned
# Trivy scanner (v0.76.0) against the current vulnerability DB, resolves the
# Go-stdlib and golang.org/x/crypto findings that the v0.76.0 image inherited.
# If v0.76.1 still has unfixable findings (e.g. golang.org/x/crypto GO-2026-5932
# not yet fixed upstream), the candidate remains unacceptable and the
# production pin stays at v0.76.0.
#
# Package provenance:
# - The base is Alpine 3.24 (apk-tools 3) with the official Alpine main/community
#   repositories configured, so the fixed packages come from Alpine's signed
#   repository. /usr/local/bin/trivy is a static Go binary and is not modified;
#   libcurl is used only by git (Trivy's repository scanning path).
# - Signature verification is never disabled.
RUN apk add --no-cache --upgrade \
      'libcurl>=8.23.0-r0' \
      'brotli-libs>=1.2.1-r0' \
      'libexpat>=2.9.0-r0' \
      'musl>=1.2.6-r3' \
      'musl-utils>=1.2.6-r3'
