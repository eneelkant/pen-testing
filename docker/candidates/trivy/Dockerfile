# Candidate only. Keep the upstream production pin unchanged until the
# custom image passes fresh digest-bound scans and all required verification.
FROM aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222

LABEL org.opencontainers.image.title="Trivy patched candidate" \
      org.opencontainers.image.description="Test candidate; not a production pin"

# The base is Alpine 3.24 (apk-tools 3) with the official Alpine main/community
# repositories configured, so the fixed packages come from Alpine's signed
# repository. /usr/local/bin/trivy is a static Go binary and is not modified;
# libcurl is used only by git (Trivy's repository scanning path).
# The binary's own Go findings (stdlib, golang.org/x/crypto GO-2026-5932) are
# not fixable by an OS-package layer and keep this candidate failing the gate.
RUN apk add --no-cache --upgrade \
      'libcurl>=8.23.0-r0' \
      'brotli-libs>=1.2.1-r0' \
      'libexpat>=2.9.0-r0' \
      'musl>=1.2.6-r3' \
      'musl-utils>=1.2.6-r3'
