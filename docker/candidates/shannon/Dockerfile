# Candidate only. This tests the newly republished official Shannon v3.5.0
# image (immutable multi-platform index digest) plus additive OS package updates.
# It must not replace the production pin unless fresh digest-bound Trivy evidence,
# the package requirements, image regression gate, and controlled Shannon runtime
# validation all pass.
FROM keygraph/shannon:3.5.0@sha256:7824cff7c54d63836d321a057bdc59c54d85dc0dde7fe486f837592a36a58c4e

LABEL org.opencontainers.image.title="Shannon patched candidate" \
      org.opencontainers.image.description="Test candidate; not a production pin"

# Package provenance:
# - The official v3.5.0 image was republished on 2026-10-29. Its current immutable
#   image index digest is pinned above; CI must still prove its exact packages
#   and vulnerabilities rather than infer safety from the upstream version tag.
# - The base image's configured repositories may lag fixed package releases.
# - The public Wolfi repository serves curl/libcurl-openssl4 8.23.0 and
#   libbrotli* 1.2.1. Its signing key (wolfi-signing.rsa.pub) is already trusted
#   in the base image, so apk verifies every package signature. Signature
#   verification must never be disabled.
# - The current required Node.js minimum (22.23.4-r0) and Chromium minimum are
#   intentionally retained in requirements.json. If the refreshed official image
#   and signed package indexes still lack those versions, CI marks the candidate
#   unacceptable and it cannot be published or promoted.
RUN set -eu; \
    printf '%s\n' "https://packages.wolfi.dev/os" >> /etc/apk/repositories; \
    test -f /etc/apk/keys/wolfi-signing.rsa.pub; \
    apk add --no-cache --upgrade \
      'curl>=8.23.0-r0' \
      'libcurl-openssl4>=8.23.0-r0' \
      'libbrotlicommon1>=1.2.0-r7' \
      'libbrotlidec1>=1.2.0-r7' \
      'libbrotlienc1>=1.2.0-r7' \
      nodejs-22
