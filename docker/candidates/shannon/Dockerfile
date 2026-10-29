# Candidate only. This must not replace the production pin unless the full
# image gate, the package requirements in docker/candidates/requirements.json,
# and the Shannon Temporal + worker --validate-model runtime test all pass.
FROM keygraph/shannon:3.4.0@sha256:4e726ed8f3a0b10e2a1dbb41185a526f20ea6fccc98740ca553e3c00c2a6bd0e

LABEL org.opencontainers.image.title="Shannon patched candidate" \
      org.opencontainers.image.description="Test candidate; not a production pin"

# Package provenance:
# - The base image's only configured repository is https://apk.cgr.dev/chainguard,
#   which (2026-10-26) still serves curl/libcurl-openssl4 8.22.0-r4 and
#   libbrotli* 1.2.0-r5.
# - The public Wolfi repository serves curl/libcurl-openssl4 8.23.0 and
#   libbrotli* 1.2.1. Its signing key (wolfi-signing.rsa.pub) is already trusted
#   in the base image, so apk verifies every package signature. Signature
#   verification must never be disabled.
# - nodejs-22 >= 22.23.4-r0 is published in neither repository (newest is
#   22.23.2-r1). It is upgraded to the newest signed build available, and the
#   minimum is enforced after the build by scripts/verify_self_built_candidates.sh
#   (docker/candidates/requirements.json). An unmet minimum makes the candidate
#   unacceptable and blocks publication; it is never reported as fixed.
# - 2026-10-29 extension (PR ci/extend-candidate-images): also upgrade chromium,
#   node-gyp, ca-certificates, and ca-certificates-bundle to their fixed versions
#   per the in-repo image baseline. Each is a Wolfi OS package
#   (result_class=os-pkgs) and therefore fixable via apk without rebuilding the
#   Shannon Node.js application.
#   NOT touched in this PR:
#     * quinn-proto 0.11.13 -> 0.11.14+ (CVE-2026-*) — result_type=cargo, a Rust
#       crate compiled into the Shannon binary. NOT apk-installable; requires
#       a new upstream keygraph/shannon release with a rebuilt binary.
#     * The 40 Node.js node_modules findings (zod, @grpc/grpc-js, brace-expansion,
#       etc.) — result_type=node-pkg, live inside /app/node_modules. Require a
#       new upstream release or an in-image `npm audit fix` which risks breaking
#       the worker; that path is intentionally not taken here.
RUN set -eu; \
    printf '%s\n' "https://packages.wolfi.dev/os" >> /etc/apk/repositories; \
    test -f /etc/apk/keys/wolfi-signing.rsa.pub; \
    apk add --no-cache --upgrade \
      'curl>=8.23.0-r0' \
      'libcurl-openssl4>=8.23.0-r0' \
      'libbrotlicommon1>=1.2.0-r7' \
      'libbrotlidec1>=1.2.0-r7' \
      'libbrotlienc1>=1.2.0-r7' \
      'chromium>=154.0.8037.92-r0' \
      'node-gyp>=13.1.0-r1' \
      'ca-certificates>=20260909-r3' \
      'ca-certificates-bundle>=20260909-r3' \
      nodejs-22
