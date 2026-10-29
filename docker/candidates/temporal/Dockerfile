# Candidate only. Keep the upstream production pin unchanged until the
# custom image passes fresh digest-bound scans and all required verification.
FROM temporalio/temporal:1.7.0@sha256:9c5b386d86bca59ba08f32ddc4c51287351c8c616b6a8359f03e96a585e137f4

LABEL org.opencontainers.image.title="Temporal patched candidate" \
      org.opencontainers.image.description="Test candidate; not a production pin"

# Package provenance:
# - The base image (temporalio/temporal:1.7.0) is Alpine 3.21-based with the
#   standard Alpine main/community repositories already configured and trusted.
# - The base image's default USER is non-root; apk needs root to write its
#   log/cache. Switch to root for the apk layer; the candidate inherits the
#   base image's runtime USER for the entrypoint.
# - 2026-10-29 addition (PR ci/extend-candidate-images): upgrade the four OS
#   packages that have fixed versions per the in-repo image baseline:
#     * musl, musl-utils (1.2.5-r23 -> 1.2.5-r24)
#     * libcrypto3, libssl3 (3.5.6-r0 -> 3.5.8-r0)
#   Following the Shannon candidate pattern: the version constraint is OMITTED
#   from `apk add` for these packages, because the fixed versions may not yet
#   be available in the base image's pinned Alpine 3.21 repos. apk installs
#   whatever's newest signed-and-available; if that's older than the minimum
#   recorded in docker/candidates/requirements.json, scripts/verify_self_built_
#   candidates.sh::check_packages flags the candidate as `unsatisfied` and the
#   candidate is marked unacceptable. The minimum in requirements.json is the
#   single source of truth; the candidate is never relabeled acceptable based
#   on a successful apk exit alone.
# - The remaining 54 findings are Go modules embedded in the Temporal binary
#   (github.com/gomarkdown/markdown, github.com/apache/thrift, stdlib,
#   golang.org/x/net, golang.org/x/sys, golang.org/x/crypto). These CANNOT be
#   fixed via apk — they require rebuilding the Temporal binary from source
#   with updated Go module dependencies, which is out of scope for this PR
#   and would require coordinating with the upstream temporalio/temporal
#   project. The candidate will continue to fail the absolute image gate on
#   those findings until upstream releases a fixed Temporal image.
USER root
RUN apk add --no-cache --upgrade \
      musl \
      musl-utils \
      libcrypto3 \
      libssl3
