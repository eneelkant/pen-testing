# Candidate only. Keep the upstream production pin unchanged until the
# custom image passes fresh digest-bound scans and all required verification.
FROM zricethezav/gitleaks:v8.21.2@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46

LABEL org.opencontainers.image.title="Gitleaks patched candidate" \
      org.opencontainers.image.description="Test candidate; not a production pin"

# Package provenance:
# - The base image (zricethezav/gitleaks:v8.21.2) is Alpine 3.20-based with the
#   standard Alpine main/community repositories already configured and trusted.
# - 2026-10-29 addition (PR ci/extend-candidate-images): upgrade the seven OS
#   packages that have fixed versions per the in-repo image baseline:
#     * openssh-client-common, openssh-client-default, openssh-keygen
#       (9.6_p1-r1 -> 9.7_p1-r0)
#     * git (2.43.5-r0 -> 2.43.6-r0)
#     * musl, musl-utils (1.2.4_git20230717-r4 -> -r5)
#     * libexpat (2.6.3-r0 -> 2.7.2-r0)
#   All seven are standard Alpine packages and should be available from the
#   base image's existing apk repositories.
# - The remaining ~34 findings are Go modules embedded in the gitleaks binary
#   (stdlib, golang.org/x/sys, golang.org/x/text, golang.org/x/crypto). These
#   CANNOT be fixed via apk — they require rebuilding the gitleaks binary
#   from source with updated Go module dependencies, which is out of scope for
#   this PR and would require coordinating with the upstream
#   zricethezav/gitleaks project. The candidate will continue to fail the
#   absolute image gate on those findings until upstream releases a fixed
#   gitleaks image.
RUN apk add --no-cache --upgrade \
      'openssh-client-common>=9.7_p1-r0' \
      'openssh-client-default>=9.7_p1-r0' \
      'openssh-keygen>=9.7_p1-r0' \
      'git>=2.43.6-r0' \
      'musl>=1.2.4_git20230717-r5' \
      'musl-utils>=1.2.4_git20230717-r5' \
      'libexpat>=2.7.2-r0'
