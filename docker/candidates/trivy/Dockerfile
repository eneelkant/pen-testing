# Candidate only. Keep the upstream production pin unchanged until the
# custom image passes fresh digest-bound scans and all required verification.
FROM aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222

LABEL org.opencontainers.image.title="Trivy patched candidate" \
      org.opencontainers.image.description="Test candidate; not a production pin"

# Retain the official Trivy binary and entrypoint while requiring the fixed
# Alpine libcurl version. The package constraint fails closed if unavailable.
RUN apk add --no-cache 'libcurl>=8.23.0-r0' \
    && apk info -v libcurl
