# Candidate only. This must not replace the production pin unless the full
# image gate and Shannon runtime validation pass.
FROM keygraph/shannon:3.4.0@sha256:4e726ed8f3a0b10e2a1dbb41185a526f20ea6fccc98740ca553e3c00c2a6bd0e

LABEL org.opencontainers.image.title="Shannon patched candidate" \
      org.opencontainers.image.description="Test candidate; not a production pin"

# The version constraints make the build fail rather than silently retain an
# older package if the fixed Wolfi versions are not available or resolvable.
RUN apk add --no-cache \
      'nodejs-22>=22.23.4-r0' \
      'curl>=8.23.0-r0' \
      'libcurl-openssl4>=8.23.0-r0' \
    && apk info -v nodejs-22 curl libcurl-openssl4
