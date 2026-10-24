# Isolated Briar worker. Do not mount Docker socket.
FROM python:3.12.15-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN adduser -D -u 10002 briar \
    && mkdir -p /work/reports /work/workspaces \
    && chown -R briar:briar /work

# Pin Briar from PyPI
RUN pip install --no-cache-dir "briar-pentest==0.4.62"

USER briar
WORKDIR /work
ENTRYPOINT ["briar"]
CMD ["--help"]
