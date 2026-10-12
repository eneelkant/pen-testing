# Isolated Briar worker. Do not mount Docker socket.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --create-home --uid 10002 briar \
    && mkdir -p /work/reports /work/workspaces \
    && chown -R briar:briar /work

# Pin Briar from PyPI
RUN pip install --no-cache-dir "briar-pentest==0.4.62"

USER briar
WORKDIR /work
ENTRYPOINT ["briar"]
CMD ["--help"]
