# Orchestrator image — no privileged mode, non-root user.
# Pin base digest in production deployments when possible.
# Prefer digest pinning in production; tag verified on Docker Hub as python:3.12-slim-bookworm.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PEN_WORK_DIR=/work/workspaces \
    PEN_REPORTS_DIR=/work/reports

WORKDIR /app

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /work/workspaces /work/reports \
    && chown -R appuser:appuser /work

COPY pyproject.toml README.md LICENSE ./
COPY core ./core
COPY integrations ./integrations
COPY providers ./providers
COPY mcp_server ./mcp_server
COPY scopes ./scopes
COPY reports/templates ./reports/templates
COPY scripts ./scripts

RUN pip install --no-cache-dir . \
    && chown -R appuser:appuser /app

USER appuser
WORKDIR /work

# Default command is diagnostics; active scans are opt-in.
CMD ["python", "-m", "core.cli", "doctor"]
