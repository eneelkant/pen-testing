# Orchestrator image — no privileged mode, non-root user.
# Pin the Bookworm slim digest that had no fixed HIGH/CRITICAL findings
# in the 2026-10-18 Trivy 0.76.0 scan. python:3.14-slim-bookworm was not used:
# that digest reported fixed highs in msgpack, setuptools, and urllib3.
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

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
