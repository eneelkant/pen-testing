# Orchestrator image — no privileged mode, non-root user.
# Pin the python:3.12.15-alpine3.24 OCI index digest. Its linux/amd64 child
# (sha256:9b98a8d3...) had zero fixed HIGH/CRITICAL and zero unscored findings
# in Trivy 0.76.0 scans on 2026-10-24 (DB UpdatedAt 01:18:19Z and 07:11:13Z).
# Every Debian python:3.12 slim digest still carries unscored findings
# (perl-base CVE-2026-82560 has no fix), so Bookworm cannot pass the gate.
FROM python:3.12.15-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PEN_WORK_DIR=/work/workspaces \
    PEN_REPORTS_DIR=/work/reports

WORKDIR /app

RUN adduser -D -u 10001 appuser \
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
