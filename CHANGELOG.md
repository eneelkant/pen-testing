# Changelog

## 0.2.0a2 — 2026-10-12

### Security

- MCP `export_report` outdir confined to `reports_dir` / `work_dir`
- Assessment IDs required to be UUIDs (blocks path-like IDs)
- Scope validation requires absolute http(s) URLs with hostnames (non-path tools)
- Assessment `timeout_seconds` bounded to 1..86400
- Logger forced to stderr with `propagate=False` for stdio MCP safety

### Added

- MCP readiness audit, tool test matrix, and security validation docs
- MCP tool-call regression suite (`tests/unit/test_mcp_tool_calls.py`)
- GitHub Actions `docker-runtime` job + `scripts/docker_runtime_verify.sh` (Engine/Compose build, orchestrator doctor, host smoke)

### Notes

- Local Cursor agent VMs may lack Docker; runtime verification is performed on `ubuntu-latest` GitHub-hosted runners
- AI client E2E UI connections remain environment-dependent

## 0.2.0a1 — 2026-10-12

### Added

- Official MCP Python SDK (`mcp` 2.x) server with constrained tools
- Installers (`installers/install.sh`, `install.ps1`) and unified `scripts/setup_all.sh`
- Client configuration helpers for Cursor, Claude Desktop, and Gemini CLI
- Reproducible requirement sets under `requirements/`
- Client compatibility matrix and release process docs
- GitHub release workflow (tag-driven)

### Security

- MCP assessments default to `dry_run=true` and require `confirm_authorized` for live runs
- Headers redirect no-follow / cross-origin refusal retained from v0.1 readiness work

### Notes

- Alpha: Docker runtime verification may be incomplete in some environments
- ChatGPT remote MCP is documented only; not auto-deployed

## 0.1.0 — 2026-10-12

Initial orchestration platform: Shannon/Briar adapters, scope engine, reporting, Docker Compose, CI.
