# pen-testing

Distributable, MCP-enabled orchestration platform for **authorized** AI-assisted security testing, bug bounty research, and reporting.

Integrates verified upstream engines out-of-process:

| Engine | Pin | Role |
|---|---|---|
| [Shannon](https://github.com/KeygraphHQ/shannon) | `@keygraph/shannon@3.4.0` | White-box web/API pentest (Docker worker) |
| [Briar](https://pypi.org/project/briar-pentest/) | `briar-pentest==0.4.62` | Black-box / optional white-box |
| Headers / Gitleaks / Trivy | see `docs/TOOL_MATRIX.md` | Passive headers, secrets, SCA |

> **Legal/ethical use only.** Public websites are not in scope unless listed in `scopes/registry.yaml`.

**Version:** `0.2.0a17` (alpha — **controlled testing**, not production-ready). See [`docs/READINESS_SCORECARD.md`](docs/READINESS_SCORECARD.md).

Docker: GitHub Actions verifies Compose build/runtime on `ubuntu-latest`, including a controlled Shannon Temporal + real-worker `--validate-model` E2E against a **local** LLM mock (no public targets). Scanner worker nets are Docker **`Internal=true`** (security boundary); `HTTP_PROXY` is convenience only. See [`docs/SCANNER_ISOLATION.md`](docs/SCANNER_ISOLATION.md) and [`docs/LICENSING_REVIEW.md`](docs/LICENSING_REVIEW.md).

## Quick install (MCP profile)

```bash
git clone https://github.com/eneelkant/pen-testing.git
cd pen-testing
chmod +x installers/*.sh scripts/*.sh
PEN_ASSUME_YES=1 bash installers/install.sh mcp
source .venv/bin/activate
python -m core.cli doctor
pen-testing-mcp   # stdio MCP server
```

Unified setup (install + print client configs + dry diagnostic):

```bash
PEN_ASSUME_YES=1 bash scripts/setup_all.sh
```

## MCP tools

`platform_status`, `check_dependencies`, `validate_target_scope`, `list_integrations`, `run_local_diagnostics`, `run_security_assessment` (dry-run by default), `get_assessment_status`, `list_findings`, `export_report`.

Details: [`mcp_server/README.md`](mcp_server/README.md)

## AI clients

| Client | Status |
|---|---|
| Cursor | Project `.cursor/mcp.json` + `installers/configure_cursor.py` |
| Claude Desktop | `installers/configure_claude.py` → `claude_desktop_config.json` |
| Gemini | Partial — `installers/configure_gemini.py` (verify your client) |
| ChatGPT | Remote HTTPS connector only — documented, not auto-deployed |

Matrix: [`docs/CLIENT_COMPATIBILITY.md`](docs/CLIENT_COMPATIBILITY.md). Shared rules: [`AGENTS.md`](AGENTS.md).

## Authorized testing

```bash
python -m core.cli scope-check --target https://staging.example.com --category active
# Prefer MCP/CLI dry-run first
```

## Docker

```bash
bash scripts/docker_runtime_verify.sh   # config, build orchestrator+briar, doctor, host smoke
```

CI job: `Docker build and runtime` (see `.github/workflows/ci.yml`).  
Install Docker yourself if needed: https://docs.docker.com/get-docker/

**Architecture note:** the orchestrator container does **not** mount the Docker socket. Shannon workers are launched from a host/environment that has Docker, not from inside the orchestrator image.

## Documentation

| Doc | Topic |
|---|---|
| [`docs/INSTALLATION.md`](docs/INSTALLATION.md) | Install profiles |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Design |
| [`docs/MCP_READINESS_AUDIT.md`](docs/MCP_READINESS_AUDIT.md) | MCP readiness audit |
| [`docs/MCP_TOOL_TEST_MATRIX.md`](docs/MCP_TOOL_TEST_MATRIX.md) | MCP tool coverage |
| [`docs/SECURITY_VALIDATION.md`](docs/SECURITY_VALIDATION.md) | Scope / authorization tests |
| [`docs/SCANNER_ISOLATION.md`](docs/SCANNER_ISOLATION.md) | Shannon/Briar/Headers isolation map |
| [`docs/LICENSING_REVIEW.md`](docs/LICENSING_REVIEW.md) | AGPL open questions (not clearance) |
| [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md) | Controlled release gates |
| [`docs/CLIENT_COMPATIBILITY.md`](docs/CLIENT_COMPATIBILITY.md) | Cursor / Claude / Gemini / ChatGPT |
| [`docs/SOURCE_AUDIT.md`](docs/SOURCE_AUDIT.md) | Upstream audit |
| [`docs/RELEASE_PROCESS.md`](docs/RELEASE_PROCESS.md) | Releases |
| [`CHANGELOG.md`](CHANGELOG.md) | Versions |

## Development

```bash
PEN_ASSUME_YES=1 bash installers/install.sh dev
source .venv/bin/activate
make test
make smoke
```

## License

Apache-2.0 — [`LICENSE`](LICENSE). Third-party: [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
