# pen-testing

Modular, Docker-friendly orchestration platform for **authorized** AI-assisted penetration testing, bug bounty research, and security reporting.

Integrates verified upstream engines:

| Engine | Pin | Role |
|---|---|---|
| [Shannon](https://github.com/KeygraphHQ/shannon) | `@keygraph/shannon@3.4.0` | White-box web/API pentest (Docker worker) |
| [Briar](https://pypi.org/project/briar-pentest/) | `briar-pentest==0.4.62` | Black-box / optional white-box pentest |
| Headers / Gitleaks / Trivy adapters | see `docs/TOOL_MATRIX.md` | Passive headers, secrets, dependency scanning |

> **Legal/ethical use only.** Public websites are not in scope unless explicitly authorized in `scopes/registry.yaml`.

## Verified features (v0.1)

- Scope/authorization preflight with expiry and category checks
- Shannon + Briar adapters with health checks and dry-run planning
- Normalized findings → JSON / Markdown / SARIF drafts
- Daily research report stub (local, redacted)
- Docker Compose orchestrator + isolated Briar worker image
- Multi-AI instruction set (`AGENTS.md` + client stubs)
- Unit tests and GitHub Actions CI (no external active attacks)

## Limitations

- Shannon **requires Docker**; this environment may not have Docker installed
- Briar is upstream **Alpha**; README claims must be verified via CLI help
- Scope wrapper cannot fully contain every browser navigation of external engines
- No automatic bounty submission
- AGPL engines are invoked out-of-process; this repo stays Apache-2.0

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the Mermaid diagram and adapter model.

## Prerequisites

- Python 3.10+
- Git
- Docker Engine/Desktop + Compose v2 (required for Shannon)
- Node.js 18+ (Shannon `npx` launcher)
- Optional AI provider API keys / Ollama

## First-run

```bash
git clone https://github.com/eneelkant/pen-testing.git
cd pen-testing
chmod +x scripts/*.sh
./scripts/setup.sh
./scripts/doctor.sh
make smoke
```

Configure `.env` from `.env.example` only when a provider is needed.

### Docker

```bash
docker compose build
docker compose run --rm orchestrator
```

### Authorized testing workflow

1. Register the exact asset in `scopes/registry.yaml`
2. `python -m core.cli scope-check --target <url> --category active`
3. Prefer staging/sandbox environments
4. Start with `--dry-run`
5. Run the permitted adapter
6. Export and **human-review** reports

```bash
python -m core.cli run --tool briar --target https://staging.example.com --mode quick
python -m core.cli export-report --input reports/out/run.json --outdir reports/out/draft
python -m core.cli daily-report
```

## AI assistants

Shared rules: [`AGENTS.md`](AGENTS.md). Setup notes: [`docs/AI_ASSISTANT_SETUP.md`](docs/AI_ASSISTANT_SETUP.md).

## Documentation

| Doc | Topic |
|---|---|
| [`docs/SOURCE_AUDIT.md`](docs/SOURCE_AUDIT.md) | Shannon/Briar audit |
| [`docs/INTEGRATION_GUIDE.md`](docs/INTEGRATION_GUIDE.md) | How to run adapters |
| [`docs/INSTALLATION.md`](docs/INSTALLATION.md) | Install / troubleshooting |
| [`docs/TOOL_MATRIX.md`](docs/TOOL_MATRIX.md) | Licenses and status |
| [`SECURITY.md`](SECURITY.md) | Disclosure policy |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contribution guide |

## Development

```bash
pip install -e ".[dev]"
make test
make smoke
```

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Third-party notices: [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Roadmap

- Semgrep CE adapter with redistributable rules only
- Stronger network egress controls for workers
- Digest-pinned base images in release builds
- Optional MCP server wrapping doctor/scope/report commands
