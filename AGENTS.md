# AGENTS.md — pen-testing platform

Shared instructions for Cursor, ChatGPT, Claude, Gemini, Copilot, and human contributors.

## Mission

This repository orchestrates **authorized** security testing via adapters for Shannon, Briar, and complementary scanners. It prioritizes scope enforcement, isolation, normalized reporting, and maintainability.

## Hard rules

1. Test only owned or explicitly authorized assets listed in `scopes/registry.yaml` (or the configured registry).
2. Never treat a public URL as authorization.
3. Never fabricate vulnerabilities, evidence, severities, or tool results.
4. Never commit or log API keys, tokens, cookies, or private finding evidence.
5. Never bypass scope checks, rate limits, or safety controls.
6. Do not submit bounty reports, upstream issues, or external PRs without human authorization.
7. Do not vendor or rewrite Shannon/Briar engines; invoke pinned upstream releases.
8. Prefer Docker isolation for active workers; do not mount the Docker socket into untrusted scanners.
9. Prefer the smallest change that passes tests.
10. Do not claim Docker/tests/PRs succeeded unless verified in this environment.

## Architecture map

See `docs/ARCHITECTURE.md`. Key packages: `core/`, `integrations/`, `providers/`, `scopes/`.

## Common commands

```bash
PEN_ASSUME_YES=1 bash installers/install.sh mcp
./scripts/doctor.sh
./scripts/smoke.sh
python -m core.cli health --tool all
python -m core.cli scope-check --target <url> --category active
python -m core.cli run --tool headers --target http://127.0.0.1:18080/ --category passive
pen-testing-mcp   # MCP stdio server
python -m pytest -q tests/unit
```

MCP assessments default to `dry_run=true`. Live runs require `confirm_authorized=true` after `validate_target_scope`.

Active Shannon/Briar scans require human intent, valid scope, and (for Shannon) Docker.

Client setup: `docs/CLIENT_COMPATIBILITY.md`.

## Development workflow

1. Branch from `main` using `cursor/<name>-39f7` when operating as the cloud agent.
2. Implement + test.
3. Keep secrets and private reports out of git.
4. Open a PR with summary, test evidence, risks, rollback.
5. Merge only when authorized and checks pass.

## Report validation

Findings use the normalized schema in `core/findings/schema.py`. Lifecycle promotions to human-confirmed require a human. Export drafts with `export-report`; do not auto-submit.
