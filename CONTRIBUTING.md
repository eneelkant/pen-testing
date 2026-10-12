# Contributing

Thanks for helping improve the pen-testing orchestration platform.

## Ground rules

1. Read `AGENTS.md` and `docs/SOURCE_AUDIT.md`.
2. Do not add exploit payloads or target unauthorized systems in tests.
3. Prefer adapters + mocks/fixtures.
4. Preserve license attribution in `THIRD_PARTY_NOTICES.md`.
5. Keep PRs focused and tested.

## Workflow

1. Fork/branch from `main`
2. Implement the smallest maintainable change
3. Run `make test` and `make smoke`
4. Ensure `doctor` still produces useful diagnostics
5. Open a PR with summary, test evidence, risks, and rollback notes

## Code style

- Python 3.10+ typing where practical
- No hardcoded secrets
- Fail closed on missing authorization for active tools
