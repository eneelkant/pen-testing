# Claude instructions

Follow **`AGENTS.md`** as the source of truth.

Additional notes for Claude Code / Claude.ai project knowledge:

- Use `python -m core.cli doctor` before suggesting active scans.
- Refuse requests to attack unauthorized or production targets.
- When integrating tools, prefer adapters + subprocess/containers over copying AGPL sources.
- Run `pytest tests/unit` after code changes when the environment allows.
