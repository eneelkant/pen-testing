# AI Assistant Setup

Shared source of truth for humans and coding agents: **`AGENTS.md`**.

Client-specific files only point at the shared rules:

| Client | File |
|---|---|
| Cursor | `AGENTS.md`, `.cursor/rules/` |
| Claude | `CLAUDE.md` |
| Gemini | `GEMINI.md` |
| GitHub Copilot | `.github/copilot-instructions.md` |
| Generic LLM crawlers | `llms.txt` |

## What placing Markdown in the repo does **not** do

- It does not install plugins, MCP servers, or browser extensions.
- It does not grant API access or store provider keys.
- It does not authorize penetration tests against any target.

## Suggested local workflow

1. Open this repository in your AI client.
2. Ensure the client loads `AGENTS.md` / project instructions.
3. Run `./scripts/doctor.sh` (or `python -m core.cli doctor`).
4. Configure provider env vars in `.env` only when a tool needs them.
5. Register authorized targets in `scopes/registry.yaml`.
6. Prefer `--dry-run` and local fixtures before any active scan.

## MCP / tool interfaces

If your client supports MCP, expose only local orchestration helpers (doctor, scope-check, report export). Do not expose unbounded shell that can launch active scans without scope checks.

## Public anonymous read access

The GitHub repository is public. Clients may fetch files without GitHub authentication where the GitHub UI/API allows anonymous read. Writing PRs still requires authentication.
