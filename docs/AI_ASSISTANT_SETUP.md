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

1. Install with `PEN_ASSUME_YES=1 bash installers/install.sh mcp`.
2. Open this repository in your AI client.
3. Ensure the client loads `AGENTS.md` / project instructions.
4. Configure MCP using `docs/CLIENT_COMPATIBILITY.md` helpers.
5. Run `./scripts/doctor.sh` (or `python -m core.cli doctor`).
6. Configure provider env vars in `.env` only when a tool needs them.
7. Register authorized targets in `scopes/registry.yaml`.
8. Prefer dry-run MCP/CLI paths and local fixtures before any active scan.

## MCP / tool interfaces

Use the packaged stdio server (`pen-testing-mcp` / `python -m mcp_server.server`). It exposes only the documented tool set — not arbitrary shell or filesystem access. Live assessments still require scope validation and `confirm_authorized`.

## Public anonymous read access

The GitHub repository is public. Clients may fetch files without GitHub authentication where the GitHub UI/API allows anonymous read. Writing PRs still requires authentication.
