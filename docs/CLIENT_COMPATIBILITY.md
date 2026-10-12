# Client Compatibility Matrix

Verification date: **2026-10-12**. Client products change frequently — re-check official docs before production use.

| Client | Integration mode | Config artifact | Automated installer | Config verified | E2E connection |
|---|---|---|---|---|---|
| **Cursor** | Local MCP stdio | `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` | `installers/configure_cursor.py` | PASS | BLOCKED (no Cursor Desktop in CI/agent) |
| **Claude Desktop** | Local MCP stdio | `claude_desktop_config.json` | `installers/configure_claude.py` | PASS | BLOCKED (app not installed) |
| **Claude web** | N/A for local stdio | — | — | NOT APPLICABLE | NOT APPLICABLE |
| **Gemini CLI / local tooling** | Client-specific MCP settings | Often `~/.gemini/settings.json` (varies) | `installers/configure_gemini.py` print + optional apply | PASS (print) | BLOCKED / Partial — verify your Gemini build |
| **Gemini web** | No local stdio MCP | — | — | NOT APPLICABLE | Unsupported |
| **ChatGPT** | Remote connector / developer MCP (plan-dependent) | HTTPS endpoint + auth | Manual — see `examples/chatgpt_remote_mcp.example.env` | PASS (docs/example only) | BLOCKED — no public HTTPS deploy |

Shared rules: **`AGENTS.md`**. Setup narrative: **`docs/AI_ASSISTANT_SETUP.md`**.

## Cursor

Official docs: https://cursor.com/docs/mcp

```bash
python installers/configure_cursor.py --print-only
python installers/configure_cursor.py --apply   # project .cursor/mcp.json with backup
```

Restart Cursor / reload MCP. Confirm the `pen-testing` server connects under Settings → MCP.

## Claude Desktop

Official local MCP docs: https://modelcontextprotocol.io/docs/2026-07-28/develop/connect-local-servers

```bash
python installers/configure_claude.py --print-only
python installers/configure_claude.py --apply
```

Fully quit and reopen Claude Desktop. Absolute Python paths are recommended.

## Gemini

Do **not** assume Gemini CLI, IDE plugins, and web apps share one schema.

```bash
python installers/configure_gemini.py --print-only
# Only if your Gemini CLI uses mcpServers in ~/.gemini/settings.json:
python installers/configure_gemini.py --apply-gemini-cli
```

## ChatGPT

ChatGPT does not load a local stdio process from this repository the way Cursor/Claude Desktop do.

Typical requirements (verify against current OpenAI docs):

- Eligible plan / developer mode / admin connector policy
- Publicly reachable **HTTPS** MCP endpoint
- Authentication in front of the service

This project can speak Streamable HTTP via the MCP SDK, but **no public remote deployment is enabled by default**. See `examples/chatgpt_remote_mcp.example.env`. Never expose an unauthenticated MCP port to the internet.

## What Markdown files do **not** do

Placing `AGENTS.md` / `CLAUDE.md` / `GEMINI.md` in the repo does not install MCP servers or grant network permissions.
