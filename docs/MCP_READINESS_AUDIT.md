# MCP Readiness Audit

Audit date: **2026-10-12**  
Baseline `main` commit: `25fec5093db6b96dea30e4b55e1ff406f0509626` (PR #1 merge)  
Audit branch head: see final report / latest commit on `cursor/mcp-audit-hardening-39f7`

## Summary

MCP is **implemented and usable** for local stdio diagnostics and dry-run orchestration via the official Python SDK (`mcp` 2.3.0). Nine tools are registered and call-tested. Docker runtime remains **BLOCKED** in this environment. ChatGPT remote end-to-end connection is **BLOCKED** (no public HTTPS deployment).

## Implementation facts

| Item | Finding | Status |
|---|---|---|
| Package | `mcp_server/` | PASS |
| Entry point | `python -m mcp_server.server` / `pen-testing-mcp` | PASS |
| SDK | `mcp==2.3.0` (`MCPServer`) | PASS |
| Transport | stdio (default); Streamable HTTP available in SDK but not productized | PASS / documented |
| Tool count | 9 | PASS |
| Arbitrary shell/FS tools | None exposed | PASS |
| Active scans on startup | No | PASS |

## Baseline tests (pre-fix)

| Check | Result |
|---|---|
| `pytest` on `main` | PASS — 47 passed, 1 skipped (historical baseline before audit hardening) |
| `scripts/smoke.sh` | PASS |
| Docker Engine | BLOCKED — not installed |
| Branch protection API | BLOCKED — token cannot read protection settings (403) |

## Post-fix verification (this branch)

| Check | Result |
|---|---|
| `python3 -m pytest -q tests/unit` | PASS — **63 passed** |
| `bash scripts/smoke.sh` | PASS |
| MCP tool discovery (`mcp.list_tools`) | PASS — 9 tools |
| Docker Engine / Compose runtime | BLOCKED — `docker: command not found` |
| Cursor / Claude / Gemini UI E2E | BLOCKED — clients not installed in agent VM |
| ChatGPT remote HTTPS connector | BLOCKED / NOT APPLICABLE locally |

## Defects found and fixed in this audit

| Defect | Severity | Fix |
|---|---|---|
| `export_report(outdir=...)` could write outside project dirs | High | Confine outdir to `reports_dir` / `work_dir` |
| `get_assessment_status` / `list_findings` / `export_report` accepted path-like IDs | High | Require UUID assessment IDs |
| `validate_target_scope("not-a-url")` fell through to scope match | Medium | Require absolute http(s) URL with hostname |
| Logging handler not explicitly bound to stderr | Medium | Force `StreamHandler(sys.stderr)` + `propagate=False` |

## Environment

| Dependency | Result |
|---|---|
| Python 3.12.3 | PASS |
| `mcp` 2.3.0 | PASS |
| PyYAML / jsonschema | PASS |
| Node/npx (Shannon launcher) | PASS |
| Docker / Compose | BLOCKED |
| Briar in system Python | FAIL (expected) — optional isolated venv |
| Shannon CLI via npx | PASS (version 3.4.0); workers need Docker |

## Client integration (config artifacts)

| Client | Result |
|---|---|
| Cursor project `.cursor/mcp.json` | PASS (present); E2E Cursor UI BLOCKED (no Cursor Desktop here) |
| Claude Desktop helper | PASS (script); E2E BLOCKED (app not installed) |
| Gemini helper | PASS (print/optional apply); E2E BLOCKED |
| ChatGPT remote | NOT APPLICABLE locally — requires authenticated HTTPS connector |

## Residual risks

1. Shannon/Briar browser/egress not fully contained by scope preflight.
2. DNS rebinding / private-IP pivot after redirect not fully enforced for upstream engines.
3. Docker image builds not runtime-verified in this environment.
4. Briar remains upstream Alpha.
