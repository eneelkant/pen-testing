# MCP Tool Test Matrix

Verification date: **2026-10-12**  
Server: `pen-testing` / `mcp_server.server` / SDK `mcp==2.3.0`

Discovery method: `await mcp.list_tools()` + `mcp.call_tool(name, args)`.

| Tool | Valid input | Missing required | Invalid type/literal | Missing deps / scope | Secrets exposure | Unintended external action | Result |
|---|---|---|---|---|---|---|---|
| `platform_status` | PASS (`ok: true`) | N/A | N/A | Reports docker missing | PASS (no secrets) | PASS (none) | **PASS** |
| `check_dependencies` | PASS | N/A | N/A | PASS lists docker missing | PASS | PASS | **PASS** |
| `validate_target_scope` | PASS allow fixture / deny example.com | PASS ToolError field required | PASS enum/literal via schema | PASS unauthorized deny | PASS | PASS | **PASS** |
| `list_integrations` | PASS shannon/briar/headers/… | N/A | N/A | PASS unhealthy when missing | PASS | PASS | **PASS** |
| `run_local_diagnostics` | PASS `destructive: false` | N/A | N/A | PASS | PASS | PASS | **PASS** |
| `run_security_assessment` | PASS dry-run authorized fixture | PASS requires tool+target | PASS rejects unknown tool | PASS blocks unconfirmed live; scope fail closed | PASS | PASS (dry-run / blocked) | **PASS** |
| `get_assessment_status` | PASS after create | PASS requires id | PASS rejects non-UUID | PASS not found | PASS | PASS | **PASS** |
| `list_findings` | PASS | PASS | PASS rejects non-UUID | PASS not found | PASS | PASS | **PASS** |
| `export_report` | PASS under reports_dir | PASS | PASS rejects non-UUID; rejects escape outdir | PASS not found | PASS | PASS | **PASS** |

## Long-running / cancellation

| Check | Result |
|---|---|
| Diagnostic tools return quickly | PASS |
| Assessment `timeout_seconds` bounds validated (1..86400) | PASS |
| Mid-flight MCP cancellation of upstream Shannon/Briar | NOT IMPLEMENTED (document limitation; use upstream stop CLIs) |

## Protocol / transport

| Check | Result |
|---|---|
| Tool schemas JSON-serializable | PASS |
| Structured content returned | PASS |
| Logging on stderr (stdio-safe) | PASS (hardened) |
| MCP Inspector interactive UI | BLOCKED (deprecated v1 CLI; no headed UI in agent) |
| stdio entrypoint importable | PASS |

## Automated coverage

- `tests/unit/test_mcp_service.py`
- `tests/unit/test_mcp_tool_calls.py`
