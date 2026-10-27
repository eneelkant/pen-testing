# MCP Server — pen-testing platform

Official MCP Python SDK (`mcp` 2.x) stdio server exposing constrained orchestration tools.

## Tools

| Tool | Destructive? | Purpose |
|---|---|---|
| `platform_status` | No | Health overview |
| `check_dependencies` | No | Missing deps |
| `validate_target_scope` | No | Authorization check |
| `list_integrations` | No | Adapter capabilities |
| `run_local_diagnostics` | No | Combined non-destructive checks |
| `run_security_assessment` | Maybe | Dry-run by default; live requires `confirm_authorized` |
| `get_assessment_status` | No | Assessment record |
| `list_findings` | No | Normalized findings |
| `export_report` | No | Draft report export |

The existing `list_integrations` MCP tool includes registry metadata for each implemented adapter: supported target types and modes, authorization requirements, dependencies, upstream source, license, isolation profile and known limitations. Planned integrations are not listed as available.

## Run

```bash
pip install -e ".[mcp]"
python -m mcp_server.server
# or
pen-testing-mcp
```

## Security

- No arbitrary shell/filesystem tools
- Active assessments require scope + explicit confirmation
- Upstream Shannon/Briar may still navigate beyond the initial URL
