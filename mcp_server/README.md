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
| `plan_assessment` | No | Build a plan; never launches a scanner |
| `authorize_assessment` | No | Issue a bound, expiring, single-use live approval |
| `run_security_assessment` | Maybe | Dry-run by default; live requires `confirm_authorized` + `approval_id` |
| `get_assessment_status` | No | Assessment record |
| `list_findings` | No | Normalized findings |
| `export_report` | No | Draft report export (no auto-submit) |

## Optional local static scanners

Checkov and MobSFScan are optional extras; install them separately with:

```bash
pip install -e '.[checkov,mobsfscan]'
python -m core.cli health --tool checkov
python -m core.cli health --tool mobsfscan
```

They accept only confined local source/configuration paths through the MCP service.
MobSFScan covers mobile source-code patterns only, not APK/IPA binaries or device
runtime testing. Both tools stay unavailable when their pinned dependencies fail
their health checks.

## Capability metadata

The CLI subcommand `pen-testing capabilities` lists integrations with in-repository
adapters. Add `--include-planned` to view roadmap candidates. Planned records are
informational only and are not supported by `run_security_assessment`.

MCP `list_integrations` returns the same metadata alongside runtime health checks.
Typed target descriptors in `core/targets.py` validate syntax only. They do not grant
scope, authorize a host/network, resolve DNS or confine a local path. Existing scope,
egress and filesystem-confinement controls remain required.

## Run

```bash
pip install -e ".[mcp]"
python -m mcp_server.server
# or
pen-testing-mcp
```

## Security

- No arbitrary shell/filesystem tools
- Transport is stdio only (remote/unauthenticated listeners are refused)
- Active assessments require scope + `confirm_authorized` + a bound `approval_id`
- Assessment profiles (for example `zoho_non_destructive`) can disable live execution
- Upstream Shannon/Briar may still navigate beyond the initial URL
- Zoho / third-party hosts must never be probed unless listed in `scopes/registry.yaml`
