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
<<<<<<< HEAD
=======
<<<<<<< HEAD
=======


## Dependency Health & Readiness Semantics

The `check_dependencies` tool distinguishes MCP runtime requirements from the
executable prerequisites used by the Shannon and Briar integrations.

| Field | Meaning |
|---|---|
| `ok` / `core_ok` | Core MCP runtime imports and Python executable are available. |
| `active_engines_ready` | The required engine executables are discoverable on `PATH`; this is not a live Docker-daemon or end-to-end test. |
| `present` | Exact executable paths resolved independently with `shutil.which`; Python uses `sys.executable`. Missing tools remain `None`. |
| `missing_core` | Missing core runtime requirements. |
| `missing_engines` | Missing engine prerequisites such as `docker`, `node`, or `npx`. |
| `optional_absent` | Optional tools missing from `PATH`, such as `git`; these do not make `core_ok` false. |
| `engines` | Per-engine prerequisite readiness for Shannon and Briar. |

The legacy `missing`, `present`, `shannon`, `briar`, and
`recommendations` fields remain available.

`platform_status.diagnostics.tools` retains the original diagnostics collector
shape, including `docker_daemon_ok`, `compose`, and `compose_ok`. The additive
`dependency_tools` field contains the independent executable-path results from
`check_dependencies`. `dependency_failures` remains engine-prerequisite-only
for compatibility; `dependency_failures_scope` labels that meaning,
`core_dependency_failures` reports core runtime failures, and
`all_dependency_failures` combines core and engine failures.
`missing_core`, `missing_engines`, `optional_absent`, and `engines` are also
available in the diagnostics summary.

Engine readiness means only that the configured executable prerequisites were
found on `PATH`. It does not prove the Docker daemon or Compose is usable, nor
that a Shannon/Briar live invocation will succeed. Use the preserved diagnostic
fields for daemon/Compose health. `platform_status.ok` means the status request
completed; it is not an aggregate all-dependencies-healthy flag. Status checks do
not launch scans or guarantee that a live engine invocation will succeed.
>>>>>>> main
>>>>>>> main
