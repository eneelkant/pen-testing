# Production Operations — `eneelkant/pen-testing`

**Document scope:** Operational runbook for running the pen-testing MCP server and CLI in production. Covers installation, configuration, health checks, logging, incident response, upgrade/rollback, and known limitations.

**Status:** Phase D draft. Sections marked **TODO** are placeholders for the repo owner to fill in with environment-specific values. Sections marked **VERIFIED** are confirmed against `main@33a6b06`.

---

## 1. Supported platforms

| Platform | Status | Evidence |
|---|---|---|
| Linux x86_64 (Ubuntu LTS, CI runner) | VERIFIED — CI green on `33a6b06` | `test-evidence.md` Section 12 |
| Linux x86_64 (any modern distro with Python 3.10+ and Docker) | VERIFIED at unit level | unit tests pass on Python 3.12.16; Docker-runtime tests delegated to CI |
| macOS | NOT VERIFIED — no macOS runner in CI or this audit | `test-evidence.md` Section 12 |
| Windows | NOT VERIFIED — `scripts/install.ps1` exists; not exercised in CI or this audit | `test-evidence.md` Section 12 |

## 2. Prerequisites

### Runtime

- Python 3.10+ (3.12+ recommended; CI uses 3.12)
- Docker Engine 24+ (for any active assessment that uses Shannon, Briar, or image scans)
- Optional: `node` 20+ and `npx` (for Shannon launcher)
- Optional: `git` (used for source-path confinement checks; absence does not block core MCP)

### Python extras

| Extra | Install | Purpose |
|---|---|---|
| `mcp` | `pip install -e '.[mcp]'` | Required for the MCP stdio server (`pen-testing-mcp`) |
| `dev` | `pip install -e '.[dev]'` | pytest + pytest-cov + mcp (for running tests) |
| `briar` | `pip install -e '.[briar]'` | Briar adapter runtime (pinned `briar-pentest==0.4.62`) |
| `checkov` | `pip install -e '.[checkov]'` | Optional IaC misconfig scanner (`checkov==3.3.29`) |
| `mobsfscan` | `pip install -e '.[mobsfscan]'` | Optional mobile source-pattern scanner (`mobsfscan==1.0.1`) |

### Pinned external images (Docker required)

| Image | Pin | Use |
|---|---|---|
| python:3.12.15-alpine3.24 | `@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d` | probe + orchestrator base |
| keygraph/shannon:3.4.0 | `@sha256:4e726ed8f3a0b10e2a1dbb41185a526f20ea6fccc98740ca553e3c00c2a6bd0e` | Shannon worker |
| temporalio/temporal:1.7.0 | `@sha256:9c5b386d86bca59ba08f32ddc4c51287351c8c616b6a8359f03e96a585e137f4` | Temporal service |
| zricethezav/gitleaks:v8.21.2 | `@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46` | Secret scanning |
| aquasec/trivy:0.76.0 | `@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222` | Image / dependency scanning |

All image refs include immutable `@sha256:` digests. Platform-specific digests (linux/amd64 child manifests) are in `core/supply_chain/images.py:PINNED_IMAGES`.

## 3. Installation (clean environment)

```bash
git clone https://github.com/eneelkant/pen-testing.git
cd pen-testing
python -m venv .venv
.venv/bin/pip install -U pip
.venv/bin/pip install -e '.[mcp,dev]'
.venv/bin/python -m pytest tests/unit --tb=short
```

Expected: `554 passed` on Python 3.12 with `mcp==2.3.0`. (CI verifies the same on Ubuntu.)

## 4. Configuration

### Required environment variables

| Variable | Purpose | Example |
|---|---|---|
| `PEN_REPORTS_DIR` | Reports/artifact root for assessments | `/var/lib/pen-testing/reports` |
| `PEN_WORK_DIR` | Working directory for in-flight assessments | `/var/lib/pen-testing/work` |
| `PEN_SCOPES_FILE` | Path to authorization registry | `/etc/pen-testing/scopes/registry.yaml` |

### Authorization registry

The registry at `scopes/registry.yaml` is the source of truth for what targets may be probed. Format:

```yaml
- target_id: zoho-bounty-portal
  program: Zoho VRP
  asset_patterns:
    - "*.bugbounty.zoho.com"
    - "bugbounty.zoho.com"
  categories: [passive, active]
  expires_at: "2026-12-31T23:59:59Z"
  non_production: false
```

**TODO (owner):** Document the actual production `scopes/registry.yaml` (do not commit the production file — it may contain private target lists).

### Optional assessment profiles

`configs/assessment_profiles/*.yaml` defines per-program profiles that can disable live execution, set rate limits, or constrain categories. See `zoho_non_destructive.yaml` and `zoho_bugbounty_portal_headers.yaml` for examples.

## 5. Running the MCP server (stdio)

```bash
.venv/bin/pen-testing-mcp
```

The server speaks stdio only — remote/unauthenticated listeners (SSE, streamable HTTP) are explicitly refused by `mcp_server/server.py:assert_supported_transport`.

### With Claude Code

PR #54 added `.mcp.json` and `.claude-plugin/{marketplace,plugin}.json` for Claude Code marketplace integration. Configuration:

```json
{
  "mcpServers": {
    "pen-testing": {
      "command": "uv",
      "args": ["run", "--directory", "${CLAUDE_PLUGIN_ROOT}", "--extra", "mcp", "pen-testing-mcp"]
    }
  }
}
```

## 6. Health and readiness checks

| Check | Command | Expected |
|---|---|---|
| Server boots | `pen-testing-mcp --help` (or stdio handshake) | No traceback |
| All 11 tools registered | `python -c "import asyncio; from mcp_server.server import mcp; print(len(asyncio.run(mcp.list_tools())))"` | `11` |
| Dependency readiness | `pen-testing capabilities` (CLI) or call `check_dependencies` MCP tool | Reports `core_ok=True`, lists `missing_engines` |
| Docker daemon health | `python -c "from mcp_server import service; print(service.check_dependencies())"` | `engines.docker=True` if Docker is running |
| Image baseline freshness | `python -m core.supply_chain images --baseline core/supply_chain/image_baseline.json --output /tmp/scan.json` | Exit `0` if no new findings vs baseline; non-zero if new blockers |

## 7. Logging, audit events, troubleshooting

### Audit log

The MCP server emits structured JSON audit events to stderr (captured by the MCP client). Example:

```json
{"event": "shannon.blocked", "timestamp": "2026-10-29T03:53:09.359414+00:00",
 "reason": "Scope check failed: No explicit authorization record matches the target. Public accessibility alone is not authorization.",
 "target": "https://staging.example.invalid"}
```

### Common errors

| Error | Cause | Resolution |
|---|---|---|
| `Authorization registry required for active assessments` | No `scopes/registry.yaml` file at `PEN_SCOPES_FILE` | Create the registry; see Section 4 |
| `confirm_authorized=true` required | Non-dry-run assessment requested without confirmation | Add `confirm_authorized=true` AND obtain a bound `approval_id` via `authorize_assessment` first |
| `MCP transport 'X' is refused` | Remote transport requested | Use stdio only — the server does not authenticate remote clients |
| `Approval expired` | `approval_id` TTL (default 900s) exceeded | Call `authorize_assessment` again for a fresh approval |
| `Plan fingerprint mismatch` | Tool, target, category, mode, or profile changed between `authorize_assessment` and `run_security_assessment` | Call `plan_assessment` → `authorize_assessment` → `run_security_assessment` with the same parameters |

## 8. Concurrency, resource limits, disk usage

| Resource | Limit | Source |
|---|---|---|
| Concurrent live assessments | 1 (single global slot) | `core/scope/rate_limit.py:acquire_scan_slot` / `release_scan_slot` |
| Per-assessment timeout | 1–86,400 seconds (default 120) | `mcp_server/service.py:run_security_assessment` |
| Assessment ID format | UUIDv4 | `mcp_server/service.py:_ASSESSMENT_ID_RE` |
| Output directory | `$PEN_REPORTS_DIR/mcp-{assessment_id}/` | `mcp_server/service.py:run_security_assessment` |
| Path traversal | Blocked — paths must resolve inside configured work/report roots | `core/paths.py:safe_write_text` |

### Disk usage monitoring

Each assessment writes:
- One JSON record at `$PEN_REPORTS_DIR/mcp-{assessment_id}/record.json`
- Adapter-specific artifacts (logs, raw scanner output, normalized findings) under the same directory
- Exported reports at `$PEN_REPORTS_DIR/export-out/` (Markdown, JSON, SARIF)

**TODO (owner):** Configure retention policy in `core/ops/retention.py` to auto-delete assessments older than N days. Default is no auto-deletion.

## 9. Worker lifecycle and orphan cleanup

Shannon and Briar workers run as Docker containers. The MCP server does NOT auto-start workers — they must be started via `docker-compose up -d` separately.

**Orphan cleanup:** `docker-compose down -v` removes worker containers and volumes. The MCP server does not track or clean orphaned containers; the operator is responsible.

**TODO (owner):** Document the operator runbook for orphaned-worker cleanup (e.g. `docker ps -q --filter "name=shannon-worker-" \| xargs -r docker rm -f`).

## 10. Backup / recovery

The MCP server is stateless across restarts (approvals are in-memory; assessments are persisted to `$PEN_REPORTS_DIR` as JSON files).

**To back up:** Copy `$PEN_REPORTS_DIR` and `$PEN_WORK_DIR` to a separate location. No database to dump.

**To restore:** Copy the directories back to the original paths and restart the MCP server.

## 11. Data retention and secure deletion

| Data type | Location | Default retention | Secure deletion |
|---|---|---|---|
| Assessment records | `$PEN_REPORTS_DIR/mcp-{id}/` | No auto-deletion | `rm -rf` (filesystem-level; no shredding) |
| Audit logs | stderr of MCP server process | Captured by client's log rotation | Client-managed |
| Approvals | In-memory (`ApprovalStore` singleton) | TTL 900s | Expire automatically; no persisted state |
| Image scan raw evidence | `image-scan-raw/` (CI) | Per CI artifact retention | CI-managed |

**TODO (owner):** Configure retention policy in `core/ops/retention.py` and document in this section.

## 12. Incident response

### If a credentials leak is suspected

1. **Revoke** any potentially exposed tokens/keys at the source (GitHub PATs: https://github.com/settings/personal-access-tokens; cloud credentials: cloud provider's IAM console).
2. **Rotate** all credentials that may have been exposed.
3. **Audit** the audit log for unexpected `shannon.started` / `briar.started` / `run_security_assessment` events with `dry_run=false`.
4. **Notify** the program owners of any targets that may have been probed without authorization.

### If an unauthorized assessment was executed

1. **Stop** the MCP server (`pkill -f pen-testing-mcp`).
2. **Quarantine** the affected assessment records: `mv $PEN_REPORTS_DIR/mcp-{id} /var/pen-testing/incidents/{date}/`.
3. **Review** the audit log to determine the scope of the unauthorized activity.
4. **Notify** the affected program owners and the repo owner.

### If a worker is stuck or orphaned

1. **List** running workers: `docker ps --filter "name=shannon-worker-" --filter "name=briar-"`.
2. **Stop** orphans: `docker rm -f <container_id>`.
3. **Verify** no orphaned processes: `ps aux | grep pen-testing`.

## 13. Credential rotation

| Credential | Rotation cadence | Rotation procedure |
|---|---|---|
| GitHub PAT (for CI merges) | 90 days | Generate new fine-grained PAT at https://github.com/settings/personal-access-tokens; update GitHub Actions secrets; revoke old PAT |
| Docker Hub pull credentials (if used) | 90 days | Update `docker-login` secrets; revoke old tokens |
| Briar / Shannon API keys (if used) | Per program owner policy | Update environment variables; restart MCP server |

**DO NOT** commit credentials to the repository. Use environment variables or a secrets manager.

## 14. Upgrade, rollback, migration

### Upgrade procedure

1. **Read** the `CHANGELOG.md` for breaking changes since the current version.
2. **Pin** the new commit SHA in your deployment config.
3. **Pull** the new code: `git fetch && git checkout <sha>`.
4. **Reinstall** dependencies: `.venv/bin/pip install -e '.[mcp,dev]'`.
5. **Run** the unit test suite: `.venv/bin/python -m pytest tests/unit --tb=short`.
6. **Restart** the MCP server: `pkill -f pen-testing-mcp && pen-testing-mcp &`.
7. **Verify** 11 tools registered (Section 6).

### Rollback procedure

1. **Stop** the MCP server.
2. **Checkout** the previous known-good SHA: `git checkout <previous_sha>`.
3. **Reinstall** dependencies.
4. **Restart** the MCP server.
5. **Verify** 11 tools registered.

### Migration (across major versions)

**TODO (owner):** Document any breaking migrations (e.g. changes to `scopes/registry.yaml` schema, assessment record format changes) in `CHANGELOG.md` and reference them here.

## 15. Licensing, third-party notices, vulnerability response

| Item | Source | Status |
|---|---|---|
| License | `LICENSE` (Apache-2.0) | VERIFIED |
| Third-party notices | `THIRD_PARTY_NOTICES.md` | EXISTS — content not fully audited in Phase A |
| Vulnerability response | `SECURITY.md` | EXISTS — content not fully audited in Phase A |
| Vulnerability disclosure policy | (in `SECURITY.md`) | TODO — review in Phase D |

## 16. Known limitations and unsupported assessment modes

See `capability-matrix.md` for the authoritative list. Headlines:

- **No web DAST adapters.** OWASP ZAP and Nuclei are not integrated. Passive HTTP security-header checks ARE supported.
- **No API security adapters.** OpenAPI/Swagger validation, GraphQL support, and Schemathesis are not integrated.
- **No general SAST.** Gitleaks covers secrets only. Semgrep or equivalent is not integrated.
- **No network/host testing.** Nmap is not integrated.
- **Limited mobile testing.** `mobsfscan` covers source-code patterns only. No APK/IPA binary scanning, no MobSF service adapter, no Android emulator, no iOS runtime testing.
- **Single concurrent live assessment.** Rate limiter enforces one slot globally. Multiple concurrent assessments are blocked.
- **Stdio MCP only.** Remote MCP transports (SSE, streamable HTTP) are refused.
- **Image-vulnerability baseline is inherited and not a waiver.** See `release-checklist.md` criterion 1 and issue #52.
- **Briar demo mode bypasses confirm_authorized and skip_scope_check.** Documented exception in `mcp_server/service.py:643`; threat model TODO in this document (Section 17).

## 17. Threat model summary

| Trust boundary | Trust assumption | Enforcement |
|---|---|---|
| MCP client ↔ MCP server | Client is trusted (stdio only; no remote transport) | `assert_supported_transport` in `mcp_server/server.py` |
| MCP server ↔ Adapter | Adapters receive validated targets + scoped profiles | `validate_profile_request`, `_confine_local_scan_path`, `engine.require` |
| Adapter ↔ External target | Target must be in `scopes/registry.yaml`; redirect-stays-in-scope enforced | `core/scope/engine.py`, `core/scope/target.py:validate_redirect_stays_in_scope` |
| Adapter ↔ Local filesystem | Paths must resolve inside `$PEN_REPORTS_DIR` / `$PEN_WORK_DIR` | `core/paths.py:safe_write_text` |
| Adapter ↔ Docker daemon | Worker network egress confined; loopback/private/link-local/metadata blocked | `core/net/ssrf.py`, `core/isolation/egress.py`, `core/isolation/destination_policy.py` |
| MCP server ↔ Approval store | Approvals are bound (target+tool+profile+plan_fingerprint), TTL'd, single-use | `core/scope/approval.py:ApprovalStore.consume` |

**TODO (owner):** Expand this section with a detailed data-flow diagram and per-flow threat analysis in Phase D.

---

## TODO list for Phase D completion

- [ ] Fill in production `scopes/registry.yaml` (Section 4) — outside the repo
- [ ] Configure retention policy (Section 8, 11) — code change in `core/ops/retention.py`
- [ ] Document orphan-worker cleanup runbook (Section 9)
- [ ] Review `SECURITY.md` and `THIRD_PARTY_NOTICES.md` (Section 15)
- [ ] Expand threat model (Section 17)
- [ ] Verify `release.yml` artifact-retention and SBOM-on-release behavior
