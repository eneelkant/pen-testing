# Zoho assessment baseline

**Branch inspected:** `main` @ `06bef95` (fast-forwarded), work on `cursor/zoho-assessment-hardening-d1de`  
**Baseline date:** 2026-10-27 (Asia/Calcutta)  
**Unit tests at inspection:** `508 passed` (`python3 -m pytest -q tests/unit`) before hardening changes  
**Live Zoho probing during this task:** none

This document records the repository state before and during Zoho-workflow hardening. It is not authorization to test Zoho systems.

## Architecture (verified)

| Area | Location | Observation |
|---|---|---|
| Orchestration / CLI | `core/` | Config, scope, execution, findings, reporting, retention, SBOM |
| MCP stdio server | `mcp_server/` | Constrained tools; remote transports refused |
| Adapters | `integrations/` | Shannon, Briar, headers, gitleaks, trivy, checkov, mobsfscan |
| Capability registry | `core/capabilities.py` | Integrated vs planned; planned not dispatchable |
| Typed targets | `core/targets.py` | Syntax only — not authorization |
| Scope registry | `scopes/registry.yaml` | Local fixture + expired demo only; no Zoho hosts |
| Isolation | `docker-compose.yml`, `core/isolation/` | Internal scanner nets, dual-gate live env flags |
| CI | `.github/workflows/ci.yml` | Unit, MCP surface, smoke, Docker runtime, image gates, gitleaks |

## Safety gates present before this work

- Default-deny scope engine with exact host matching (no subdomain expansion)
- MCP `dry_run=true` default; live required `confirm_authorized=true`
- Dual-gate env disables (`PEN_ALLOW_*` companions)
- Live Shannon/Briar require `PEN_ALLOW_SHANNON_LIVE` / `PEN_ALLOW_BRIAR_LIVE`
- Host Briar requires `PEN_ALLOW_BRIAR_HOST_NET`
- Launch-time DNS / non-public destination policy
- Compose: non-root, `cap_drop: ALL`, no Docker socket on workers, internal nets
- Finding lifecycle refuses AI auto-promotion to human-confirmed
- Assessment path confinement, redaction, encryption options

## Confirmed gaps (pre-hardening)

| Gap | Impact | Status in this change set |
|---|---|---|
| `confirm_authorized` was a boolean, not bound to target/tool/plan/expiry | Live approval could be reused conceptually across requests | Fixed: `plan_assessment` + `authorize_assessment` + bound `approval_id` |
| No Zoho-oriented assessment profile | Easy to enable destructive/active tools accidentally | Added `configs/assessment_profiles/zoho_non_destructive.yaml` (live disabled) |
| Validation status for Zoho-style review incomplete | Scanner high severity could be mistaken for validated | Added `ValidationStatus` + evidence policy |
| Scope records lacked schemes/ports/live flag/policy audit fields | Weaker authorization-first model | Extended with backward-compatible defaults |
| Report Markdown did not escape hostile titles | Downstream viewer injection risk | Escaped in export |
| Official Zoho program terms not captured in-repo | Operators could rely on stale memory | Added `docs/ZOHO_PROGRAM_REQUIREMENTS.md` |
| Rate-limit field was process-local only | Documented limitation remains | Unchanged; still process-local |
| Upstream browser navigation containment | Residual — not claimed | Unchanged |
| Absolute image vulnerability gate | Release blocked by pinned-image CVEs | Unchanged; not waived |

## Environment flags (verified defaults)

| Flag | Default | Notes |
|---|---|---|
| `PEN_ALLOW_BRIAR_LIVE` | false | Required for live Briar |
| `PEN_ALLOW_BRIAR_HOST_NET` | false | Extra ack for host exec |
| `PEN_ALLOW_SHANNON_LIVE` | false | Required for live Shannon |
| `PEN_ALLOW_SHANNON_UNCONTAINED_NET` | false | Skip controlled net prepare |
| `PEN_ALLOW_SHANNON_FULL_PIPELINE` | false | Full exploit pipeline |
| `PEN_BRIAR_EXEC` | compose | `host` needs host-net ack |
| `PEN_REQUIRE_SCOPE` | true | Disable needs `PEN_ALLOW_SCOPE_DISABLE` |
| `PEN_REQUIRE_EGRESS_POLICY` | true | Disable needs `PEN_ALLOW_EGRESS_DISABLE` |

Empty / unset values do not enable live gates (`_truthy` treats empty as default).

## Integrations and runtime requirements

| Tool | Runtime | Live remote? |
|---|---|---|
| headers | In-process HTTP | Yes, scope + approval gated |
| Shannon | Node/npx + Docker worker | Yes, plus live env gates |
| Briar | venv or Compose worker | Yes, plus live env gates |
| gitleaks / trivy / checkov / mobsfscan | Local confined paths | No remote URL scope |

## CI status

CI workflows exist for unit tests, Docker runtime isolation, secret scanning, dependency metadata, and pinned-image regression. Absolute image release gate remains a known production blocker per `docs/PRODUCTION_READINESS_PLAN.md`. This task does not claim those gates passed for a release.

## Production readiness

Platform version `0.2.0a18` remains **controlled testing / not production-ready**. Ready for **manual, authorized** assessment preparation using synthetic fixtures and human review — not for unrestricted Zoho scanning.
