# FYERS Assessment Baseline

**Status:** Repository hardening baseline only. This document is not authorization to assess FYERS production systems.

**Retrieval / inspection date:** 2026-10-27 (Asia/Calcutta)  
**Source repository:** https://github.com/eneelkant/pen-testing  
**Baseline commit (after rebase onto `origin/main`):** `06bef95` (`docs: redesign README with beginner-friendly diagrams and MCP quick start (#45)`)  
**Working branch:** `cursor/fyers-bounty-readiness-97ed`  
**Working tree at inspection:** clean before feature changes

## Baseline commands and results

| Check | Command | Result |
|---|---|---|
| Unit suite | `python -m pytest -q tests/unit` | **508 passed** (11.30s) on Python 3.12.3 after rebase |
| Platform version | `from core import __version__` | `0.2.0a18` |
| Live FYERS assessment | — | **Not run** (explicitly out of scope for this work) |

Environment notes: a local `.venv` was created in this cloud workspace because none was present. `python3-venv` was installed via apt to enable it.

## Architecture (existing)

| Area | Location | Notes |
|---|---|---|
| Scope / authz registry | `core/scope/`, `scopes/registry.yaml` | Default-deny; exact/host match; expiry; production active blocked by default |
| Redirect origin checks | `core/scope/target.py` | Same-origin only for platform-owned redirect following |
| Destination / SSRF helpers | `core/net/ssrf.py`, `core/isolation/` | Headers + launch-time egress; not Shannon/Briar in-engine containment |
| MCP tools | `mcp_server/service.py`, `mcp_server/server.py` | Dry-run default; live needs `confirm_authorized=true` |
| Adapters | Shannon, Briar, headers, gitleaks, trivy, checkov, mobsfscan | Pinned upstream; Docker isolation for active workers |
| Findings | `core/findings/` | Normalize + pattern redaction; lifecycle does not auto-promote to human-confirmed |
| Typed targets / capabilities | `core/targets.py`, `core/capabilities.py` | Syntax/metadata only; not authorization |
| Assessment profiles | — | **Missing** at baseline |
| Bound execution approvals | — | **Missing**; live gate is boolean `confirm_authorized` |
| Synthetic financial / auth fixtures | — | **Missing** (headers/LLM/redirect fixtures only) |
| FYERS docs / non-destructive profile | — | **Missing** |

Executable registry assets at baseline are local fixtures only (`http://127.0.0.1:18080/` …) plus an intentionally expired example. No FYERS production hosts are present.

## Live-execution entry points

1. MCP `run_security_assessment(..., dry_run=false, confirm_authorized=true)`
2. CLI `python -m core.cli run --live ...` (plus Shannon/Briar live env dual-gates)
3. Adapter `run()` after `preflight` / `egress_preflight`

Dry-run paths must not launch scanners. Live Shannon/Briar additionally require operator env gates (`PEN_ALLOW_SHANNON_LIVE`, `PEN_ALLOW_BRIAR_LIVE`, etc.).

## Existing controls relevant to financial apps

Present: scope registry, redirect same-origin checks, rate/concurrency budgets, assessment UUID confinement, pattern redaction, optional Fernet encryption, Docker internal networks, evidence lifecycle starting at `candidate`.

Gaps confirmed at baseline (to address in this branch):

1. No expiring, single-use approval bound to target + profile + category + plan.
2. `confirm_authorized=true` is a client-supplied boolean, not independent proof of authorization.
3. No assessment profile that disables live execution and transaction capabilities by default.
4. Redaction lacks OTP / cookie / session / account-oriented patterns beyond generic token shapes.
5. No synthetic auth / account-isolation / trading-integrity mock for local regression.
6. Finding validation statuses do not include quarantine states such as `blocked` / `duplicate` / `rejected` as first-class evidence gates.
7. No FYERS program mapping, threat model, runbook, or manual disclosure template.

## Known CI / release blockers (pre-existing)

See `docs/READINESS_SCORECARD.md`, `docs/IMAGE_BASELINE.md`, and `docs/THREAT_MODEL.md`. Absolute image gates may still fail for Shannon/Temporal/Gitleaks/Trivy upstream findings tracked in baseline. This FYERS readiness work must not lower those gates.

## Safety stance for this effort

- No live requests to FYERS hosts.
- No trading, fund movement, OTP sending, credential stuffing, or customer enumeration.
- Synthetic hostnames such as `fyers-api.example.test` are fixtures only.
- Vulnerability reports are never auto-submitted.
