# Independent review bundle (preparation)

**Date:** 2026-10-25 (Asia/Calcutta)  
**Head described:** `main` @ `be3a023cad79f86f2158d19784f4a8c03da192e5` plus open readiness PRs  
**Status:** Bundle for a human reviewer. **Not** a completed external security review. **Not** legal clearance.

## Scope

Single-operator authorized-testing orchestrator: stdio MCP, Docker Compose, Shannon/Briar adapters, digest-pinned supply chain. Public multi-tenant SaaS is out of scope.

## Read first

1. `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/NETWORK_ARCHITECTURE.md`, `docs/SCANNER_ISOLATION.md`
2. `docs/EXTERNAL_SECURITY_REVIEW.md` (request list — engagement not commissioned)
3. `docs/PRODUCTION_READINESS_PLAN.md` (gap register G1–G14)
4. `docs/IMAGE_BASELINE.md` (merge regression vs absolute release gates)
5. `docs/LICENSING_REVIEW.md` + `THIRD_PARTY_NOTICES.md`

## Code paths

| Area | Paths |
|---|---|
| MCP transport / tools | `mcp_server/server.py`, `mcp_server/service.py` |
| Scope / rate limits | `core/scope/`, `integrations/base.py` |
| Isolation / egress | `core/isolation/`, `docker/egress-gateway/`, `docker-compose.yml` |
| Data protection | `core/ops/crypto.py`, `core/ops/backup.py`, `core/paths.py` |
| Supply chain | `core/supply_chain/images.py`, `baseline.py`, `image_baseline.json` |
| CI / release | `.github/workflows/ci.yml`, `release.yml`, `image-candidate-monitor.yml` |

## Runtime / CI evidence (verified)

| Check | Result | Evidence |
|---|---|---|
| Unit tests (local) | PASS 374–378 depending on open PR head | `pytest tests/unit` |
| Main CI `40153361168` | Lint/Docker/Gitleaks/Deps/Regression **success**; Absolute images **failure** | GitHub Actions |
| Absolute upstream | Shannon 980 / Temporal 58 / Gitleaks 41 / Trivy 6 = **1085** | `image-scan-upstream` artifact |
| Python Alpine pin | PASS blocking 0 | same run |
| Candidates 2026-10-25 | `NO_ACCEPTABLE_CANDIDATE` | host Trivy DB UpdatedAt 2026-10-25T01:20:33Z |
| Baseline | Approved `neelkantekbote-66degree`; expires 2026-11-25 | `image_baseline.json` |

Raw scanner JSON from CI should be downloaded by the reviewer (`gh run download 40153361168`). Do not treat inherited baseline findings as fixed.

## Remaining known risks (not waived)

- Upstream image absolute gate red until vendors ship clean digests (or an evidence-backed policy change that is **not** proposed here).
- Browser clients that ignore `HTTP(S)_PROXY` are not intercepted; containment is Docker `Internal=true`.
- No multi-user authentication; stdio MCP trusts the local operator.
- Admin branch-protection bypass may still be possible (`enforcement_level: non_admins`).
- AGPL counsel questions unanswered.

## Reviewer actions

1. Independent maintainer (`neelkantekbote-66degree` if still authorized): review security PRs on GitHub; do not rubber-stamp.
2. Commission external review per `docs/EXTERNAL_SECURITY_REVIEW.md`.
3. Route `docs/LICENSING_REVIEW.md` to qualified counsel before any production distribution claim.
4. Administrator: enforce CODEOWNERS + disable admin bypass on `main`.

## Non-claims

This bundle does not assert production readiness, completed external review, or legal clearance.
