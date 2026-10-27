# Independent review bundle (preparation)

**Date:** 2026-10-25 (Asia/Calcutta)  
**Head described:** `main` @ `be3a023cad79f86f2158d19784f4a8c03da192e5` plus open readiness PRs (re-check `main` before starting)  
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

## Review status

| Review | Status |
|---|---|
| Independent external security review | **Not commissioned, not completed.** `docs/EXTERNAL_SECURITY_REVIEW.md` is a request list only. |
| Qualified counsel licence review | **Not commissioned, not completed.** `docs/LICENSING_REVIEW.md` lists the questions. |
| Maintainer PR reviews on GitHub | Per-PR code review by an independent maintainer. These are **not** an external security review and are tracked on each PR, not here. |
| Internal / AI-assisted audits | Engineering input only. Not a substitute for either review above. |

## Runtime / CI evidence

Current gate results, counts, run links and candidate decisions are maintained in one place: `docs/PRODUCTION_READINESS_PLAN.md` ("Current state"). This bundle does not repeat them, so it cannot drift from that record. The reviewer should download raw scanner JSON from the linked runs (`gh run download <run-id>`) rather than rely on summaries, and should not treat inherited baseline findings as fixed.

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
