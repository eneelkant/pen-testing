# Production readiness plan

**Status:** Working plan for `0.2.0a18` on `main` @ `be3a023cad79f86f2158d19784f4a8c03da192e5`.  
**Verdict:** Controlled testing. **Not production-ready.** Absolute image gate blocks any release tag.  
**Plan date:** 2026-10-25 (Asia/Calcutta). Evidence under `/tmp/prod-readiness-evidence/latest/` (not committed).

This document tracks gaps, owners, and acceptance tests. It does not waive findings, invent approvals, or authorize a release.

## Verified starting state (2026-10-25)

| Item | Evidence |
|---|---|
| `origin/main` SHA | `be3a023cad79f86f2158d19784f4a8c03da192e5` (merge of PR #28) |
| Version | `0.2.0a18` (alpha / controlled testing) |
| Open PRs | none |
| Open issues | none |
| GitHub Releases / tags | none |
| Latest main CI | run [40153361168](https://github.com/eneelkant/pen-testing/actions/runs/40153361168) (2026-10-25 07:39:14 Asia/Calcutta) |
| Required merge checks (non-admins) | `Pinned image regression gate`, `Lint and unit tests`, `Docker build and runtime`, `Secret scanning (gitleaks)`, `Dependency metadata check` — `branches/main` reports `protected: true`, `enforcement_level: non_admins` |
| Absolute image job | **failure** (not a required merge check; required for release) |
| Regression gate | **success**, `inherited_blocking_count` **1085**, `new_blocking_count` 0 |
| Baseline | `core/supply_chain/image_baseline.json` — 4 entries (Shannon/Temporal/Gitleaks/Trivy); `approved_by=neelkantekbote-66degree`; `approval_ref` PR #28; `expires_at=2026-11-25T01:51:37Z` (~30.9 days remaining); source run `40119376385` @ `f7cbcc0…` |
| Branch protection API write / GraphQL rules | HTTP **403** for this integration — admin bypass (`enforcement_level: non_admins`) **not** changed here |
| CODEOWNERS | `.github/CODEOWNERS` lists only `@eneelkant` |

### Absolute image findings (CI run 40153361168)

| Image | Status | Blocking | Unscored | Digest (index) |
|---|---|---:|---:|---|
| python Alpine pin | PASS | 0 | 0 | `b658b05c…7815d` |
| shannon-worker | FAIL | 980 | 423 | `4e726ed8…bd0e` |
| temporal | FAIL | 58 | 4 | `9c5b386d…37f4` |
| gitleaks | FAIL | 41 | 1 | `0e99e882…7f46` |
| trivy-scanner | FAIL | 6 | 3 | `2416d1f7…d222` |

Upstream aggregate **1085**. Artifact hashes recorded in evidence `MANIFEST.json`. Regression PASS is merge-only inherited risk; release still requires zero blocking findings.

### Fresh candidate monitor (host Trivy 0.76.0, DB UpdatedAt 2026-10-25T01:20:33Z)

`python -m core.supply_chain candidates` → **`NO_ACCEPTABLE_CANDIDATE`**. Acceptable list empty. Temporal `1.9.1@150d6208…` reclassified **FAIL** blocking **15** (includes unscored `GO-2026-5932` on `golang.org/x/crypto` with empty FixedVersion). Trivy latest / `0.76.1@2e6c00d7…` FAIL blocking 4. Gitleaks latest / `v8.30.1@b109bc5f…` FAIL blocking 78. No Shannon tag newer than `3.4.0` on Hub for the current major line tip used by this repo.

**Release blocker remains.** Pins stay. Do not seed baselines for candidates that should be clean.

## Gap register

| ID | Severity | Gap | Root cause | Remediation | Acceptance test | PR / owner |
|---|---|---|---|---|---|---|
| G1 | **CRITICAL** (release) | Absolute upstream image gate FAIL (1085) | Upstream images ship fixed HIGH/CRITICAL + unscored findings; no clean official digest | Keep pins; run candidate monitor; adopt only `ACCEPTABLE_CANDIDATE` with runtime/Shannon `--validate-model`; separate pin PR then baseline cleanup | `python -m core.supply_chain images` exit 0 on every pin; release job green | Upstream vendors + maintainer; **blocked** |
| G2 | HIGH | Classifier can PASS digest-pinned images when Trivy omits RepoDigests and only a tag matches ArtifactName | Fail-open name/tag identity when `expected` digest set | Require digest evidence in RepoDigests or ArtifactName; else `NOT_VERIFIED` | Unit: empty digests / tag-only ArtifactName → NOT_VERIFIED | Engineering PR (this effort) |
| G3 | HIGH | Trivy/Gitleaks adapters use mutable tags; Trivy adapter still `0.58.1` | Adapter pins diverged from `PINNED_IMAGES` | Docker fallbacks use digest-pinned `PINNED_IMAGES` refs | Unit asserts adapter image refs equal pins | Engineering PR |
| G4 | HIGH | `PEN_REQUIRE_SCOPE=false` + dual-gate skips unscoped rate limit | Early return omits `enforce_unscoped_rate_limit` | Rate-limit live dual-gate disable path | Unit: second live preflight raises under `PEN_SKIP_SCOPE_RATE_LIMIT_RPS=1` | Engineering PR |
| G5 | MEDIUM | Regression/release artifact upload `if-no-files-found: warn` | Soft-fail evidence | Set `error` (keep `if: always()`) | Workflow review; CI still uploads on failure | Engineering PR |
| G6 | MEDIUM | MCP local-scan confinement includes `Path.cwd()` | Over-broad roots | MCP confines to work_dir + reports_dir only | Unit: path under cwd but outside work/reports blocked | Engineering PR |
| G7 | MEDIUM | Restore-onto-symlink leaf lacks dedicated unit test | Behavior exists; coverage gap | Add adversarial unit test | Test proves `PermissionError` | Engineering PR |
| G8 | HIGH (ops) | Branch protection `enforcement_level: non_admins` — admins can bypass required checks | GitHub setting; API 403 for this agent | Admin UI: enable “Do not allow bypassing the above settings” / admin enforcement; require CODEOWNERS review | `gh api …/branches/main` shows admin enforcement / ruleset equivalent | **Human admin** (`eneelkant`) |
| G9 | HIGH (ops) | CODEOWNERS only `@eneelkant`; author cannot satisfy code-owner self-review | Incomplete CODEOWNERS for independent review | Propose adding `@neelkantekbote-66degree` (current baseline approver) after they accept ownership | CODEOWNERS review required + independent APPROVED on security PRs | **Human** — propose via PR; do not claim ownership without acceptance |
| G10 | HIGH (release) | No external security review commissioned | Process | Engage independent reviewer per `docs/EXTERNAL_SECURITY_REVIEW.md`; remediate findings | Separate published review + retest evidence | **Human** |
| G11 | HIGH (release) | Qualified counsel AGPL/license clearance pending | Process | Counsel answers in `docs/LICENSING_REVIEW.md`; update notices | Documented counsel sign-off before production distribution | **Human / counsel** |
| G12 | MEDIUM | No backup scheduler / external alerting / multi-user auth | Out of single-operator design | Keep interfaces; document operator provisioning; do not claim deployed | Docs accuracy; no false “production SaaS” claims | Docs (this plan) |
| G13 | LOW | `docs/IMAGE_BASELINE.md` still said `protected: false` after checks were enabled | Stale doc | Update to verified protection state + remaining admin-bypass gap | Doc matches `gh api` | Docs PR |
| G14 | LOW | Baseline expires 2026-11-25 | Time-bounded inherited risk | Renew from fresh CI artifacts before expiry; never hand-edit `expires_at` | Regression gate still PASS with renewed entry | Maintainer before 2026-11-25 |

## Local verification on this effort (2026-10-25 Asia/Calcutta)

| Command | Result |
|---|---|
| `python3 -m compileall …` | PASS |
| `python3 -m pytest -q tests/unit` | PASS — **374 passed** |
| `bash scripts/smoke.sh` | PASS |
| `python3 -m core.supply_chain audit` | PASS — 24 components |
| `python3 -m core.supply_chain emit` | PASS — CycloneDX 1.5, 24 components |
| `python3 -m core.supply_chain vuln` | PASS — blocking 0 |
| `python3 -m core.supply_chain images --name python-3.12-probe` | PASS — blocking 0; DB UpdatedAt 2026-10-25T01:20:33Z |
| `python3 -m core.supply_chain candidates` | FAIL status `NO_ACCEPTABLE_CANDIDATE` (expected) |
| Host Trivy Temporal `1.9.1@150d6208…` | FAIL blocking 15 (GO-2026-5932 present) |
| `bash scripts/docker_runtime_verify.sh` | **NOT_VERIFIED** locally (Docker Engine absent); green on main CI job |
| Gitleaks binary | **NOT_VERIFIED** locally; green on main CI job |

## Open PRs from this effort

| PR | Branch | Purpose |
|---|---|---|
| [#30](https://github.com/eneelkant/pen-testing/pull/30) | `cursor/prod-readiness-plan-7e32` | This plan + evidence docs |
| [#31](https://github.com/eneelkant/pen-testing/pull/31) | `cursor/image-digest-failclosed-7e32` | Digest identity fail-closed (G2) |
| [#32](https://github.com/eneelkant/pen-testing/pull/32) | `cursor/security-hardening-gaps-7e32` | Adapters / rate limit / MCP / uploads (G3–G7) |
| [#33](https://github.com/eneelkant/pen-testing/pull/33) | `cursor/codeowners-second-reviewer-7e32` | Propose second CODEOWNER (G9) |
| [#34](https://github.com/eneelkant/pen-testing/pull/34) | `cursor/review-package-7e32` | Review bundle + counsel inventory (G10/G11 prep) |

Independent review must be submitted on GitHub by an authorized human. This agent cannot approve PRs or request reviewers (API 403). Absolute image scan FAIL on these PRs is expected until G1 is cleared; it is not a required merge check.

## Phased work (this effort)

1. **Docs / plan** — this file, scorecard update, IMAGE_BASELINE protection correction, exceptions/remediation reconciliation with fresh candidate evidence.  
2. **Image digest fail-closed** — G2 only; no pin/baseline changes.  
3. **Security hardening** — G3–G7 (adapters, rate limit, MCP confinement, upload strictness, restore test).  
4. **CODEOWNERS proposal** — G9 as a dedicated PR requesting `@neelkantekbote-66degree` accept code ownership.  
5. **Review package** — refresh external-review checklist pointers; counsel questions unchanged.  
6. **Release** — **do not tag** until G1 absolute zero-blocking + G10 + G11 + ops checklist complete.

## Explicit non-claims

- Not production-ready.  
- Regression PASS ≠ release PASS.  
- No legal clearance.  
- No independent external security review completed.  
- No multi-tenant authentication.  
- Admin branch-protection bypass not confirmed disabled.
