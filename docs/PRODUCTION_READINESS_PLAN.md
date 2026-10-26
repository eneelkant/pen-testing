# Production readiness plan

**Status:** Working plan for `0.2.0a18` on `main` @ `be3a023cad79f86f2158d19784f4a8c03da192e5`.

**Verdict:** Controlled testing. **Not production-ready.** The absolute image gate blocks any release tag.

**Last verified:** 2026-10-26 (UTC), against GitHub Actions runs linked below. Earlier dated sections are kept for provenance and are marked as superseded.

This document tracks gaps, owners, and acceptance tests. It does not waive findings, invent approvals, or authorize a release. Live PR and review status belongs on GitHub, not here.

## Current state (verified 2026-10-26)

| Item | Evidence |
|---|---|
| `origin/main` SHA | `be3a023cad79f86f2158d19784f4a8c03da192e5` (merge of PR #28) |
| Version | `0.2.0a18` (alpha / controlled testing) |
| GitHub Releases / tags | none |
| Required merge checks (non-admins) | `Pinned image regression gate`, `Lint and unit tests`, `Docker build and runtime`, `Secret scanning (gitleaks)`, `Dependency metadata check`. `GET branches/main` reports `protected: true`, `enforcement_level: non_admins`. Review-requirement settings (code-owner review, stale-review dismissal) are **not readable** with this integration's token (HTTP 403) and are therefore not claimed here. |
| Vulnerability DB | Trivy 0.76.0, DB `UpdatedAt` **2026-10-26T07:15:18Z** |
| Absolute image gate | **FAIL**, 1,086 blockers on the unchanged pinned digests (table below). Release remains blocked. |
| Merge regression gate on `main`'s baseline | **FAIL** since the 2026-10-26 DB update: 1 new and 4 changed blocking findings against the PR #28 baseline (CI run [40294357096](https://github.com/eneelkant/pen-testing/actions/runs/40294357096)). Every PR inherits this failure. |
| Baseline renewal | PR #36 regenerates the baseline from CI evidence with the documented CLI. On its head, the gate reports `new_blocking=0 changed_blocking=0 inherited_blocking=1086`; its only remaining error is the missing independent APPROVED review on the exact head (CI run [40328020356](https://github.com/eneelkant/pen-testing/actions/runs/40328020356)). |
| Candidate monitor | Scheduled run [40327397325](https://github.com/eneelkant/pen-testing/actions/runs/40327397325) (2026-10-26, same DB): **`NO_ACCEPTABLE_CANDIDATE`**, `acceptable: []` |
| CODEOWNERS on `main` | `@eneelkant` only. PR #33 proposes `@neelkantekbote-66degree` as a second owner. |

### Absolute image findings (CI run 40328020356, scanned 2026-10-26T13:09Z)

| Image | Status | Blocking | Unscored | Digest (index) |
|---|---|---:|---:|---|
| python Alpine pin | PASS | 0 | 0 | `b658b05c…7815d` |
| shannon-worker | FAIL | 980 | 419 | `4e726ed8…bd0e` |
| temporal | FAIL | 58 | 4 | `9c5b386d…37f4` |
| gitleaks | FAIL | 41 | 1 | `0e99e882…7f46` |
| trivy-scanner | FAIL | 7 | 3 | `2416d1f7…d222` |

Upstream aggregate **1,086**. A regression PASS is merge-only inherited risk; release still requires zero blocking findings.

### What changed with the 2026-10-26 DB (same digests)

From the raw report in [image-regression-gate, run 40294357096](https://github.com/eneelkant/pen-testing/actions/runs/40294357096/artifacts/12636848958):

| Image | Finding | Detail |
|---|---|---|
| trivy-scanner | **New** `CVE-2026-92392` | Alpine `libcurl` `8.22.0-r0`, fixed `8.23.0-r0` ([curl advisory](https://curl.se/docs/CVE-2026-92392.html)) |
| shannon-worker | **Changed** UNKNOWN → HIGH | `CVE-2026-105481`, `CVE-2026-106072`, `CVE-2026-106073`, `CVE-2026-106074` in Wolfi `nodejs-22` `22.23.2-r1`, fixed `22.23.4-r0`. These are OS-package rows, not npm rows. |

### Candidate decision (2026-10-26)

**No image pin was changed.**

- The monitor run above reports Shannon `latest` as `SKIPPED_PINNED`: its `linux/amd64` digest (`sha256:9e53649e…644a`) is the pinned platform digest. Re-pinning it, or switching to `latest`, would not fix anything.
- Rejected on the 2026-10-26 DB: Temporal `latest` (15 blocking, 3 unscored, including `GO-2026-5932`), Gitleaks `latest` (78 / 6), Trivy `latest` (5 / 3), Python `3.12-slim-bookworm` (4 / 2), Python `3.13-slim-bookworm` (8 / 2).
- The self-built candidate pipeline (PR #35) also rejects both candidates: Shannon still has the Chromium, application-dependency and `nodejs-22` rows; the Trivy binary still embeds Go `stdlib` CVE-2026-111943 and `GO-2026-5932`. See `docs/SELF_BUILT_IMAGE_CANDIDATES.md` on that branch.

**Do not silence the gate or add findings to the baseline without CI evidence and independent review.** Accept a candidate only with zero fixed HIGH/CRITICAL and zero unscored rows, plus the documented runtime tests (including Shannon `--validate-model`), in a separate pin PR.

## Gap register

| ID | Severity | Gap | Root cause | Remediation | Acceptance test | PR / owner |
|---|---|---|---|---|---|---|
| G1 | **CRITICAL** (release) | Absolute upstream image gate FAIL (1,086) | Upstream images ship fixed HIGH/CRITICAL + unscored findings; no clean official digest | Keep pins; run candidate monitor; adopt only `ACCEPTABLE_CANDIDATE` with runtime/Shannon `--validate-model`; separate pin PR then baseline cleanup | `python -m core.supply_chain images` exit 0 on every pin; release job green | Upstream vendors + maintainer; **blocked** |
| G2 | HIGH | Classifier could PASS digest-pinned images without manifest-digest evidence (tag-only `ArtifactName`; config `ImageID` or layer `DiffIDs`; substring/suffix matches) | Fail-open identity matching | Require a complete `sha256` digest after `@` in `ArtifactName` or `Metadata.RepoDigests` that exactly equals the pin; otherwise `NOT_VERIFIED` | Unit: empty digests, tag-only, ImageID-only, DiffID-only, lookalikes and malformed fields → `NOT_VERIFIED`; RepoDigests-only and artifact-digest → PASS | PR #31 |
| G3 | HIGH | Trivy/Gitleaks adapters used mutable tags; Trivy adapter was `0.58.1` | Adapter pins diverged from `PINNED_IMAGES` | Docker fallbacks use digest-pinned `PINNED_IMAGES` refs | Unit: adapter refs equal pins; docker commands use the digest ref with `--network none` | PR #32 |
| G4 | HIGH | `PEN_REQUIRE_SCOPE=false` + dual-gate skipped the unscoped rate limit | Early return omitted `enforce_unscoped_rate_limit` | Rate-limit the live dual-gate disable path | Unit: second live preflight raises under `PEN_SKIP_SCOPE_RATE_LIMIT_RPS=1`; dry-run does not consume budget | PR #32 |
| G5 | MEDIUM | Regression/release artifact upload used `if-no-files-found: warn` | Soft-fail evidence | Set `error` (keep `if: always()`) | Workflow review | PR #32 |
| G6 | MEDIUM | MCP local-scan confinement included `Path.cwd()` | Over-broad roots | MCP confines to `work_dir` + `reports_dir` only | Unit: path under cwd but outside roots, `../` traversal, symlink escape and out-of-root `repo_path` are refused | PR #32 |
| G7 | MEDIUM | Restore-onto-symlink leaf lacked a dedicated unit test | Coverage gap | Adversarial unit test | Test proves `PermissionError` and the outside file is untouched | PR #32 |
| G8 | HIGH (ops) | Branch protection `enforcement_level: non_admins`: admins can bypass required checks | GitHub setting; protection write API returns 403 for this integration | Admin UI: "Do not allow bypassing the above settings"; require code-owner review | `gh api …/branches/main` shows admin enforcement (or an equivalent ruleset) | **Human admin** (`eneelkant`) |
| G9 | HIGH (ops) | CODEOWNERS only `@eneelkant`; an author cannot satisfy code-owner review on their own PR | Single owner | Add `@neelkantekbote-66degree` once they accept ownership | Independent APPROVED review on security PRs; code-owner review required in settings | PR #33 + **human acceptance** |
| G10 | HIGH (release) | No external security review commissioned | Process | Engage an independent reviewer per `docs/EXTERNAL_SECURITY_REVIEW.md` | Separate published review + retest evidence | **Human** |
| G11 | HIGH (release) | Qualified counsel AGPL/licence clearance pending | Process | Counsel answers in `docs/LICENSING_REVIEW.md`; update notices | Documented counsel sign-off before production distribution | **Human / counsel** |
| G12 | MEDIUM | No backup scheduler / external alerting / multi-user auth | Out of single-operator design | Keep interfaces; document operator provisioning; do not claim deployed | No false "production SaaS" claims | Docs (this plan) |
| G13 | LOW | `docs/IMAGE_BASELINE.md` said `protected: false` after checks were enabled | Stale doc | Update to the verified protection state and remaining gaps | Doc matches `gh api` | PR #30 |
| G14 | MEDIUM | Baseline invalidated by the 2026-10-26 DB; PR #28 entries expire 2026-11-25 | Time-bounded inherited risk; DB reclassification | Renew from fresh CI artifacts with the documented CLI and an independent approval on the exact head; never hand-edit `expires_at` | Regression gate PASS on the renewal PR's head | PR #36 + **human approval** |

## Local verification

| Command | Result (2026-10-26, this branch) |
|---|---|
| `python -m compileall core integrations providers mcp_server installers` | PASS |
| `python -m pytest -q tests/unit` | PASS (count varies by branch; see each PR's CI) |
| `python -m core.supply_chain audit` | PASS, 24 requirements |
| `bash scripts/docker_runtime_verify.sh` | Verified by the CI job "Docker build and runtime" on each PR head, not claimed from a local run |

## Superseded snapshot (2026-10-25, before the DB update)

Kept for provenance only. On CI run [40153361168](https://github.com/eneelkant/pen-testing/actions/runs/40153361168) the regression gate passed (`inherited_blocking_count` 1,085, `new_blocking_count` 0) and the absolute gate failed with Shannon 980 / Temporal 58 / Gitleaks 41 / Trivy 6. Host Trivy candidate scans with DB `UpdatedAt` 2026-10-25T01:20:33Z returned `NO_ACCEPTABLE_CANDIDATE`. These numbers no longer describe the current state.

## Release sequence

1. Merge the baseline renewal (#36) after independent approval of its exact head; then the CODEOWNERS change (#33).
2. Merge security fixes (#31, #32) and the candidate pipeline (#35) after independent review of their latest heads.
3. **Do not tag** until G1 (absolute zero-blocking), G10, G11 and the ops checklist are complete.

## Explicit non-claims

- Not production-ready.
- Regression PASS ≠ release PASS. An approved inherited-risk baseline is not evidence that an image is safe.
- No legal clearance.
- No independent external security review completed.
- No multi-tenant authentication.
- Admin branch-protection bypass not confirmed disabled; code-owner review requirement not verifiable with this token.
