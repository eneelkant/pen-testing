# Pinned image remediation report

**Branch:** `cursor/image-remediation-7e32` (separate from PR #25 evidence-reuse work).  
**Decision:** **No safe pin updates.** Production digests in `core/supply_chain/images.py` are unchanged.  
**Gate:** zero fixed HIGH/CRITICAL + zero unscored, with digest/platform/scanner/DB-freshness-bound evidence. Missing or mismatched evidence is `NOT_VERIFIED`, not a pass.

## Baseline (reproduced locally)

Scanner: Trivy **0.76.0**. Vulnerability DB `UpdatedAt` **2026-10-24T01:18:19.814880615Z** (`NextUpdate` 2026-10-25T01:18:19Z, `DownloadedAt` 2026-10-24T01:56:42Z). Platform **linux/amd64**. Image JSON does not embed `VulnerabilityDB`; classification used the `trivy version --format json` probe.

Matches GitHub Actions run **40066307720** upstream aggregate (**1,075** blocking) and Python FAIL:

| Pin | Digest (prefix) | Fixed HIGH/CRITICAL | Unscored | Blocking | Rows / unique |
|---|---|---:|---:|---:|---|
| `python:3.12-slim-bookworm` | `34386ef0…` | 0 | 3 | **3** | 290 / 131 |
| `keygraph/shannon:3.4.0` | `4e726ed8…` | 551 | 419 | **970** | 1793 / 1777 |
| `temporalio/temporal:1.7.0` | `9c5b386d…` | 54 | 4 | **58** | 138 / 102 |
| `zricethezav/gitleaks:v8.21.2` | `0e99e882…` | 40 | 1 | **41** | 124 / 107 |
| `aquasec/trivy:0.76.0` | `2416d1f7…` | 3 | 3 | **6** | 7 / 6 |

- **Python gate:** FAIL (3 unscored blockers; no fixed HIGH/CRITICAL).
- **Upstream gate:** FAIL (**1,075** blocking = 970 + 58 + 41 + 6).
- CI keeps these as separate steps/`image-scan-python` vs `image-scan-upstream` artifacts so each failure stays diagnosable.

Raw local reports (not committed): under `artifacts/image-remediation/raw/` (gitignored). CI continues to upload scan JSON as workflow artifacts.

## Root cause by image

| Image | Root cause | Upstream dependency |
|---|---|---|
| Python slim-bookworm | Unscored/UNKNOWN rows (`DLA-*`, `CVE-2026-82560`) plus many unfixed Debian package CVEs | Debian / official `library/python` rebuilds that clear UNKNOWN and ship fixed package versions |
| Shannon worker | Hundreds of fixed HIGH/CRITICAL and unscored findings in the published worker image | Keygraph Shannon image rebuild; npm `@keygraph/shannon` still `3.4.0` |
| Temporal | Fixed HIGH/CRITICAL + unscored on `1.7.0` and every newer tag scanned | Temporalio image rebuild; any bump still needs Shannon `--validate-model` |
| Gitleaks | Fixed HIGH/CRITICAL + unscored on `v8.21.2`; newer `v8.30.1` is worse | Gitleaks image rebuild |
| Trivy scanner | Fixed HIGH + unscored on pinned `0.76.0`; `0.76.1`/canary still have unscored blockers | Aqua Trivy image rebuild that clears unscored rows |

## Candidates evaluated (all rejected)

Every candidate below was resolved to an immutable Hub `linux/amd64` digest, scanned with Trivy 0.76.0 against DB `UpdatedAt` 2026-10-24T01:18:19Z (or classified with that probe metadata), and rejected under the existing gate. No floating tags were proposed for production.

| Candidate | Digest (prefix) | Fixed HC | Unscored | Blocking | Decision |
|---|---|---:|---:|---:|---|
| `python:3.12-slim-bookworm` tip | `57d96f71…` | 0 | 2 | 2 | Rejected (unscored) |
| `python:3.12.13-slim-bookworm` | `6e13e65c…` | 11 | 7 | 18 | Rejected (worse than pin) |
| `python:3.13-slim-bookworm` tip | `4cea12ab…` | 4 | 2 | 6 | Rejected |
| `python:3.14-slim-bookworm` tip | `7dff1730…` | 4 | 2 | 6 | Rejected |
| `python:3.12-slim` tip | `e8a38829…` | 0 | 1 | 1 | Rejected (unscored; not bookworm pin family) |
| `keygraph/shannon:3.4.0` Hub tip | `9e53649e…` | 551 | 419 | 970 | Rejected |
| `temporalio/temporal:1.7.3` | `1683f097…` | 27 | 3 | 30 | Rejected; `--validate-model` not run |
| `temporalio/temporal:1.8.1` | `d7fe04db…` | 32 | 3 | 35 | Rejected; `--validate-model` not run |
| `temporalio/temporal:1.9.1` / `latest` | `150d6208…` | 8 | 3 | 11 | Rejected; `--validate-model` not run |
| `zricethezav/gitleaks:v8.30.1` | `b109bc5f…` | 72 | 6 | 78 | Rejected (worse) |
| `aquasec/trivy:0.76.1` / `latest` | `2e6c00d7…` | 1 | 3 | 4 | Rejected |
| `aquasec/trivy:canary` | `307afa4f…` | 0 | 3 | 3 | Rejected (unscored; canary not a pin) |

Closest non-passing Trivy tip is canary (0 fixed HIGH/CRITICAL, 3 unscored). Still fails the unscored rule. Temporal `1.9.1` is the lowest Temporal blocking count among scanned tags but still fails; Shannon model compatibility was **not** validated because the vulnerability gate never cleared.

Committed reject inventory: `core/supply_chain/candidate_rejects.json` (includes `6e13e65c…` and `1683f097…`). Monitor status remains `NO_ACCEPTABLE_CANDIDATE`.

## Safe pin updates justified?

**No.** No official digest passed the complete gate with fresh digest-bound evidence. Pins stay:

- `python:3.12-slim-bookworm@sha256:34386ef0…`
- `keygraph/shannon:3.4.0@sha256:4e726ed8…`
- `temporalio/temporal:1.7.0@sha256:9c5b386d…`
- `zricethezav/gitleaks:v8.21.2@sha256:0e99e882…`
- `aquasec/trivy:0.76.0@sha256:2416d1f7…`

## Recommended next action

1. Keep the fail-closed CI gates split (Python vs upstream).
2. Continue the candidate monitor; adopt a pin only after `ACCEPTABLE_CANDIDATE` plus build/runtime tests (and Temporal + Shannon `--validate-model`).
3. Prefer remediating in order of leverage once clean digests exist: **Trivy → Temporal (with Shannon validate-model) → Gitleaks → Python → Shannon**.
4. Do not suppress findings, invent severities, or switch production to floating tags.

## Files changed on this remediation branch

- `docs/IMAGE_REMEDIATION.md` (this report)
- `docs/SECURITY_EXCEPTIONS.md` (baseline + new candidate rows)
- `core/supply_chain/candidate_rejects.json` (new reject digests)
- `core/supply_chain/candidates.py` (reject incomplete reused evidence; do not accept PASS+unscored)
- `tests/unit/test_image_candidates.py` (rejection / evidence / gate-separation regressions)
- `CHANGELOG.md` / `.gitignore` as needed

`docs/READINESS_SCORECARD.md` local uncommitted edit is preserved and not part of this change set.
