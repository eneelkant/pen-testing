# Pinned image remediation report

**Branch:** `cursor/image-remediation-7e32` (separate from PR #25 evidence-reuse work); updated on PR #28 (`cursor/python-alpine-base-7e32`).

**Decision:** **Python pin moved (PR #28); upstream pins unchanged.** The Python base passed the gate on an Alpine digest (below). Shannon, Temporal, Gitleaks and Trivy have no passing candidate, so their digests in `core/supply_chain/images.py` are unchanged.

**Gate:** zero fixed HIGH/CRITICAL + zero unscored. Candidate evidence reuse requires exact digest, `linux/amd64`, scanner `0.76.0`, fresh CreatedAt/DB UpdatedAt, and a **live** `trivy version` DB probe (age alone is not enough). Pre-classified `PASS` without raw Trivy `Results` is rejected. Missing or mismatched evidence is `NOT_VERIFIED`, not a pass. Platform is never invented when omitted.

## Current status: PR #28 head `0812b53`, CI run 40115310455

Source: GitHub Actions run [40115310455](https://github.com/eneelkant/pen-testing/actions/runs/40115310455) (push, 2026-10-24T17:15Z), job "Pinned image vulnerability scans" log and its `image-scan-python`, `image-scan-upstream` and `image-scan-raw` artifacts. Scanner Trivy **0.76.0** (report `Trivy.Version` and probe agree). DB `UpdatedAt` **2026-10-24T13:07:23.340317483Z**. Every raw file's sha256 matches `raw_evidence.sha256` in its summary, and each report names the exact pinned index digest with `linux/amd64`.

| Pin | Immutable ref (index) | linux/amd64 child | Fixed HIGH/CRITICAL | Unscored | Blocking | Gate |
|---|---|---|---:|---:|---:|---|
| python-3.12-probe / -orchestrator | `python:3.12.15-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d` | `sha256:9b98a8d37794ca093ba8d5afe1ffac52f5a15168b9b4e67594d86c20e14fa681` | 0 | 0 | **0** | **PASS** (exit 0) |
| shannon-worker | `keygraph/shannon:3.4.0@sha256:4e726ed8…` | `sha256:9e53649e…` | 557 | 423 | **980** | FAIL |
| temporal | `temporalio/temporal:1.7.0@sha256:9c5b386d…` | `sha256:6dc6fda8…` | 54 | 4 | **58** | FAIL |
| gitleaks | `zricethezav/gitleaks:v8.21.2@sha256:0e99e882…` | `sha256:e5fa09c7…` | 40 | 1 | **41** | FAIL |
| trivy-scanner | `aquasec/trivy:0.76.0@sha256:2416d1f7…` | `sha256:166061a4…` | 3 | 3 | **6** | FAIL |

Upstream gate: **FAIL, 1,085 blocking** (exit 1), so "Enforce pinned image scan gates" fails on `upstream_image_scan_exit=1` only. In the same run, "Lint and unit tests" (312 passed; isolation 42 passed), "Docker build and runtime" (all three project images built `FROM` the Alpine pin; real Shannon + Temporal `--validate-model` E2E: `SHANNON_E2E_PATH temporal+worker+validate-model+local-llm-mock`, `SHANNON_E2E_NETWORK_MODE controlled`; "Docker runtime verification passed"), "Secret scanning (gitleaks)" and "Dependency metadata check" succeeded.

The Python move is from `python:3.12-slim-bookworm@sha256:34386ef0…` (3 unscored blockers, including `perl-base` CVE-2026-82560, which has no Debian fix and is present in every Debian Python image) to the Alpine digest above. UIDs 10001/10002/10003 are unchanged (`adduser -D -u`).

### Why the upstream images remain blocked (verified 2026-10-24)

- **No newer upstream releases.** Docker Hub tips: Shannon `3.4.0` (npm `@keygraph/shannon` latest `3.4.0`), Temporal `1.9.1`, Gitleaks `v8.30.1`, Trivy `0.76.1` / `canary`. All were scanned and rejected (table below).
- **`GO-2026-5932` (`golang.org/x/crypto/openpgp` unmaintained).** OSV range `introduced: 0`, no fixed version, no severity, so Trivy reports it as unscored, and therefore blocking, for every image whose Go binary depends on any `golang.org/x/crypto` version. No fixed version will be published: the advisory says to stop using the package (fork: `github.com/ProtonMail/go-crypto/openpgp`). **Evidence on the affected binaries (corrected 2026-10-24; an earlier revision of this file wrongly said the package was linked):** `go list -deps` with the release build settings (`CGO_ENABLED=0 GOOS=linux GOARCH=amd64`, no build tags) at the exact source revisions (`temporalio/cli` v1.7.0 `62fa893`, `aquasecurity/trivy` v0.76.0 `531360e`) contains no `golang.org/x/crypto/openpgp*` package. The function-name tables of the shipped binaries (`temporal` 1.7.0 and 1.9.1, `trivy` 0.76.0 and 0.76.1) contain no `golang.org/x/crypto/openpgp` functions, while other `x/crypto` packages are present; `trivy` contains the ProtonMail fork instead. `govulncheck -mode=binary` package frames for this advisory are not evidence of linkage: these binaries are stripped (`-s -w`), so govulncheck cannot resolve symbols and lists every package the advisory names. So for these images the finding is a module-version match, not a linked vulnerable package. It still blocks under the current policy, because the gate classifies by Trivy rows and has no reachability exception. Whole-program call-graph analysis was not completed (out of memory in the sandbox).
- **Shannon:** blockers are almost all Wolfi Chromium 149 rows plus `nodejs-22`, `libbrotli*` and app Node/Rust dependencies, all with published fixes. This needs a Keygraph image rebuild; a local `apk upgrade` cannot fix the app dependencies.
- **Gitleaks `v8.21.2`:** every blocker has a fix (Go stdlib 1.22.8, Alpine 3.19.4 EOSL packages, `x/sys` CVE-2026-39824), but no upstream image ships them. `v8.30.1` adds `x/crypto` (so Trivy reports `GO-2026-5932`; its unstripped binary has no `openpgp` package) and 78 blockers in total.

### Conditions to resume upstream remediation

| Image | Condition |
|---|---|
| Temporal, Trivy | An upstream release that clears the fixed HIGH/CRITICAL rows and the other unscored rows (Temporal `1.9.1` still has 12 fixed HIGH/CRITICAL plus musl `CVE-2026-107891`; Trivy `canary` still has musl `CVE-2026-107891` ×2). `GO-2026-5932` will keep matching any binary that depends on `golang.org/x/crypto`, so clearing it needs an owner-approved, evidence-backed policy decision (the package is not compiled in; see above) or upstream dropping `x/crypto` entirely. This report does not make that decision. For Temporal, then run Shannon `--validate-model`. |
| Shannon | A Keygraph release newer than `3.4.0` with current Chromium/Node/Wolfi packages and bumped app dependencies |
| Gitleaks | An upstream image on a supported Alpine with current Go stdlib/`x/sys` and no linked `x/crypto/openpgp`, or a project decision to build and publish its own Gitleaks image |

## Baseline (reproduced locally, superseded by the section above)

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
| `keygraph/shannon:3.4.0` Hub tip | `9e53649e…` | 551 | 419 | 970 | Not a candidate: this is the linux/amd64 child of the pinned index `4e726ed8…` |
| `temporalio/temporal:1.7.3` | `1683f097…` | 27 | 3 | 30 | Rejected; `--validate-model` not run |
| `temporalio/temporal:1.8.1` | `d7fe04db…` | 32 | 3 | 35 | Rejected; `--validate-model` not run |
| `temporalio/temporal:1.9.1` / `latest` | `150d6208…` | 8 | 3 | 11 | Rejected; `--validate-model` not run |
| `zricethezav/gitleaks:v8.30.1` | `b109bc5f…` | 72 | 6 | 78 | Rejected (worse) |
| `aquasec/trivy:0.76.1` / `latest` | `2e6c00d7…` | 1 | 3 | 4 | Rejected |
| `aquasec/trivy:canary` | `307afa4f…` | 0 | 3 | 3 | Rejected (unscored; canary not a pin) |

Closest non-passing Trivy tip is canary (0 fixed HIGH/CRITICAL, 3 unscored). Still fails the unscored rule. Temporal `1.9.1` is the lowest Temporal blocking count among scanned tags but still fails; Shannon model compatibility was **not** validated because the vulnerability gate never cleared.

Committed reject inventory: `core/supply_chain/candidate_rejects.json` (includes `6e13e65c…` and `1683f097…`). Monitor status remains `NO_ACCEPTABLE_CANDIDATE`.

## Safe pin updates justified?

**Python only (PR #28).** `python:3.12.15-alpine3.24` (index `b658b05c…`, amd64 `9b98a8d3…`) passed the complete gate with fresh digest-bound evidence plus build and runtime tests, including Shannon `--validate-model` (see "Current status"). Every other candidate failed, so these pins stay:

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
- `core/supply_chain/candidates.py` (`evidence_reusable` + live DB requirement; never trust PASS without raw Results)
- `core/supply_chain/__main__.py` (CLI live DB probe; fail closed when probe missing)
- `tests/unit/test_image_candidates.py` (rejection / evidence / gate-separation regressions)
- `CHANGELOG.md` / `.gitignore` as needed

`docs/READINESS_SCORECARD.md` local uncommitted edit is preserved and not part of this change set.

## Evidence-reuse guarantees (implemented)

| Check | Behavior |
|---|---|
| Digest | Recorded evidence digest must equal Hub-resolved digest |
| Platform | Must be present and equal `linux/amd64`; missing → not reused / `NOT_VERIFIED` |
| Scanner | Must equal pinned Trivy tag `0.76.0` |
| DB age | Evidence DB `UpdatedAt` within max age **and** not older than live probe |
| Live probe | Required for reuse and for `ACCEPTABLE_CANDIDATE`; CLI fails `NOT_VERIFIED` if probe missing |
| Pre-classified PASS | Without Trivy `Results`, cannot become acceptable; blockers in stored findings demote to FAIL |
