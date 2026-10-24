# Image regression baseline (merge gate)

**What this is:** a reviewed record of blocking image findings that already exist in the current pinned images. A merge passes the image check only if it adds nothing beyond that record. It is **not a waiver**. It does not say a finding is harmless, fixed, or accepted forever. Every listed finding stays open, stays in every report, and still fails the release gate.

## Two gates

| Gate | Command | Where it runs | Passes when |
|---|---|---|---|
| **Absolute image gate** (policy Option A, release gate) | `python -m core.supply_chain images` | CI job "Pinned image vulnerability scans" on every PR and push; release workflow job "Absolute pinned image gate (release)" | Zero fixed HIGH/CRITICAL and zero unscored findings in every pinned image |
| **Regression gate** (policy Option B, merge gate) | `python -m core.supply_chain images --baseline core/supply_chain/image_baseline.json` | CI job "Pinned image regression gate" | Every current blocking finding is in an approved, unexpired baseline entry for the exact pinned digest |

- The release workflow (`.github/workflows/release.yml`) does not publish unless the absolute gate passes. The baseline is never used there.
- A regression-gate PASS is reported as `regression_gate: PASS` next to `absolute_image_gate: FAIL blocking=N`. It is never reported as an image PASS.

## Fail-closed rules

The regression gate fails when any of these is true:

- **The scan cannot be trusted.**
  - It is `NOT_VERIFIED`: missing, malformed, or stale Trivy evidence, the wrong platform or scanner, or a failed live DB probe.
  - Its raw rows do not align with the canonical classifier.
- **The baseline file is invalid.** Any one of these makes it invalid:
  - It is missing, is not JSON, or has unknown, missing, or duplicate fields or findings.
  - Its schema version is not supported.
  - A digest is malformed.
  - Provenance is missing: the source repository, CI run, commit, artifact path, and raw-evidence sha256 are all required.
  - Approval is missing: `approved_by`, a GitHub PR or issue `approval_ref`, `approved_at`, and `expires_at` are all required.
  - An approval was given more than 7 days after the scan, or before it.
  - An expiry is more than **31 days** after approval.
  - An entry has expired.
- **A failing image has no entry for its exact index digest** (`UNRECOGNISED_DIGEST`). A new digest never inherits an older entry.
- **An entry's details do not match the scan.** The platform digest, platform, or scanner version differs (`PLATFORM_DIGEST_MISMATCH`, `PLATFORM_MISMATCH`, `SCANNER_CHANGED`).
- **A current blocking finding is not in the entry** (`NEW_BLOCKING`). This includes findings that appear only because the vulnerability database was updated. That is intentional: a newly disclosed vulnerability needs a human to acknowledge it.

The gate reports, but does not fail on:

- **Baseline findings that disappeared** (`resolved_baseline_findings`). Remove them in a follow-up baseline PR.
- **Entries for images that are no longer pinned.** Remove them in a follow-up. They cannot be removed in the same PR as the pin change; see below.
- **Entries for images that now pass the absolute gate.**

## Finding identity

Each finding is identified by `(vulnerability_id, pkg_name, pkg_path, installed_version, result_class, result_type, target)`, taken from the Trivy row.

- `target` is `""` for OS packages, because Trivy puts the image reference in that target. For language packages it is the file path inside the image.
- Trivy's `Fingerprint` field is not used.
- A version change of an affected package is a new identity.
- Whether a row is blocking comes from `classify_trivy_document` itself; the baseline code does not re-implement severity rules.

## File: `core/supply_chain/image_baseline.json`

`schema_version: 1`. There is one entry per `(pin_name, ref)`. Each entry has:

| Field | What it holds |
|---|---|
| `ref`, `platform`, `platform_digest` | Exact image identity |
| `scanner_version`, `db_updated_at`, `scanned_at` | Scan provenance |
| `source` | `repository`, `ci_run_id`, `commit`, `artifact`, `raw_path`, `raw_sha256` |
| `approval` | `approved_by`, `approval_ref`, `approved_at`, `expires_at` |
| `findings` | Each with `key`, `severity`, `fixed_version`, `gate_reason`, `remediation_status` |

`remediation_status` is either:

- `awaiting-upstream-release`: a fixed version exists, but no upstream image ships it.
- `no-fixed-version-published`: no fixed version exists.

## Procedures

### Create or renew entries (from CI evidence only)

1. Download `image-scan-python`, `image-scan-upstream` and `image-scan-raw` from a CI run of the commit you want to baseline. Use the Actions UI or `gh run download <run-id>`.
2. Build candidate entries. The tool verifies every raw file's sha256 against the summary, re-classifies the raw report, and checks identity, platform, scanner version and database freshness. It refuses anything that does not verify.

   ```bash
   python -m core.supply_chain baseline candidate \
     --summary image-scan-python/image-scan-python.json --raw-dir image-scan-raw/python --raw-prefix python/ \
     --summary image-scan-upstream/image-scan-upstream.json --raw-dir image-scan-raw/upstream --raw-prefix upstream/ \
     --repository eneelkant/pen-testing --ci-run-id <run-id> --commit <full sha> \
     --output core/supply_chain/image_baseline.json
   ```

   Candidates have `"approval": null`. The regression gate rejects them until an owner approves them.
3. Open a PR that changes **only** the baseline. Do not change image pins in the same PR; the CI guard rejects that.
4. **Owner review.** A code owner (see `.github/CODEOWNERS`) reviews the listed findings against the CI artifacts. If they agree, they approve on the PR and record the approval:

   ```bash
   python -m core.supply_chain baseline approve --baseline core/supply_chain/image_baseline.json \
     --approved-by <github-login> --approval-ref https://github.com/eneelkant/pen-testing/pull/<n> --expires-in-days 31
   ```

   `--expires-in-days` must be between 1 and 31. Approval must happen within 7 days of the scan.
5. Commit the approved file to the same PR. Merge after the required checks pass.

### Expiry

Entries stop working at `expires_at`, and the regression gate then fails for every PR. Renew before expiry by repeating the steps above with a fresh CI scan. Never edit `expires_at` by hand.

### Changing an image pin

- **If the new image passes the absolute gate:** change the pin in a normal PR. The old entry then shows as "does not match a current pin"; remove it in a follow-up baseline PR.
- **If the new image still has blocking findings:** first land a baseline-only PR with an approved entry for the new digest, built from a CI scan of that digest. Then change the pin in a separate PR.

## Required GitHub settings (administrator)

The checks below are only *required* when GitHub enforces them. As of 2026-10-25, `main` reports `protected: false` with no required checks and no rulesets. This session could not change that, because the protection API returned HTTP 403. An administrator must configure branch protection or a ruleset for `main` with:

- **Require a pull request before merging**, with at least one approving review.
- **Require review from Code Owners.**
- **Require status checks to pass:**
  - `Pinned image regression gate`
  - `Lint and unit tests`
  - `Docker build and runtime`
  - `Secret scanning (gitleaks)`
  - `Dependency metadata check`
- **Do not** make `Pinned image vulnerability scans` a required merge check. It stays visible on every PR and is enforced at release by `.github/workflows/release.yml`.
- **Code-owner approval needs a second account.** GitHub does not let a PR author approve their own PR. With `@eneelkant` as the only code owner and the author of the open PRs, a code-owner approval needs a second maintainer, or a different PR author.
