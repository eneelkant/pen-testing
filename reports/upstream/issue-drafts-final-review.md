# Upstream Issue Drafts — Corrected Evidence Review

**Investigation date:** 2026-10-31 (UTC)
**Repository:** `eneelkant/pen-testing`
**Verified main SHA:** `372e43529bfbc2aa39d07cf12c957cd414d5c07f`
**Scanner version:** Trivy 0.76.0 (pinned by digest)
**Vulnerability DB timestamp:** 2026-10-27T07:13:33Z
**Baseline source:** CI run `40475334312`, commit `9d0824a41a`

## Evidence provenance

The raw Trivy scan JSON artifacts are NOT committed to the repository. They were produced as CI artifacts in workflow run `40475334312` and are referenced by SHA-256 hashes in `core/supply_chain/image_baseline.json`:

| Image | Raw path | SHA-256 | Available in repo? |
|---|---|---|---|
| Shannon | `upstream/00-shannon-worker.trivy.json` | `3da6c3abb637eaed0015f513e5b49083ea23b2d6fec24e0875fa9c55a81f3c6c` | **NO** (CI artifact) |
| Temporal | `upstream/01-temporal.trivy.json` | `58e5efb30a468f845c693964b7f8c9cd89d976852de8aa8f4ee05d797bc02e51` | **NO** (CI artifact) |
| Gitleaks | `upstream/02-gitleaks.trivy.json` | `9d78d9e86960b447d07e65e7929b367e763d11b5c16d7ae38510220efcdc656e` | **NO** (CI artifact) |
| Trivy | `upstream/03-trivy-scanner.trivy.json` | `70ea99e75451567d5fa49389f73a2f314ea6bf97a0f182963512356a879f34f9` | **NO** (CI artifact) |

**Limitation:** The raw scan JSON files could not be independently re-read from the repository. The finding counts and package/version information in this document are derived from the committed baseline (`core/supply_chain/image_baseline.json`), which was generated from the raw artifacts. The baseline's integrity is verified by its SHA-256 hashes, but the raw artifacts themselves are not available for independent re-analysis.

---

## Report 1 — Trivy: GO-2026-5932

**Upstream repository:** `aquasecurity/trivy`
**Existing issue:** [#11435](https://github.com/aquasecurity/trivy/issues/11435) — **CLOSED**
**Existing title:** "GO-2026-5932 matches a pbkdf2-only binary with no OpenPGP imports, including in precise mode"

### Duplicate analysis

Issue #11435 was created on 2026-10-19 by another reporter and describes the **exact same behavior** as our Draft 1: Trivy reports GO-2026-5932 for a binary that imports only `golang.org/x/crypto/pbkdf2` (not OpenPGP). The issue is **CLOSED**.

Our controlled binary experiment (PR #65) independently confirms this behavior using a bcrypt-importing binary and an openpgp-importing binary, both scanned with Trivy 0.76.0. The result (`MODULE_LEVEL_REPORTING`) is consistent with #11435's findings.

### Status: `DUPLICATE_OR_ALREADY_COVERED`

**Recommendation:** Do NOT create a new upstream issue. Our PR #65 controlled-binary evidence is an internal observation that independently confirms the already-reported behavior. If the Trivy maintainers reopen #11435 or request additional evidence, our PR #65 workflow can be referenced.

### Corrected claims

| Original claim | Correction |
|---|---|
| "0 duplicate issues found" | **INCORRECT** — issue #11435 already exists and is closed |
| "APPROVED FOR PUBLICATION" | **INCORRECT** — should be `DUPLICATE_OR_ALREADY_COVERED` |
| Implied all production images are unaffected | **NOT ESTABLISHED** — controlled binary proves scanner behavior only, not production image reachability |

---

## Report 2 — Shannon: Node.js dependencies

**Upstream repository:** `KeygraphHQ/shannon`
**Existing issue:** [#479](https://github.com/KeygraphHQ/shannon/issues/479) — **OPEN**
**Existing title:** "Docker image keygraph/shannon:3.3.0 has 462 critical / 1179 high CVEs (mostly Chromium 149.0.7827.53)"

### Duplicate analysis

Issue #479 covers Shannon v3.3.0 vulnerabilities. A supplementary comment by `eneelkant` was already posted on 2026-10-31 with v3.4.0 scan evidence. Our Draft 2 proposed creating a new issue — this would be a **DUPLICATE** of #479.

### Status: `DUPLICATE_OR_ALREADY_COVERED` — supplementary comment already posted

**Recommendation:** Do NOT create a new issue. The v3.4.0 evidence has already been submitted as a comment on #479. Monitor the issue for maintainer response.

### Corrected findings (from baseline)

The baseline records 40 node-pkg rows for Shannon v3.4.0. These are scanner rows, not necessarily 40 unique vulnerabilities. Some packages may have multiple advisories. The 16 unique package names previously identified were derived from the baseline data.

| Category | Count | Notes |
|---|---|---|
| Wolfi OS packages | 941 rows | OS-level findings; apk-fixable |
| Node.js packages | 40 rows | 16 unique packages; mix of direct and transitive |
| Cargo packages | 3 rows | quinn-proto (2 advisories), rustls-webpki (1 advisory) |
| **Total scanner rows** | **984** | Rows ≠ unique vulnerabilities |

### Unverified claims

| Claim | Status |
|---|---|
| "2 direct dependencies" | **UNVERIFIED** — derived from cross-referencing `apps/worker/package.json`, not from raw scan artifact |
| "14 transitive dependencies" | **UNVERIFIED** — same derivation method |
| Fixed versions for all 16 packages | **UNVERIFIED** — raw scan JSON not available for re-validation |

---

## Report 3 — Temporal: Go dependencies

**Correct upstream repository:** `temporalio/cli` (NOT `temporalio/temporal`)
**Existing issue:** [#1249](https://github.com/temporalio/cli/issues/1249) — **OPEN**
**Existing title:** "[Bug] CLI 1.9.1 ships vulnerable golang.org/x/net and Go stdlib"

### Attribution correction

Our Draft 3 incorrectly targeted `temporalio/temporal`. The Docker image `temporalio/temporal:1.7.0` is a CLI/development-server image. The correct upstream repository for CLI vulnerabilities is `temporalio/cli`. Issue #1249 already exists on `temporalio/cli`.

A supplementary comment by `eneelkant` was already posted on #1249.

### Duplicate analysis

Issue #1249 covers CLI v1.9.1 vulnerabilities (Go stdlib + golang.org/x/net). Our evidence covers v1.7.0 which is an older version with the same dependency family. The v1.7.0 evidence is **SUPPLEMENTARY** to #1249, not a duplicate.

### Status: `DUPLICATE_OR_ALREADY_COVERED` — supplementary comment already posted; attribution corrected

**Recommendation:** Do NOT create a new issue. The v1.7.0 evidence has already been submitted as a comment on #1249. The repository attribution in our draft was incorrect (`temporalio/temporal` → should be `temporalio/cli`).

### Corrected findings (from baseline)

| Category | Count | Notes |
|---|---|---|
| Go binary findings | 52 rows | stdlib, golang.org/x/*, gomarkdown, thrift |
| Alpine OS findings | 6 rows | musl, libcrypto3, libssl3 |
| GO-2026-5932 | 1 row | Module-level false positive (see Report 1) |
| **Total scanner rows** | **58** (historical) / **59** (with GO-2026-5932) | Rows ≠ unique vulnerabilities |

### Version mapping note

GitHub releases use server versioning (v1.31.x); Docker Hub tags use CLI versioning (1.7.0, 1.9.1). The Docker image has not been updated since 1.9.1 (2026-09-14).

---

## Report 4 — Gitleaks: Go dependencies

**Upstream repository:** `gitleaks/gitleaks` (moved from `zricethezav/gitleaks`)
**Existing issue:** [#2305](https://github.com/gitleaks/gitleaks/issues/2305) — **OPEN**
**Existing title:** "Please Resolve CVEs in 8.30.1"

### Duplicate analysis

Issue #2305 covers Gitleaks v8.30.1 CVEs. Our evidence covers v8.21.2 (older version). The existing issue already covers the same dependency family (Go stdlib, golang.org/x/*). Our v8.21.2 evidence is **SUPPLEMENTARY** to #2305.

### Status: `DUPLICATE_OR_ALREADY_COVERED` — supplementary evidence for older version

**Recommendation:** Do NOT create a new issue. If a supplementary comment with v8.21.2-specific evidence is warranted, post it on #2305. The repository has moved from `zricethezav/gitleaks` to `gitleaks/gitleaks`.

### Corrected findings (from baseline)

| Category | Count | Notes |
|---|---|---|
| Go binary findings | 29 rows | stdlib v1.22.8, golang.org/x/sys, golang.org/x/text |
| Alpine OS findings | 12 rows | openssh, git, musl, libexpat |
| **Total scanner rows** | **41** | Rows ≠ unique vulnerabilities |

---

## Summary of corrections

| Draft | Original status | Corrected status | Key correction |
|---|---|---|---|
| 1 (Trivy) | "APPROVED FOR PUBLICATION" | `DUPLICATE_OR_ALREADY_COVERED` | Issue #11435 already exists and is closed |
| 2 (Shannon) | "APPROVED FOR PUBLICATION" | `DUPLICATE_OR_ALREADY_COVERED` | Comment already posted on #479 |
| 3 (Temporal) | "APPROVED FOR PUBLICATION" | `DUPLICATE_OR_ALREADY_COVERED` + attribution error | Wrong repo (temporalio/temporal → temporalio/cli); comment already posted on #1249 |
| 4 (Gitleaks) | "APPROVED FOR PUBLICATION" | `DUPLICATE_OR_ALREADY_COVERED` | Issue #2305 already covers v8.30.1; repo moved to gitleaks/gitleaks |

## Owner approval checklist

| Item | Status | Action needed |
|---|---|---|
| Trivy Draft 1 | **DO NOT PUBLISH** — duplicate of closed #11435 | None — retain as internal observation |
| Shannon Draft 2 | **ALREADY PUBLISHED** — comment on #479 | Monitor for maintainer response |
| Temporal Draft 3 | **ALREADY PUBLISHED** — comment on #1249 (wrong repo attribution corrected) | Monitor for maintainer response |
| Gitleaks Draft 4 | **DO NOT PUBLISH as new issue** — #2305 exists | Optionally post v8.21.2 supplementary comment on #2305 |

## Evidence limitations

1. **Raw scan JSON artifacts are NOT in the repository.** They were CI artifacts in workflow run `40475334312`. SHA-256 hashes are recorded in the baseline but the raw files cannot be independently re-read.
2. **Scanner rows ≠ unique vulnerabilities.** A single package may have multiple advisory rows. The counts (984, 58, 41, 7) are scanner row counts, not unique vulnerability counts.
3. **Controlled binary evidence (PR #65) proves scanner behavior, not production image reachability.** The experiment shows Trivy reports GO-2026-5932 at module level; it does not prove that Temporal or Trivy production images are free of affected OpenPGP code.
4. **Package-to-direct/transitive attribution was derived from source inspection, not from raw scan artifacts.** The `apps/worker/package.json` cross-reference for Shannon was done via GitHub API, not from the scan JSON.
5. **Fixed versions were taken from the baseline's `fixed_version` field**, which was populated from the Trivy scan. They have not been independently verified against OSV or NVD.
