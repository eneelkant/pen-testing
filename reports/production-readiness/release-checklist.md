# Release Checklist — `eneelkant/pen-testing`

**Owner:** release manager (currently the repo owner, `eneelkant`)
**Document status:** Phase A snapshot at `main@33a6b06`. Items marked `[ ]` are unchecked; items marked `[x]` have objective evidence and reference the source. Items marked `[BLOCKED]` cannot be checked in this audit environment.

This checklist mirrors the 14 mandatory production-readiness acceptance criteria from Section 12 of the master task.

## Mandatory acceptance criteria

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | No unresolved critical security defect in the supported release scope | [BLOCKED] | Issue #52 documents 1,090 blocking image-vulnerability findings, all `awaiting-upstream-release`. The repo's policy is fail-closed (baseline explicitly "not a waiver"). Until upstream releases are available AND a verified pin-update PR passes the regression gate, this remains unresolved. See `security-findings.md` C-1. |
| 2 | Image vulnerability gates pass under the unchanged security policy | [ ] | Image-gates workflow did not run on `33a6b06` (paths filter excluded). Historical result on PR #51 (CI run `40671223439`): 1,101 blocking findings, gate FAIL. Local reproduction BLOCKED (no Docker, no Trivy). See `test-evidence.md` Section 8. |
| 3 | Authorization and scope enforcement pass adversarial regression tests | [ ] | Adversarial regression tests NOT RUN (Phase B deliverable). Phase A.4 read-only audit verified 15 controls by code inspection but did not execute adversarial cases. See `security-findings.md`. |
| 4 | Worker isolation is verified by runtime evidence | [PARTIAL] | CI `Docker build and runtime` check on `33a6b06` PASS — objective evidence that the build passes on GitHub's runner. NOT independently verified in this audit (no Docker daemon in sandbox). See `test-evidence.md` Section 7. |
| 5 | No false-success or false-zero-finding behavior | [ ] | NOT VERIFIED. Requires per-adapter integration tests that demonstrate (a) a failed scanner cannot produce a successful zero-finding report, (b) partial assessments are clearly marked partial. Phase B/C deliverable. |
| 6 | All advertised adapters have positive and negative integration tests | [ ] | NOT RUN. See `test-evidence.md` Section 6. No adapter has both positive and negative integration tests in this audit. |
| 7 | All required CI checks pass on the exact release-candidate SHA | [PARTIAL] | 4/4 required CI checks pass on `33a6b06` (Lint+unit, Docker, Secret scan, Dep metadata). Image-gates and image-regression-gate did not run on this commit. See `test-evidence.md` Section 3. |
| 8 | SBOM, image digests, and build provenance are available | [PARTIAL] | SBOM generation AVAILABLE (`python -m core.supply_chain emit --output`). Image digests pinned with immutable `@sha256:` refs in `core/supply_chain/images.py:PINNED_IMAGES`. SBOM-on-release artifact retention NOT VERIFIED (`release.yml` not fully inspected). See `baseline.md` Section 6. |
| 9 | No known exposed active credentials remain unrevoked | [ ] | 4 PATs exposed in chat history during the merge session that produced `33a6b06`. One had write access (highest priority to revoke). All 4 require revocation at https://github.com/settings/personal-access-tokens. See `baseline.md` Section 10. |
| 10 | Clean-install and operational smoke tests pass | [ ] | NOT RUN. Phase D deliverable. |
| 11 | Documentation matches actual supported capabilities | [ ] | Not yet updated. Phase D deliverable: README "supported capabilities / known limitations" section + `docs/PRODUCTION_OPERATIONS.md`. See `capability-matrix.md` for the authoritative capability list. |
| 12 | Upgrade, rollback, incident response, and retention procedures are documented | [ ] | NOT YET. Phase D deliverable. |
| 13 | All release blockers are closed or explicitly resolved under a documented, approved release policy | [BLOCKED] | Issue #52 (image blockers) is open and awaiting upstream release. Issue #39 (capability roadmap) is open with 12 ROADMAP and 2 BLOCKED capabilities. Neither can be auto-closed by the work in this audit. |
| 14 | A final evidence-backed readiness report has been reviewed | [ ] | This checklist + the other deliverables in `reports/production-readiness/` are the basis; final report (release-candidate verification) is the Phase E deliverable. |

## Release-candidate freeze procedure (Phase E)

When ready to declare a release candidate:

1. **Freeze the SHA.** Pick the commit on `main` to release. Record the SHA, commit date, and parent SHAs.
2. **Verify HEAD matches.** `gh api repos/eneelkant/pen-testing/branches/main` — confirm `commit.sha` matches the frozen SHA.
3. **Run the full test matrix on that exact SHA.** See `test-evidence.md` for the matrix.
4. **Verify all CI check-runs are green** on the frozen SHA. `GET /commits/{sha}/check-runs?per_page=30`.
5. **Trigger image-gates workflow manually** if it didn't run on the frozen SHA. `gh workflow run image-gates.yml --ref main`.
6. **Verify no new image-scan findings** beyond the documented baseline.
7. **Run `python -m core.supply_chain emit --output sbom.cdx.json`** on a host with the pinned dependencies installed. Attach the SBOM to the release.
8. **Verify all 4 exposed PATs are revoked.**
9. **Verify all open PRs are reviewed and either merged or explicitly deferred.**
10. **Verify all open issues that block release are either closed or have a documented exception approved by the repo owner.**
11. **Tag the release:** `git tag -s v0.2.0 -m "..."` (signed tag), `git push origin v0.2.0`. The `release.yml` workflow should produce the GitHub Release with attached SBOM and provenance.
12. **Publish the release notes** referencing the final readiness report and the test-evidence document.

## Approved exceptions (none yet)

No exceptions have been approved. Any future exception must be:
- Documented in this section with the issue/finding it applies to.
- Approved in writing by the repo owner.
- Time-bounded (with an expiration date and a re-review trigger).
- Reviewed in the next release cycle.

## Status

**Current release-candidate SHA:** `33a6b06392c1d971dec39e942863eb2f90524d4b`

**Current status:** `NOT_PRODUCTION_READY`

**Reason:** Of 14 mandatory criteria, 0 are fully satisfied, 3 are PARTIAL, 9 are unchecked (require Phase B–E work), and 2 are BLOCKED by external dependencies (upstream image releases for #52; PAT revocation by owner). The repository is a working MCP server with a sound authorization boundary, but cannot be declared production-ready at this commit.

**Next required actions (in priority order):**

1. **Owner revokes 4 exposed PATs** (criterion 9) — highest urgency, no engineering work.
2. **Owner triggers image-gates workflow on `33a6b06`** (criterion 2) — refresh evidence; needs `Actions: write` scope.
3. **Owner documents the required-status-checks list** in `docs/PRODUCTION_OPERATIONS.md` (criterion 7).
4. **Phase B PRs** — adversarial regression tests for the authorization boundary (criteria 3, 5).
5. **Phase C PRs** — one focused adapter PR per ROADMAP engine (criteria 6, 11).
6. **Phase D PRs** — `docs/PRODUCTION_OPERATIONS.md`, README supported-capabilities section, clean-install tests (criteria 10, 11, 12).
7. **Phase E** — release-candidate freeze and final verification (criteria 1, 13, 14).
