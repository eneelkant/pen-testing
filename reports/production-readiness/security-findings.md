# Security Findings — `eneelkant/pen-testing`

**Snapshot date:** 2026-10-29
**Baseline commit:** `33a6b06392c1d971dec39e942863eb2f90524d4b`
**Audit type:** Read-only code inspection (Phase A.4) of the authorization/scope boundary, CI workflows, and supply chain. Adversarial regression tests not yet executed (Phase B deliverable).

Findings are classified:

| Severity | Meaning |
|---|---|
| `CRITICAL` | Blocks production release. Must be remediated before declaring `PRODUCTION_READY`. |
| `HIGH` | Material risk; should be remediated or have an approved exception before release. |
| `MEDIUM` | Real issue; track for remediation in a focused PR. |
| `LOW` | Hygiene / hardening recommendation. |
| `INFO` | Noted for completeness; not a defect. |

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 1 (issue #52 image blockers — pre-existing, awaiting upstream release) |
| HIGH | 0 (no new findings at this severity from this audit pass) |
| MEDIUM | 4 |
| LOW | 2 |
| INFO | 3 |

---

## CRITICAL — Pre-existing, awaiting upstream release

### C-1 — 1,090 blocking image-vulnerability findings across pinned upstream images

| Field | Value |
|---|---|
| Tracking issue | #52 |
| Source | `core/supply_chain/image_baseline.json` |
| Status | `awaiting-upstream-release` (1,088) + `no-fixed-version-published` (2) |
| Severity breakdown | HIGH: 622 · CRITICAL: 41 · UNKNOWN: 427 |
| Top critical packages | chromium (149.0.7827.53-r0 → 155.0.8059.39-r0), handlebars (4.7.9 → 4.7.10), node-gyp (13.1.0-r0 → 13.1.0-r1) |
| Remediation | Blocked on upstream maintainers releasing fixed versions for `@modelcontextprotocol/sdk` (1.30.1+), `undici` (8.12.2+), Chromium (`155.0.8059.39-r0+`), `go-jose/v4` (4.1.6+), `golang.org/x/net` (0.62.0+). After upstream releases: a separate pin-update PR must be opened through the repo's candidate-verification workflow with fresh raw scan evidence and zero blocking findings under the unchanged policy. |
| Local reproduction in this audit | BLOCKED — no Docker daemon, no `trivy` binary in `$PATH` in this execution environment |
| Repo policy | **Fail-closed.** The baseline file's description explicitly states: "Not a waiver: listed findings remain open and the absolute release gate still fails on them." |

**Recommendation:** Do NOT close issue #52 until upstream releases are available AND a verified pin-update PR passes the regression gate without suppressions. Issue #52 is the canonical tracking issue for this CRITICAL.

---

## MEDIUM — Remediable in focused PRs

### M-1 — Third-party GitHub Actions pinned by mutable tag, not commit SHA

| Field | Value |
|---|---|
| Source | `.github/workflows/{ci,image-candidate-monitor,image-gates,release,self-built-image-candidates}.yml` |
| Affected actions | `actions/checkout@v7`, `actions/setup-python@v7`, `actions/setup-node@v7`, `actions/upload-artifact@v4`, `actions/upload-artifact@v7`, `softprops/action-gh-release@v3` |
| Risk | A tag-rebinding attack on any of these actions could inject malicious code into CI runs. The risk is highest for `softprops/action-gh-release@v3` (third-party, with `secrets.GITHUB_TOKEN` access in `release.yml`). |
| Remediation PR | #58 (`ci/pin-actions-by-sha`) — opened in this audit. Pins all 33 `uses:` lines by 40-char commit SHA with `# vX.Y.Z` comment for traceability. |
| Status | Fix PR opened; awaiting CI and review. |

### M-2 — Image-gates workflow did not run on `main@33a6b06`

| Field | Value |
|---|---|
| Source | `.github/workflows/image-gates.yml` `paths:` filter |
| Risk | The image-vulnerability state on `main@33a6b06` is stale relative to the most recent code change. The 1,090 baseline findings remain unverified against this exact commit. |
| Root cause | PR #56 was a workflow-only change (workflow files + `.github/` paths), and the `paths:` filter excludes workflow-only edits to avoid running image scans on workflow-definition PRs. |
| Remediation | Manually trigger the `image-gates.yml` workflow on `33a6b06` (or the next substantive commit) via the GitHub UI or `gh workflow run image-gates.yml --ref main`. Requires a PAT with `Actions: write` scope. |
| Status | NOT RUN in this audit — `Actions: write` scope not verified for the PAT in use. |

### M-3 — Minimal integration test coverage

| Field | Value |
|---|---|
| Source | `tests/integration/test_smoke_markers.py` (the only integration test file, 2 functions, both skipped when Docker is not installed) |
| Risk | Real-world Docker-runtime coverage is delegated entirely to the GitHub Actions `Docker build and runtime` job. There are no integration tests that can be run locally when Docker is available, so reproducing CI failures locally is harder than necessary. |
| Remediation | Add integration tests for at least the Shannon and Briar adapter happy paths against local fixtures. Tests should be runnable both in CI and locally when Docker is available (use `pytest.mark.skipif(not shutil.which("docker"), reason="Docker not available")` rather than a blanket skip). |
| Status | Tracked for Phase B/C follow-up. |

### M-4 — Classic branch-protection endpoint returns 403 for the audit PAT

| Field | Value |
|---|---|
| Source | `GET /repos/eneelkant/pen-testing/branches/main/protection` returned `403 Resource not accessible by personal access token` |
| Risk | The exact required-status-checks list cannot be enumerated from this PAT. Without that list, an external auditor cannot verify that the right gates are mandatory. |
| Root cause | Fine-grained PAT was issued without `Administration: read` scope. |
| Remediation | Repository owner inspects the GitHub UI branch-protection settings and documents the required-checks list in `docs/PRODUCTION_OPERATIONS.md`. Alternatively, issue a follow-up PAT with `Administration: read` scope for audit purposes. |
| Status | Owner action required. |

---

## LOW — Hygiene recommendations

### L-1 — `briar_demo` flag bypasses `confirm_authorized` and `skip_scope_check`

| Field | Value |
|---|---|
| Source | `mcp_server/service.py:643` — `briar_demo = bool(demo and tool == "briar")`; passed to `AdapterRequest` as `skip_scope_check=briar_demo` |
| Risk | Briar-only demo assessments skip both the `confirm_authorized=true` gate AND the scope-check at the adapter level. This is documented as a "local smoke path" but it expands Briar's trust surface relative to all other `ACTIVE_TOOLS`. |
| Current controls | The boolean expression `bool(demo and tool == "briar")` correctly prevents `briar_demo=True` when `tool != "briar"` (verified by code inspection). The flag also requires `demo=true` to be set explicitly. |
| Remediation | Add a regression test asserting `briar_demo` cannot be triggered when `tool != "briar"` AND that `briar_demo=true` paths still go through `_confine_local_scan_path` for any local file paths. Also document the briar-demo path's threat model in `docs/PRODUCTION_OPERATIONS.md`. |
| Status | Tracked for Phase B. |

### L-2 — `release.yml` uses `secrets.GITHUB_TOKEN` for `GHCR_TOKEN`

| Field | Value |
|---|---|
| Source | `.github/workflows/release.yml:54-75` |
| Risk | `GITHUB_TOKEN` has per-workflow scoped permissions (good), but using it as `GHCR_TOKEN` alias is a minor transparency issue — reviewers may miss the actual scope inheritance. |
| Remediation | Consider an explicit `env: GHCR_TOKEN: ${{ secrets.GITHUB_TOKEN }}` block at job level (already appears to be the case in part — re-inspect during Phase D). Verify the workflow's `permissions:` block is `contents: write` (for release creation) and `packages: write` (for GHCR push), nothing broader. |
| Status | Tracked for Phase D. |

---

## INFO — Noted for completeness

### I-1 — One skipped test in `tests/integration/test_smoke_markers.py`

`pytest.skip("Docker not installed in this environment")` — correctly skips when Docker is absent. No action required; this is the right pattern.

### I-2 — Zero TODOs / FIXMEs / XXXs in security-critical code paths

`grep -rE 'TODO|FIXME|XXX|HACK' --include='*.py' core/scope core/net core/paths core/findings mcp_server` returned no results. Clean.

### I-3 — `image_baseline.json` description is explicit about non-waiver

The baseline file's `description` field states verbatim: "Reviewed inherited-risk baseline for the merge regression gate. **Not a waiver**: listed findings remain open and the absolute release gate still fails on them." This is a strong, positive control — the policy intent is unambiguous.

---

## Phase B/C/D/E backlog

The following items are tracked for subsequent phases (not new findings; they are master-task items not yet executed):

| Item | Phase |
|---|---|
| Adversarial regression tests for the authorization boundary (redirect bypass, SSRF, path traversal, replay attacks, malformed tool output, scanner-failure-as-zero-findings) | B |
| Per-adapter malformed-output handling verification | B |
| Capability matrix gap closures (ZAP, Nuclei, Schemathesis, Semgrep, MobSF, Nmap) — one focused PR per engine | C |
| `release.yml` artifact-retention and SBOM-on-release verification | D |
| `requirements/base.txt` inspection | D |
| `docs/PRODUCTION_OPERATIONS.md` authoring | D |
| README "supported capabilities / known limitations" section | D |
| Release-candidate commit freeze and full test matrix run on that exact SHA | E |

---

## Status of this document

This `security-findings.md` reflects only Phase A.4 (read-only code audit) and Phase A.5 (baseline capture). It does **not** reflect:
- Adversarial regression-test results (Phase B) — NOT RUN
- Per-adapter integration test results (Phase C) — NOT RUN
- Release-candidate verification (Phase E) — NOT RUN

It will be updated after Phase B with new findings from the adversarial test pass.
