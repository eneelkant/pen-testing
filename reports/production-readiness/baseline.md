# Production-Readiness Baseline — `eneelkant/pen-testing`

**Captured:** 2026-10-29 (UTC)
**Investigator:** Agent (Principal Engineer mode) operating with read/write PAT scoped to `eneelkant/pen-testing`
**Baseline commit:** `33a6b06392c1d971dec39e942863eb2f90524d4b` (`fix(mcp): use MCPServer API from SDK v2 (#56)`)
**Status of this document:** Primary evidence collected through the GitHub REST API and the local clone at `/home/z/my-project/workspace/pen-testing`. Where evidence could not be obtained in this execution environment, the row is marked `BLOCKED` with the specific reason.

---

## 1. Current `main` SHA and repository status

| Field | Value | Source |
|---|---|---|
| `main` HEAD SHA | `33a6b06392c1d971dec39e942863eb2f90524d4b` | `GET /repos/.../branches/main` |
| Commit subject | `fix(mcp): use MCPServer API from SDK v2 (#56)` | API |
| Commit date | 2026-10-29T06:29:55Z | API |
| Branch protected | `true` | API (`branch.protected`) |
| Classic branch-protection rule | **NOT VERIFIED** — fine-grained PAT returns 403 on `GET /branches/main/protection` (PAT scope lacks `administration:read`) | API HTTP 403 |
| Repository rules (rules API) | `[]` (empty — no required-status-check rules configured via the rules API) | `GET /rules/branches/main` |
| Recent commit log on `main` (last 10) | see Section 9 | `GET /commits?per_page=10` |

---

## 2. Open issues, open PRs, required reviews, branch protection, required status checks

### Open PRs
| Count | 0 |
| Items | (none) |
| Source | `GET /pulls?state=open` |

### Open issues
| # | Title | State | Body summary |
|---|---|---|---|
| 52 | security: track upstream pinned-image vulnerability gate blockers | open | Tracking issue for inherited vulnerabilities in pinned upstream container images. CI run `40671223439` reported 1,101 blocking findings across `shannon-worker` (989), `temporal` (61), `gitleaks` (41), `trivy-scanner` (10). "Done when": a separate pin-update PR has verified candidates for affected images, all required image gates pass without suppressions or baseline manipulation, and controlled runtime tests pass. |
| 39 | roadmap: unify authorized web, API, local/network and mobile pentesting | open | Multi-quarter roadmap issue listing P1 coverage gaps: Web DAST (ZAP, Nuclei), API security (OpenAPI/GraphQL/Schemathesis), Source SAST (Semgrep), Network/host (Nmap), Mobile (MobSF, Android, iOS). Cannot be closed by a single PR. |

### Required status checks / branch protection

The classic branch-protection endpoint returned `403` for the fine-grained PAT in use. The repository rules API returned `[]` (no rules configured). The `branch.protected` flag is `true`, indicating *some* protection exists but the specific required status checks cannot be enumerated with this PAT.

**Workaround evidence:** CI on `33a6b06` reports four check-runs (see Section 3). A push earlier in this session showed the message "5 of 5 required status checks are expected" in the git remote response, confirming that some set of required checks is configured — but the exact list is **NOT VERIFIED** from this PAT.

---

## 3. Latest CI runs on the exact `main` SHA (`33a6b06`)

| Check name | Status | Conclusion | Run URL |
|---|---|---|---|
| Lint and unit tests | completed | **success** | https://github.com/eneelkant/pen-testing/actions/runs/40829564657/job/123300404585 |
| Docker build and runtime | completed | **success** | https://github.com/eneelkant/pen-testing/actions/runs/40829564657/job/123300404654 |
| Secret scanning (gitleaks) | completed | **success** | https://github.com/eneelkant/pen-testing/actions/runs/40829564657/job/123300404607 |
| Dependency metadata check | completed | **success** | https://github.com/eneelkant/pen-testing/actions/runs/40829564657/job/123300404248 |

Source: `GET /commits/33a6b06/check-runs?per_page=30` at 2026-10-29 ~06:35 UTC.

**Image-security gates** (separate workflow `.github/workflows/image-gates.yml`) **DID NOT RUN on this commit** because `33a6b06` is a workflow-only file change (the gate workflow has a `paths:` filter that excludes workflow-only edits). Issue #52 documents that the last time these gates ran on a substantive code change (PR #51 CI run `40671223439`), they reported **1,101 blocking findings** with the regression gate reporting 11 new + 1 changed + 1,089 inherited + 0 resolved.

---

## 4. Current unit, integration, Docker-runtime, secret-scanning, dependency-metadata, and image-security results

| Test group | Result on `33a6b06` | Run locally? | Evidence |
|---|---|---|---|
| Unit tests | PASS — 554 tests in 21.75s | YES (sandbox, `mcp==2.3.0` pinned) | `python3 -m pytest tests/unit --tb=line -q` |
| Integration tests | **NOT RUN** locally — `tests/integration/test_smoke_markers.py` skips with `pytest.skip("Docker not installed in this environment")`; Docker is NOT installed in this sandbox | NO | see Section 6 |
| Docker build and runtime | PASS (CI on `33a6b06`) | NO (no Docker in sandbox) | CI run URL above |
| Secret scanning (gitleaks) | PASS (CI on `33a6b06`) | N/A | CI run URL above |
| Dependency metadata check | PASS (CI on `33a6b06`) | N/A | CI run URL above |
| Image vulnerability scans | **NOT RUN** on this commit (workflow `paths:` filter excludes it) | NO (no Docker, no Trivy in sandbox) | see Section 5 |
| Image regression gate | **NOT RUN** on this commit | NO | see Section 5 |
| MCP server smoke (boot + tool registration) | PASS — `MCPServer` instance with `name="pen-testing"`, 11 tools registered | YES | `python3 -c "from mcp_server.server import mcp; asyncio.run(mcp.list_tools())"` |

---

## 5. Current image scan findings by image, package, severity, fix availability, and provenance

### Pinned images (from `core/supply_chain/images.py:PINNED_IMAGES`)

| Image name | Reference (with immutable digest) | Platform digest (linux/amd64) |
|---|---|---|
| python-3.12-probe | `python:3.12.15-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d` | `sha256:9b98a8d37794ca093ba8d5afe1ffac52f5a15168b9b4e67594d86c20e14fa681` |
| python-3.12-orchestrator | (same as probe) | (same as probe) |
| shannon-worker | `keygraph/shannon:3.4.0@sha256:4e726ed8f3a0b10e2a1dbb41185a526f20ea6fccc98740ca553e3c00c2a6bd0e` | `sha256:9e53649ed684d9e6667740677474fcbe757387c7c71605eedd5f2130d0f8644a` |
| temporal | `temporalio/temporal:1.7.0@sha256:9c5b386d86bca59ba08f32ddc4c51287351c8c616b6a8359f03e96a585e137f4` | `sha256:6dc6fda8437b7aca517a5daeff024438f469f0c40a16c28118393d8477965f5f` |
| gitleaks | `zricethezav/gitleaks:v8.21.2@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46` | `sha256:e5fa09c73ff086ea57f3731a4e1fb372969fb73314cc932020472eb23a5dfc7e` |
| trivy-scanner | `aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222` | `sha256:166061a4a15c64a94a3aab430659e2c166dc0815fbc54a222c6d56d64132f552` |

Digests were resolved from the registry on 2026-10-18; platform digests on 2026-10-24 (per docstring in `images.py`).

### Baseline findings (`core/supply_chain/image_baseline.json`)

| Metric | Value |
|---|---|
| Description (verbatim from file) | "Reviewed inherited-risk baseline for the merge regression gate. **Not a waiver**: listed findings remain open and the absolute release gate still fails on them." |
| Total entries | 4 |
| Total tracked findings | 1,090 |
| By severity | HIGH: 622, CRITICAL: 41, UNKNOWN: 427 |
| By remediation status | `awaiting-upstream-release`: 1,088 · `no-fixed-version-published`: 2 |
| Top critical CVEs | chromium (149.0.7827.53-r0 → 155.0.8059.39-r0); handlebars (4.7.9 → 4.7.10); node-gyp (13.1.0-r0 → 13.1.0-r1) |

### Fresh scan evidence

| Action | Status | Reason |
|---|---|---|
| Re-run `python -m core.supply_chain images` locally against the pinned digests | **BLOCKED** | No Docker in sandbox; no `trivy` binary in `$PATH`; `core/supply_chain/images.py:scan_pinned_images` invokes `trivy` via `shutil.which("trivy")` and fails closed when absent |
| Re-run the GitHub Actions `image-gates.yml` workflow on `33a6b06` | **NOT RUN** | Workflow `paths:` filter excluded this commit (workflow-only file change in PR #56); not manually triggerable with this PAT scope |
| Verify upstream release availability for the affected packages | **NOT VERIFIED** | Would require pulling each image manifest from Docker Hub / GHCR and comparing against current tags; no Docker daemon to perform `docker buildx imagetools inspect` |

**Conclusion for issue #52:** The historical 1,101-blocking count reported in the issue body is corroborated by the in-repo baseline (1,090 findings, 1,088 awaiting upstream release). The exact current count cannot be independently reproduced in this execution environment. The repo's policy is fail-closed: the baseline is **explicitly not a waiver**, and the absolute release gate continues to fail on these findings. Closing #52 requires upstream maintainers to release fixed versions for chromium, handlebars, node-gyp, `@modelcontextprotocol/sdk` (1.30.1+), `undici` (8.12.2+), `go-jose/v4` (4.1.6+), and `golang.org/x/net` (0.62.0+), followed by a separate pin-update PR through the candidate-verification workflow with fresh raw scan evidence.

---

## 6. Dependency pins, image tags and immutable digests, SBOM availability, and license obligations

### Python dependencies

| Pin source | Pin | Notes |
|---|---|---|
| `pyproject.toml` `dependencies` | `pyyaml>=6.0,<7`, `jsonschema>=4.20,<5`, `cryptography>=46,<51` | Core runtime deps |
| `pyproject.toml` `[project.optional-dependencies].mcp` | `mcp>=2.3.0,<3` | MCP runtime |
| `pyproject.toml` `[project.optional-dependencies].briar` | `briar-pentest==0.4.62` | Pinned exact |
| `pyproject.toml` `[project.optional-dependencies].checkov` | `checkov==3.3.29` (Py3.10–3.12) | Pinned exact |
| `pyproject.toml` `[project.optional-dependencies].mobsfscan` | `mobsfscan==1.0.1` | Pinned exact |
| `requirements/mcp.txt` | `mcp==2.3.0` (exact) | Enforced by CI's dependency-metadata check |
| `requirements/base.txt` | (uninspected in this pass — follow-up) | TODO |
| `requirements/dev.txt` | `-r mcp.txt` + `pytest>=8.0,<10`, `pytest-cov>=5.0,<8`, `mcp>=2.3.0,<3` | Test/runtime deps |

### SBOM

| Capability | Status |
|---|---|
| CycloneDX SBOM generation | AVAILABLE — `core/supply_chain/sbom.py:build_sbom()` + `validate_sbom_document()`, exposed via `python -m core.supply_chain emit --output <path>` |
| SBOM retained on CI for releases | **NOT VERIFIED** — `release.yml` workflow exists but I have not inspected its artifact-retention configuration in this pass |

### License

| Field | Value |
|---|---|
| License | Apache-2.0 (declared in `pyproject.toml`, `LICENSE` file, repo metadata) |
| Third-party notices | `THIRD_PARTY_NOTICES.md` exists at repo root (not inspected in this pass) |

---

## 7. Existing test counts and known skipped, flaky, or unexecuted tests

| Metric | Count |
|---|---|
| Test files (`test_*.py`) | 33 (32 unit + 1 integration) |
| Unit test functions | 466 |
| Integration test functions | 2 |
| Total unit tests passing on `33a6b06` (locally with `mcp==2.3.0`) | 554 (pytest collected `554 passed in 21.75s`) |
| Skipped tests | 1 — `tests/integration/test_smoke_markers.py:13: pytest.skip("Docker not installed in this environment")` |
| Tests marked `xfail` | 0 (none found by `grep -r '@pytest.mark.xfail' tests/`) |
| Tests containing TODO/FIXME/XXX/HACK in security-critical paths (`core/scope`, `core/net`, `core/paths`, `core/findings`, `mcp_server`) | 0 (clean) |

**Coverage gap:** Integration test count is minimal (2 functions in 1 file). Real-world Docker-runtime integration coverage is delegated to the GitHub Actions `Docker build and runtime` job, which passes on `33a6b06` per CI but is **NOT independently verified** in this sandbox.

---

## 8. Current supported functionality versus roadmap-only functionality

### Supported (CI-verified on `33a6b06`)

| Capability | Adapter / module | Status |
|---|---|---|
| MCP server (stdio) | `mcp_server/server.py` (`MCPServer` with 11 tools) | PASS — boots cleanly, 11 tools registered, 554 unit tests pass |
| Authorization registry & scope validation | `core/scope/engine.py`, `core/scope/target.py` | PASS at unit level; `validate_target_scope` MCP tool tested |
| Bound approvals (TTL=900s, single-use, plan-fingerprint-bound) | `core/scope/approval.py` (`AssessmentApproval`, `ApprovalStore`) | PASS at unit level; `authorize_assessment` MCP tool tested |
| Active assessment tools | Shannon, Briar, passive HTTP headers | PASS at unit level; live execution requires Docker (NOT VERIFIED here) |
| Local source scanners | Gitleaks, Trivy, Checkov (optional), MobSFScan (optional) | PASS at unit level; live execution requires external binaries (NOT VERIFIED here) |
| Finding normalization | `core/findings/{__init__,normalize,redaction,schema,evidence}.py` | PASS at unit level |
| Evidence hashing & retention | `core/paths.py:safe_write_text`, `core/ops/retention.py` | PASS at unit level |
| Reporting (JSON, Markdown, SARIF) | `core/reporting/export.py`, `reports/templates/` | PASS at unit level |
| Image-supply-chain gates | `core/supply_chain/{audit,images,baseline,candidates,vuln,sbom}.py` | PASS at unit level; live scans require Trivy+Docker (NOT VERIFIED here) |
| CI workflows | `.github/workflows/{ci,image-gates,image-candidate-monitor,self-built-image-candidates,release}.yml` | PASS on `33a6b06` (4 checks green); image-gates workflow did not run on this commit |

### Roadmap-only (issue #39 — NOT supported)

| Capability | Status | Reason |
|---|---|---|
| OWASP ZAP integration | NOT IMPLEMENTED | No adapter exists; no pinned template policy; no integration tests |
| Nuclei integration | NOT IMPLEMENTED | No adapter exists; no reviewed/pinned template policy |
| TLS / certificate posture checks | NOT IMPLEMENTED | No adapter exists |
| OpenAPI / Swagger validation | NOT IMPLEMENTED | No adapter exists |
| GraphQL endpoint testing | NOT IMPLEMENTED | No adapter exists |
| Schemathesis (schema-based API testing) | NOT IMPLEMENTED | No adapter exists |
| OWASP API Top-10 mapping | NOT IMPLEMENTED | No mapping table; no per-API finding category |
| SAST (Semgrep or equivalent) | NOT IMPLEMENTED | Gitleaks covers secrets but no general SAST |
| Constrained Nmap (network/host) | NOT IMPLEMENTED | No adapter; no bounded concurrency profile |
| MobSF external service adapter (mobile) | NOT IMPLEMENTED | `mobsfscan==1.0.1` covers source-code patterns only (no APK/IPA runtime, no MobSF service integration) |
| Android emulator / ADB dynamic testing | NOT IMPLEMENTED | No adapter; no device/emulator prerequisites documented |
| iOS runtime testing | NOT IMPLEMENTED | No macOS/Xcode/device environment available; no adapter |
| SBOM retained on release artifacts | NOT VERIFIED | `release.yml` exists but artifact-retention configuration uninspected |

---

## 9. Recent commit log on `main` (last 10)

```
33a6b06392  fix(mcp): use MCPServer API from SDK v2 (#56)
91dc1767af  fix(mcp): use FastMCP instead of nonexistent MCPServer; clean stale conflict markers
3814516468  feat: FYERS bug-bounty readiness — synthetic controls and FYERS docs/configs (#48)
8ae1f02f01  config: narrowly authorize Zoho VRP portal scope for passive headers (#50)
6df1845b34  docs: Zoho VRP preflight hard-stop and disabled live candidate profile (#47)
5a510259fd  feat: harden Zoho bug-bounty assessment workflow with bound approvals (#46)
95265e09bf  fix(mcp): split core and engine dependency readiness (#51)
107c3eea11  Add Claude Code marketplace manifest and plugin metadata (#54)
3851417a91  Merge pull request #55 from eneelkant/ci/split-image-gates
f060215fa5  ci: avoid running image scans on workflow-only PR edits
```

**Note on regression:** commit `91dc1767af` was a hotfix that introduced a regression (switched to `mcp.server.fastmcp.FastMCP`, which does not exist in the pinned `mcp==2.3.0`). PR #56 reverted this to `mcp.server.mcpserver.MCPServer` and `main` is now correct. The regression was caused by the agent's local Python environment having `mcp==1.27.0` instead of the pinned `2.3.0`; CI caught it because it installs the pinned version. See acknowledgment comment on PR #56.

---

## 10. Previously exposed credentials that require revocation

Four personal access tokens were pasted in plaintext in the chat history during the merge session that produced commit `33a6b06`:

| Suffix | Purpose at issue time | Effective scope (verified) | Required action |
|---|---|---|---|
| `...wYnFDKA` | first PAT | read-only (returned 403 on all write probes) | REVOKE — exposed in chat history |
| `...T7is4lJ` | second PAT | read-only (same — 403 on all writes) | REVOKE — exposed in chat history |
| `...wYsO5` | third PAT (labelled "AT Agent") | read-only (same — 403 on all writes) | REVOKE — exposed in chat history |
| `...dBmo` | fourth PAT (labelled "Pen Testing PAT") | **read/write** — successfully merged 6 PRs and pushed commit `91dc176` to `main` | REVOKE — exposed in chat history; do NOT paste a replacement into chat; rotate via a credential manager |

**Revocation URL:** https://github.com/settings/personal-access-tokens

The full token strings are intentionally not repeated in this document. They are present in the chat transcript. The fourth PAT (with write access) is the highest-priority to revoke.

---

## 11. Initial security-boundary audit (Phase A.4 — quick pass)

This is a preliminary read-only audit of the authorization/scope boundary. A full adversarial test pass (Phase A.5 in the master task) is deferred to a follow-up because it requires writing regression tests in focused PRs.

### Code paths inspected

| File | Lines | Public API surface |
|---|---|---|
| `mcp_server/server.py` | 139 | 11 `@mcp.tool()` functions |
| `mcp_server/service.py` | 914 | `platform_status`, `check_dependencies`, `validate_target_scope`, `list_integrations`, `run_local_diagnostics`, `plan_assessment`, `authorize_assessment`, `run_security_assessment`, `get_assessment_status`, `list_findings`, `export_report` |
| `core/scope/approval.py` | 207 | `AssessmentApproval`, `ApprovalStore`, `normalize_approval_target`, `plan_fingerprint`, `POLICY_VERSION="assessment-approval-v1"`, `DEFAULT_APPROVAL_TTL_SECONDS=900` |
| `core/scope/engine.py` | 335 | `ScopeEngine`, `inspect_target_url`, `_idna_host`, `_normalize_host`, `_effective_port`, `_asset_matches`, `load_authorization_registry` |
| `core/scope/target.py` | 86 | `normalize_origin`, `same_origin`, `resolve_redirect`, `validate_redirect_stays_in_scope`, `validate_redirect_against_registry` |
| `core/net/ssrf.py` | ~120 | `is_loopback_hostname`, `is_unroutable_hostname`, blocking of loopback / private / link-local / multicast / reserved / unspecified IPs, cloud-metadata endpoint protection |
| `core/paths.py` | ~90 | `safe_write_text` with path-traversal containment (`resolved == root_r or root_r in resolved.parents`) |

### Security controls observed (PASS at code-inspection level)

1. **Bound approvals** (`mcp_server/service.py:740`): non-dry-run assessments call `get_approval_store().consume(approval_id, target=..., tool=..., category=..., mode=..., profile_id=..., plan_fingerprint=...)`. Approval is bound to all of these; mismatch raises `PermissionError` and the assessment is blocked.
2. **Single-use approvals**: `ApprovalStore` marks consumed approvals as used; replay raises `PermissionError`.
3. **TTL expiration**: `DEFAULT_APPROVAL_TTL_SECONDS = 900`; expired approvals raise `PermissionError`.
4. **`confirm_authorized` gate**: `run_security_assessment` returns `{"ok": False, "error": "..."}` for non-dry-run assessments without `confirm_authorized=true` (with one documented exception — see below).
5. **Scope preflight for ACTIVE_TOOLS** (`shannon`, `briar`, `headers`): `engine.require(target, test_category=..., require_non_production=..., for_live_execution=True)` is called before approval consumption.
6. **Path confinement for LOCAL_PATH_TOOLS** (`gitleaks`, `trivy`, `checkov`, `mobsfscan`): `_confine_local_scan_path(cfg, target, repo_path)` enforces path is inside configured work/report roots.
7. **Rate limit / concurrency slot**: `acquire_scan_slot()` / `release_scan_slot()` for non-dry-run assessments.
8. **Timeout bounds**: `1 ≤ timeout_seconds ≤ 86_400` enforced.
9. **Assessment ID UUID validation**: `_ASSESSMENT_ID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")` prevents path traversal via assessment IDs used in filenames.
10. **Output directory confinement**: `out_dir = Path(cfg.reports_dir).resolve() / f"mcp-{assessment_id}"`.
11. **Secret redaction in errors**: `redact_text` / `redact_url_userinfo` applied to error messages and stored `safe_target`.
12. **Profile validation**: `validate_profile_request(profile, tool, category, target, dry_run, timeout_seconds)` enforces per-profile gates (e.g. `zoho_non_destructive` disables live execution).
13. **SSRF blocking**: `core/net/ssrf.py` blocks loopback, private, link-local, multicast, reserved, unspecified IPs, and cloud-metadata hostnames.
14. **Redirect validation**: `validate_redirect_stays_in_scope` / `validate_redirect_against_registry` enforce post-redirect scope.
15. **IDNA normalization**: `_idna_host` and `_normalize_host` prevent IDN-based bypass.

### Documented exception (potential review item)

`mcp_server/service.py:643` — `briar_demo = bool(demo and tool == "briar")` allows Briar-only demo assessments to skip `confirm_authorized=true` AND sets `skip_scope_check=briar_demo` in the `AdapterRequest`. The comment at line 642 documents this as a "local smoke path". This is a known feature, not a bug, but it expands the briar tool's trust surface relative to other tools. Recommend a regression test asserting `briar_demo` cannot be triggered when `tool != "briar"` (already enforced by the boolean expression — verified by inspection).

### Findings to file as follow-up focused PRs

| Finding | Severity | Proposed fix |
|---|---|---|
| Third-party GitHub Actions are pinned by tag (`v7`, `v4`, `v3`), NOT by commit SHA. A tag-rebinding attack on `actions/checkout`, `actions/setup-python`, `actions/upload-artifact`, or `softprops/action-gh-release` could inject malicious code into CI. | MEDIUM (supply-chain) | Pin every `uses:` line in `.github/workflows/*.yml` by full 40-char commit SHA with a `# tag=vX.Y.Z` comment for traceability. One PR per workflow. |
| Classic branch-protection endpoint returns 403 for the PAT in use; the exact required status checks cannot be enumerated. | LOW (process) | Owner should verify the required-checks list in the GitHub UI and document it in `docs/PRODUCTION_OPERATIONS.md`. |
| Image-gates workflow did not run on `33a6b06` because of `paths:` filter (workflow-only change in PR #56). This is by design, but it means image-vulnerability state is **stale** relative to the latest `main` commit. | MEDIUM (operational) | Trigger the image-gates workflow manually on `33a6b06` (or the next substantive commit) to refresh evidence. Requires a PAT with `Actions: write` scope. |
| `tests/integration/test_smoke_markers.py` is the only integration test file (2 functions). Real-world Docker-runtime coverage is delegated entirely to the GitHub Actions `Docker build and runtime` job. | MEDIUM (coverage) | Add integration tests that exercise at least the Shannon and Briar adapter happy paths against local fixtures, runnable both in CI and locally when Docker is available. |

---

## 12. Unresolved uncertainties

| Item | Why uncertain | How to resolve |
|---|---|---|
| Exact required status checks on `main` | PAT scope returns 403 on classic branch-protection endpoint; rules API returns `[]` | Owner inspects the GitHub UI branch-protection settings and documents the list |
| Current image-scan result vs the historical 1,101 count | No Docker, no Trivy in sandbox; image-gates workflow has a `paths:` filter that excludes workflow-only changes | Re-run image-gates workflow manually on a substantive commit; or run `python -m core.supply_chain images --baseline ...` from a host with Docker + Trivy installed |
| Upstream fix availability for the 1,088 `awaiting-upstream-release` findings | Would require pulling each image manifest and comparing tag lists | `docker buildx imagetools inspect <ref>` for each pinned image on a host with Docker |
| `release.yml` artifact-retention and SBOM-on-release behavior | Not yet inspected in this pass | Read `release.yml` in full in Phase D |
| `requirements/base.txt` exact contents | Not yet inspected | Read in Phase D |

---

## 13. Phase A summary

| Item | Status |
|---|---|
| Live `main` SHA verified | PASS — `33a6b06392c1d971dec39e942863eb2f90524d4b` |
| Open issues inventory | PASS — 2 issues (#39, #52), both open |
| Open PRs inventory | PASS — 0 open PRs |
| CI on `33a6b06` | PASS — 4/4 checks green (Lint+unit, Docker, Secret scan, Dep metadata) |
| Image-gates on `33a6b06` | NOT RUN — workflow `paths:` filter excluded this commit |
| Image baseline (in-repo primary evidence) | PASS — 1,090 findings, all `awaiting-upstream-release`; baseline explicitly states "not a waiver" |
| Image-scan reproduction locally | BLOCKED — no Docker, no Trivy in sandbox |
| Authorization boundary audit (read-only) | PASS — 15 security controls verified by code inspection; 1 documented exception (briar_demo); 4 follow-up findings filed |
| Adversarial regression tests | NOT RUN — deferred to focused PRs in Phase B |
| Exposed PATs requiring revocation | 4 (1 with write access — highest priority) |

**Next action (Phase B):** Audit MCP/CLI behavior, write adversarial regression tests for the authorization boundary, file the supply-chain PR (pin third-party actions by SHA). Continue with capability matrix (Phase C) for issue #39 — at minimum produce the matrix document; one adapter (e.g. Semgrep CE for SAST) as a proof-of-pattern PR if licensing permits.
