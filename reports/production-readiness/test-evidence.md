# Test Evidence — `eneelkant/pen-testing`

**Snapshot date:** 2026-10-29
**Baseline commit:** `33a6b06392c1d971dec39e942863eb2f90524d4b`
**Investigator:** Agent (Principal Engineer mode)
**Execution environment:** Linux sandbox at `/home/z/my-project/workspace/pen-testing`; Python 3.12.16; `mcp==2.3.0` (pinned to match CI); no Docker daemon; no scanner binaries (`trivy`, `grype`, `gitleaks`, `syft`, `semgrep`, `nuclei`, `zap`, `checkov`, `mobsfscan`, `nmap`) in `$PATH`.

Each test group below is marked with one of:

| Result | Meaning |
|---|---|
| `PASS` | Test executed and passed; objective evidence captured. |
| `FAIL` | Test executed and failed; defect report referenced. |
| `BLOCKED` | Test cannot be executed in this environment; specific reason given. |
| `NOT RUN` | Test not yet attempted in this audit pass; tracked for a later phase. |
| `NOT VERIFIED` | Test executed but its output cannot be independently verified. |

## 1. Unit tests

| Field | Value |
|---|---|
| Command | `python3 -m pytest tests/unit --tb=line -q` |
| Working directory | `/home/z/my-project/workspace/pen-testing` |
| Branch | `main` at `33a6b06` |
| Python | 3.12.16 |
| pytest | 9.0.2 |
| `mcp` package | 2.3.0 (matches `requirements/mcp.txt` pin) |
| Result | **PASS** — `554 passed in 21.75s` |
| Skipped | 0 (no `s` in output) |
| Failed | 0 |
| Errors (collection) | 0 |
| Total tests collected | 554 |
| Test files | 32 (in `tests/unit/`) |
| Test functions | 466 (per `grep -rE '^def test_' tests/unit \| wc -l`) |
| Note | The 554-vs-466 difference is parametrized tests (one `def test_*` can collect multiple cases via `@pytest.mark.parametrize`). |

**Local unit-test evidence file:** none (pytest output captured only in this conversation transcript). Re-run command is reproducible.

## 2. Integration tests

| Field | Value |
|---|---|
| Command | `python3 -m pytest tests/integration --tb=short` |
| Working directory | `/home/z/my-project/workspace/pen-testing` |
| Branch | `main` at `33a6b06` |
| Result | **BLOCKED** — `tests/integration/test_smoke_markers.py:13: pytest.skip("Docker not installed in this environment")` |
| Reason | No Docker daemon in sandbox; integration tests are Docker-dependent and skip on hosts without Docker. |
| Workaround | The GitHub Actions `Docker build and runtime` job on commit `33a6b06` covers a subset of the same coverage. See CI evidence in Section 3. |
| Required to UNBLOCK | Install Docker in the audit environment OR run the tests on a host with Docker. |

## 3. CI checks on `main@33a6b06` (GitHub Actions)

Source: `GET /repos/eneelkant/pen-testing/commits/33a6b06/check-runs?per_page=30` at 2026-10-29 ~06:35 UTC.

| Check name | Status | Conclusion | Run URL |
|---|---|---|---|
| Lint and unit tests | completed | **success** | https://github.com/eneelkant/pen-testing/actions/runs/40829564657/job/123300404585 |
| Docker build and runtime | completed | **success** | https://github.com/eneelkant/pen-testing/actions/runs/40829564657/job/123300404654 |
| Secret scanning (gitleaks) | completed | **success** | https://github.com/eneelkant/pen-testing/actions/runs/40829564657/job/123300404607 |
| Dependency metadata check | completed | **success** | https://github.com/eneelkant/pen-testing/actions/runs/40829564657/job/123300404248 |
| Image vulnerability scans | **NOT RUN** | (workflow `paths:` filter excluded this commit) | n/a — issue #52 documents the historical result (1,101 blocking findings) |
| Image regression gate | **NOT RUN** | (workflow `paths:` filter excluded this commit) | n/a |

## 4. MCP server smoke

| Field | Value |
|---|---|
| Command | `python3 -c "from mcp_server.server import mcp; print(type(mcp).__name__); print(mcp.name); import asyncio; tools = asyncio.run(mcp.list_tools()); print(len(tools)); [print(t.name) for t in tools]"` |
| Working directory | `/home/z/my-project/workspace/pen-testing` |
| Branch | `main` at `33a6b06` |
| `mcp` package | 2.3.0 |
| Result | **PASS** |
| Server class | `MCPServer` (from `mcp.server.mcpserver`) |
| Server name | `pen-testing` |
| Tool count | 11 |
| Tools registered | `platform_status`, `check_dependencies`, `validate_target_scope`, `list_integrations`, `run_local_diagnostics`, `plan_assessment`, `authorize_assessment`, `run_security_assessment`, `get_assessment_status`, `list_findings`, `export_report` |

## 5. Authorization boundary — adversarial regression tests

| Field | Value |
|---|---|
| Status | **NOT RUN** |
| Reason | Phase B deliverable. Requires writing new regression tests in focused PRs against the boundary code paths (`scope/approval.py`, `scope/engine.py`, `scope/target.py`, `mcp_server/service.py`). The Phase A.4 read-only audit (see `security-findings.md`) verified 15 controls by code inspection but did not execute adversarial cases. |
| Planned cases | (a) missing / invalid / expired / mismatched / replayed approvals; (b) scope expansion via redirects, alternate hostnames, IP literals, DNS resolution, subdomains, encoded URLs, IPv6, malformed input; (c) SSRF attempts to loopback, private networks, cloud metadata; (d) path traversal, symlink escapes, unsafe archive extraction, output-path injection; (e) shell injection, malformed tool output, oversized output, timeouts, subprocess failures; (f) concurrent assessments sharing mutable state; (g) approval revocation and policy changes during a run; (h) scanner failure incorrectly reported as zero findings. |
| Required to UNBLOCK | Open focused PRs with the new regression tests, one boundary area per PR. |

## 6. Adapter integration tests

| Adapter | Status | Evidence |
|---|---|---|
| `headers` (passive HTTP security-header checks) | NOT RUN | Phase C. Requires fixtures for a local vulnerable headers target (e.g. `tests/fixtures/headers_server.py` exists but no live integration test runs it). |
| `gitleaks` (secret detection) | NOT RUN | Phase C. Requires `gitleaks` binary installed in `$PATH` (currently NOT INSTALLED in this sandbox). |
| `trivy` (dependency / config analysis) | NOT RUN | Phase C. Requires `trivy` binary installed in `$PATH` and Docker for image scans. |
| `checkov` (IaC misconfig; optional) | NOT RUN | Phase C. Requires `pip install '.[checkov]'` and Checkov CLI in `$PATH`. |
| `mobsfscan` (mobile source patterns; optional) | NOT RUN | Phase C. Requires `pip install '.[mobsfscan]'`. |
| `shannon` (AI-assisted white-box web/API) | NOT RUN | Phase C. Requires Docker, Shannon worker image (`keygraph/shannon:3.4.0@sha256:...`), and `npx`. |
| `briar` (black-box web) | NOT RUN | Phase C. Requires Docker and Briar adapter runtime. |

## 7. Docker runtime + worker isolation tests

| Field | Value |
|---|---|
| Local | **BLOCKED** — no Docker daemon in sandbox. |
| CI on `33a6b06` | **PASS** — `Docker build and runtime` check-run reports `success`. See Section 3 for run URL. |
| Note | CI success is objective evidence that the Docker build passes on GitHub's runner; it is NOT independent verification in this audit environment. |

## 8. Supply-chain / image vulnerability tests

| Field | Value |
|---|---|
| Local | **BLOCKED** — no `trivy` binary, no Docker daemon. |
| CI on `33a6b06` | **NOT RUN** — `image-gates.yml` workflow `paths:` filter excluded this commit (workflow-only change in PR #56). |
| Last historical result | Issue #52 documents CI run `40671223439` on PR #51 reported `1,101 blocking findings`; image regression gate reported `11 new + 1 changed + 1,089 inherited + 0 resolved`. |
| In-repo baseline | `core/supply_chain/image_baseline.json` lists `1,090` findings, all `awaiting-upstream-release` (1,088) or `no-fixed-version-published` (2). The baseline's `description` field states: "Not a waiver: listed findings remain open and the absolute release gate still fails on them." |
| Required to UNBLOCK | Re-trigger the image-gates workflow on `33a6b06` (or the next substantive commit) via `gh workflow run image-gates.yml --ref main`; OR run `python -m core.supply_chain images --baseline core/supply_chain/image_baseline.json` on a host with Docker + Trivy installed. |

## 9. Secret scanning

| Field | Value |
|---|---|
| Local | **NOT RUN** — `gitleaks` binary not installed in sandbox. |
| CI on `33a6b06` | **PASS** — `Secret scanning (gitleaks)` check-run reports `success`. |
| Note | CI's gitleaks uses the pinned `zricethezav/gitleaks:v8.21.2@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46` image (per `core/supply_chain/images.py:PINNED_IMAGES`). |

## 10. Dependency metadata check

| Field | Value |
|---|---|
| Local | **NOT RUN** — same as CI (uses `python -m core.supply_chain audit`). |
| CI on `33a6b06` | **PASS** — `Dependency metadata check` check-run reports `success`. |

## 11. Clean-environment installation test

| Field | Value |
|---|---|
| Status | **NOT RUN** — Phase D deliverable. |
| Plan | On a clean host with only Python 3.12 + pip: `python -m venv .venv && .venv/bin/pip install -e '.[mcp,dev]' && .venv/bin/python -m pytest tests/unit`. Verify zero errors and full 554-test pass. |

## 12. Supported platform tests

| Platform | Status |
|---|---|
| Linux x86_64 (CI runner) | **PASS** — CI green on `33a6b06`. |
| Linux x86_64 (this sandbox) | PARTIAL — unit tests pass; Docker-runtime tests BLOCKED. |
| macOS | **NOT VERIFIED** — no macOS runner available. |
| Windows | **NOT VERIFIED** — `scripts/install.ps1` exists; not exercised in this audit. |

## 13. Summary

| Test group | Local result | CI result on `33a6b06` |
|---|---|---|
| Unit tests | PASS (554) | PASS |
| Integration tests | BLOCKED (no Docker) | (covered by Docker-runtime check) |
| Docker build and runtime | BLOCKED | PASS |
| Secret scanning (gitleaks) | NOT RUN | PASS |
| Dependency metadata check | NOT RUN | PASS |
| Image vulnerability scans | BLOCKED | NOT RUN (paths filter excluded) |
| Image regression gate | BLOCKED | NOT RUN (paths filter excluded) |
| MCP server smoke | PASS | (covered by Lint+unit) |
| Authorization adversarial regression | NOT RUN | NOT RUN |
| Adapter integration tests | NOT RUN | NOT RUN |
| Clean-environment install | NOT RUN | NOT RUN |
| Cross-platform (macOS / Windows) | NOT VERIFIED | NOT VERIFIED |

**Conclusion:** Of 12 test groups, only 4 have objective PASS evidence in this audit (unit tests locally + Lint+unit / Docker / Secret scan / Dep metadata on CI). The other 8 are BLOCKED, NOT RUN, or NOT VERIFIED. This is sufficient evidence to support the Phase A baseline but is NOT sufficient evidence to declare production readiness.
