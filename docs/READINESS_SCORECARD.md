# Readiness scorecard

Review date: **2026-10-17**  
Integrated baseline: `origin/main` `4162e41c5d3b65464c10b3b6386f0afafa1ba5af` (merge of PR #20, package `0.2.0a13`).
This document is the `0.2.0a14` integration of that baseline. Local commands recorded below were run on this tree before CI on the pushed SHA. CI on that SHA is the release gate.

**Verdict: not production-ready.** Engineering controls below are partial. Legal clearance and independent security review have not happened. A green unit run is not a production sign-off.

Statuses used here: `PASS`, `PARTIAL`, `BLOCKED`, `FAIL`, `NOT VERIFIED`.

## Milestones

### 1. Authorization and scope — PARTIAL

- Implemented: the scope engine denies unknown hosts, expired records, production targets, and scheme-less whole-host expansion. Disabling scope requires `PEN_ALLOW_SCOPE_DISABLE`. Egress checks stay on when scope is skipped.
- This release enforces `rate_limit_rps` on non-dry-run adapter preflight and caps live CLI/MCP scans with `PEN_MAX_INFLIGHT_SCANS` (default 4). Both counters are process-local and reset on exit.
- Tests: `tests/unit/test_scope.py`, `tests/unit/test_readiness_security.py`, `tests/unit/test_rate_limit.py`.
- Outstanding: the operator must maintain `scopes/registry.yaml`. Skipping the registry also skips the per-record rate limit. There is no multi-user authentication. This is a single-operator model.
- Next action: keep authorization records current for each target. Do not expose the MCP server as a multi-user service.

### 2. Network isolation — PARTIAL

- Implemented and present after the PR #20 merge: shared destination policy (host allowlist, resolve-time private/metadata deny, default ports 80/443), Docker `Internal=true` scanner networks, and `PEN_ALLOW_SHANNON_FULL_PIPELINE` defaulting off. `HTTP_PROXY` is not the connection boundary.
- Local unit tests covering destination policy, egress, and scanner isolation passed in the 2026-10-17 suite (`187 passed, 1 skipped`). The skip is `tests/integration/test_smoke_markers.py` because Docker is not installed in that environment.
- Historical runtime markers (`PROXY_DENIES_UNLISTED_HOST`, `SHANNON_E2E_VALIDATE_MODEL_SUCCEEDED`, and the Briar/Shannon direct-block markers) were logged on earlier SHAs, including PR #20 and `2cadf8d`. They have not been re-run on this integrated tree in the local environment.
- Outstanding: in-engine browser DNS, redirect, and rebinding paths inside Shannon or Briar are not enforced by this repository. The Shannon end-to-end path uses a local mock LLM (`--validate-model`), not a production-LLM exploit pipeline.
- Next action: read the Docker runtime job on the integrated SHA and confirm the markers. Leave the full-pipeline gate off.

### 3. Secret handling — PARTIAL

- Implemented: assessment records are redacted before they are written. Patterns cover URL userinfo, JWT-like strings, AWS-key-like strings, GitHub tokens, Slack tokens and webhooks, `sk-` style keys, PEM private keys, and sensitive key names. Nested structures are included. CLI errors shown to the operator are redacted.
- Tests: `tests/unit/test_ops_data_protection.py`.
- Outstanding: pattern matching misses unknown formats. Shannon, Briar, and container logs written outside this process are not redacted. No live credential was found by the local gitleaks run; that does not prove historical git objects are clean beyond what that scan saw (`--no-git` on the working tree).
- Next action: keep secrets out of command lines and scanner configs. Rotate anything a future scan reports.

### 4. Report and file access — PARTIAL

- Implemented: assessment IDs must be UUIDs. Reads and writes refuse symlink components, including parents. Exports stay under the reports directory, work directory, or, for the CLI, the current directory. Corrupt assessment JSON fails closed. Cleanup is dry-run unless `--apply`, ignores symlink entries, and is not invoked by MCP status.
- Tests: `tests/unit/test_ops_data_protection.py`.
- Outstanding: files are plaintext. Encryption at rest is not implemented. There is no per-user authorization beyond the OS account that runs the process. A race that replaces a path with a symlink after the open is mitigated by `O_NOFOLLOW` on the final component and by rejecting symlink parents before the open; it is not a cross-host guarantee.
- Next action: restrict OS permissions on `PEN_WORK_DIR` and `PEN_REPORTS_DIR`. Do not claim encryption or backups.

### 5. Supply chain — PARTIAL

- Implemented: `python -m core.supply_chain audit` checks declared requirements and does not query a vulnerability database. `emit` writes CycloneDX 1.5 from `requirements/*.txt` and the structural check rejects a `vulnerabilities` array. That check is not a full CycloneDX JSON Schema certification. `rpds-py` is pinned to `2026.9.1` (the version resolved with `jsonschema==4.26.0`).
- Local evidence on 2026-10-17: audit exit 0, 21 components, unpinned findings empty. `emit` exit 0. `vuln` exit 0, status `PASS`, `blocking_count` 0, `generated_at` `2026-10-17T17:39:47.114382+00:00`, database `https://api.osv.dev/v1/querybatch`. The same client returned blocking unscored findings `GHSA-8q59-q68h-6hv4` and `PYSEC-2021-142` for `pyyaml==5.3.1`, so an empty result on the pinned set is not a client that ignores the API. OSV `querybatch` does not return a database snapshot time.
- Local gitleaks `v8.21.2` (`detect --no-git`) exit 0, no leaks. CI still runs the gitleaks container on the pushed SHA; that job is not a result for this unpushed tree.
- Outstanding: container images (Shannon, Briar, Temporal, Trivy, Gitleaks, the unpinned `python:3.12-slim-bookworm` fixture) are outside this Python scan. AGPL questions in `docs/LICENSING_REVIEW.md` are unresolved. Counsel review is pending. A `PASS` from OSV is not a claim about unscanned images or unpinned ranges that are not in this lock set.
- Next action: keep the CI OSV step failing closed on `FAIL` and `NOT_VERIFIED`. Send `docs/LICENSING_REVIEW.md` to qualified counsel before any production distribution claim.

### 6. Operational reliability — PARTIAL

- Implemented: retention default 14 days, cleanup dry-run unless `--apply`, Compose services drop all capabilities, set `no-new-privileges`, run as non-root, and set memory and CPU limits. Scanner networks used by workers are `internal: true`. The orchestrator service command is `doctor`, not a public listener. No application database is part of this architecture, so there is no database backup job to configure.
- Tests: cleanup cases in `tests/unit/test_ops_data_protection.py`. Worker restart and abandoned-container cleanup are in `scripts/docker_runtime_verify.sh` and were not executed locally (Docker absent).
- Outstanding: retention is not a daemon. There is no backup, no external alerting integration, and no multi-instance lock. Health is `pen-testing doctor` / MCP `platform_status`, not a hosted monitor. Rollback is a git revert of the release commit plus image rebuild; it is not an automated deployment.
- Next action: run `pen-testing cleanup` on a schedule the operator chooses, and confirm the Docker job on the integrated SHA.

## Release gates that remain mandatory

1. Required CI checks green on the exact release SHA, including the OSV query. A local `PASS` does not replace that run.
2. Repository review and branch protection, where GitHub enforces them. A 403 from the protection API is not evidence that review is optional.
3. `PEN_ALLOW_SHANNON_FULL_PIPELINE` remains unset.
4. Counsel review of `docs/LICENSING_REVIEW.md` for the intended distribution model.
5. No statement that encryption at rest, backups, multi-user auth, or in-engine browser containment exist.

## What this scorecard does not claim

- Production readiness
- Multi-tenant SaaS
- Legal clearance
- Independent penetration-test sign-off of this platform
- Zero CVEs in container images
