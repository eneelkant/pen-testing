# Readiness scorecard

Review date: **2026-10-24** (Asia/Calcutta).
Parent of this change: `origin/main` `9c02a031d05e1915393fa4e8db2f169739d51a69` (merge of PR #24, pluggy 1.7.0; earlier PR #22 was `312d858`).
This document describes `0.2.0a18` on PR #23 (`cursor/readiness-gaps-87c9`). Local unit commands and host-Trivy image rescans were run on this working tree. CI on the pushed SHA is the release gate. Docker Engine and gitleaks are not installed here, so Compose runtime markers remain `NOT_VERIFIED` locally.

**Verdict: controlled testing.** Not a release candidate and not production-ready. Legal clearance and an independent security review have not happened. Upstream container images have fixed HIGH/CRITICAL findings and their digests were not changed. Classification: **`BLOCKED_BY_SECURITY_GATE`**.

Statuses used here: `PASS`, `PARTIAL`, `BLOCKED`, `FAIL`, `NOT_VERIFIED`.

## Milestones

### 1. Authorization and scope — PARTIAL

- Implemented: scope engine, egress independent of scope skip, in-process rate and concurrency limits, CLI dry-run unless `--live`. MCP transports other than stdio raise `PermissionError` before a listener starts.
- Tests: `tests/unit/test_scope.py`, `tests/unit/test_rate_limit.py`, `tests/unit/test_readiness_followup.py`, `tests/unit/test_readiness_a16.py`, `tests/unit/test_readiness_a18.py`. Full unit suite on this tree: `227 passed` (no skips in `tests/unit`).
- Outstanding: limits are process-local. There is no multi-user authentication. The operator still maintains `scopes/registry.yaml`.
- Next action: do not expose the CLI or MCP server as a shared service. A multi-user design needs its own review.

### 2. Network isolation — PARTIAL

- Implemented: destination policy, Docker `Internal=true` worker networks, Shannon full pipeline default off, gateway connect-to-approved-address, proxied redirect recheck. Strict doctor fails when `PEN_ALLOW_SHANNON_FULL_PIPELINE` is set. Compose sets that variable to `false`.
- Outstanding: a browser that ignores `HTTP(S)_PROXY` is not intercepted. Runtime markers in `scripts/docker_runtime_verify.sh` and `scripts/shannon_e2e_verify.sh` were not re-run here (`NOT_VERIFIED` locally). Prior CI on `ac712a4` printed `ORCHESTRATOR_STRICT_MISSING_KEY_BLOCKED`, `ORCHESTRATOR_STRICT_DOCTOR_OK`, and `SHANNON_E2E_VALIDATE_MODEL_SUCCEEDED`.
- Next action: read the Docker job on the release SHA. Leave the full pipeline unset.

### 3. Secret handling — PARTIAL

- Implemented: pattern redaction of assessment records and of execution-result logs, errors, artifacts, and metadata.
- Outstanding: unknown secret formats are not detected. Shannon, Briar, Temporal, and container-engine logs are outside this process.
- Next action: keep provider keys out of scanner configs.

### 4. Report and file access — PARTIAL

- Implemented: UUID assessment ids, symlink refusal, export confinement, Fernet encryption when `PEN_DATA_KEY` is a valid key, encrypted backup members, restore path checks. Compose requires encryption (`PEN_REQUIRE_DATA_ENCRYPTION=true`, key from the host environment). Strict doctor fails when encryption is off or the key is invalid. Local CLI use can still write plaintext when encryption is not required.
- `0.2.0a18` adds atomic `safe_write_text`, all-or-nothing backup create via staging directory, and restore that decrypts/checksums every member before committing. Wrong-key and corrupt-member restores write nothing. Failed writes do not truncate existing valid files.
- Tests cover invalid keys, strict failure without a key, multi-file wrong-key restore, checksum failure before commit, create-backup failure preserving an existing archive, and mixed plaintext members under an encrypted manifest.
- Outstanding: not disk encryption, no key escrow, overwrite-before-unlink is not forensic erasure. Backup storage is the operator's host. Docker proof of the missing-key container exit is `NOT_VERIFIED` locally; the script contains `ORCHESTRATOR_STRICT_MISSING_KEY_BLOCKED`.
- Next action: set `PEN_DATA_KEY` before `docker compose up`. Do not commit the key. See `docs/OPERATIONS.md` and `docs/DATA_PROTECTION.md`.

### 5. Supply chain — FAIL

- Python OSV and the CycloneDX SBOM behavior from `0.2.0a15` are unchanged. Local re-run on this tree: audit 24 components, emit CycloneDX 1.5 with 24 components, vuln `PASS` blocking 0.
- Local host-Trivy rescan 2026-10-24 (Trivy 0.76.0, DB `UpdatedAt` 2026-10-23T19:15:43Z): pinned Python `FAIL`, `blocking_count` **3** unscored (`DLA-4845-1`, `CVE-2026-82560`, `DLA-4854-1`). Fixed HIGH/CRITICAL remains 0. Full report: 290 rows / 131 unique ids. Inventory in `docs/SECURITY_EXCEPTIONS.md`. Unfixed rows are not a waiver. Unscored rows are blocking under the documented gate.
- Same local rescan of Shannon, Temporal, Gitleaks, and Trivy pins: `FAIL`, aggregate upstream `blocking_count` **1069** (642 fixed HIGH/CRITICAL + 427 unscored). Per image blocking: Shannon 967; Temporal 55; Gitleaks 41; Trivy 6. Digests were not moved. No ignore file was added.
- Candidate tags for Python tip, Gitleaks `v8.30.1`, Temporal `1.7.3` / `1.9.1`, and Trivy `latest` were rescanned on the same DB and all still fail; none were adopted.
- Reporting fix: Trivy image JSON omits `VulnerabilityDB`. Classification now requires DB `UpdatedAt` (from the report or a `trivy version --format json` probe). Missing DB metadata is `NOT_VERIFIED`, not PASS. CI logs print tool version and DB timestamps.
- Counsel review is pending.
- Next action: wait for images with zero fixed HIGH/CRITICAL and zero unscored findings, then run the Shannon `--validate-model` path and the unit suite before changing a pin. Do not add a Trivy ignore to turn CI green.

### 6. Operational reliability — PARTIAL

- Implemented: retention cleanup, backup/restore commands, Compose non-root and capability drop, strict doctor. Operator-run backup, key loss, storage ownership, and rollback are documented in `docs/OPERATIONS.md`. There is still no backup daemon and no external alerter. Strict mode is the fail-closed check the process can perform.
- Outstanding: worker restart evidence is the Docker CI job (`NOT_VERIFIED` locally). No multi-instance lock. No application database.
- Next action: run `pen-testing backup --apply` on a schedule you operate yourself, and store the archive with the key.

## Local verification on this tree

| Command | Exit | Result |
|---|---|---|
| `python3 -m pytest -q tests/unit` on this `0.2.0a18` tree | 0 | 227 passed |
| `python3 -m compileall core integrations providers mcp_server installers` | 0 | compiled |
| gitleaks | `NOT_VERIFIED` locally | gitleaks binary not installed in this environment |
| `python3 -m core.supply_chain audit` | 0 | 24 components; metadata only |
| `python3 -m core.supply_chain emit --output /tmp/sbom.json` | 0 | CycloneDX 1.5, 24 components, no `vulnerabilities` array |
| `python3 -m core.supply_chain vuln` | 0 | `PASS`, `blocking_count` 0, `generated_at` `2026-10-24T01:22:01.554129+00:00` |
| `python3 -m core.supply_chain images --name python-3.12-probe` | 1 | `FAIL`, blocking 3 unscored; tool 0.76.0; DB `UpdatedAt` 2026-10-23T19:15:43Z (injected from `trivy version`) |
| Host Trivy rescan of all pinned upstream images | 1 (expected) | Aggregate blocking 1069; see `docs/SECURITY_EXCEPTIONS.md` |
| `bash scripts/docker_runtime_verify.sh` | not run locally | `NOT_VERIFIED` locally (Docker not installed). Prior CI on `ac712a4` / `79a6dea` succeeded for the runtime script markers |

## CI on `d0b4a6f` (current PR head)

PR run `40050425111` and push run `40050421096` on `d0b4a6f0d4a0d9b7b5412e6d8ccd1268bd21a7cb`:

| Job | Result |
|---|---|
| Lint and unit tests | success |
| Secret scanning (gitleaks) | success |
| Dependency metadata check | success |
| Docker build and runtime | **success** |
| Pinned image vulnerability scans | **failure**. Python `FAIL` blocking **3** unscored (`DLA-4845-1`, `CVE-2026-82560`, `DLA-4854-1`); upstream `FAIL` blocking **1069**. Tool 0.76.0; DB `UpdatedAt` 2026-10-23T19:15:43Z recorded on both artifacts. Gate not waived |

## CI on `abfd437` (DB inject without cold-cache download)

PR run `40049776184` and push run `40049772354` on `abfd437de02046c69c08bca126be4b3130913cef`:

| Job | Result |
|---|---|
| Lint and unit tests | success |
| Secret scanning (gitleaks) | success |
| Dependency metadata check | success |
| Docker build and runtime | **success** |
| Pinned image vulnerability scans | **failure**. Python step `NOT_VERIFIED` (`UpdatedAt` missing: version probe ran on empty cache before DB download). Upstream step `FAIL` blocking **1069** after the first scan warmed the shared cache. Fixed by `--download-db-only` on `d0b4a6f` |

## CI on `79a6dea` (previous PR head before DB-metadata fix)

PR run `40008170156` and push run `40008162945`:

| Job | Result |
|---|---|
| Lint and unit tests | success |
| Secret scanning (gitleaks) | success |
| Dependency metadata check | success |
| Docker build and runtime | **success** |
| Pinned image vulnerability scans | **failure**. Genuine unscored/fixed findings. Artifacts uploaded. Gate not waived |

## CI on `46ef944` (historical after job split)

PR run `40007096658` and push run `40007085301`:

| Job | Result |
|---|---|
| Lint and unit tests | success |
| Secret scanning (gitleaks) | success |
| Dependency metadata check | success |
| Docker build and runtime | **success** (Compose + Shannon `--validate-model` path) |
| Pinned image vulnerability scans | **failure**. Python `blocking_count` 2; upstream `blocking_count` 1068. Artifacts uploaded. Gate not waived |

## CI diagnosis for older jobs named “Docker build and runtime” on `85ac470`

PR run `40005558585` job `120592446563` and push run `40005547895` job `120592410406` shared one root cause. It was **not** a Compose/runtime defect:

| Step | Result |
|---|---|
| Docker Engine / Compose / install | success |
| Docker runtime verification (`scripts/docker_runtime_verify.sh`) | success |
| Pinned base + upstream image scans | reports written; exits 1 |
| Enforce pinned image scan gates | **failure** (`PYTHON_IMAGE_SCAN_EXIT=1`, `UPSTREAM_IMAGE_SCAN_EXIT=1`) |

Python report: `blocking_count` 2 (unscored). Upstream report: `blocking_count` 1068. Artifacts uploaded. Gate not waived. Image scans were later moved to job `Pinned image vulnerability scans`.

## CI on `85ac470` (PR #23)

PR run `40005558585` (and push run `40005547895`):

| Job / step | Result |
|---|---|
| Lint and unit tests | success |
| Secret scanning (gitleaks) | success |
| Dependency metadata check | success |
| Docker runtime verification | success |
| Pinned base image vulnerability scan | step completed; report `FAIL`, `blocking_count` 2 (unscored). Artifact `image-scan-python` uploaded |
| Pinned upstream image vulnerability scan | step completed; report `FAIL`, `blocking_count` 1068 (641 fixed HIGH/CRITICAL + 427 unscored). Artifact `image-scan-upstream` uploaded |
| Enforce pinned image scan gates | failure (nonzero scan exits). Not waived |

## CI on `4e8453d` (historical for this PR)

PR run `40004715041`: unit/gitleaks/deps/runtime success; Python scan `FAIL` blocking 2; upstream scan skipped before the workflow fix; no upstream artifact on that head.

## CI on prior PR head `ac712a4` (historical)

Push/PR run `39089581237` (PR #23):

| Job | Result |
|---|---|
| Lint and unit tests | success |
| Secret scanning (gitleaks) | success |
| Dependency metadata check | success |
| Docker runtime verification | success. Log contains `ORCHESTRATOR_STRICT_MISSING_KEY_BLOCKED`, `ORCHESTRATOR_STRICT_DOCTOR_OK`, and `SHANNON_E2E_VALIDATE_MODEL_SUCCEEDED` |
| Pinned base image vulnerability scan | success under the old HIGH/CRITICAL-only Trivy filter. Artifact `image-scan-python` uploaded |
| Pinned upstream image vulnerability scan | failure, exit 1, `blocking_count` 612. Artifact `image-scan-upstream` uploaded after the failure |

## Release gates that remain mandatory

1. Required CI checks green on the exact release SHA, including OSV, the Python base image scan, and the upstream image scan. The upstream scan is a known failure until those images are replaced without an ignore file.
2. Repository review and branch protection, where GitHub enforces them.
3. `PEN_ALLOW_SHANNON_FULL_PIPELINE` remains unset. Strict doctor must fail if it is set.
4. Counsel review of `docs/LICENSING_REVIEW.md`.
5. An external review against `docs/EXTERNAL_SECURITY_REVIEW.md`. This scorecard is not that review.
6. No statement that multi-user auth, disk encryption, forensic erasure, or in-engine browser containment exist.

## What this scorecard does not claim

- Production readiness or release-candidate status
- Multi-tenant SaaS
- Legal clearance
- Independent security review (`docs/THREAT_MODEL.md` is an internal model)
- Zero CVEs in container images
