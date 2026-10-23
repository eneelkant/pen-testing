# Readiness scorecard

Review date: **2026-10-23** (Asia/Calcutta).
Parent of this change: `origin/main` `312d8586cb9c917f218861960ee882c1928e890a` (merge of PR #22, package `0.2.0a15`).
This document describes `0.2.0a18` on PR #23 (`cursor/readiness-gaps-87c9`). Local unit commands were run on this working tree. CI on the pushed SHA is the release gate. Docker Engine and Trivy are not installed in the environment that produced the local numbers, so Compose runtime markers and a fresh image rescan are `NOT_VERIFIED` locally. The last completed upstream image evidence on this PR is CI run `39089581237` on head `ac712a4` (`blocking_count` 612). Recompute that count from the artifact after this commit's workflow finishes; do not treat the historical 612 as a live result for the new head.

**Verdict: controlled testing.** Not a release candidate and not production-ready. Legal clearance and an independent security review have not happened. Upstream container images have fixed HIGH/CRITICAL findings and their digests were not changed.

Statuses used here: `PASS`, `PARTIAL`, `BLOCKED`, `FAIL`, `NOT_VERIFIED`.

## Milestones

### 1. Authorization and scope — PARTIAL

- Implemented: scope engine, egress independent of scope skip, in-process rate and concurrency limits, CLI dry-run unless `--live`. MCP transports other than stdio raise `PermissionError` before a listener starts.
- Tests: `tests/unit/test_scope.py`, `tests/unit/test_rate_limit.py`, `tests/unit/test_readiness_followup.py`, `tests/unit/test_readiness_a16.py`, `tests/unit/test_readiness_a18.py`. Full unit suite on this tree: `221 passed` (no skips in `tests/unit`).
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

- Python OSV and the CycloneDX SBOM behavior from `0.2.0a15` are unchanged. Re-run them on this tree and record the exit codes below.
- `python:3.12-slim-bookworm` digest above: last CI Trivy result on `ac712a4` was `PASS` for fixed HIGH/CRITICAL, 63 unfixed rows / 16 CVE ids. Inventory in `docs/SECURITY_EXCEPTIONS.md`. Unfixed rows are not a waiver.
- Shannon, Temporal, Gitleaks, and Trivy images: last CI classified report on `ac712a4` was `FAIL` with `blocking_count` 612 (523 + 49 + 39 + 1). Digests were not moved. No ignore file was added. `0.2.0a18` records digest/platform/scanner/DB/exit metadata, unique CVE vs row counts, and treats empty, schema-only, mismatched, stale, and nonzero-exit-with-clean-body reports as `NOT_VERIFIED`. The CI step `Pinned upstream image vulnerability scan` is still expected to fail until a compatible cleaner digest exists.
- Counsel review is pending.
- Next action: wait for an upstream image with zero fixed HIGH/CRITICAL findings, then run the Shannon `--validate-model` path and the unit suite before changing a pin. Do not add a Trivy ignore to turn CI green.

### 6. Operational reliability — PARTIAL

- Implemented: retention cleanup, backup/restore commands, Compose non-root and capability drop, strict doctor. Operator-run backup, key loss, storage ownership, and rollback are documented in `docs/OPERATIONS.md`. There is still no backup daemon and no external alerter. Strict mode is the fail-closed check the process can perform.
- Outstanding: worker restart evidence is the Docker CI job (`NOT_VERIFIED` locally). No multi-instance lock. No application database.
- Next action: run `pen-testing backup --apply` on a schedule you operate yourself, and store the archive with the key.

## Local verification on this tree

| Command | Exit | Result |
|---|---|---|
| `python3 -m pytest -q tests/unit` on this `0.2.0a18` tree | 0 | 221 passed |
| `python3 -m compileall core integrations providers mcp_server installers` | 0 | compiled |
| gitleaks | `NOT_VERIFIED` locally | Docker/gitleaks image not available in this environment |
| `python3 -m core.supply_chain audit` | 0 | 24 components; metadata only |
| `python3 -m core.supply_chain emit` | 0 | CycloneDX 1.5, 24 components, no `vulnerabilities` array |
| `python3 -m core.supply_chain vuln` | 0 | `PASS`, `blocking_count` 0, `generated_at` `2026-10-23T18:36:18.771506+00:00` |
| `python3 -m core.supply_chain images` | 2 | `NOT_VERIFIED` locally (`trivy and docker are unavailable`) |
| `bash scripts/docker_runtime_verify.sh` | not run locally | `NOT_VERIFIED` locally (Docker not installed). Prior CI on `ac712a4` succeeded for the runtime script markers listed above |

## CI on prior PR head `ac712a4` (historical)

Push/PR run `39089581237` (PR #23):

| Job | Result |
|---|---|
| Lint and unit tests | success |
| Secret scanning (gitleaks) | success |
| Dependency metadata check | success |
| Docker runtime verification | success. Log contains `ORCHESTRATOR_STRICT_MISSING_KEY_BLOCKED`, `ORCHESTRATOR_STRICT_DOCTOR_OK`, and `SHANNON_E2E_VALIDATE_MODEL_SUCCEEDED` |
| Pinned base image vulnerability scan | success. Artifact `image-scan-python` uploaded |
| Pinned upstream image vulnerability scan | failure, exit 1, `blocking_count` 612. Artifact `image-scan-upstream` uploaded after the failure |

The workflow conclusion is failure. That failure was not waived. Recompute `blocking_count` from the artifact produced by the `0.2.0a18` head after push.

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
