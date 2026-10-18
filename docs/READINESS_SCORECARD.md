# Readiness scorecard

Review date: **2026-10-18**
Parent of this change: `origin/main` `312d8586cb9c917f218861960ee882c1928e890a` (merge of PR #22, package `0.2.0a15`).
This document describes `0.2.0a16`. Local commands were run on this working tree. CI on the pushed SHA is the release gate. Docker Engine is not installed in the environment that produced the local numbers, so Compose runtime markers are `NOT VERIFIED` locally.

**Verdict: controlled testing.** Not a release candidate and not production-ready. Legal clearance and an independent security review have not happened. Upstream container images have fixed HIGH/CRITICAL findings and their digests were not changed.

Statuses used here: `PASS`, `PARTIAL`, `BLOCKED`, `FAIL`, `NOT VERIFIED`.

## Milestones

### 1. Authorization and scope — PARTIAL

- Implemented: scope engine, egress independent of scope skip, in-process rate and concurrency limits, CLI dry-run unless `--live`. `0.2.0a16` refuses MCP transports other than stdio (`sse` and `streamable-http` raise `PermissionError` before a listener starts).
- Tests: `tests/unit/test_scope.py`, `tests/unit/test_rate_limit.py`, `tests/unit/test_readiness_followup.py`, `tests/unit/test_readiness_a16.py`. Baseline on `312d858` before these edits: `198 passed, 1 skipped`. Full suite after the edits: `206 passed, 1 skipped`.
- Outstanding: limits are process-local. There is no multi-user authentication. The operator still maintains `scopes/registry.yaml`.
- Next action: do not expose the CLI or MCP server as a shared service. A multi-user design needs its own review.

### 2. Network isolation — PARTIAL

- Implemented: destination policy, Docker `Internal=true` worker networks, Shannon full pipeline default off, gateway connect-to-approved-address, proxied redirect recheck. `0.2.0a16` adds no in-engine browser control. Strict doctor fails when `PEN_ALLOW_SHANNON_FULL_PIPELINE` is set. Compose sets that variable to `false`.
- Outstanding: a browser that ignores `HTTP(S)_PROXY` is not intercepted. Runtime markers in `scripts/docker_runtime_verify.sh` and `scripts/shannon_e2e_verify.sh` were not re-run here (`NOT VERIFIED` locally).
- Next action: read the Docker job on the release SHA. Leave the full pipeline unset.

### 3. Secret handling — PARTIAL

- Implemented: pattern redaction of assessment records and of execution-result logs, errors, artifacts, and metadata.
- Outstanding: unknown secret formats are not detected. Shannon, Briar, Temporal, and container-engine logs are outside this process.
- Next action: keep provider keys out of scanner configs.

### 4. Report and file access — PARTIAL

- Implemented: UUID assessment ids, symlink refusal, export confinement, Fernet encryption when `PEN_DATA_KEY` is a valid key, encrypted backup members, restore path checks. `0.2.0a16` makes encryption mandatory for the Compose orchestrator (`PEN_REQUIRE_DATA_ENCRYPTION=true`, key from the host environment, not baked into the image). Strict doctor fails when encryption is off or the key is invalid. Local CLI use can still write plaintext.
- Tests cover invalid keys, strict failure without a key, and the Compose environment block.
- Outstanding: not disk encryption, no key escrow, overwrite-before-unlink is not forensic erasure. Backup storage is the operator's host. Docker proof of the missing-key container exit is `NOT VERIFIED` locally; the script contains `ORCHESTRATOR_STRICT_MISSING_KEY_BLOCKED`.
- Next action: set `PEN_DATA_KEY` before `docker compose up`. Do not commit the key. See `docs/OPERATIONS.md` and `docs/DATA_PROTECTION.md`.

### 5. Supply chain — FAIL

- Python OSV and the CycloneDX SBOM behavior from `0.2.0a15` are unchanged. Re-run them on this tree and record the exit codes in the PR.
- `python:3.12-slim-bookworm` digest above: Trivy `PASS` for fixed HIGH/CRITICAL, 63 unfixed rows, 16 CVE ids. Inventory in `docs/SECURITY_EXCEPTIONS.md`. Unfixed rows are not a waiver.
- Shannon, Temporal, Gitleaks, and Trivy images: local Trivy `FAIL` (523, 49, 39, and 1 fixed HIGH/CRITICAL rows). Digests were not moved. No ignore file was added. The CI step `Pinned upstream image vulnerability scan` runs those four names and fails the job while the findings remain.
- Counsel review is pending.
- Next action: replace an upstream digest only after the Shannon `--validate-model` path and the unit suite run against that digest. Do not add a Trivy ignore to turn CI green.

### 6. Operational reliability — PARTIAL

- Implemented: retention cleanup, backup/restore commands, Compose non-root and capability drop, strict doctor. `0.2.0a16` documents operator-run backup, key loss, storage ownership, and rollback in `docs/OPERATIONS.md`. There is still no backup daemon and no external alerter. Strict mode is the fail-closed check the process can perform.
- Outstanding: worker restart evidence is the Docker CI job (`NOT VERIFIED` locally). No multi-instance lock. No application database.
- Next action: run `pen-testing backup --apply` on a schedule you operate yourself, and store the archive with the key.

## Local verification on this tree

| Command | Exit | Result |
|---|---|---|
| `python -m pytest -q` on `312d858` before edits | 0 | 198 passed, 1 skipped |
| `python -m pytest -q` after edits | 0 | 206 passed, 1 skipped (`tests/integration/test_smoke_markers.py`: Docker not installed) |
| `python -m compileall core integrations providers mcp_server installers` | 0 | compiled |
| gitleaks 8.21.2 `detect --source . --no-git` | 0 | no leaks |
| `python -m core.supply_chain audit` | 0 | 24 components |
| `python -m core.supply_chain emit` | 0 | CycloneDX 1.5, 24 components, no `vulnerabilities` array, structural validation empty |
| `python -m core.supply_chain vuln` | 0 | `PASS`, `blocking_count` 0, `generated_at` `2026-10-18T01:48:52.160600+00:00`, database `https://api.osv.dev/v1/querybatch` |
| `python -m core.supply_chain images --name python-3.12-probe` | 0 | `PASS`, blocking 0, unfixed 63 |
| `python -m core.supply_chain images --name trivy-scanner` | 1 | `FAIL`, blocking 1, `CVE-2026-77214` |
| `bash scripts/docker_runtime_verify.sh` | not run locally | `NOT VERIFIED` locally (Docker not installed). GitHub Actions run `39087905596` step succeeded and printed `ORCHESTRATOR_STRICT_MISSING_KEY_BLOCKED`, `ORCHESTRATOR_STRICT_DOCTOR_OK`, `PEN_SCANNER_ISOLATED_INTERNAL=true`, and `SHANNON_E2E_VALIDATE_MODEL_SUCCEEDED` |

## CI on `29e2d88`

Push run `39087905596` and pull request run `39087918349` (PR #23):

| Job | Result |
|---|---|
| Lint and unit tests | success |
| Secret scanning (gitleaks) | success |
| Dependency metadata check | success |
| Docker runtime verification | success |
| Pinned base image vulnerability scan (`python-3.12-probe`) | success |
| Pinned upstream image vulnerability scan | failure, exit 1, `blocking_count` 612 (Shannon 523, Temporal 49, Gitleaks 39, Trivy scanner 1). `error` empty. This is the fixed-finding gate, not a scanner crash |

The workflow conclusion is failure. That failure was not waived.

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
