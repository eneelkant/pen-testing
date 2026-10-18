# Readiness scorecard

Review date: **2026-10-18**
Baseline: `origin/main` `90664e86a0865585a0fa9f7c10f0111847fa5911` (PR #21 merged, package `0.2.0a14`).
This document describes the `0.2.0a15` follow-up. Local commands below were run on this working tree before CI on the pushed SHA. CI on that SHA is the release gate.

**Verdict: not production-ready.** Legal clearance and independent security review have not happened.

Statuses used here: `PASS`, `PARTIAL`, `BLOCKED`, `FAIL`, `NOT VERIFIED`.

## Milestones

### 1. Authorization and scope — PARTIAL

- Implemented: scope engine, egress independent of scope skip, `rate_limit_rps` on non-dry-run preflight, and `PEN_MAX_INFLIGHT_SCANS`. `0.2.0a15` adds a default dry-run for `pen-testing run` (`--live` is required to execute) and `PEN_SKIP_SCOPE_RATE_LIMIT_RPS` (default 1) for live scans that skip the registry.
- Tests: `tests/unit/test_scope.py`, `tests/unit/test_rate_limit.py`, `tests/unit/test_readiness_followup.py`. Local suite on 2026-10-18: `198 passed, 1 skipped`.
- Outstanding: limits are process-local and reset on exit. There is no multi-user authentication. The operator still maintains `scopes/registry.yaml`.
- Next action: do not expose the CLI or MCP server as a shared service.

### 2. Network isolation — PARTIAL

- Implemented: destination policy from `0.2.0a13`, Docker `Internal=true` worker networks, Shannon full pipeline default off. `0.2.0a15` makes the egress gateway connect to the IP approved in that same decision and checks every proxied redirect hop. Unit tests cover an allowlisted public answer and a hop to `169.254.169.254`.
- Outstanding: a browser that ignores `HTTP(S)_PROXY` is not intercepted by the gateway. Internal networks are the connection boundary for that case. The Shannon CI path remains `--validate-model` with a local mock LLM, not a production-LLM exploit pipeline. Local Docker is not installed here, so runtime markers are CI evidence on the pushed SHA, not a local re-run.
- Next action: read the Docker job on the release SHA. Leave `PEN_ALLOW_SHANNON_FULL_PIPELINE` unset.

### 3. Secret handling — PARTIAL

- Implemented: redaction before assessment writes, plus redaction of execution-result logs, errors, artifacts, and metadata in `to_dict`. Pattern coverage is unchanged (URL userinfo, JWT-like strings, AWS-key-like strings, GitHub and Slack tokens, `sk-` keys, PEM blocks, sensitive key names).
- Tests: `tests/unit/test_ops_data_protection.py`, `tests/unit/test_readiness_followup.py`. Local gitleaks 8.21.2 `detect --no-git` exit 0.
- Outstanding: pattern matching misses unknown formats. Shannon, Briar, and container logs that this process does not capture are not redacted.
- Next action: keep secrets out of scanner configs. Rotate anything a future scan reports.

### 4. Report and file access — PARTIAL

- Implemented: UUID assessment IDs, symlink refusal, export confinement, dry-run cleanup. `0.2.0a15` encrypts assessment records and backup members when `PEN_DATA_KEY` is set, refuses plaintext when `PEN_REQUIRE_DATA_ENCRYPTION=1`, and overwrites regular files before unlink. Backup and restore skip symlinks and reject manifest paths that leave the destination root.
- Tests: `tests/unit/test_readiness_followup.py` (encrypt, required-plaintext refusal, backup symlink skip, restore checksum, traversal refusal, cleanup apply).
- Outstanding: encryption is off unless the operator sets a key. It is not disk encryption. Overwrite is not a guarantee on SSDs or snapshots. Access control is the OS account running the process.
- Next action: set `PEN_DATA_KEY` for any deployment that stores assessment files you cannot afford to leave plaintext. Do not commit the key.

### 5. Supply chain — PARTIAL

- Implemented: CycloneDX SBOM without a `vulnerabilities` array, OSV query, and digest pins for the Python, Shannon worker, Temporal, Gitleaks, and Trivy images recorded in `core/supply_chain/images.py`. `cryptography==50.0.2` is pinned with `cffi==2.1.1` and `pycparser==3.11`.
- Local evidence on 2026-10-18: audit exit 0, 24 components. OSV exit 0, `PASS`, `blocking_count` 0, `generated_at` `2026-10-18T01:22:03.473405+00:00`. Trivy 0.76.0 against `python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258` reported `PASS`, 0 fixed HIGH/CRITICAL, 63 unfixed HIGH/CRITICAL, `CreatedAt` `2026-10-18T01:22:03.774118549Z`. Unfixed findings do not fail the gate and are not a waiver.
- CI on `d99f100` scanned `python:3.14-slim-bookworm@sha256:48b13b003dda20b16f9442b8475aa05fe21bf6579a8c881db92ffb4d8fd20f83` and failed on four fixed HIGH findings: `GHSA-6v7p-g79w-8964` (msgpack 1.1.2, fix 1.2.1), `CVE-2025-47273` (setuptools 70.3.0, fix 78.1.1), `CVE-2026-97687` and `CVE-2026-97689` (urllib3 2.7.0, fix 2.8.0). The orchestrator image therefore uses the 3.12 digest above. That 3.14 digest is not a supported base.
- Outstanding: counsel review is pending. A Python OSV pass does not cover container images. CI must scan the pinned Python bases on the release SHA.
- Next action: send `docs/LICENSING_REVIEW.md` to qualified counsel. Keep the image scan failing closed on fixed HIGH/CRITICAL and on `NOT_VERIFIED`.

### 6. Operational reliability — PARTIAL

- Implemented: retention cleanup, Compose non-root and capability drop, `pen-testing backup` / `restore`, and `PEN_DOCTOR_STRICT=1` which fails when the registry or a required encryption key is missing. Doctor reports encryption state and limit settings without the key.
- Tests: backup and strict-doctor cases in `tests/unit/test_readiness_followup.py`. Worker restart evidence remains the Docker CI job, which was not re-run locally.
- Outstanding: no external alerting, no scheduled deletion daemon, no multi-instance lock. Backup storage and key custody are the operator's job. There is no application database.
- Next action: run backups on the schedule you choose and keep the archive with the same care as the source files.

## Release gates that remain mandatory

1. Required CI checks green on the exact release SHA, including OSV and the pinned-image scan.
2. Repository review and branch protection, where GitHub enforces them.
3. `PEN_ALLOW_SHANNON_FULL_PIPELINE` remains unset.
4. Counsel review of `docs/LICENSING_REVIEW.md`.
5. No statement that multi-user auth, disk encryption, or in-engine browser containment exist.

## What this scorecard does not claim

- Production readiness
- Multi-tenant SaaS
- Legal clearance
- Independent security review
- Zero CVEs in container images
