# External security review plan

**Engagement status (2026-10-25):** No independent external security review has been commissioned or completed. This file remains a request list. An internal reading, AI-assisted audit, or repository self-review is **not** that review. Track remediation of any future findings through separate PRs with retest evidence. See also `docs/PRODUCTION_READINESS_PLAN.md` (gaps G10/G11) and the readiness scorecard on `main` @ `be3a023`.

Priority is the order a reviewer should spend time. Each item names the question, the code to read, and the result that would change the scorecard.

## 1. Authorization

Question: Can a party other than the host operator invoke a live scan or read assessment files?

Read: `mcp_server/server.py` (`assert_supported_transport`), `core/cli.py` (`--live`), `core/scope/`, `core/scope/rate_limit.py`.

Pass looks like: remote MCP transports stay refused; scope skip still cannot disable egress; limits are described as process-local. A fail is any unauthenticated listener or a path that runs a live tool without `--live` and `confirm_authorized`.

Multi-user authentication is out of scope unless a later design is reviewed on its own. Do not treat the single-operator model as tenant isolation.

## 2. Network containment

Question: What can a Shannon or Briar browser send if it ignores `HTTP(S)_PROXY`, follows a redirect, or re-resolves DNS?

Read: `docs/NETWORK_ARCHITECTURE.md`, `docker/egress-gateway/proxy_main.py`, `core/isolation/destination_policy.py`, `scripts/docker_runtime_verify.sh`, `scripts/shannon_e2e_verify.sh`.

Pass looks like: evidence, from a runtime the reviewer runs, that worker networks are `Internal=true` and that proxied hops are rechecked. Do not accept a claim that the gateway sees traffic from a client that never connects to it. In-engine browser controls that are not executed in that runtime are not a pass.

## 3. Secrets and report access

Question: Where do assessment bytes, errors, and artifacts land, and who can read them?

Read: `core/findings/redaction.py`, `core/ops/crypto.py`, `core/ops/backup.py`, `core/results/`, `mcp_server/service.py`, `docs/DATA_PROTECTION.md`.

Pass looks like: symlink refusal and path confinement hold; Compose refuses to start strict doctor without a valid Fernet key; redaction limits and the absence of upstream-log redaction stay documented. A fail is a key baked into the image, a restore path that writes outside the destination root, or a claim that overwrite-before-unlink is forensic erasure.

## 4. Container isolation

Question: Can a worker or the orchestrator use the host Docker daemon, add capabilities, or leave its network?

Read: `docker-compose.yml`, `Dockerfile`, `core/isolation/network_assert.py`.

Pass looks like: no `docker.sock` on the orchestrator or workers, `cap_drop: ALL`, non-root users, and internal scanner networks. A fail is a Compose change that attaches a worker to `pen-control`, `pen-egress`, or the host network without the existing dual-gate.

## 5. Supply chain

Question: Which pinned images and Python packages have fixed HIGH or CRITICAL findings, and were any findings ignored to make CI green?

Read: `core/supply_chain/images.py`, `core/supply_chain/vuln.py`, `.github/workflows/ci.yml`, `docs/SECURITY_EXCEPTIONS.md`, `docs/LICENSING_REVIEW.md`.

Pass looks like: the reviewer can reproduce the Trivy and OSV results, fixed findings fail the image command, and the exception register matches the tool output. A fail is an ignore file, a removed image name, or a pin bump that was not run through the Shannon `--validate-model` path and the unit suite. On 2026-10-18 the maintained candidates for Gitleaks, Temporal, and Trivy still had fixed HIGH or CRITICAL findings, and Shannon had no release after `3.4.0`. Those pins were left in place. License questions stay with counsel; this review does not clear AGPL obligations. This paragraph is a request for that review, not a record that it happened.

## Reporting

The reviewer should publish a separate report. This repository must not label that report, or this plan, as already completed.
