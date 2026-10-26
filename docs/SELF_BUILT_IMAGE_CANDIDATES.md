# Self-built image candidates

**Status:** Candidate pipeline proposal. No production pins are changed by this workflow.  
**Current decision:** Do not adopt or publish a candidate as production-ready until it passes the full gates below.

## Candidate builds

The candidate Dockerfiles layer security-package upgrades over the existing immutable upstream image digests:

- Shannon: **Wolfi nodejs-22 >= 22.23.4-r0**, **curl >= 8.23.0-r0**, and **libcurl-openssl4 >= 8.23.0-r0**.
- Trivy: **Alpine libcurl >= 8.23.0-r0**.

The version constraints intentionally make the build fail if the package repositories cannot supply the required fixed versions. The base image digests in the candidate Dockerfiles are explicit. Do not replace them with tags or change core/supply_chain/images.py in this PR.

## Observed CI blocker (2026-10-26)

The first candidate workflow run confirms that the current Wolfi package index still resolves `nodejs-22` to `22.23.2-r1`. The Shannon candidate build therefore fails the explicit `nodejs-22>=22.23.4-r0` constraint. This is an expected fail-closed result, not a patched image. Do not weaken the constraint or merge this draft as though remediation succeeded. A follow-up must either wait for the fixed package to become available or implement and independently verify a reproducible source/package build that maintains package provenance. The same workflow run also shows the existing pinned-image regression gate failing against the current vulnerability database; that gate must not be bypassed to merge this PR.

## Verification and publication

.github/workflows/self-built-image-candidates.yml builds both images for linux/amd64, records raw Trivy reports, checks freshness / scanner / platform / raw-result integrity, and runs the project's controlled Shannon Temporal + worker --validate-model E2E against the local mock fixtures.

A completed scan that reports vulnerabilities is recorded as FAIL and marked not acceptable; this is not treated as successful remediation. Missing, malformed, stale, or mismatched scan evidence is NOT_VERIFIED and fails evidence collection.

The build-and-scan job on pull requests is evidence collection, not a waiver or a production acceptance check. It may complete while a candidate remains blocked so the report can show what still needs remediation. The manual publication path is stricter:

1. A maintainer must dispatch the workflow from main and explicitly select publish_candidates=true.
2. Both local candidate scans must pass with zero fixed HIGH/CRITICAL and zero unscored findings.
3. The candidates are pushed to the dedicated GHCR candidate packages, and each published immutable digest is rescanned with the existing digest-pinned Trivy scanner.
4. The published-digest scans must pass the same strict checks. The workflow does not modify production image pins or merge a pin PR.

A published candidate is not automatically approved. Before changing PINNED_IMAGES, use a separate reviewed PR and retain the fresh raw scan artifacts, SHA-256 evidence, immutable digest, platform, scanner version, database timestamp, and successful runtime verification.

## Important limits

- Upgrading these packages may not remove other fixed HIGH/CRITICAL or unscored findings in the upstream images. The strict gate intentionally rejects such candidates; do not weaken thresholds or move findings into the baseline to make the workflow green.
- The Trivy candidate is built from the current Trivy pin. Its binary, operating-system base and vulnerability database behavior are not upgraded by the libcurl layer.
- No candidate has passed until GitHub Actions reports a fresh clean result for the exact published digest. Candidate build success alone is not a security pass.
- Existing pinned-image absolute and regression gates remain unchanged. Do not bypass a failing required check to merge this work.
- GHCR publication is opt-in, from main only, and uses GITHUB_TOKEN with packages: write only in the publication job.
