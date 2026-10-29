# Upstream image scan failure: remediation runbook

**Purpose:** Diagnose `UPSTREAM_IMAGE_SCAN_EXIT=1` without weakening the release gate.

## What the exit means

The CI step scans the exact digest-pinned images configured in
`core/supply_chain/images.py`: Shannon worker, Temporal, Gitleaks, and Trivy scanner.
The absolute gate blocks fixed HIGH/CRITICAL and unscored findings. A regression gate
that reports no new findings is not equivalent to a clean release scan.

## Triage

1. Open the `image-scan-upstream` and `image-scan-raw` artifacts from the failing run.
2. Check the Trivy database `UpdatedAt`, scanner version, pinned index digest, and
   `linux/amd64` platform recorded by the scan. If evidence is missing or mismatched,
   fix verification first; never interpret `NOT_VERIFIED` as clean.
3. Read the CI per-image summary. Prioritise packages with a concrete fixed version;
   findings without a fixed version remain visible and should be tracked to an upstream fix.
4. Run `.github/workflows/self-built-image-candidates.yml` for the supported Shannon
   and Trivy candidate path. Review `candidate-reports/*-summary.json`, package checks,
   raw scan evidence, and runtime results.
5. Do not change production refs until the candidate policy accepts the image with fresh,
   digest-bound evidence and all required runtime tests succeed. Shannon requires the
   controlled `--validate-model` integration test.
6. If there is no acceptable candidate, retain the production pin and the failing absolute
   gate. File an upstream issue or wait for a vendor release; do not claim remediation.

## Do not do this

- Do not invent or copy an unrelated SHA-256 digest.
- Do not replace digest pins with mutable tags.
- Do not add blanket CVE ignores, suppress unscored findings, or lower severity thresholds
  simply to get green CI.
- Do not rewrite Git history unless a real credential was exposed. If a real secret was
  committed, revoke/rotate it first and follow a dedicated incident/history-cleanup process.
- Do not run `apt-get upgrade` in unrelated container images: the project uses different
  image families, and in-layer package upgrades must be verified against the image's
  package manager and compatibility tests.

## Acceptance criteria

- Each image has a complete scan report bound to its immutable digest and required platform.
- Scanner version and vulnerability DB timestamp are present and current.
- Zero fixed HIGH/CRITICAL and zero unscored findings for a release-acceptable image.
- Package requirements and required runtime checks pass.
- The absolute pinned-image scan exits zero; baseline/regression success alone is insufficient.

The CI reporting change is diagnostic only. It does not remediate or waive the existing
upstream findings.
