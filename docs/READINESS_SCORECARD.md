# Readiness scorecard

Review date: **2026-10-17**  
Baseline: `main` at `bb13cd23` (PR #19 merged).  
This scorecard includes the local operations, data-protection, and supply-chain changes on top of that baseline.  
It does **not** include unmerged PR #20.

**Verdict: not production-ready.** No milestone below is a production sign-off. "Met" means the listed local control exists and has the evidence named in the row, not that the residual gaps are closed.

PR #20 (`cursor/prod-network-destination-policy-39f7`, head `ddba5a85bea29b549d387689bf5e80aba121872b`) was re-checked on 2026-10-17. Latest GitHub Actions conclusions for that head, from both recorded workflow runs, are success for Lint and unit tests, Docker build and runtime, Secret scanning (gitleaks), and Dependency metadata check. That work is destination-level proxy policy and the Shannon full-pipeline gate. It is not duplicated here and is not merged.

## Milestones

| # | Milestone | Status | Evidence already on `main` or in this change | Incomplete | External dependencies |
|---|---|---|---|---|---|
| 1 | Authorization and scope | Partial | Scope engine denies unknown hosts, expired records, production targets, and scheme-less whole-host expansion. Dual gate for disabling scope. Unit tests in `tests/unit/test_scope.py` and `tests/unit/test_readiness_security.py`. | Network rate limits are stored, not enforced. Human must maintain `scopes/registry.yaml`. | Operator-supplied authorization records |
| 2 | Network isolation | Partial | Through `0.2.0a12`: Compose scanner networks are Docker `Internal=true`; Briar live and Shannon controlled paths have runtime markers; Shannon `--validate-model` E2E uses a local mock LLM. See `docs/SCANNER_ISOLATION.md` and `docs/SECURITY_VALIDATION.md`. | PR #20 destination port/IP policy is not merged. In-engine browser navigation and DNS rebinding are not claimed. Full Shannon exploit pipeline with a production LLM is not run. | Docker Engine on the validating host; upstream Shannon and Briar images; PR #20 review and merge |
| 3 | Secret handling | Partial | Provider status does not print secret values. URL userinfo, JWT-like strings, AWS-key-like strings, GitHub tokens, Slack tokens and webhooks, and `sk-` style keys are redacted in findings and stored assessments. | Pattern redaction misses unknown formats. Upstream tools can still write their own logs outside this process. | Operator secret storage; rotation if a real secret is ever logged |
| 4 | Report and file access | Partial | UUID assessment IDs. Export paths confined to reports/work (CLI also allows the current directory). Symlink components refused for reads and writes. Corrupt assessment JSON fails closed. | No per-user authentication or authorization. A local operator can still read files their OS account can read. | OS file permissions on the host running the CLI/MCP server |
| 5 | Supply chain | Partial | Gitleaks CI job on `main` and on PR #20. This change adds a metadata audit and a CycloneDX SBOM generated from `requirements/*.txt`. Unpinned `rpds-py` is reported and is not hidden. The SBOM has no vulnerability list. | No live OSV, pip-audit, or other CVE database in CI. `rpds-py` is still a floor pin (`>=0.30.0`). AGPL obligations for Shannon/Briar are documented, not cleared by counsel. | Gitleaks container image in CI; a chosen vulnerability database and network access if a real CVE scan is required; legal review (`docs/LICENSING_REVIEW.md`) |
| 6 | Operational reliability | Partial | CI keeps `main` Docker runs from being cancelled. Compose cleanup runs in the Docker job. `pen-testing cleanup` is dry-run unless `--apply`, skips symlinks, and is not invoked by MCP status. | Retention is not automatic. No backups, no multi-instance locking, no hosted queue. Docker runtime for this change is not yet a new green CI run. | GitHub Actions Docker runners for image/runtime jobs; an operator to run cleanup |

## Release gates that are still mandatory

Do not describe a build as production-ready until all of the following have evidence on the exact commit:

1. Required CI checks green on that SHA (unit, Docker runtime, gitleaks, dependency audit). A local unit run is not a substitute for the Docker job.
2. Repository review rules satisfied, including human review where branch protection requires it.
3. PR #20 either merged with its own green CI or explicitly excluded, with the network non-claims still documented.
4. A vulnerability scan, if required by the release, executed against a real database and its findings left visible. Do not convert a metadata-only SBOM into a "no CVEs" result.
5. Licensing review completed for the intended distribution model.
6. No live Shannon/Briar gate enabled by default.

## What this scorecard does not claim

- Multi-tenant SaaS, billing, or remote authentication
- Complete containment of Shannon or Briar after their processes start
- Automatic deletion of artifacts
- A clean bill of health for third-party dependencies
