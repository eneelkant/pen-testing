# Licensing review notes (Shannon / Briar AGPL)

**Status:** Qualified counsel review is **pending**. Image digest pins and the stdio-only MCP guard do not change that. This document is not legal clearance.
**Date:** 2026-10-18 (questions unchanged; stdio refusal noted under operator guidance)
**Packages:** `@keygraph/shannon@3.4.0` (AGPL-3.0-only), `briar-pentest==0.4.62` (AGPL-3.0)
**Also in the runtime path:** Temporal server image `temporalio/temporal:1.7.0` (Shannon 3.4.0 compose runs that tag), `keygraph/shannon:3.4.0` worker image, Briar Compose image, `aquasec/trivy:0.76.0` when the supply-chain command has no local `trivy` binary, and `zricethezav/gitleaks:v8.21.2` for CI secret scanning. Gitleaks `v8.30.1` and Temporal `1.7.3` / `1.9.1` were scanned and not adopted. Their licenses are not cleared by this file.

## How this repository integrates them

| Aspect | Shannon | Briar |
|---|---|---|
| Distribution of upstream source in this repo | Not vendored | Not vendored |
| Invocation | Host `npx` → upstream Docker workers | Compose image `pip install` pin / host CLI |
| Modification of upstream code | None (subprocess/container only) | None (subprocess/container only) |
| Combined into a single binary with this code | No | No |
| Network service exposing AGPL code to users | Shannon workers / Temporal UI may be network-reachable on localhost during a scan | Briar may expose local services depending on mode |
| Attribution | `THIRD_PARTY_NOTICES.md` | `THIRD_PARTY_NOTICES.md` |

## Questions requiring human legal review

1. Does invoking AGPL tools as unmodified separate processes/containers from an Apache-2.0 orchestrator create AGPL obligations for the orchestrator’s source distribution?
2. Does shipping a Docker image that `pip install`s Briar (AGPL) require offering corresponding source under AGPL for the image contents and/or the orchestrator?
3. Does MCP remote exposure of assessment APIs that trigger AGPL tools constitute “conveying” or a network interaction that triggers AGPL §13 (Affero) obligations?
4. What notices and source-offer process are required for SaaS vs on-prem operator installs?
5. Briar’s “Alpha” status: any additional upstream license/terms beyond the PyPI AGPL classifier?
6. The Shannon path starts a Temporal server container and a `keygraph/shannon` worker. Does distributing or operating that Compose stack require source offers for Temporal's license and for the Shannon image, separately from the orchestrator?
7. Trivy and Gitleaks images are pulled at scan time. Does the operator's redistribution of a lockfile or Compose file that names those images create a source-offer duty for those images' licenses?
8. Transitive Python dependencies in `requirements/*.txt` include packages beyond PyYAML and jsonschema (see the generated CycloneDX SBOM). Counsel still needs to review those license identifiers; this repository does not assert that every transitive license is Apache-2.0 compatible.
9. If an operator exposes the MCP server beyond localhost, do questions 1 and 3 change because a remote user can trigger AGPL tools without receiving the orchestrator source?

## Operator guidance until counsel advises

- Keep Shannon/Briar optional; do not vendor their source into this tree.
- Preserve `THIRD_PARTY_NOTICES.md` and upstream license texts in downstream distributions.
- Do not remove or weaken AGPL notices to “make packaging easier.”
- Treat public redistribution of combined images/services as needing legal sign-off before a production release claim.
- `0.2.0a16` refuses MCP transports other than stdio. That reduces one way to expose the tools remotely. It does not answer questions 3 or 9.

## Non-goals of automation

CI cannot certify AGPL compliance. Passing tests must not be interpreted as legal clearance.
