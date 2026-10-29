# Capability Matrix — `eneelkant/pen-testing`

**Snapshot date:** 2026-10-29
**Baseline commit:** `33a6b06392c1d971dec39e942863eb2f90524d4b`

This matrix is the authoritative answer to issue #39 ("roadmap: unify authorized web, API, local/network and mobile pentesting"). Each row maps to a P1 item from the issue body and is marked with one of:

| Status | Meaning |
|---|---|
| `SUPPORTED` | Adapter exists, integrated with the common security/evidence model, has positive and negative tests, and is documented as supported. |
| `PARTIAL` | Adapter exists but lacks test coverage, has known gaps in the security model, or is optional (not installed by default). |
| `ROADMAP` | No adapter exists. Listed in issue #39 as a future P1 integration. Not advertised as supported. |
| `BLOCKED` | Cannot be implemented in this environment (licensing, hardware, OS, or external approval required). |

## 1. Web application testing

| Capability | Adapter / module | Status | Evidence / blocker |
|---|---|---|---|
| Passive HTTP security-header checks | `integrations/scanners/headers.py` | SUPPORTED | Unit tests pass on `main@33a6b06`; `headers` is in `ACTIVE_TOOLS`; MCP tool exposes `run_security_assessment` with `tool="headers"`. |
| Controlled crawling / endpoint discovery | (none) | ROADMAP | No adapter exists. |
| OWASP ZAP (passive baseline + active profiles) | (none) | ROADMAP | No adapter, no pinned-template policy, no authenticated-context fixture. |
| Nuclei (curated, version-pinned template policy) | (none) | ROADMAP | No adapter, no reviewed template policy. |
| TLS / certificate posture checks | (none) | ROADMAP | No adapter. |
| Authentication profiles (no plaintext credentials) | `core/scope/`, `configs/assessment_profiles/*.yaml` | PARTIAL | Profile loader exists; no authenticated-session fixture for ZAP/Briar/Shannon; no credential-vault integration. |

## 2. API security

| Capability | Adapter / module | Status | Evidence / blocker |
|---|---|---|---|
| OpenAPI / Swagger input validation | (none) | ROADMAP | No adapter. |
| GraphQL support | (none) | ROADMAP | No adapter. |
| API endpoint discovery / schema validation | (none) | ROADMAP | No adapter. |
| Schemathesis (schema-based testing) | (none) | ROADMAP | No adapter. |
| OWASP API Top-10 mapping | (none) | ROADMAP | No mapping table; no per-API finding category. |
| Mutating/destructive API tests disabled by default | (architecture) | SUPPORTED | All live runs require `confirm_authorized=true` + bound `approval_id`; `dry_run=true` is the default. |

## 3. Source-code and local artifact testing

| Capability | Adapter / module | Status | Evidence / blocker |
|---|---|---|---|
| Secret detection (Gitleaks) | `integrations/scanners/gitleaks.py` | SUPPORTED | Unit tests pass; `gitleaks` is in `LOCAL_PATH_TOOLS`; path-confined to configured work/report roots. |
| Dependency / config analysis (Trivy) | `integrations/scanners/trivy.py` | SUPPORTED | Unit tests pass; `trivy` is in `LOCAL_PATH_TOOLS`. |
| Static SAST (Semgrep CE or equivalent) | (none) | ROADMAP | No adapter. Licensing review for Semgrep CE rule packs required before integration. |
| Dockerfile / Compose / K8s / Terraform misconfig (Checkov) | `integrations/scanners/checkov.py` | PARTIAL | Adapter exists; `checkov` is in `LOCAL_PATH_TOOLS`; declared as optional extra (`checkov==3.3.29`) — not installed by default. Live execution requires `pip install '.[checkov]'`. |
| Portable SBOM output | `core/supply_chain/sbom.py` | SUPPORTED | CycloneDX SBOM via `python -m core.supply_chain emit --output <path>`. |
| Findings tied to source locations | `core/findings/normalize.py` | SUPPORTED | Normalized finding schema includes `file`, `line`, `column` fields. |

## 4. Network and host testing

| Capability | Adapter / module | Status | Evidence / blocker |
|---|---|---|---|
| Constrained Nmap integration | (none) | ROADMAP | No adapter; no bounded-concurrency profile. |
| Explicit host/CIDR + port-range authorization | `core/scope/engine.py`, `scopes/registry.yaml` | SUPPORTED (framework, not Nmap-specific) | Scope engine validates hosts and patterns; CIDR and port-range authorization would require an Nmap adapter to be exercised. |
| Bounded concurrency / conservative default profiles | `core/scope/rate_limit.py` | SUPPORTED (framework) | `acquire_scan_slot` / `release_scan_slot` enforce a single concurrent live assessment; per-tool rate limits would be set by adapters. |
| No DoS scripts / no unapproved target expansion | `core/scope/`, `core/isolation/` | SUPPORTED | Fail-closed scope enforcement; egress isolation in `core/isolation/egress.py`. |

## 5. Mobile application testing

| Capability | Adapter / module | Status | Evidence / blocker |
|---|---|---|---|
| Android static analysis (source-code patterns) | `integrations/scanners/mobsfscan.py` | PARTIAL | Adapter exists; declared as optional extra (`mobsfscan==1.0.1`); covers source-code patterns only, not APK/IPA binaries or device runtime. |
| MobSF external service adapter (APK/AAB/IPA static + dynamic) | (none) | ROADMAP | No external MobSF service adapter; licensing and architecture compatibility unverified. |
| Android emulator / ADB dynamic testing | (none) | BLOCKED | Requires Android SDK + emulator; no prerequisites documented; no adapter. |
| iOS runtime testing | (none) | BLOCKED | Requires macOS / Xcode / physical device; not available in this environment; no adapter. |

## 6. Adapter requirements (per the master task)

Every supported adapter (`SUPPORTED` or `PARTIAL` in the rows above) must use the common security and evidence model. Status of each requirement:

| Requirement | Implemented? | Evidence |
|---|---|---|
| Shared authorization preflight | YES | `mcp_server/service.py:run_security_assessment` calls `engine.require()` for `ACTIVE_TOOLS` before approval consumption; `_confine_local_scan_path()` for `LOCAL_PATH_TOOLS`. |
| Typed target and asset scopes | YES | `core/scope/target.py:normalize_origin`, `core/scope/engine.py:_idna_host`. |
| Rate limits, timeouts, cancellation, output limits | PARTIAL | Rate limits: `acquire_scan_slot`/`release_scan_slot` (single concurrent slot). Timeouts: `1 ≤ timeout_seconds ≤ 86_400`. Cancellation: NOT VERIFIED. Output limits: `core/paths.py:safe_write_text` confines artifacts. |
| Secret redaction and safe subprocess invocation | YES | `core/findings/redaction.py:redact_secrets`, `redact_text`, `redact_url_userinfo`. Subprocess invocation: `core/isolation/briar_exec.py`, `core/isolation/destination_policy.py`. |
| Tool version, image digest, config, template provenance | PARTIAL | Image digests: `core/supply_chain/images.py:PINNED_IMAGES` with immutable `@sha256:` refs. Tool versions: pinned in `requirements/*.txt` and `pyproject.toml`. Template/config provenance for future Nuclei/ZAP adapters: NOT IMPLEMENTED. |
| Robust handling of missing tools, malformed output, partial failures | PARTIAL | `mcp_server/service.py:check_dependencies` reports missing tools; `_assessment_error()` handles exceptions. Adapters' own malformed-output handling: NOT VERIFIED per-adapter. |
| Normalized findings with evidence, severity, confidence, remediation | YES | `core/findings/schema.py` defines the normalized finding schema with `evidence`, `severity`, `confidence`, `remediation` fields. |
| Explicit distinctions between `NOT RUN`, `BLOCKED`, `FAILED`, `NO FINDINGS`, `FINDINGS PRESENT` | PARTIAL | `run_security_assessment` returns `status: "blocked"` for scope failures; result adapter returns `status: "succeeded" \| "skipped"`; the literal string `NOT RUN` is not used. |

## 7. Summary

| Category | SUPPORTED | PARTIAL | ROADMAP | BLOCKED |
|---|---|---|---|---|
| Web application testing | 1 | 1 | 4 | 0 |
| API security | 1 | 0 | 5 | 0 |
| Source-code and local artifact | 3 | 1 | 1 | 0 |
| Network and host | 2 (framework) | 0 | 1 | 0 |
| Mobile application | 0 | 1 | 1 | 2 |
| **Total** | **7** | **3** | **12** | **2** |

**Conclusion for issue #39:** 7 of 24 capabilities are SUPPORTED, 3 are PARTIAL, 12 are ROADMAP (require new adapter integrations), and 2 are BLOCKED by environment. The repository is a working MCP server with a constrained active-assessment workflow and three working scanner adapters (headers, gitleaks, trivy), but it is not yet the unified authorized assessment orchestrator described in issue #39's goal. Closing #39 requires shipping the 12 ROADMAP adapters across focused PRs (one engine per PR per the master task rules), with the 2 BLOCKED items explicitly deferred in the README.

**Issue #39 should remain open.** Closing it would misrepresent coverage.
