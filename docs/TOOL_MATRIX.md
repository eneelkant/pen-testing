# Tool Matrix

Metadata reviewed: 2026-10-27. The runtime capability registry is in core/capabilities.py. This table describes integration status, not a claim that all tools are installed or healthy on every operator machine.

## Integrated into the current CLI/MCP

| Tool | Purpose | Testing mode | Runtime | License | Status and limitations |
|---|---|---|---|---|---|
| [Shannon](https://github.com/KeygraphHQ/shannon) (@keygraph/shannon@3.4.0) | White-box/source-informed web and API assessment | Active + source-informed | Node.js/npx, Docker worker, configured LLM provider | AGPL-3.0-only | Integrated; active/mutative, requires explicit scope and live gates; verify worker egress controls |
| [Briar](https://github.com/Stiimy/briar) (briar-pentest==0.4.62) | Black-box, optional source-informed web assessment | Active + optional source | Python >=3.10; dedicated venv/container recommended | AGPL-3.0 | Integrated; optional dependency, live and host networking separately gated |
| [HTTP security headers](https://github.com/eneelkant/pen-testing) | Selected response-header checks | Passive HTTP GET | Python standard library | Apache-2.0 repository code | Integrated; limited header checks only, no TLS grade or comprehensive DAST |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secret detection on configured local source | Static | Binary or digest-pinned container | MIT | Integrated; local path only; Docker fallback network-disabled |
| [Trivy](https://github.com/aquasecurity/trivy) | Local filesystem, dependency and configuration checks | Static/dependency/configuration | Binary or digest-pinned container | Apache-2.0 | Integrated; current adapter is filesystem-oriented; not a general network or host scanner |

## Candidate integrations — NOT yet available through CLI/MCP

| Tool / standard | Source | Primary use | License / review note | Status |
|---|---|---|---|---|
| OWASP ZAP | https://github.com/zaproxy/zaproxy | Web DAST, passive baseline and controlled active plans | Apache-2.0; review add-ons and automation behavior | Proposed |
| Nuclei | https://github.com/projectdiscovery/nuclei | Template-driven DAST | MIT engine; review template provenance, terms and impact | Proposed |
| Schemathesis | https://github.com/schemathesis/schemathesis | Schema-driven API testing | MIT; validate supported schemas and current version | Proposed |
| OWASP API Security Testing Framework | https://github.com/OWASP/api-security-testing-framework | API-specific security testing | Verify repository activity, license and runtime contracts | Evaluate |
| MobSF | https://github.com/MobSF/Mobile-Security-Framework-MobSF | Mobile static/dynamic analysis | GPL-3.0; distribution review required | Proposed |
| MobSFScan | https://github.com/MobSF/mobsfscan | Mobile/source-code pattern analysis | Verify exact pinned-version license and behavior | Proposed |
| Nmap | https://github.com/nmap/nmap | Authorized host/service discovery | GPL-2.0+; distribution review and explicit host/CIDR scope required | Proposed |
| testssl.sh | https://github.com/testssl/testssl.sh | TLS posture assessment | GPL-2.0; distribution review required | Proposed |
| Checkov | https://github.com/bridgecrewio/checkov | IaC/configuration analysis | Apache-2.0; verify supported scanners and policies | Proposed |
| Semgrep | https://github.com/semgrep/semgrep | SAST | Review engine and individual rule licenses separately | Proposed |

## Safety, license and release notes

- Proposed tools are not registered as integrated capabilities and cannot be launched from this repository until adapters and tests land.
- A tool listing is not a health check. Check the adapter's runtime health and dependency status before use.
- A shared target-type vocabulary does not mean every tool supports every target type.
- Active assessments require explicit authorization and scope checks; public URLs are not implicitly authorized.
- Keep scanning policies, rate limits, timeouts, cancellation, redirect validation, egress isolation and evidence redaction enforced at the platform boundary.
- Do not redistribute whole upstream repositories, templates or rules without verifying the exact license and retaining required notices.
- A passing image regression gate does not remediate inherited vulnerabilities. The absolute pinned-image vulnerability gate remains a separate production-release requirement.
