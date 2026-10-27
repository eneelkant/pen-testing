# Tool Matrix

Last reviewed: 2026-10-27.

The machine-readable descriptive registry is `core/capabilities.py`. Use
`pen-testing capabilities` to list integrations that have in-repository adapters,
and `pen-testing capabilities --include-planned` to include roadmap candidates.
Checkov and MobSFScan are optional local-only source scanners. Their presence does not imply a full mobile binary/device workflow. A registry entry does not mean that an external executable is installed or healthy;
runtime availability comes from adapter health checks. Planned entries are not
dispatchable and must not be described as implemented.

| Tool | Purpose | Target types / modes | Runtime / isolation | License (verify selected release) | Status | Important limitations |
|---|---|---|---|---|---|---|
| [Shannon](https://github.com/KeygraphHQ/shannon) `@keygraph/shannon@3.4.0` | AI-assisted web assessment | Web URL / active | Node.js+npx; upstream Docker worker | AGPL-3.0-only | Integrated adapter | Requires Docker and compatible target/source setup; mutative behavior possible; not an API-schema test runner. |
| [Briar](https://github.com/Stiimy/briar) `briar-pentest==0.4.62` | AI-assisted black-box web assessment | Web URL / active | Dedicated venv or Compose worker | AGPL-3.0 | Integrated adapter | Check runtime health and current upstream compatibility; no claim of comprehensive coverage. |
| Headers adapter | Small set of HTTP security-header checks | Web URL / passive | In-process HTTP GET with destination controls | Apache-2.0 | Integrated / tested | Not a comprehensive web scanner; does not provide TLS grading. |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secret detection | Source path / static | Pinned binary or isolated container | MIT | Integrated adapter | Absence of a finding does not prove that no secret exists. |
| [Trivy](https://github.com/aquasecurity/trivy) | Filesystem, dependency and supported configuration analysis | Source path / static | Pinned binary or isolated container | Apache-2.0 | Integrated adapter | Image release gate is separate; current absolute pinned-image gate may block release. |
| [OWASP ZAP](https://github.com/zaproxy/zaproxy) | Web/API DAST | Web/API URL / passive then active | Planned isolated automation worker | Apache-2.0 | Planned | No adapter yet; do not advertise as runnable. |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Template-driven security checks | Web/API URL and host / active | Planned pinned worker and reviewed template policy | MIT | Planned | Template integrity, quality, license, impact and scope must be controlled. |
| [Schemathesis](https://github.com/schemathesis/schemathesis) | Schema-based API tests | OpenAPI and supported GraphQL/API inputs | Planned worker with destination and request bounds | Verify selected release | Planned | No schema-driven API adapter yet; every generated request must remain in scope. |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Mobile app analysis | Android/iOS artifacts; static/dynamic modes differ | Planned isolated local service | GPL-3.0 | Planned | Artifact support, OS runtime requirements and distribution obligations must be reviewed. |
| [Nmap](https://github.com/nmap/nmap) | Host/service discovery | Explicit host or CIDR / network | Planned least-privilege worker | Verify NPSL terms for selected release | Planned | No network scanner is integrated; CIDR syntax metadata is not authorization. |
| [Checkov](https://github.com/bridgecrewio/checkov) `checkov==3.3.29` | IaC/configuration scanning | Local source path / static | Optional Python CLI over confined workspace; external-module downloads and uploads disabled | Apache-2.0; review transitive dependencies | Integrated adapter (optional extra) | Not a remote scanner; verify runtime health and review output. |
| [MobSFScan](https://github.com/MobSF/mobsfscan) `mobsfscan==1.0.1` | Android/iOS source-code pattern analysis | Local source path / static | Optional Python CLI; raw source-bearing report is temporary and sanitized | LGPL-3.0-or-later; review Semgrep/rule dependencies | Integrated adapter (optional extra) | Not full MobSF; does not scan APK/IPA binaries or perform device/runtime tests. |
| [testssl.sh](https://github.com/testssl/testssl.sh) | TLS posture assessment | Authorized host / TLS | Planned isolated worker | Verify GPL-2.0 terms for selected release | Planned | No adapter yet; only within explicitly approved hosts and ports. |
| [Semgrep](https://github.com/semgrep/semgrep) | Candidate SAST | Source path / static | Not selected | Engine and rules need separate license review | Planned candidate | Do not redistribute rules without verified permission. |

## Integration rules

- Every integrated adapter must have version metadata, a health check, timeout behavior, normalized output, negative tests and a documented isolation profile.
- Syntax validation is not authorization. A valid target must still pass the existing scope, egress and local-path confinement controls before any live action.
- Do not add arbitrary community templates or silently enable destructive scans.
- Distinguish `integrated`, `planned`, `unavailable`, `blocked_by_scope`, `failed` and `completed`; never turn a missing scanner into a clean result.
- Review license terms for the exact version and separately for rules, templates, embedded data and redistributable assets.

## Reference standards and test labs

- [OWASP Web Security Testing Guide](https://owasp.org/projects/web-security-testing-guide)
- [OWASP API Security](https://owasp.org/API-Security/)
- [OWASP Mobile Application Security Testing Guide](https://mas.owasp.org/MASTG/)
- [OWASP crAPI](https://github.com/OWASP/crAPI) and [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) for isolated, intentionally vulnerable test environments.
