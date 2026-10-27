# Capability registry and integration roadmap

Updated: 2026-10-27

## Runtime truth

The runtime registry is implemented in core/capabilities.py. It contains only tools actually wired into the current CLI and MCP service. The command

    python -m core.cli capabilities

prints the supported adapters and their target types, modes, dependencies, licensing metadata, source URLs and limitations. Use

    python -m core.cli capabilities --tool headers

to inspect one adapter.

A target type in the shared vocabulary is not proof that a tool supports it. Planned integrations are deliberately excluded from the runtime registry until their adapters, tests and execution constraints exist. Missing dependencies must remain visible in health checks; they must not be described as a successful scan.

## Integrated now

| Tool | Actual supported use | Upstream | Licensing note |
|---|---|---|---|
| Shannon | Authorized web/API dynamic and source-informed assessment | https://github.com/KeygraphHQ/shannon | AGPL-3.0-only; review distribution model |
| Briar | Authorized web-oriented dynamic assessment | https://github.com/Stiimy/briar | AGPL-3.0; review distribution model |
| HTTP security headers | Selected response-header checks | https://github.com/eneelkant/pen-testing | First-party repository code |
| Gitleaks | Configured local source secret detection | https://github.com/gitleaks/gitleaks | MIT |
| Trivy | Configured local filesystem/dependency/configuration checks | https://github.com/aquasecurity/trivy | Apache-2.0 |

Current support does not yet mean a complete all-in-one coverage of every target category. The existing scope registry still primarily represents URL fixtures. Host/CIDR, OpenAPI documents, GraphQL-specific, mobile artifact/device and network-service targets need dedicated scope schemas and tested authorization behavior before active scanning support is advertised.

## Proposed integrations (not callable from CLI/MCP yet)

Implement candidates as separate, optional adapter PRs. Inspect source, exact version, runtime contract and LICENSE before coding. Do not vendor entire upstream engines or execute unreviewed templates.

| Candidate | Source repository | Official documentation | Intended first scope |
|---|---|---|---|
| OWASP ZAP | https://github.com/zaproxy/zaproxy | https://www.zaproxy.org/docs/desktop/addons/automation-framework/ | Passive baseline first; controlled active plan later |
| Nuclei | https://github.com/projectdiscovery/nuclei | https://docs.projectdiscovery.io/tools/nuclei/overview | Pinned binary plus curated templates, strict scope and impact policy |
| Schemathesis | https://github.com/schemathesis/schemathesis | https://schemathesis.readthedocs.io/en/stable/ | Schema-driven API tests using explicitly authorized OpenAPI/GraphQL targets |
| OWASP API Security Testing Framework | https://github.com/OWASP/api-security-testing-framework | https://github.com/OWASP/api-security-testing-framework | Evaluate compatibility and licensing before implementing |
| MobSF | https://github.com/MobSF/Mobile-Security-Framework-MobSF | https://mobsf.github.io/docs/ | Isolated mobile static analysis first; validate exact artifact formats |
| MobSFScan | https://github.com/MobSF/mobsfscan | https://github.com/MobSF/mobsfscan | Optional source-code pattern checks |
| Nmap | https://github.com/nmap/nmap | https://nmap.org/book/ | Explicit host/CIDR and port scopes; conservative rate and timeout defaults |
| testssl.sh | https://github.com/testssl/testssl.sh | https://testssl.sh/ | TLS posture checks against an authorized URL/host |
| Checkov | https://github.com/bridgecrewio/checkov | https://www.checkov.io/ | IaC/container configuration scanning |
| Semgrep | https://github.com/semgrep/semgrep | https://semgrep.dev/docs/ | SAST evaluation after engine and rules licensing review |

### Licensing and source reuse

The platform repository is Apache-2.0, but its upstream engines and rules can have different terms. Before embedding, distributing or modifying third-party source, examine the exact LICENSE at the pinned version and retain required notices. In particular, document the consequences of AGPL engines and GPL mobile/network tools for the intended distribution. A process/container boundary is a useful architecture choice but is not, by itself, a legal clearance determination.

## Integration acceptance checklist

- [ ] One immutable capability record per implemented adapter; registry ID matches CLI/MCP adapter ID.
- [ ] Supported target type, mode, license, upstream URL, pin, dependencies, isolation profile and limitations documented.
- [ ] Target and all redirects/destination addresses are checked against authorization and egress policy.
- [ ] Dry-run never launches an active scan or makes unexpected network requests.
- [ ] Missing dependency, unsupported target, timeout, scanner crash and malformed output are reported as unavailable/blocked/failed, never as a clean result.
- [ ] Findings use the common schema and include tool/version, time, target/scope, evidence hash and verification state where available.
- [ ] Tests use local fixtures; no arbitrary public target in CI.
- [ ] CI and real-worker isolation checks pass.
- [ ] Third-party notices and license review updated.
- [ ] Tool matrix and readiness scorecard updated with verifiable evidence.

## Release caveat

The image regression baseline is not a security waiver. A passing regression gate means only that the scan found no new unapproved blocking findings against the reviewed baseline. The absolute pinned-image vulnerability gate must pass under the documented policy before a production release. This registry PR does not change, suppress or waive that gate.
