# Tool Matrix

Verification date: 2026-10-12.

| Tool | Purpose | Testing mode | Runtime | License | Integration | Limitations | Status |
|---|---|---|---|---|---|---|---|
| [Shannon](https://github.com/KeygraphHQ/shannon) (`@keygraph/shannon@3.4.0`) | AI white-box web/API pentest with exploit validation | Dynamic + source-informed | Node.js 18+ launcher, Docker worker, LLM provider | AGPL-3.0-only | Adapter via `npx` | Requires Docker + source repo path; mutative exploits; model cost/time | Integrated (adapter) |
| [Briar](https://github.com/Stiimy/briar) (`briar-pentest==0.4.62`) | AI black-box/optional white-box web pentest | Dynamic (+ optional source) | Python ≥3.10; Docker optional | AGPL-3.0 | Adapter via isolated venv/container | Alpha; README outdated; browser via `full`/deep mode | Integrated (adapter) |
| Headers adapter (in-repo) | Missing security headers | Passive HTTP GET | Python stdlib | Apache-2.0 | `HeadersAdapter` | Header presence only; no TLS grade | Integrated / tested |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secret detection | Static | Go binary or container | MIT | `GitleaksAdapter` | Needs binary/Docker | Integrated (optional binary) |
| [Trivy](https://github.com/aquasecurity/trivy) | FS/dependency vulns | Dependency / config | Binary or container | Apache-2.0 | `TrivyAdapter` | Needs binary/Docker; DB download | Integrated (optional binary) |
| [Semgrep CE](https://github.com/semgrep/semgrep) | SAST | Static | Python/CLI | LGPL-2.1 engine; **rules often non-OSI** | Proposed reference only | Do not redistribute Semgrep Registry rules in a competing SaaS | Proposed |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Template DAST | Dynamic | Go binary | MIT | Not integrated in v0.1 | Template quality varies; still needs scope controls | Proposed |
| SSL Labs scan clients | TLS posture | Passive/remote | Various | Apache-2.0 (legacy tool) | Not integrated | External dependency on Qualys service for full grades | Proposed |

## Selection rationale

v0.1 prioritizes:

1. Verified Shannon + Briar adapters with scope gates
2. One pure-Python passive checker for reliable CI tests
3. Two widely maintained SCA/secret tools with permissive licenses

Nuclei/Semgrep remain extension points without bundling aggressive templates or non-redistributable rules.
