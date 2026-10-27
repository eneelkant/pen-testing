# Third-Party Notices

This repository is licensed under Apache-2.0. It integrates external tools by invoking them as separate programs or containers.

## Shannon

- Project: Shannon by Keygraph
- Source: https://github.com/KeygraphHQ/shannon
- Package: `@keygraph/shannon`
- License: GNU Affero General Public License v3.0 only
- Usage in this project: subprocess/`npx` invocation; source not vendored

## Briar

- Project: Briar
- PyPI: https://pypi.org/project/briar-pentest/
- Source (from PyPI metadata): https://github.com/Stiimy/briar
- Package: `briar-pentest`
- License: GNU Affero General Public License v3.0
- Usage in this project: isolated venv/container invocation; source not vendored

## Gitleaks

- Source: https://github.com/gitleaks/gitleaks
- License: MIT
- Usage: optional binary/container via adapter

## Trivy

- Source: https://github.com/aquasecurity/trivy
- License: Apache-2.0
- Usage: optional binary/container via adapter

## Checkov (optional local scanner)

- Project: Checkov
- Source: https://github.com/bridgecrewio/checkov
- Optional distribution pin: `checkov==3.3.29` (Python 3.10–3.12 in this project's optional extra)
- License: Apache-2.0 (verify the exact release and transitive dependencies before redistribution)
- Usage: separate local executable invoked through an adapter; source is not vendored
- Official CLI reference: https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html

## MobSFScan (optional mobile source scanner)

- Project: MobSFScan
- Source: https://github.com/MobSF/mobsfscan
- Optional distribution pin: `mobsfscan==1.0.1`
- License: GNU Lesser General Public License v3 or later (LGPL-3.0-or-later), per upstream PyPI metadata
- Usage: separate local executable invoked through an adapter; source is not vendored
- Scope: mobile application source-code pattern checks only; not APK/IPA binary analysis or dynamic device testing
- Upstream release: https://github.com/MobSF/mobsfscan/releases/tag/1.0.1
- Note: MobSFScan pulls Semgrep and other dependencies. Review the full dependency license inventory before redistribution. This notice is not legal clearance.

## Semgrep (proposed / transitive dependency of MobSFScan)

- Source: https://github.com/semgrep/semgrep
- Engine license: verify the exact pinned package's license; MobSFScan 1.0.1 declares semgrep==1.172.0 as a dependency
- Rules: rules have separate terms; do not redistribute rules without license review


- Source: https://github.com/semgrep/semgrep
- Engine license: LGPL-2.1
- Rules: often under Semgrep Rules License (not redistributed here)

## MCP Python SDK

- Package: `mcp`
- Source: https://github.com/modelcontextprotocol/python-sdk
- License: MIT
- Usage: optional extra `[mcp]` for the stdio/HTTP MCP server

## Python dependencies

Runtime orchestrator dependencies are declared in `pyproject.toml` / `requirements/` and carry their own upstream licenses.
