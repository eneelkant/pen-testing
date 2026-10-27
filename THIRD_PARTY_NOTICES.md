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

- Source: https://github.com/bridgecrewio/checkov
- Optional distribution pin: `checkov==3.3.29` (extra limited to Python 3.10–3.12)
- License: Apache-2.0; verify transitive dependencies for the intended distribution
- Usage: invoked as a separate local executable; source is not vendored
- Official CLI reference: https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html
- Policy: cloud uploads and external Terraform-module downloads are disabled by the adapter

## MobSFScan (optional mobile source scanner)

- Source: https://github.com/MobSF/mobsfscan
- Optional distribution pin: `mobsfscan==1.0.1`
- License: LGPL-3.0-or-later according to upstream package metadata; verify the exact release
- Usage: invoked as a separate local executable; source is not vendored
- Scope: mobile source-code pattern checks only; not APK/IPA binary analysis or dynamic device testing
- Release: https://github.com/MobSF/mobsfscan/releases/tag/1.0.1
- Note: MobSFScan brings Semgrep and other transitive dependencies; review their license and rule terms separately. This is not legal clearance.

## Semgrep (proposed)

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
