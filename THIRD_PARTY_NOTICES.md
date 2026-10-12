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
