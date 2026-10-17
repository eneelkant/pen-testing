# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.0a14 | Security fixes on the current alpha line |
| 0.1.x | Historical; no longer the development line |

## Responsible disclosure

Report security issues in **this repository** privately via GitHub Security Advisories when available, or by contacting the repository owner.

Please include:

- Affected component/path
- Impact description
- Minimal reproduction against a local fixture when possible
- Whether any secrets were exposed

Do **not** open public issues with exploit details for unpatched flaws.

## Scope of this project

This project helps orchestrate authorized testing. Misuse against systems without permission is prohibited. Maintainers are not responsible for unlawful use of integrated upstream tools.

## Secrets

- Never commit `.env` files or API keys
- Rotate credentials if they appear in logs or CI artifacts
- Private bounty evidence must stay out of public PRs
