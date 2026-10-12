# Source Audit

Verification date: **2026-10-12** (agent run environment).

This audit treats advertised features as hypotheses until confirmed against authoritative sources.

## Repository under development

| Field | Value |
|---|---|
| Repository | https://github.com/eneelkant/pen-testing |
| Prior content | Apache-2.0 `LICENSE`, minimal README (`# pen-testing` / “Check the website”) |
| Branches | `main` only at audit start |
| Decision | Greenfield platform scaffolding on Apache-2.0; integrate AGPL tools via **separate process/container invocation**, not by vendoring their source |

## Shannon (Keygraph)

| Field | Verified value |
|---|---|
| Source | https://github.com/KeygraphHQ/shannon |
| npm package | `@keygraph/shannon` |
| Verified release | **3.4.0** (npm `latest` on audit date) |
| License | **AGPL-3.0-only** |
| Execution model | `npx @keygraph/shannon@…` launcher; pulls worker image; requires **Docker** + **Node.js ≥ 18** |
| Typical commands | `setup`, `start -u <url> -r <repo>`, `stop`, `status`, `logs`, `scans`, `version`, `reset` |
| Source requirement | White-box OSS edition requires repository path (`-r`) plus running target URL (`-u`) |
| Reports | PDF, Markdown, JSON, **SARIF 2.1.0** (enabled by default for exploit-mode scans per upstream README) |
| Providers | Anthropic, OpenAI, xAI, AWS Bedrock, Pi catalogue providers, custom base URL / local OpenAI-compatible endpoints |
| Safety | Upstream warns it executes real exploits; use only on owned/authorized non-production systems |
| Integration recommendation | **Invoke pinned npx package from adapter**; do not copy Shannon source into this repo. Document AGPL obligations if you modify Shannon itself. Preserve attribution in `THIRD_PARTY_NOTICES.md`. |

Verified CLI help excerpt (3.4.0):

```text
npx @keygraph/shannon start --url <url> --repo <path> [options]
```

## Briar (`briar-pentest`)

| Field | Verified value |
|---|---|
| PyPI | https://pypi.org/project/briar-pentest/ |
| Verified release | **0.4.62** |
| Requires Python | **≥3.10** (classifiers list 3.12–3.14) |
| Canonical source (from PyPI `project_urls`) | https://github.com/Stiimy/briar |
| License (PyPI / upstream LICENSE header) | **AGPL-3.0** |
| Maintainer (PyPI author) | Stiimy |
| Maintenance signal | GitHub `pushed_at` 2026-08-10; PyPI classifier **Alpha** |
| CLI entrypoint | `briar` → `briar.cli:cli` |
| Confirmed commands | `setup`, `scan`, `demo`, `serve`, `status`, `workspaces`, `resume`, `diff` |
| Confirmed scan flags | `-u/--url`, `-r/--repo`, `--quick`, `--deep`, `-c`, `-o`, `--output-json`, `--lang`, `--resume` |
| Browser automation | Selenium listed under extra `full`; `--deep` help text references browser |
| Docker | Upstream advertises “No Docker required”; optional for isolation in this platform |
| Providers (from setup prompt mapping in installed package) | ollama, openai, anthropic, deepseek, groq, mistral, plus custom endpoint path |
| Safe self-test | `briar demo` — built-in vulnerable app, no external target/API key required (per `--help`) |
| Integration recommendation | Install into **isolated venv or container** pinned to `briar-pentest==0.4.62`. Enforce scope in this platform’s wrapper before `briar scan`. Prefer `briar demo` for CI smoke. Do not vendor Briar source. |

Hypothesis check:

| Claim | Result |
|---|---|
| `briar setup` exists | **Confirmed** |
| `briar scan` exists | **Confirmed** |
| `--quick` / `--deep` exist | **Confirmed** on 0.4.62 |
| Works with URL-only black-box | **Supported by CLI** (`-u` without requiring `-r`) |
| No Docker required | **Upstream claim**; this platform still recommends Docker isolation |

## Additional candidates (shortlist)

See `docs/TOOL_MATRIX.md` for full matrix. Selected for first version:

1. **Security headers checker** — in-tree passive GET adapter (Apache-2.0 with this repo).
2. **Gitleaks** — MIT; secrets detection via binary/container.
3. **Trivy** — Apache-2.0; filesystem/dependency scanning via binary/container.
4. **Semgrep CE** — LGPL-2.1 engine; rules licensing is separate (Semgrep Rules License) — **proposed**, not bundled.

## Licensing implications for this repository

- This repository remains **Apache-2.0**.
- Shannon and Briar are **AGPL-3.0**. Invoking them as separate programs/containers is the integration strategy.
- Modifying or serving modified Shannon/Briar code triggers AGPL source-offer obligations — out of scope for this orchestrator.
- Do not combine AGPL application code into a single linked Python package with this orchestrator.

## Blockers observed during audit

| Blocker | Impact |
|---|---|
| Docker Engine not installed in the cloud agent VM | Cannot run Shannon worker or compose-based smoke against containers here |
| `python3-venv` missing in agent image | Host venv creation failed; used `pip install --target` for Briar CLI inspection |
| Briar README marked outdated by upstream | Relied on installed CLI `--help` and PyPI metadata over README marketing text |
