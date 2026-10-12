# Integration Guide

## Authorization {#authorization}

Active and remote passive checks require an entry in `scopes/registry.yaml` (or `PEN_SCOPES_FILE`).

Before each active run the ScopeEngine:

1. Resolves the exact target string
2. Matches it against `allowed_assets` (exact URL/host/CIDR — **no subdomain expansion**)
3. Applies exclusions
4. Checks test category, start/expiry, and production refusal defaults
5. Records an allow/deny decision

Public websites are not authorized by default.

```bash
python -m core.cli scope-check --target https://staging.example.com --category active
```

## Shannon

Pinned package: `@keygraph/shannon@3.4.0` (override with `PEN_SHANNON_PACKAGE`).

Prerequisites: Docker daemon, Node.js 18+, provider credentials as required by Shannon.

```bash
# Health
python -m core.cli health --tool shannon

# Dry-run (prints planned command; no scan)
python -m core.cli run --tool shannon \
  --target https://staging.example.com \
  --repo /path/to/source \
  --dry-run

# Live run only after scope allow + human intent
python -m core.cli run --tool shannon \
  --target https://staging.example.com \
  --repo /path/to/source \
  --output reports/out/shannon-1
```

Equivalent upstream command:

```bash
npx @keygraph/shannon@3.4.0 start -u <url> -r <repo> -o <outdir>
```

## Briar

Pinned package: `briar-pentest==0.4.62` (override with `PEN_BRIAR_PACKAGE`).

```bash
python3 -m venv .venv-briar
.venv-briar/bin/pip install 'briar-pentest==0.4.62'
export PEN_BRIAR_PYTHON=$PWD/.venv-briar/bin/python

python -m core.cli health --tool briar

# Built-in demo (no external target) — preferred local smoke
# --skip-scope-check requires an explicit fixture gate (scope only; egress still enforced):
PEN_ALLOW_SKIP_SCOPE=1 python -m core.cli run --tool briar --target demo --demo --skip-scope-check

# Authorized URL scan modes: quick | standard | deep
python -m core.cli run --tool briar --target https://staging.example.com --mode quick
```

Scope enforcement is implemented in the wrapper. It cannot guarantee containment of every browser navigation Briar may perform; keep network policy tight and targets staging-only.

## Headers / Gitleaks / Trivy

```bash
python -m core.cli run --tool headers --target http://127.0.0.1:18080/ --category passive
python -m core.cli run --tool gitleaks --target . --repo .
python -m core.cli run --tool trivy --target . --repo .
```

## Reports

```bash
python -m core.cli export-report --input reports/out/run.json --outdir reports/out/draft
python -m core.cli daily-report --output reports/out/daily-report.md
```

Drafts require human review. Nothing is submitted to bounty platforms automatically.
