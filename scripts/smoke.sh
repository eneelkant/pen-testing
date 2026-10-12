#!/usr/bin/env bash
# Safe local smoke test: unit tests + scope rejection + headers against local fixture.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="${ROOT}${PYTHONPATH:+:$PYTHONPATH}"

echo "== unit tests =="
python3 -m pytest -q tests/unit

echo "== scope rejection for unauthorized public URL =="
if python3 -m core.cli scope-check --target "https://example.com" --category active; then
  echo "ERROR: unauthorized target was allowed" >&2
  exit 1
else
  echo "OK: unauthorized target blocked"
fi

echo "== dry-run shannon/briar without executing scans =="
# Fixture-only skip requires an explicit env gate (see CLI --skip-scope-check).
PEN_ALLOW_SKIP_SCOPE=1 python3 -m core.cli run --tool shannon --target "https://127.0.0.1:9" --repo "$ROOT" --dry-run --skip-scope-check >/dev/null
PEN_ALLOW_SKIP_SCOPE=1 python3 -m core.cli run --tool briar --target "https://127.0.0.1:9" --mode quick --dry-run --skip-scope-check >/dev/null
echo "OK: dry-runs completed"

echo "== daily report stub =="
python3 -m core.cli daily-report --output reports/out/smoke-daily.md >/dev/null
echo "Smoke test passed."
