#!/usr/bin/env bash
# One-command setup: base+MCP install, diagnostics, optional client config printouts.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PEN_ASSUME_YES="${PEN_ASSUME_YES:-0}"

echo "== Unified setup =="
bash installers/install.sh mcp

# shellcheck disable=SC1091
source .venv/bin/activate
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

echo
echo "== Client configuration (print-only; no overwrite) =="
python3 installers/configure_cursor.py --print-only || true
python3 installers/configure_claude.py --print-only || true
python3 installers/configure_gemini.py --print-only || true

echo
echo "== Harmless end-to-end diagnostic =="
python - <<'PY'
from mcp_server import service
print(service.validate_target_scope("https://example.com", "active"))
r = service.run_security_assessment(tool="headers", target="http://127.0.0.1:9", dry_run=True, confirm_authorized=False)
print({"dry_run_status": r.get("status"), "ok": r.get("ok"), "assessment_id": r.get("assessment_id")})
PY

echo
echo "Setup finished."
echo "To apply Cursor project MCP config: python installers/configure_cursor.py --apply"
echo "Docker still required for Shannon — install separately if needed."
