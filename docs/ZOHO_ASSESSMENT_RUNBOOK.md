# Zoho assessment runbook (safe / authorization-first)

**Audience:** Authorized researchers operating this platform  
**Default mode:** Dry-run + synthetic fixtures  
**Forbidden in automated CI / this agent task:** Live requests to Zoho or other third-party hosts

## 0. Preconditions

1. Re-read https://bugbounty.zohocorp.com/bb/info on the day of testing.
2. Confirm researcher eligibility and Service-Specific Terms for the product under test.
3. Confirm the **exact** hostname/URL is eligible. Parent domains and brand membership are insufficient.
4. Add that exact asset to `scopes/registry.yaml` only after human verification (never commit secrets).
5. Keep `configs/assessment_profiles/zoho_non_destructive.yaml` live-disabled until a human explicitly enables it for a verified asset and capability set.

## 1. Local readiness

```bash
PEN_ASSUME_YES=1 bash installers/install.sh mcp
source .venv/bin/activate
python -m core.cli doctor
python -m pytest -q tests/unit/test_zoho_workflow.py tests/unit/test_scanner_isolation.py
```

Do not set `PEN_ALLOW_SHANNON_LIVE`, `PEN_ALLOW_BRIAR_LIVE`, or host-net acks unless the live path is intentionally authorized and isolated.

## 2. Scope validation

```bash
python -m core.cli scope-check --target https://app.example.test/ --category passive
```

MCP:

1. `validate_target_scope(target=..., category="passive")`
2. Reject if `allowed=false`

Unknown, lookalike, expired, wrong scheme/port, or production+active (default) must fail closed.

## 3. Plan (no scanner launch)

MCP: `plan_assessment(tool="headers", target=..., category="passive", profile_id="zoho_non_destructive")`

Expect `launches_scanner=false`. Planning must not start Shannon/Briar/headers workers.

## 4. Dry-run

MCP: `run_security_assessment(..., dry_run=true, profile_id="zoho_non_destructive")`

CLI dry-run equivalents are preferred for local fixtures (`http://127.0.0.1:18080/`).

## 5. Live authorization (human only)

Only after steps 0–4 and a verified registry entry:

1. `authorize_assessment(..., confirm_authorized=true, profile_id=...)` → receive `approval_id`
2. `run_security_assessment(..., dry_run=false, confirm_authorized=true, approval_id=...)`
3. Approval is single-use, time-bound, and target/tool/mode/profile specific
4. Re-validate scope immediately before execution (platform does this again)

If the Zoho profile still has `live_execution_enabled: false`, live runs must fail. That is intentional.

## 6. Finding review

1. `list_findings(assessment_id)`
2. Treat all scanner results as `candidate` / `needs_review`
3. Do **not** submit missing-header-only or other excluded classes
4. Require primary evidence + human confirmation before `validated`
5. Block out-of-scope assets from the report path

## 7. Report preparation

1. `export_report(assessment_id)` → Markdown/JSON/SARIF drafts
2. Complete `reports/templates/zoho_vrp_submission.md` manually
3. Redact cookies, tokens, PII, and unrelated response bodies
4. Submit **manually** via https://bugbounty.zohocorp.com/ — never automate submission

## 8. Abort criteria

Stop immediately if:

- Scope check fails or registry evidence is stale
- Traffic leaves authorized origins / private or metadata addresses appear
- Unauthorized user data is observed
- Service degradation symptoms appear
- Approval expires or policy/profile changes mid-run

## 9. Residual limitations (do not claim otherwise)

- Shannon/Briar may navigate beyond the initial URL inside their engines
- Process-local rate limits are not a multi-tenant quota service
- Platform DNS preflight is not in-engine containment
- Absolute container image CVE gate may still block production releases
