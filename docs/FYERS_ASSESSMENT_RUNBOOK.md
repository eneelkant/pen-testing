# FYERS Assessment Runbook

**Purpose:** Operate this platform safely for an *authorized* FYERS bug-bounty effort.  
**Default mode:** local synthetic fixtures + dry-run.  
**Do not** run live FYERS assessments from this runbook until a human verifies current program scope and binds authorization.

## 1. Verify current official program scope

1. Open https://fyers.in/bug-bounty-program and re-read Terms & Conditions.  
2. Confirm in-scope categories, prohibited techniques, evidence rules, and submission channel.  
3. Treat any hostname not explicitly marked in-scope as **out of scope**.  
4. Record the retrieval date in your notes. If unclear, stop (`UNVERIFIED`).  
5. Do **not** submit anything from automation.

## 2. Configure a synthetic target

1. Use `fyers-api.example.test` as a fixture hostname only (see `configs/assessment_profiles/fyers_non_destructive.yaml`).  
2. Optional sample registry: `scopes/examples/fyers-synthetic.sample.yaml` (not production authz).  
3. Never add real FYERS production hosts to `scopes/registry.yaml` without explicit human approval.  
4. Prefer `http://127.0.0.1:18080/` for headers dry-runs already authorized for local fixtures.

## 3. Run local tests

```bash
source .venv/bin/activate
python -m pytest -q tests/unit
python -m pytest -q tests/unit/test_fyers_readiness.py
```

Synthetic auth/account tests live under unit tests and do not contact FYERS.

## 4. Generate a dry-run plan

```bash
python -m core.cli run --tool headers --target http://127.0.0.1:18080/ --category passive
# MCP equivalent: run_security_assessment(..., dry_run=true, assessment_profile="fyers_non_destructive")
```

`list_assessment_profiles` shows profile metadata. Profiles are not authorization.

## 5. Review and authorize a permitted assessment

1. `validate_target_scope` must succeed for the exact URL/category.  
2. `issue_execution_approval` creates a single-use, expiring approval bound to target/tool/category/profile/plan/policy.  
3. Live runs require `confirm_authorized=true` **and**, for this profile, a valid `approval_id`.  
4. The FYERS profile keeps `live_execution_enabled: false` — live execution remains blocked until a human changes policy intentionally.  
5. Environment flags must not silently authorize unknown targets.

**Stop gate:** If a live FYERS host or dedicated test account is required, produce a manual checklist and stop. Do not proceed without human authorization matching the official program.

## 6. Inspect and redact evidence

- Assessments are saved after `redact_secrets`.  
- Exports use an allowlist of finding fields.  
- Do not paste access tokens, refresh tokens, OTPs, cookies, or customer financial data into tickets.  
- Prefer synthetic account labels (`TEST_ACCOUNT_A` / `TEST_ACCOUNT_B`) in local proofs.

## 7. Validate findings

- Scanner severity never promotes a finding to validated/human-confirmed.  
- Use evidence validation statuses: `candidate`, `needs_review`, `validated`, `rejected`, `duplicate`, `blocked`.  
- Authorization findings need expected vs observed behavior on synthetic accounts.  
- Reject cross-account evidence blends and out-of-scope assets.

## 8. Prepare a report for manual submission

1. Export drafts with `export_report` / `pen-testing export-report`.  
2. Copy into `docs/templates/FYERS_VULNERABILITY_REPORT.md`.  
3. Submit only via the official Zoho form linked from the program page.  
4. Never auto-submit from this platform.

## 9. Stop an assessment safely

1. Prefer dry-run; avoid live workers unless dual-gates and approvals are satisfied.  
2. Respect timeouts; process-local scan slots release in `finally`.  
3. For Compose workers, use existing stop/cleanup procedures in `docs/OPERATIONS.md` / `docs/SCANNER_ISOLATION.md`.  
4. Do not leave transaction mocks enabled (`allow_transactions` must stay false for ordinary assessments).

## 10. What remains unverified

- Concrete FYERS in-scope hostname inventory on the program page.  
- Dedicated researcher test-account availability.  
- Whether any specific production API FQDN is marked in-scope.  
- Form field nuances beyond the public page summary.

Until verified and human-authorized, keep execution on synthetic fixtures and dry-run plans only.
