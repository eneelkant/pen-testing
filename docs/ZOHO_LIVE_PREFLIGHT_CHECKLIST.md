# Zoho VRP live preflight checklist

**Session date:** 2026-10-27 (Asia/Calcutta)  
**Branch:** `cursor/zoho-vrp-preflight-d1de`  
**Official rules re-fetched:** https://bugbounty.zohocorp.com/bb/info (page “Last updated on: 11th April 2024”; retrieved 2026-10-27 Asia/Calcutta)  
**Requested target:** `REPLACE_WITH_EXACT_AUTHORIZED_HOST_AND_BASE_URL`  
**Live Zoho requests this session:** **0** (hard stop)

This checklist must be completed by a human before any live request to a Zoho asset. Completing repository unit tests alone does **not** authorize testing.

## Blockers that stopped this session

| ID | Blocker | Status |
|---|---|---|
| B1 | Exact host/base URL is still the placeholder string | BLOCKING |
| B2 | `scopes/registry.yaml` contains no Zoho assets (only local fixture + expired demo) | BLOCKING |
| B3 | `zoho_non_destructive` has `live_execution_enabled: false` and synthetic-only targets | EXPECTED / BLOCKING for live |
| B4 | Proposed `zoho_live_candidate` also remains `live_execution_enabled: false` | EXPECTED until human enablement |
| B5 | Service-Specific Terms for a selected product were not identified (product unknown) | BLOCKING |
| B6 | Researcher-owned test accounts / attestation not provided to this agent | BLOCKING |
| B7 | Absolute pinned-image release gate remains blocked on the platform (unrelated to VRP scope, but platform is not production-ready) | INFORMATIONAL |

## Human verification checklist (required)

### A. Program and eligibility

- [ ] Re-read https://bugbounty.zohocorp.com/bb/info on the assessment day
- [ ] Confirm researcher eligibility (age, employment, sanctions, family rules)
- [ ] Identify the specific Zoho / ManageEngine / other listed product under test
- [ ] Read that product’s Service-Specific Terms and record URL + retrieval date
- [ ] Confirm the intended tests are not in the published exclusion list

### B. Exact target evidence

- [ ] Exact hostname (no wildcards, no parent-domain assumption)
- [ ] Exact base URL including scheme and port if non-default
- [ ] Evidence the host is an eligible Zoho-owned / branded asset **and** permitted for the planned test type
- [ ] Confirmation that `bugbounty.zohocorp.com`, `*.zoho.com`, redirects, DNS, or certificates alone were **not** used as authorization
- [ ] Explicitly rejected lookalikes / related hosts documented

### C. Registry and profile

- [ ] Add **only** the verified exact asset(s) to a local (or reviewed) `scopes/registry.yaml` entry
- [ ] Set `allowed_test_categories`, `prohibited_actions`, `rate_limit_rps`, schemes/ports, expiry, `live_execution_allowed`
- [ ] Record `last_verified_at` and `approval_evidence` / policy reference
- [ ] Do not commit secrets, cookies, or session material
- [ ] Review `configs/assessment_profiles/zoho_live_candidate.yaml` and replace PLACEHOLDER notes
- [ ] Enable `live_execution_enabled` only in a reviewed change after the above

### D. Accounts and data

- [ ] Use only researcher-owned accounts (or accounts with explicit owner consent)
- [ ] Prepare only test-owned records; never access other customers’ data
- [ ] If two-account authz testing is planned, both accounts are researcher-controlled
- [ ] Plan hard-stop if unauthorized personal/tenant data appears

### E. Execution controls

- [ ] `validate_target_scope` returns allowed for the exact URL/category
- [ ] `plan_assessment` returns `launches_scanner=false`
- [ ] Dry-run rehearsed against synthetic/local fixtures first
- [ ] Live path uses `authorize_assessment` → bound `approval_id` → `run_security_assessment`
- [ ] Operator budget: ≤1 request/second, ≤60 live requests/session
- [ ] Shannon/Briar live env gates remain off unless a separate isolation plan is reviewed
- [ ] No broad crawl, fuzzing campaign, credential attacks, or DDoS

### F. Reporting

- [ ] Treat scanner output as candidate only
- [ ] Do not report missing-header-only / excluded classes without eligible impact
- [ ] Draft via `reports/templates/zoho_vrp_submission.md`
- [ ] Manual submission only through https://bugbounty.zohocorp.com/

## What to send this agent next (to unblock live work)

Provide all of the following in plain text (no cookies/tokens):

1. Exact authorized `https://host/...` base URL  
2. Product name + Service-Specific Terms URL + retrieval date  
3. Scope evidence notes (why this exact host is eligible)  
4. Whether headers-only passive checks are the intended first live tool  
5. Confirmation you own the test account(s)  
6. Explicit instruction to enable `zoho_live_candidate` live execution after registry update  

Until then, **no live Zoho assessment will be performed**.
