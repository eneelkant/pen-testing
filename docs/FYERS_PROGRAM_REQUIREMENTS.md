# FYERS Bug Bounty Program Requirements

**Retrieval date:** 2026-10-27 (Asia/Calcutta)  
**Primary source:** https://fyers.in/bug-bounty-program  
**Additional official references reviewed (not used as authorization):**  
- https://fyers.in/notice-board/bug-bounty-program-is-now-live/  
- Community guidance that submissions go through the bug bounty portal (not email/forums)

**Important:** Public API hostnames found in third-party or developer docs are **not** treated as in-scope assets for automated testing. Hostname inference is refused.

## Verified program facts (from official page)

| Topic | Official evidence | Status |
|---|---|---|
| Eligible assets (high level) | “FYERS Trading Platform (Web & Mobile App)” and “FYERS APIs part of trading platform”; only FYERS-owned/operated/maintained systems with full technical control | Verified |
| Explicit hostname / URL inventory | Page says assets must be “explicitly listed / marked In Scope”; no concrete production hostname list was published on the retrieved page | **UNVERIFIED** (inventory) |
| Production APIs in scope | “FYERS APIs part of trading platform” are in-scope at category level; specific API hosts not listed on the page | Category verified; hosts **UNVERIFIED** |
| Web + mobile covered | Explicitly listed under In-Scope | Verified |
| Auth / account testing rules | PoC must use researcher’s own account; accessing other users’ trading accounts is disqualifying; no brute-force of credentials/2FA/client IDs | Verified |
| OTP / SMS / email / recovery | Sending OTPs/messages/emails/SMS to other users prohibited; OTP abuse causing DoS is a severity example for High, not a permitted technique license | Verified (prohibited against other users) |
| MFA bypass | Login + OTP bypass is Critical *when demonstrated*; attempting brute-force of 2FA is prohibited | Verified |
| Rate limits / automation | DoS, resource exhaustion, rate-limit bypass, and automated high-volume scanning prohibited | Verified |
| Financial / PII handling | Avoid bulk extraction; delete inadvertent sensitive data; PAN/Aadhaar/BO-DP exposure listed as Critical impacts; do not access other users’ data | Verified |
| Excluded classes | Third-party/partner/legacy/internal/marketing; known/accepted issues; functional/UI; missing non-security headers; many hardening observations; theoretical chains | Verified |
| Evidence requirements | Clear steps, impact, PoC, screenshots/video; demonstrated practical impact; own account only; minimum interaction | Verified |
| Disclosure | No public disclosure without FYERS written approval; official Zoho form only; email submissions not valid for bounty | Verified |
| Dedicated test accounts | Not stated on the retrieved official page | **UNVERIFIED** |
| Rewards | Critical up to ₹1,00,000; High ₹50,000; Medium ₹20,000; Low ₹5,000; discretionary; INR + KYC | **Confirmed on official page** as published maxima; not a guarantee that every Critical finding pays the maximum |
| Safe harbor | Page states FYERS provides **no** “safe harbor” protections for activity deemed unlawful under Indian law | Verified |
| Market-hours restriction | Actions affecting live trading systems during market hours are prohibited | Verified |

Submission channel (do not auto-use from this platform): official Zoho form linked from the program page; queries: `bugbounty@fyers.in`.

## Requirement mapping

| Requirement | Official evidence | Existing control | Gap | Proposed action |
|---|---|---|---|---|
| Test only explicitly in-scope FYERS assets | Program scope + “any domain/subdomain not explicitly marked In Scope” | `scopes/registry.yaml` default-deny | No FYERS hosts in registry (correct); no profile documenting non-executable stance | Add disabled `fyers_non_destructive` profile with synthetic fixture only |
| Do not infer scope from public API docs | Scope language; out-of-scope unlisted domains | Scope engine requires registry match | Operators could still add production hosts manually | Runbook: refuse hostname inference; keep production hosts out of executable configs |
| No high-volume / DoS / rate-limit stress | Prohibited testing techniques | `prohibited_actions`, rate limits, concurrency caps | Profile must exclude destructive/high-volume categories | Profile + policy checks exclude DoS/high-volume |
| No credential stuffing / OTP brute force | Prohibited techniques | Not modeled as a scanner capability today | Need explicit profile prohibitions + synthetic OTP tests only | Profile excludes auth attacks; local OTP mock for regression |
| Own-account PoC only; no cross-account access | PoC + disqualification rules | N/A (no FYERS client) | Need local account-isolation fixtures | Synthetic `TEST_ACCOUNT_A/B` API + tests |
| No unauthorized trading / fund changes | Critical examples + prohibited live trading impact | No trading integration | Must keep transaction ops out of default assessment | Profile excludes transactions; mock trading disabled by default |
| Redact secrets / financial evidence in drafts | Confidentiality + PoC limits | `redact_secrets` | Missing OTP/cookie/session/account patterns | Extend redaction + report allowlist discipline |
| Manual submission only | Zoho form; no email submissions for bounty | `export_report` marks human review; no auto-submit | Need FYERS report template + runbook | Add template; never wire submission |
| Rewards are discretionary maxima | Reward bands + right to withhold | Docs previously treated ₹1,00,000 as marketing | Operators may over-claim eligibility | Document confirmed maxima with non-guarantee wording |
| Dedicated test accounts / staging | Not published | N/A | Cannot automate live FYERS without human authz + accounts | Checklist stop-gate in runbook |
| Exact host/port/scheme + redirect safety | Implied by asset listing / PoC constraints | Host match + same-origin redirect helpers | Bound live approvals + revalidation gaps | Approval tokens + stricter live gates |
| Evidence must prove impact without other users’ data | Demonstrated impact rules | Finding lifecycle + candidate default | Need assessment-bound evidence validation statuses | Evidence validator + quarantine statuses |

## Unverified items (stop and ask a human)

1. Concrete in-scope hostname / mobile package inventory.  
2. Whether production API hosts (any specific FQDN) are marked in-scope.  
3. Availability of dedicated researcher test accounts.  
4. Whether any staging environment is offered to researchers.  
5. Current form field requirements beyond the page summary (follow the Zoho form manually; do not submit from automation).

Until those are verified and a human binds an authorization record, **live FYERS execution remains blocked** by platform policy and by the assessment profile defaults introduced in this branch.
